# Python Shellcode Encrypter

Python3 shellcode encryptor and obfuscator script <br />
Uses XOR or AES encryption and outputs shellcode in different encoded formats <br />
**_Output encrypted shellcode will be copied to clipboard in all cases except for the raw file output!_**<br />
<br />
**Runs on Windows, MacOS and Linux!**<br />

Shellcode output formats:
- Base64 encoded
- C hex format (\x00\x00...)
- CSharp hex format (0x00,0x00...)
- Raw file output - "shellcode-raw-encrypted.bin" file in current directory

**REQUIREMENTS:**<br />
ALL Operating Systems:
```
pip3 install pyperclip pycrypto pycryptodome
```
Additional Linux OS requirements:
```
sudo apt-get install xclip
```

**GETTING STARTED:**<br />
First, generate raw shellcode from Cobalt Strike as input:
```
Cobalt Strike --> Payloads --> Windows Stageless Payload 
--> Select Listener & Output = Raw
```
Use raw **shellcode.bin** file as input to the **Py-Crypter.py** script, or use any other file type you want to encrypt+encode!

--------------------------------------
## **USAGE:**
```
python3 Py-Crypter.py -h
usage: Py-Crypter.py [-h] [-file FILE] [-algo {xor,aes}] [-key KEY] [-output {b64,hex,csharp,raw}]

Shellcode XOR/AES encrypter

optional arguments:
  -h, --help            show this help message and exit
  -file FILE, -f FILE   Raw binary shellcode file from C2
  -algo {xor,aes}, -a {xor,aes}
                        The encryption algorithm
  -key KEY, -k KEY      Create a random encryption key or use key provide by input (Use "random" as argument
                        or provide your own key)
  -output {b64,hex,csharp,raw}, -o {b64,hex,csharp,raw}
                        Type of shellcode to output (args: base64, hex, csharp, raw)
```

**BASE64 encoded, encrypted format output**<br />
Format = "IyBQeXRob24gU2hlbGxjb2RlIEVuY3J5..."
```
python3 Py-Crypter.py -f beacon64.bin -a xor -output b64 -k random
[+] Encrypted BASE64 shellcode has been copied to Clipboard!
[+] XOR KEY: 07BR0DA8K7R7E11TW6GX
```

**C hex format, AES encrypted output**<br />
Format = "\x12\x34\x56\x78\x9a..."
```
python3 Py-Crypter.py -f beacon64.bin -a aes -output hex -k MyEncryptionKey
[+] Encrypted HEX shellcode has been copied to Clipboard!
[+] AES KEY: mykeymykeyasdfgh
[+] AESkey[] = { 0x6d,0x79,0x6b,0x65,0x79,0x6d,0x79,0x6b,0x65,0x79,0x61,0x73,0x64,0x66,0x67,0x68 };
[+] IV[] = { 0x5c,0xf3,0x68,0x8e,0x2d,0xd5,0x7d,0x11,0xef,0x17,0xcf,0xf,0x5a,0xf4,0xf,0xef };
```

**CSharp hex format, XOR encrypted output**<br />
Format = "0xc9,0x1f,0xb3,0xac,0xc0,0xac,0x94,0x34..."
```
python3 Py-Crypter.py -f beacon64.bin -a xor -k random -o csharp
[+] Encrypted CSharp shellcode has been copied to Clipboard!
[+] XOR KEY: 5W0H0DT4U1FS0CKP
```

**RAW binary, XOR encrypted output (UTF-8 encoding)**
```
python3 Py-Crypter.py -f beacon64.bin -a xor -o raw -k random
[+] Saving encrypted shellcode to output binary file
[+] Output file name: shellcode-raw-encrypted.bin
[+] XOR KEY: FL4PKBJ1AU30DBQT1W0Q
```
