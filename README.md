# Python Shellcode Encrypter

Python3 shellcode encryptor and obfuscator script.<br />
Uses XOR or AES encryption and outputs shellcode in different encoded formats.<br />
**_Output encrypted shellcode will be copied to clipboard in all cases except for the raw file output!_**<br />
<br />
**Runs on Windows, MacOS, and Linux!**<br />

Shellcode output formats:
- Base64 encoded (`dGhpcyBpcyB0aGUgb3V0cHV0IGZvcm1hdA==`)
- C hex format (`\x00\x01...`)
- CSharp hex format (`0x00,0x01...`)
- Chunked shellcode - Output any of the above encrypted formats and split shellcode into even "chunks" on 4 to 5 newlines
- Manifest file - Output shellcode into an embedded 'config.manifest' file that's encrypted + hex encoded
- Raw file output - `shellcode-raw-encrypted.bin` file in current directory


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
usage: Py-Crypter.py [-h] [-file FILE] [-algo {xor,aes}] [-key KEY] [-output {b64,hex,csharp,raw}] [OPTIONAL: -chunked]

Shellcode XOR/AES encrypter

optional arguments:
  -h, --help            show this help message and exit
  -file FILE, -f FILE   Raw binary shellcode file from C2
  -algo {xor,aes}, -a {xor,aes}
                        The encryption algorithm
  -key KEY, -k KEY      Create a random encryption key or use key provide by input (Use "random" as argument
                        or provide your own key)
  -output {b64,hex,csharp,manifest,raw}, -o {b64,hex,csharp,manifest,raw}
                        Type of shellcode to output (args: base64, hex, csharp, manifest, raw)
  -chunked, -c          Split shellcode into 4 even chunks (separated by new lines)
```

**BASE64 encoded, encrypted format output**<br />
Format = "*IyBQeXRob24gU2hlbGxjb2RlIEVuY3J5...*"
```
python3 Py-Crypter.py -f beacon64.bin -a xor -output b64 -k random
[*] Shellcode input length: 334159
[+] Encrypted BASE64 shellcode has been copied to Clipboard!
[+] XOR KEY: 07BR0DA8K7R7E11TW6GX
```

**C hex format, AES encrypted output**<br />
Format = "*\x12\x34\x56\x78\x9a...*"
```
python3 Py-Crypter.py -f beacon64.bin -a aes -output hex -k MyEncryptionKey
[*] Shellcode input length: 334159
[+] Encrypted HEX shellcode has been copied to Clipboard!
[+] AES KEY: mykeymykeyasdfgh
[+] AESkey[] = { 0x6d,0x79,0x6b,0x65,0x79,0x6d,0x79,0x6b,0x65,0x79,0x61,0x73,0x64,0x66,0x67,0x68 };
[+] IV[] = { 0x5c,0xf3,0x68,0x8e,0x2d,0xd5,0x7d,0x11,0xef,0x17,0xcf,0xf,0x5a,0xf4,0xf,0xef };
```

**CSharp hex format, XOR encrypted output**<br />
Format = "*0xc9,0x1f,0xb3,0xac,0xc0,0xac,0x94,0x34...*"
```
python3 Py-Crypter.py -f beacon64.bin -a xor -k random -o csharp
[*] Shellcode input length: 334159
[+] Encrypted CSharp shellcode has been copied to Clipboard!
[+] XOR KEY: 5W0H0DT4U1FS0CKP
```

**Chunked shellcode using one of the above output formats**<br />
Format = <br />
*txq03L7Q90xXMhAaBmUVZx0aBuorcLweN3raGV9...*<br />
*ahfHFQ4ZSpe+x75LUjdwy/hDKx8zgRvMfV9ywBI...*<br />
*aJoy7R9ywBITcU/oUQ3cPhkPzHVbf0qCdrNKsH9...*<br />
*NktSNzhOcLrBVjNRSwaPdr0k1cjt9dgqZl1z6+3...*<br />
```
python3 Py-Crypter.py -f beacon64.bin -a xor -k random -o b64 -chunked
[*] Shellcode input length: 334159
[+] Chunking shellcode into 4-5 parts with average length of 92
[+] Encrypted BASE64 shellcode has been copied to Clipboard!
[+] XOR Encryption KEY: KR78N87LW2QKG5G6
```

**Manifest file output - Creates 'config'manifest' file with embedded shellcode**
```
python3 Py-Crypter.py -f beacon64.bin -a xor -k random -o manifest
[*] Getting shellcode from file: calc-x64.bin
[+] Manifest shellcode file contents copied to Clipboard!
[+] Successfully created manifest file: 'config.manifest'
[+] XOR KEY: LM2S20LUE87YKFR2
```

**RAW binary, XOR encrypted output (UTF-8 encoding)**
```
python3 Py-Crypter.py -f beacon64.bin -a xor -o raw -k random
[*] Shellcode input length: 334159
[+] Saving encrypted shellcode to output binary file
[+] Output file name: shellcode-raw-encrypted.bin
[+] XOR KEY: FL4PKBJ1AU30DBQT1W0Q
```
