# Python Shellcode Encrypter

Python3 shellcode encryptor and obfuscator script <br />
Uses XOR or AES encryption and outputs shellcode in different encoded formats <br />
**Runs on Windows, MacOS and Linux**<br />

Shellcode output formats:
- Base64 encoded
- C hex format
- CSharp hex format
- Raw file output - "shellcode-raw-encrypted.bin" file in current dir

**REQUIREMENTS:**<br />
<br />
Windows and MacOS
```
pip3 install pyperclip pycrypto
```
Linux
```
pip3 install pyperclip pycrypto
sudo apt-get install xclip
```


## **USAGE:**
```
python3 test.py -h
usage: test.py [-h] [-file FILE] [-algo {xor,aes}] [-key KEY] [-output {b64,hex,csharp,raw}]

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
python3 Py-Crypter.py -f beacon64.bin -output b64 -k random
[+] Encrypted BASE64 shellcode has been copied to Clipboard!)
[+] XOR KEY: 07BR0DA8K7R7E11TW6GX
```

**C encrypted hex format output**<br />
Format = "\x12\x34\x56\x78\x9a..."
```
python3 Py-Crypter.py -f beacon64.bin -output hex -k MyEncryptionKey
[+] Encrypted HEX shellcode has been copied to Clipboard!
[+] XOR KEY: MyEncryptionKey
```

**CSharp encrypted hex format output**<br />
Format = "0xc9,0x1f,0xb3,0xac,0xc0,0xac,0x94,0x34..."
```
python3 Py-Crypter.py -f beacon64.bin -k random -o csharp
[+] Encrypted CSharp shellcode has been copied to Clipboard!
[+] XOR KEY: 5W0H0DT4U1FS0CKP
```

**RAW encrypted binary output (UTF-8 encoding)**
```
python3 Py-Crypter.py -f beacon64.bin -o raw -k random
[+] Saving encrypted shellcode to output binary file
[+] Output file name: SC-raw-encrypted.bin
[+] XOR KEY: FL4PKBJ1AU30DBQT1W0Q
```
