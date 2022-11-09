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
