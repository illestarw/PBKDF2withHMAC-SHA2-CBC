# PBKDF2withHMAC-SHA2-CBC
Java encryption framework implementation using Password-Based Key Derivation Function #2

# Purpose
To serve as an extendable framework that process cryptographic safe encryption and decryption.

# Current supported Cipher / keyed-hash Message Authentication Code
## Cipher
AES, Triple DES
## Mode
CBC
## HMAC
SHA-256, SHA-512

# Usage
Run the project 
```sh
$ java Launcher.java 
```
Follow the instruction on the command interface of the Launcher, select the mode and configurations to encrypt/decrypt a file.

# Input
```sh
file_name.file_extension
```
Please place your file at the following location
  UNIX-based OS:  (user home directory)/javaenc
  Windows OS:     C:\\(user directory)\\javaenc
  
# Output
```sh
file_name.file_extension
```
file will be generated under the same directory
  UNIX-based OS:  (user home directory)/javaenc
  Windows OS:     C:\\(user directory)\\javaenc
