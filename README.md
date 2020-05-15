# FileSecure_AES
File Secure can be used to encrypt and decrypt your files using AES 128, 192 and 256

Steps to perform Encryption
1. run python FileSecure.py
2. Choose 1 for Encryption
3. Choose between available encryption schemes (128, 192 and 256)
4. Enter the fileName with path to be encrypted
5. Application would provide the key used for encryption on the console and would also write the key in file Key.txt (use this key for decryption)
6. Your file is encrypted once system prints File Encrypted

Steps to perform decryption
1. run python FileSecure.py
2. Choose 2 for Decryption
3. Choose between available encryption schemes (128, 192 and 256), make sure to choose the scheme with which file was encrypted
4. Enter the fileName to be given after decryption, also provide the origional format of file
5. Enter the AES Key provided during encryption
6. Your file is decrypted once system prints File Decrypted
