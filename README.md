# PaddingOracleAttack

A content decryption attack using Padding Oracle Attack.

For running:
1. you need to have pycryptodome library (install with the command : pip3 pycryptodome).
2. clone the repository
3. cd to the folder 'PaddingOracleAttack'
4. run : python3 main.py ENCRYPTED_CONTENT KEY IV

example: 
python3 main.py 83e10d51e6d122ca3faf089c7a924a7b 6D796465736B6579 0000000000000000 

83e10d51e6d122ca3faf089c7a924a7b is the cipher text
6D796465736B6579 = mydeskey in hex
0000000000000000 is the iv

the program will print Hello World (decode 83e10d51e6d122ca3faf089c7a924a7b to Hello World)
