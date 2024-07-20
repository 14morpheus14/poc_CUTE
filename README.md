# A proof-of-concept for tx/rx using spoofed source IP address. 

P.S.: Implements ipcrypt to encrypt original source IP addressesn (See https://github.com/14morpheus14/ipcrypt.git)

Alice sends a message, along with its encrypted real IP address, and the Code Identifier of Bob to CR.

CR encrypts the Code ID of Bob, scrapes encrypted source IP address of Alice, puts a fake IP address as Source IP address, and forwards the packet to RP.

RP decrypts the Code ID of Bob, finds the associated real IP address of Bob and forwards the packet to Bob.

Bob reads the packet and decrypts the real IP address of Alice.

Prerequisite: `openssl`
Comilation:
`gcc filename.c -lcrypto -o output_file_name`
Execution (Alice to be run last):
`sudo output_file_name`
