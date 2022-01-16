# Cryptography Concepts Between Client And Server Example

## Description:
### This project demonstrates several key cryptography concepts such as hashing, hash-based message authentication codes (HMAC), asymmetric encryption with public/private key pairs, and signing.

## Notes:
This project uses a HTTP connection between the client and server. Though this is not encouraged where security is a real consideration, this design choice was made to avoid extra boilerplate and the machine specific configurations required for allowing a client and server to run and communicate from localhost. Didn't want to over-engineer.

This demonstration uses RSA key pairs in .pem format. The project contains a method to generate these files and instructions for generating outside of the program. The choice to use files over copy-pasting was done to avoid terminal issues when pasting multi-line text.

## Instructions
- Clone the project and `cd` into the directory from a terminal
- No need to run npm intall as all the modules are contained within NodeJS
- Start the server with a password added as an argument: `node server [password]`
- In a new terminal, start the client: `node client`
- The client shows you a menu with options 1-5, enter the number for the option and press enter

### Here are details on the menu options:
1. Authenticate With Server
- The 'admin' username is hard-coded as this project doesn't have multiple user accounts. 
- Enter the password that you used when you started the server to authenticate the user.
2. Add Public Key To Server
- You must be authenticated with the server to perform this action. 
- It will ask you to provide a .pem file with the users public key so that it can store it on the server. 
- It defaults to a file called 'public.pem'.
3. Sign A Message
- You can sign a message with a private key and get the signature. 
- This will ask you for the message and the location of the private key (in .pem file format). 
- It defaults to a file called 'private.pem' It will save the message and signature to signed-message.txt for your future reference.
4. Check Signed Message
- This asks for a username (only hard-coded 'admin' user exists on server). 
- You can press enter and it will default to admin user. 
- Then it will ask for the message and the signature. 
- You can copy and paste them from the signed-message.txt file. 
- This will return whether the message was signed by the user you entered.
5. Generate RSA Key Pair To Files
- This was added for convenience. 
- This option will generate two files, private.pem and public.pem with RSA keys. 
- You can do this outside of the program with the following commands on Windows: 
- `ssh-keygen -t rsa -b 4096 -m PEM -f private.pem` to generate the private key and then 
- `openssl rsa -in private.pem -pubout -out public.pem` to generate the public key.

