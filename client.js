/************************************************************
 * This file primarily contains the functions that facilitate 
 * a users ability to choose different menu options. 
 * The meatier functions are in clientMethods.js.
 ************************************************************/
const {
    login,
    addPublicKey,
    signMessage,
    checkSignedMessage,
    generateKeyPair
} = require('./clientMethods.js');

// Setup question method for use in menu
const readln = require('readline');
let cl = readln.createInterface(process.stdin, process.stdout);
let question = (q) => {
    return new Promise((res, rej) => {
        cl.question(q, answer => {
            res(answer);
        })
    });
};

const main = async () => {
    let done = false;
    let answer;
    while (done === false) {
        answer = await question(
            `\nMain Menu:
1. Authenticate With Server
2. Add Public Key To Server (authentication required)
3. Sign A Message
4. Check Signed Message
5. Generate RSA Key Pair To Files
Type your selection and press enter: `);
        console.log('\n');
        if (answer == 1) {
            // authenticate with server
            console.log('Hardcoded username: admin');
            let password = await question('Enter password: ');
            console.log('Authenticating with server');
            // send request to server
            login('admin', password);
        } else if (answer == 2) {
            // add public key to server
            let publicKey = await question('Enter public key file name (defaults to public.pem): ');
            console.log('Attempting to save public key to server for user: admin');
            // send request to server
            addPublicKey(publicKey);
        } else if (answer == 3) {
            // sign a message with private key
            let message = await question('Enter message: ');
            let privateKey = await question('Enter private key file name (defaults to private.pem): ');
            signMessage(message, privateKey);
        } else if (answer == 4) {
            // check signed message
            let username = await question('Enter username to check (defaults to admin): ');
            let signedMessage = await question('Enter message: ');
            let signature = await question('Enter signature: ');
            checkSignedMessage(username, signedMessage, signature);
        } else if (answer == 5) {
            // check signed message
            console.log('Generating a new key pair');
            generateKeyPair();
        } else {
            console.log('Please enter a valid option');
        }
        await question('\nPress enter to continue');
    }
}

main();