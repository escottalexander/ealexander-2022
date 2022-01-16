const http = require('http');
const crypto = require('crypto');
const fs = require('fs');

const endpoints = {
    loginUrl: 'http://localhost:5000/authenticate',
    addPublicKeyUrl: 'http://localhost:5000/add-public-key',
    checkSignedMessageUrl: 'http://localhost:5000/check-signed-message'
}

let authToken = '';

// create boilerplate for sending requests to server
const sendRequest = (url, opts, callback) => {
    try {
        let req = http.request(url, opts, (res) => {
            if (res.statusCode !== 200) {
                console.log('Error:', res.statusCode);
                return;
            }
            let body = '';
            res.on('data', (chunk) => {
                body += chunk;
            });
            res.on('end', () => {
                callback(body);
            });
        })

        if (opts.body && opts.method == 'POST') {
            req.write(JSON.stringify(opts.body));
        }

        req.end();
    } catch (err) {
        console.error(err);
    }

};

// sets the auth token for future authenticated requests
const setAuth = (data) => {
    data = JSON.parse(data);
    console.log(`\nMessage: ${data.message}\n`);
    authToken = data.token;
}

// displays the response from the api
const handleApiResponse = (data) => {
    data = JSON.parse(data);
    console.log(`\nMessage: ${data.message}\n`);
}

// primary methods
const login = (username, password) => {
    // hardcoded username
    let body = {
        username: 'admin',
        password: password
    }
    sendRequest(endpoints.loginUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(JSON.stringify(body))
        },
        body: {
            username: 'admin',
            password: password
        }
    }, setAuth);


}
const addPublicKey = (publicKeyFileName) => {
    // send public key to server - must be authenticated
    if (authToken.length == 0) {
        console.log('You must login before adding a public key');
        return;
    }
    if (publicKeyFileName.length == 0) {
        publicKeyFileName = 'public.pem';
    }
    const publicKey = fs.readFileSync(publicKeyFileName).toString();
    let body = {
        publicKey
    }
    sendRequest(endpoints.addPublicKeyUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(JSON.stringify(body)),
            'Username': 'admin',
            'Token': authToken
        },
        body
    }, handleApiResponse);

}

// sign message with private key
const signMessage = (message, privateKeyFileName) => {
    if (message.length == 0) {
        console.log('Message cannot be empty.');
        return;
    }
    if (privateKeyFileName.length == 0) {
        privateKeyFileName = 'private.pem';
    }
    // get private key from file
    const privateKey = fs.readFileSync(privateKeyFileName);
    const signer = crypto.createSign('rsa-sha256');
    signer.update(message);
    const signature = signer.sign(privateKey, 'hex');

    // display signature and write signed message to file for future reference
    console.log('Signature:', signature);
    console.log('writing message and signature to signed-message.txt');
    fs.writeFileSync('signed-message.txt', `${message}\n\n${signature}`);
}

// send message to server to check if signature was signed by user
const checkSignedMessage = (username, signedMessage, signature) => {
    if (username.length == 0) {
        username = 'admin';
    }
    let body = {
        username,
        signedMessage,
        signature
    }
    sendRequest(endpoints.checkSignedMessageUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(JSON.stringify(body)),
        },
        body
    }, handleApiResponse);
}

// generate rsa key pair in pem format - added for convenience and testing
const generateKeyPair = () => {
    const {
        privateKey,
        publicKey
    } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 512,
        publicKeyEncoding: {
            type: 'spki', // recommended to be 'spki' by the Node.js docs
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8', // recommended to be 'pkcs8' by the Node.js docs
            format: 'pem',
        },
    });
    console.log('Private key:', privateKey);
    console.log('Public key:', publicKey);
    fs.writeFileSync('private.pem', privateKey);
    fs.writeFileSync('public.pem', publicKey);
    console.log('New RSA key pair generated and written to private.pem and public.pem files');
}

module.exports = {
    login,
    addPublicKey,
    signMessage,
    checkSignedMessage,
    generateKeyPair
}