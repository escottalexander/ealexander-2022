const crypto = require('crypto');
const http = require('http');

// create server with various routes
const server = http.createServer((request, response) => {
    console.log(`request received ${request.url}`);
    let data = '';
    request.on('data', chunk => {
        data += chunk;
    })
    request.on('end', () => {
        data = JSON.parse(data);
        // define actions for the various endpoints
        if (request.url === '/') {
            response.writeHead(200, {
                'Content-Type': 'application/json'
            });
            response.write(JSON.stringify({
                success: true,
                message: 'server is running',
            }));
            response.end();
        } else if (request.url === '/authenticate') {
            // authenticate user
            response.writeHead(200, {
                'Content-Type': 'application/json'
            });
            response.write(JSON.stringify(
                login(data.username, data.password)
            ));
            response.end();
        } else if (request.url === '/add-public-key') {
            // store public key for authenticated user
            // make sure user is authenticated
            if (authenticate(request.headers.username, request.headers.token)) {
                savePublicKey(request.headers.username, data.publicKey);
                response.writeHead(200, {
                    'Content-Type': 'application/json'
                });
                response.write(JSON.stringify({
                    success: true,
                    message: 'public key successfully added'
                }));
            } else {
                response.writeHead(401, {
                    'Content-Type': 'application/json'
                });
                response.write(JSON.stringify({
                    success: false,
                    message: 'unauthorized'
                }));
            }
            response.end();
        } else if (request.url === '/check-signed-message') {
            // check signed message to see if the user signed it
            let success = checkSignedMessage(data.username, data.signedMessage, data.signature);
            response.writeHead(200, {
                'Content-Type': 'application/json'
            });
            if (success) {
                response.write(JSON.stringify({
                    success: true,
                    message: 'message has been signed by user'
                }));
            } else {
                response.write(JSON.stringify({
                    success: false,
                    message: 'message was not signed by user'
                }));
            }
            response.end();
        } else {
            response.writeHead(404, {
                'Content-Type': 'application/json'
            });
            response.write(JSON.stringify({
                success: true,
                message: 'endpoint not found',
            }));
            response.end();
        }
    })
});

const signUp = (username, password) => {
    // save password hash to memory
    const salt = crypto.randomBytes(10).toString('hex');
    // appending salt to password before hashing to prevent rainbow table attacks
    let passwordHash = salt + ':' + crypto.createHash('sha256').update(`${salt}${password}`).digest('hex');
    if (serverMemory.users.find(user => user.username === username)) {
        console.log('user already exists');
        return false;
    } else {
        serverMemory.users.push({
            username,
            password: passwordHash
        });
        console.log('user added');
        return true;
    }
}

const login = (username, password) => {
    // check credentials and send back token if valid
    if (serverMemory.users.find(user => user.username === username)) {
        // compare given password with stored password
        const storedHash = serverMemory.users.find(user => user.username === username).password;
        const salt = storedHash.split(':')[0];
        const passwordHash = storedHash.split(':')[1];
        const attemptHash = crypto.createHash('sha256').update(`${salt}${password}`).digest('hex');
        // check if password hashes match with timing attack safe function
        const match = crypto.timingSafeEqual(Buffer.from(passwordHash), Buffer.from(attemptHash));
        if (match) {
            console.log('authentication successful');
            // create token based on user credentials
            const hmac = crypto.createHmac('sha256', storedHash).update(username).digest('hex');

            return {
                success: true,
                token: hmac,
                message: 'authentication successful'
            };
        } else {
            console.log('incorrect credentials');
            return {
                success: false,
                message: 'incorrect credentials'
            };
        }
    } else {
        // technically user does not exist but we don't want to reveal that
        console.log('incorrect credentials');
        return {
            success: false,
            message: 'incorrect credentials'
        };
    }
}

const authenticate = (username, token) => {
    // compare token from client with token based on credentials from memory
    // to make this better we could give the token a time out period
    if (serverMemory.users.find(user => user.username === username)) {
        const storedHash = serverMemory.users.find(user => user.username === username).password;
        const hmac = crypto.createHmac('sha256', storedHash).update(username).digest('hex');
        if (hmac === token) {
            console.log('authorized');
            return true;
        } else {
            console.log('authentication failed');
            return false;
        }
    } else {
        console.log('token is invalid');
        return false;
    }
}

const savePublicKey = (username, publicKey) => {
    // save public key to memory
    console.log('saving public key for user: admin');
    serverMemory.users.find(user => user.username = username).publicKey = publicKey;
    return true;
}

const checkSignedMessage = (username, signedMessage, signature) => {
    // check if signed message was signed by user
    if (serverMemory.users.find(user => user.username === username)) {
        const publicKey = serverMemory.users.find(user => user.username === username).publicKey;
        if (publicKey) {
            // verify signed message
            const verified = crypto.createVerify('rsa-sha256').update(signedMessage).verify(publicKey, signature, 'hex');
            if (verified) {
                console.log('message verified');
                return true;
            } else {
                console.log('message could not be verified');
                return false;
            }
        } else {
            console.log('user does not have public key');
            return false;
        }
    } else {
        console.log('user does not exist');
        return false;
    }
}

let serverMemory = {
    users: []
};

const main = () => {
    if (process.argv[2]) {
        // create account for hardcoded username and entered password
        signUp('admin', process.argv[2]);

        server.listen(5000, 'localhost', () => {
            console.log('server is running on port 5000');
        });
    } else {
        console.log('Please provide password as argument');
        process.exit(1);
    }
}

main();