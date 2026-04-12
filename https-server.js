const https = require('https');
const fs = require('fs');
const express = require('express');

const app = express();

app.get('/hello', (req, res) => {
    res.send('Hello from Hress Anzhelika-Mariia KP-31');
});

const options = {
    key: fs.readFileSync('localhost-key.pem'),
    cert: fs.readFileSync('localhost.pem'),

    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',

    ciphers: [
        'RSA+AES128-GCM-SHA256',
        'RSA+AES256-GCM-SHA384'
    ].join(':')
};

https.createServer(options, app).listen(3443, () => {
    console.log('HTTPS server running on https://localhost:3443');
});