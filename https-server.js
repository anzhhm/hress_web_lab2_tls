require('dotenv').config();

const https = require('https');
const fs = require('fs');
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// Підключаємо парсер кукі та роздачу статичних файлів (фронтенду)
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const CASDOOR_ENDPOINT = process.env.CASDOOR_ENDPOINT;
const CLIENT_ID = process.env.CASDOOR_CLIENT_ID;
const CLIENT_SECRET = process.env.CASDOOR_CLIENT_SECRET;
const REDIRECT_URI = process.env.CASDOOR_REDIRECT_URI;

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

app.get('/login', (req, res) => {
    const authUrl = `${CASDOOR_ENDPOINT}/login/oauth/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&scope=openid profile email`;
    res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
    const code = req.query.code;
    
    if (!code) {
        return res.status(400).send('Authorization code is missing');
    }

    try {
        const response = await axios.post(`${CASDOOR_ENDPOINT}/api/login/oauth/access_token`, null, {
            params: {
                grant_type: 'authorization_code',
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                code: code,
                redirect_uri: REDIRECT_URI
            },
            httpsAgent
        });

        const accessToken = response.data.access_token;
        
        if (accessToken) {
            res.cookie('access_token', accessToken, { 
                httpOnly: true, 
                secure: true, 
                path: '/' 
            });
            res.redirect('/');
        } else {
            res.status(500).send('Failed to obtain access token');
        }
    } catch (error) {
        console.error('Error getting token:', error.message);
        res.status(500).send('Authentication failed');
    }
});

app.get('/user-info', async (req, res) => {
    const token = req.cookies.access_token;
    
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    try {
        // Валідація токена та отримання інформації через IAM
        const response = await axios.get(`${CASDOOR_ENDPOINT}/api/userinfo`, {
            headers: { Authorization: `Bearer ${token}` },
            httpsAgent
        });
        
        res.json(response.data);
    } catch (err) {
        res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('access_token');
    res.redirect('/');
});

const options = {
    key: fs.readFileSync('./nginx/localhost-key.pem'),
    cert: fs.readFileSync('./nginx/localhost.pem'),
    
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