require('dotenv').config();

const https   = require('https');
const fs      = require('fs');
const express = require('express');
const axios   = require('axios');
const cookieParser = require('cookie-parser');
const path    = require('path');
const jwt     = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const WebSocket  = require('ws');
const protobuf   = require('protobufjs');

// ─── App bootstrap ────────────────────────────────────────────────────────────

const app = express();
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Serve the proto file so the browser can load it directly
app.get('/market.proto', (_req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.sendFile(path.join(__dirname, 'market.proto'));
});

// ─── Casdoor / OIDC config ────────────────────────────────────────────────────

const CASDOOR_ENDPOINT = process.env.CASDOOR_ENDPOINT;
const CLIENT_ID        = process.env.CASDOOR_CLIENT_ID;
const CLIENT_SECRET    = process.env.CASDOOR_CLIENT_SECRET;
const REDIRECT_URI     = process.env.CASDOOR_REDIRECT_URI;

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

const jwks = jwksClient({
  jwksUri:      `${CASDOOR_ENDPOINT}/.well-known/jwks`,
  requestAgent: httpsAgent,
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err, null);
    callback(null, key.publicKey || key.rsaPublicKey);
  });
}

function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) =>
      err ? reject(err) : resolve(decoded)
    );
  });
}

// ─── HTTP routes ──────────────────────────────────────

app.get('/login', (_req, res) => {
  const authUrl =
    `${CASDOOR_ENDPOINT}/login/oauth/authorize` +
    `?client_id=${CLIENT_ID}&response_type=code` +
    `&redirect_uri=${REDIRECT_URI}&scope=openid profile email`;
  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Authorization code is missing');

  try {
    const response = await axios.post(
      `${CASDOOR_ENDPOINT}/api/login/oauth/access_token`,
      null,
      {
        params: {
          grant_type:    'authorization_code',
          client_id:     CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code,
          redirect_uri:  REDIRECT_URI,
        },
        httpsAgent,
      }
    );

    const accessToken = response.data.access_token;
    if (!accessToken) return res.status(500).send('Failed to obtain access token');

    res.cookie('access_token', accessToken, { httpOnly: true, secure: true, path: '/' });
    res.redirect('/');
  } catch (error) {
    console.error('Error getting token:', error.message);
    res.status(500).send('Authentication failed');
  }
});

app.get('/user-info', (req, res) => {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized: No token provided' });

  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      console.error('Token validation error:', err.message);
      return res.status(401).json({ error: 'Unauthorized: Invalid token signature' });
    }
    res.json(decoded);
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.redirect('/');
});

// ─── TLS options ──────────────────────────────────────────────────────────────

const tlsOptions = {
  key:  fs.readFileSync('./nginx/localhost-key.pem'),
  cert: fs.readFileSync('./nginx/localhost.pem'),
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.2',
  ciphers: ['RSA+AES128-GCM-SHA256', 'RSA+AES256-GCM-SHA384'].join(':'),
};

const server = https.createServer(tlsOptions, app);

// ─── Protobuf setup ───────────────────────────────────────────────────────────

let PriceUpdate;

protobuf.load(path.join(__dirname, 'market.proto')).then((root) => {
  PriceUpdate = root.lookupType('PriceUpdate');
  console.log('Protobuf schema loaded');
}).catch((err) => {
  console.error('Failed to load protobuf schema:', err);
  process.exit(1);
});

// ─── Binance stream manager ───────────────────────────────────────────────────
//
// binanceClients : Map<symbol, Set<WebSocket>>   – app clients subscribed to a symbol
// binanceSockets : Map<symbol, WebSocket>        – one Binance WS per symbol

const binanceClients = new Map();
const binanceSockets = new Map();

function ensureBinanceStream(symbol) {
  if (binanceSockets.has(symbol)) return;

  const url = `wss://stream.binance.com:9443/ws/${symbol.toLowerCase()}@ticker`;
  const bws  = new WebSocket(url);

  bws.on('open', () => console.log(`[Binance] Connected: ${symbol}`));

  bws.on('message', (raw) => {
    if (!PriceUpdate) return;

    let ticker;
    try { ticker = JSON.parse(raw); } catch { return; }

    const update = PriceUpdate.create({
      symbol:    ticker.s,
      price:     ticker.c,
      timestamp: Date.now(),
      change:    ticker.P,
      volume:    ticker.v,
      high:      ticker.h,
      low:       ticker.l,
    });

    const encoded = PriceUpdate.encode(update).finish();

    const subscribers = binanceClients.get(symbol);
    if (!subscribers) return;

    subscribers.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(encoded);
      }
    });
  });

  bws.on('error', (err) => console.error(`[Binance] ${symbol} error:`, err.message));

  bws.on('close', () => {
    console.log(`[Binance] Disconnected: ${symbol}`);
    binanceSockets.delete(symbol);
    setTimeout(() => {
      if (binanceClients.get(symbol)?.size > 0) ensureBinanceStream(symbol);
    }, 3000);
  });

  binanceSockets.set(symbol, bws);
}

function removeBinanceIfEmpty(symbol) {
  const clients = binanceClients.get(symbol);
  if (!clients || clients.size === 0) {
    binanceClients.delete(symbol);
    const bws = binanceSockets.get(symbol);
    if (bws) {
      bws.close();
      binanceSockets.delete(symbol);
    }
  }
}

// ─── WebSocket server ─────────────────────────────────────────────────────────

const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', async (ws, req) => {
  let token = null;

  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    for (const part of cookieHeader.split(';')) {
      const [k, v] = part.trim().split('=');
      if (k === 'access_token') { token = v; break; }
    }
  }

  if (!token) {
    const url = new URL(req.url, 'https://localhost');
    token = url.searchParams.get('token');
  }

  if (!token) {
    console.warn('[WS] Rejected: no token');
    ws.close(4001, 'Unauthorized: No token');
    return;
  }

  let user;
  try {
    user = await verifyToken(token);
  } catch (err) {
    console.warn('[WS] Rejected: invalid token –', err.message);
    ws.close(4003, 'Unauthorized: Invalid token');
    return;
  }

  console.log(`[WS] Session opened for user: ${user.name || user.sub}`);

  
  const sessionSymbols = new Set();

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch {
      ws.send(JSON.stringify({ error: 'Invalid JSON message' }));
      return;
    }

    const action  = (msg.action  || '').toLowerCase();
    const symbols = (msg.symbols || []).map((s) => s.toUpperCase().trim()).filter(Boolean);

    if (!['subscribe', 'unsubscribe'].includes(action) || symbols.length === 0) {
      ws.send(JSON.stringify({ error: 'Expected { action: "subscribe"|"unsubscribe", symbols: [...] }' }));
      return;
    }

    if (action === 'subscribe') {
      symbols.forEach((sym) => {
        if (sessionSymbols.has(sym)) return;
        sessionSymbols.add(sym);
        if (!binanceClients.has(sym)) binanceClients.set(sym, new Set());
        binanceClients.get(sym).add(ws);
        ensureBinanceStream(sym);
        console.log(`[WS] ${user.name || user.sub} subscribed to ${sym}`);
      });
      ws.send(JSON.stringify({ type: 'subscribed', symbols: [...sessionSymbols] }));

    } else if (action === 'unsubscribe') {
      symbols.forEach((sym) => {
        sessionSymbols.delete(sym);
        binanceClients.get(sym)?.delete(ws);
        removeBinanceIfEmpty(sym);
        console.log(`[WS] ${user.name || user.sub} unsubscribed from ${sym}`);
      });
      ws.send(JSON.stringify({ type: 'unsubscribed', symbols }));
    }
  });

  ws.on('close', () => {
    console.log(`[WS] Session closed for: ${user.name || user.sub}`);
    sessionSymbols.forEach((sym) => {
      binanceClients.get(sym)?.delete(ws);
      removeBinanceIfEmpty(sym);
    });
  });

  ws.on('error', (err) => console.error('[WS] Socket error:', err.message));
});

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(3443, () => {
  console.log('HTTPS/WSS server running on https://localhost:3443');
});