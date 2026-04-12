const express = require('express');

const app = express();

app.get('/hello', (req, res) => {
    res.send('Hello from Hress Anzhelika-Mariia KP-31');
});

app.listen(3000, () => {
    console.log('HTTP server running on http://localhost:3000');
});