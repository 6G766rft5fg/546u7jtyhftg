const express = require('express');
const crypto = require('crypto');
const app = express();

// Retrieve secret key and hash text from environment variables
const SECRET_KEY = process.env.SECRET_KEY;
const hashText = process.env.HASH_TEXT;

app.get('/hash.txt', (req, res) => {
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send('Authorization header missing or invalid.');
    }

    const token = authHeader.split('Bearer ')[1];
    const [calculatedHash, nonce, timestamp] = token.split(':');
    const currentTimestamp = Date.now();

    // Check timestamp drift (e.g., 5 minutes)
    const ALLOWED_TIME_DRIFT_MS = 5 * 60 * 1000;
    if (Math.abs(currentTimestamp - timestamp) > ALLOWED_TIME_DRIFT_MS) {
        return res.status(403).send('Request denied: Time drift too large.');
    }

    // Validate HMAC
    const expectedToken = crypto.createHmac('sha256', SECRET_KEY)
                                .update(`${calculatedHash}:${nonce}:${timestamp}`)
                                .digest('hex');

    if (expectedToken !== token) {
        return res.status(403).send('Request denied: Invalid token.');
    }

    // Return the hash.txt content
    res.send(hashText);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
