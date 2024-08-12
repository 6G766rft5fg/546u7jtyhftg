const express = require('express');
const crypto = require('crypto');
const app = express();

// Access the secret key and expected hash from environment variables
const HASH_SECRET_KEY = process.env.SECRET_KEY;  // Securely stored in environment variables
const hashText = process.env.HASH_TEXT;  // Securely stored in environment variables

app.get('/hash.txt', (req, res) => {
    const token = req.header('Authorization').split('Bearer ')[1];
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

const listener = app.listen(process.env.PORT || 3000, () => {
    console.log('Your app is listening on port ' + listener.address().port);
});
