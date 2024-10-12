// index.js

const express = require('express');
const bodyParser = require('body-parser');
const forge = require('node-forge');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());

// Mock function to get user's public key from Appwrite
// In a real scenario, replace this with Appwrite SDK calls or API requests
const getUserPublicKey = async (userId) => {
    // TODO: Implement retrieval of public key from Appwrite
    // For example, using Appwrite SDK:
    // const account = new Account(client);
    // const user = await account.get();
    // return user.prefs.publicKey;
    return "-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY_HERE\n-----END PUBLIC KEY-----";
};

app.post('/verify-signature', async (req, res) => {
    const { signature, challenge, userId } = req.body;

    if (!signature || !challenge || !userId) {
        return res.status(400).json({ success: false, message: 'Missing parameters.' });
    }

    try {
        const publicKeyPem = await getUserPublicKey(userId);
        if (!publicKeyPem) {
            return res.status(400).json({ success: false, message: 'Public key not found.' });
        }

        // Convert PEM to Forge public key
        const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);

        // Hash the challenge
        const md = forge.md.sha256.create();
        md.update(challenge, 'utf8');

        // Decode the signature from Base64
        const decodedSignature = forge.util.decode64(signature);

        // Verify the signature
        const verified = publicKey.verify(md.digest().bytes(), decodedSignature);

        if (verified) {
            return res.status(200).json({ success: true, message: 'Signature verified successfully.' });
        } else {
            return res.status(400).json({ success: false, message: 'Signature verification failed.' });
        }
    } catch (error) {
        console.error('Error verifying signature:', error);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

app.listen(port, () => {
    console.log(`Signature verification server running on port ${port}`);
});
