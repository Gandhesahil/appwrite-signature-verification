const express = require('express');
const bodyParser = require('body-parser');
const forge = require('node-forge');
const { Client, Account, Databases } = require('appwrite'); // Import Appwrite SDK

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
// Initialize Appwrite SDK
const client = new Client();
client
    .setEndpoint('https://cloud.appwrite.io/v1') // Set your Appwrite endpoint
    .setProject('66e57bf0001e54fb8a20'); // Set your Appwrite project ID

const account = new Account(client);
const databases = new Databases(client);

// Function to get user's public key from Appwrite preferences
const getUserPublicKey = async (userId) => {
    try {
        // Fetch the user's account using their userId
        const user = await account.get(userId);

        // Assuming the public key is stored in user preferences
        if (user && user.prefs && user.prefs.publicKey) {
            return user.prefs.publicKey;
        } else {
            return null;
        }
    } catch (error) {
        console.error('Error retrieving user public key:', error);
        return null;
    }
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
