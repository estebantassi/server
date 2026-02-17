const axios = require("axios");
const { OAuth2Client } = require('google-auth-library');

const clientid = process.env.GOOGLE_CLIENT_ID;
const clientsecret = process.env.GOOGLE_CLIENT_SECRET;
const client = new OAuth2Client(clientid);

const GetGoogleUser = async (redirectURI, codeVerifier, code) => {
    try {
        const tokenResponse = await axios.post(
            "https://oauth2.googleapis.com/token",
            {
                client_id: clientid,
                client_secret: clientsecret,
                code,
                code_verifier: codeVerifier,
                redirect_uri: redirectURI,
                grant_type: "authorization_code",
            },
            { headers: { "Content-Type": "application/json", }, }
        );

        const ticket = await client.verifyIdToken({
            idToken: tokenResponse.data.id_token,
            audience: clientid,
        });
        const payload = ticket.getPayload();

        const avatarURL = payload.picture.replace(/=s\d+(-c)?$/, "=s512-c") || null;
        const username = (payload.name || payload.given_name || "User").slice(0, 30);
        const email = payload.email;
        const verified = payload.email_verified;

        return { username, email, verified, avatarURL };
    } catch (err) {
        if (process.env.LOGERRORS === 'true') console.error(err);
        return null;
    }
};

module.exports = { GetGoogleUser };