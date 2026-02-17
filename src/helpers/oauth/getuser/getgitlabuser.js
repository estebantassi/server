const axios = require("axios");
const { createRemoteJWKSet, jwtVerify } = require("jose");
const qs = require("qs");

const clientid = process.env.GITLAB_CLIENT_ID;
const clientsecret = process.env.GITLAB_CLIENT_SECRET;

const GetGitlabUser = async (redirectURI, codeVerifier, code) => {
    try {
        const tokenResponse = await axios.post(
            "https://gitlab.com/oauth/token",
            qs.stringify({
                client_id: clientid,
                client_secret: clientsecret,
                redirect_uri: redirectURI,
                grant_type: "authorization_code",
                code_verifier: codeVerifier,
                code
            }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const JWKS = createRemoteJWKSet(
            new URL("https://gitlab.com/oauth/discovery/keys")
        );

        const { payload } = await jwtVerify(tokenResponse.data.id_token, JWKS, {
            issuer: "https://gitlab.com",
            audience: clientid,
        });

        const avatarURL = payload.picture || null;
        const username = (payload.nickname || payload.preferred_username || "User").slice(0, 30);
        const email = payload.email;
        const verified = payload.email_verified;

        return { username, email, verified, avatarURL };
    } catch (err) {
        if (process.env.LOGERRORS === 'true') console.error(err);
        return null;
    }
};

module.exports = { GetGitlabUser };