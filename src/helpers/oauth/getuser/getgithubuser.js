const axios = require("axios");
const qs = require("qs");

const clientid = process.env.GITHUB_CLIENT_ID;
const clientsecret = process.env.GITHUB_CLIENT_SECRET;

const GetGithubUser = async (redirectURI, codeVerifier, code) => {
    try {
        const tokenResponse = await axios.post(
            "https://github.com/login/oauth/access_token",
            qs.stringify({
                client_id: clientid,
                client_secret: clientsecret,
                redirect_uri: redirectURI,
                code_verifier: codeVerifier,
                code,
            }),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json"
                }
            }
        );

        const userResponse = await axios.get("https://api.github.com/user", {
            headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` }
        });

        const emailResponse = await axios.get("https://api.github.com/user/emails", {
            headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` }
        });

        const primaryEmailObj = emailResponse.data.find(e => e.primary && e.verified);

        const avatarURL = userResponse.data.avatar_url ? userResponse.data.avatar_url + "?s=512" : null;
        const username = (userResponse.data.name || userResponse.data.login || "User").slice(0, 30);
        const email = primaryEmailObj.email;
        const verified = primaryEmailObj != null;

        return { username, email, verified, avatarURL };
    } catch (err) {
        if (process.env.LOGERRORS === 'true') console.error(err);
        return null;
    }
};

module.exports = { GetGithubUser };