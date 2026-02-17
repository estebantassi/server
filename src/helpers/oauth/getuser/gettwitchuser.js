const axios = require("axios");
const qs = require("qs");

const clientid = process.env.TWITCH_CLIENT_ID;
const clientsecret = process.env.TWITCH_CLIENT_SECRET;

const GetTwitchUser = async (redirectURI, codeVerifier, code) => {
    try {
        const tokenResponse = await axios.post(
            "https://id.twitch.tv/oauth2/token",
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

        const userResponse = await axios.get("https://api.twitch.tv/helix/users", {
            headers: {
                Authorization: `Bearer ${tokenResponse.data.access_token}`,
                "Client-Id": clientid,
            },
        });

        const avatarURL = userResponse.data.data[0].profile_image_url || null;
        const username = (userResponse.data.data[0].display_name || userResponse.data.data[0].login || "User").slice(0, 30);
        const email = userResponse.data.data[0].email;
        const verified = true;

        return { username, email, verified, avatarURL };
    } catch (err) {
        if (process.env.LOGERRORS === 'true') console.error(err);
        return null;
    }
};

module.exports = { GetTwitchUser };