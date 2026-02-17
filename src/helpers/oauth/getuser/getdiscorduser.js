const axios = require("axios");
const qs = require("qs");

const clientid = process.env.DISCORD_CLIENT_ID;
const clientsecret = process.env.DISCORD_CLIENT_SECRET;

const GetDiscordUser = async (redirectURI, codeVerifier, code) => {
    try {
        const tokenResponse = await axios.post(
            "https://discord.com/api/oauth2/token",
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

        const userResponse = await axios.get("https://discord.com/api/users/@me", {
            headers: {
                Authorization: `Bearer ${tokenResponse.data.access_token}`
            }
        });

        const user = userResponse.data;
        const format = user?.avatar?.startsWith("a_") ? "gif" : "png";
        const defaultAvatar = Number(BigInt(user.id) >> 22n) % 6;
        const avatarURL = user?.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${format}?size=512` : `https://cdn.discordapp.com/embed/avatars/${defaultAvatar}.png`;
        const username = (user.global_name || user.username || "User").slice(0, 30);
        const email = user.email;
        const verified = user.verified;

        return {username, email, verified, avatarURL};
    } catch (err) {
        if (process.env.LOGERRORS === 'true') console.error(err);
        return null;
    }
};

module.exports = { GetDiscordUser };