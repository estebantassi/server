const { GetDiscordUser } = require('../../../helpers/oauth/getuser/getdiscorduser');
const { GetGoogleUser } = require('../../../helpers/oauth/getuser/getgoogleuser');
const { GetGitlabUser } = require('../../../helpers/oauth/getuser/getgitlabuser');
const { GetGithubUser } = require('../../../helpers/oauth/getuser/getgithubuser');
const { GetTwitchUser } = require('../../../helpers/oauth/getuser/gettwitchuser');
const db = require("../../../config/db/db");
const { Encrypt } = require("../../../helpers/encryption");
const Token = require("../../../helpers/token");
const crypto = require('crypto');
const { default: axios } = require('axios');
const { CompressImage } = require('../../../helpers/compressimage');
const bucket = require('../../../config/gcs/gcs');

const clientURL = process.env.CLIENT_URL;
const serverURL = process.env.SERVER_URL;
const emailHashVersion = process.env.EMAIL_HASH_SECRET_VERSION;
const emailEncryptedVersion = process.env.EMAIL_ENCRYPTION_SECRET_VERSION;


module.exports = (app) => {
    app.get("/auth/oauth/login/callback", async (req, res) => {

        const errorURL = clientURL + `/login?oauth=error&error=`;

        if (req?.query?.state !== req?.cookies?.oauthState) return res.redirect(errorURL + encodeURIComponent("Invalid State"));

        const code = req?.query?.code;
        if (!code) return res.redirect(errorURL + encodeURIComponent("Error providing the code"));

        const codeVerifier = req?.cookies?.codeVerifier;
        if (!codeVerifier) return res.redirect(errorURL + encodeURIComponent("Error providing the verifier"));

        res.clearCookie('oauthState');
        res.clearCookie("codeVerifier");

        const provider = req?.query?.provider?.toLowerCase();
        if (!provider || !["discord", "google", "gitlab", "twitch", "github"].includes(provider)) return res.status(400).json({ "message": "Invalid OAuth provider" });

        const redirectURI = serverURL + "/auth/oauth/login/callback?provider=" + provider;

        let user;
        switch (provider) {
            case "discord":
                user = await GetDiscordUser(redirectURI, codeVerifier, code);
                break;
            case "google":
                user = await GetGoogleUser(redirectURI, codeVerifier, code);
                break;
            case "gitlab":
                user = await GetGitlabUser(redirectURI, codeVerifier, code);
                break;
            case "twitch":
                user = await GetTwitchUser(redirectURI, codeVerifier, code);
                break;
            case "github":
                user = await GetGithubUser(redirectURI, codeVerifier, code);
                break;
            default:
                return res.status(400).json({ "message": "Invalid OAuth provider" });
        }

        const providerPretty = provider.charAt(0).toUpperCase() + provider.slice(1);
        if (!user) return res.redirect(errorURL + encodeURIComponent("Couldn't fetch user information from the " + providerPretty + " provider"));
        if (!user.verified) return res.redirect(errorURL + encodeURIComponent("Your email is not verified"));
        if (!user.username || !user.email) return res.redirect(errorURL + encodeURIComponent("Couldn't fetch user information from the " + providerPretty + " provider"));

        const emailHash = crypto.createHmac('sha256', process.env["EMAIL_HASH_SECRET_V" + emailHashVersion]).update(user.email).digest('hex');
        const emailEncrypted = Encrypt(emailEncryptedVersion + ":" + user.email, process.env['EMAIL_ENCRYPTION_SECRET_V' + emailEncryptedVersion]);

        const connection = await db.connect();
        try {

            let avatar;
            if (user.avatarURL)
            {
                const avatarReq = await axios.get(user.avatarURL, { responseType: 'arraybuffer' });
                avatar = await CompressImage(avatarReq.data, "avatar");
                if (!avatar.data) return res.redirect(errorURL + encodeURIComponent(avatar.message));
            }

            await connection.query('BEGIN');
            const request = await connection.query(`
                INSERT INTO users (created_at, hashed_email, encrypted_email, auth_method, username, avatar, verified)
                VALUES ($1, $2, $3, $4, $5, $6, true)
                ON CONFLICT (hashed_email)
                DO UPDATE SET hashed_email = users.hashed_email
                RETURNING uuid, username, auth_method, avatar, (xmax = 0) AS inserted;
            `, [new Date().toISOString(), emailHash, emailEncrypted, providerPretty, user.username, avatar?.data != null]);

            if (providerPretty != request.rows[0].auth_method) {
                await connection.query('ROLLBACK');
                return res.redirect(errorURL + encodeURIComponent('You already have an account associated with this email using another service (' + request.rows[0].auth_method + ')'));
            }

            user = {
                uuid: request.rows[0].uuid,
                'username': request.rows[0].username,
            };

            const accessToken = new Token(user.uuid, Token.Type.ACCESS, Token.StorageType.CACHE);
            if (!await accessToken.Save(res, null, true)) {
                await connection.query('ROLLBACK');
                return res.redirect(errorURL + encodeURIComponent("Couldn't create a token"));
            }
            const refreshToken = new Token(user.uuid, Token.Type.REFRESH, Token.StorageType.DATABASE, { "accessjti": accessToken.content.jti });
            if (!await refreshToken.Save(res, connection, false)) {
                await connection.query('ROLLBACK');
                return res.redirect(errorURL + encodeURIComponent("Couldn't create a token"));
            }

            //Insert image last to minimize the chances of having it uploaded on error.
            if (request.rows[0].inserted && avatar?.data)
            {
                try {
                    await bucket.file(`users/${user.uuid}/avatar`).save(avatar.data, {
                        metadata: {
                            contentType: 'image/webp',
                            cacheControl: 'no-store'
                        }
                    });
                } catch (err)
                {
                    if (process.env.LOGERRORS === 'true') console.error(err);
                    await connection.query('ROLLBACK');
                    return res.redirect(errorURL + encodeURIComponent("Error with Google Cloud Storage"));
                }
            }

            await connection.query('COMMIT');
            return res.redirect(clientURL + "/profile?oauth=success&data=" + encodeURIComponent(JSON.stringify(user)));
        } catch (err) {
            if (process.env.LOGERRORS === 'true') console.error(err);
            await connection.query('ROLLBACK');
            return res.redirect(errorURL + encodeURIComponent("Internal server error"));
        } finally {
            connection.release();
        }
    });
};