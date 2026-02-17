const crypto = require('crypto');
const db = require('../../../config/db/db');
const Token = require('../../../helpers/token');
const srp = require('secure-remote-password/server');
const { setCachedValue, getCachedValue, deleteCachedValue } = require('../../../config/cache/redis');
const { GetImage } = require('../../../helpers/gcstools');
const { validateEmail } = require('../../../helpers/validate/validate');

const emailHashVersion = process.env.EMAIL_HASH_SECRET_VERSION;

module.exports = (app) => {
    app.post("/auth/loginstart", async (req, res) => {
        const email = req?.body?.email?.toLowerCase();
        if (!validateEmail(email)) return res.status(400).json({ message: "Invalid email format" });
        const emailHash = crypto.createHmac('sha256', process.env["EMAIL_HASH_SECRET_V" + emailHashVersion]).update(email).digest('hex');

        try{
            const request = await db.query(`
                SELECT uuid, srp_salt, srp_verifier, verified
                FROM users
                WHERE hashed_email=$1
            `, [emailHash]);

            if (!request.rows[0]) return res.status(400).json({message: "User not found"});
            if (!request.rows[0].verified) return res.status(400).json({message: "User not verified"});

            const srpSalt = request.rows[0].srp_salt;
            const srpVerifier = request.rows[0].srp_verifier;
            
            const loginToken = new Token(request.rows[0].uuid, Token.Type.LOGIN, Token.StorageType.CACHE, { step: 0 });
            if (!await loginToken.Save(res, null)) return res.status(500).json({message: "Couldn't create a token"});
            
            const srpServerEphemeral = srp.generateEphemeral(srpVerifier);
            await setCachedValue(`${request.rows[0].uuid}/login/ephemeral`, 60 * 5, srpServerEphemeral.secret);

            return res.status(200).json({ message: 'Successfully requested public salt', srpSalt, srpServerEphemeral: srpServerEphemeral.public });
        } catch (err) {
            if (process.env.LOGERRORS === 'true') console.error(err);
            return res.status(500).json({ message: "Internal server error" });
        }
    });

    app.post("/auth/login", async (req, res) => {
        const email = req?.body?.email?.toLowerCase();
        const srpProof = req?.body?.srpProof;
        const srpClientEphemeral = req?.body?.srpClientEphemeral;
        const loginToken = req?.cookies?.token_login;

        if (!validateEmail(email)) return res.status(400).json({ message: "Invalid email format" });

        const tokenData = await Token.GetData(loginToken, Token.Type.LOGIN);
        if (!tokenData) return res.status(401).json({message: "Invalid token"});

        if (tokenData?.step != 0) return res.status(401).json({message: "Token step invalid"});

        const emailHash = crypto.createHmac('sha256', process.env["EMAIL_HASH_SECRET_V" + emailHashVersion]).update(email).digest('hex');

        try {
            const request = await db.query(`
                SELECT uuid, srp_salt, srp_verifier, username, avatar
                FROM users
                WHERE hashed_email=$1
            `, [emailHash]);

            
            if (!request.rows[0]) return res.status(400).json({message: "User not found"});
            const srpSalt = request.rows[0].srp_salt;
            const srpVerifier = request.rows[0].srp_verifier;

            const user = {
                uuid: request.rows[0].uuid,
                username: request.rows[0].username,
                avatar: request.rows[0].avatar
            };

            const srpSecretEphemeral = await getCachedValue(`${user.uuid}/login/ephemeral`);

            let srpServerSession;
            try {
                srpServerSession = srp.deriveSession(srpSecretEphemeral, srpClientEphemeral, srpSalt, email, srpVerifier, srpProof);
            } catch {
                return res.status(400).json({message: "Wrong password"});
            }
            if (!srpServerSession || !srpServerSession.proof) {
                return res.status(400).json({message: "Wrong password"});
            }

            const avatarURL = user.avatar ? `users/${user.uuid}/avatar` : `Default/avatar`;
            user.avatar = await GetImage(avatarURL);
            if (!user.avatar) return res.status(400).json({message: "Error fetching avatar"});

            const accessToken = new Token(user.uuid, Token.Type.ACCESS, Token.StorageType.CACHE);
            if (!await accessToken.Save(res, null, true)) return res.status(400).json({ message: "Couldn't create a token" });

            const refreshToken = new Token(user.uuid, Token.Type.REFRESH, Token.StorageType.DATABASE, { "accessjti": accessToken.content.jti });
            if (!await refreshToken.Save(res, db, false)) return res.status(400).json({ message: "Couldn't create a token" });

            res.clearCookie("token_login", { path: "/auth/login" });
            try {
                deleteCachedValue(`${user.uuid}/tokens/${Token.Type.LOGIN}/${tokenData.jti}`);
            } catch (err) { err; }

            return res.status(200).json({ message: 'Successfully logged in',  srpProof: srpServerSession.proof, user });
        } catch (err) {
            if (process.env.LOGERRORS === 'true') console.error(err);
            return res.status(500).json({ message: "Internal server error" });
        }
    });
};