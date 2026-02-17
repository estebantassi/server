const { deleteCachedValue } = require("../../../config/cache/redis");
const db = require("../../../config/db/db");
const { GetImage } = require("../../../helpers/gcstools");
const Token = require("../../../helpers/token");

module.exports = (app) => {
    app.post("/auth/verify", async (req, res) => {
        const verifyToken = req?.cookies?.token_verify;

        const tokenData = await Token.GetData(verifyToken, Token.Type.VERIFY);
        if (!tokenData) return res.status(401).json({message: "Invalid token"});

        const connection = await db.connect();
        try {
            await connection.query('BEGIN');
            const request = await connection.query(`
            UPDATE users
            SET verified = true
            WHERE uuid = $1
            RETURNING uuid, username, avatar
            `, [tokenData.useruuid]);

            if (!request?.rows[0]) {
                await connection.query('ROLLBACK');
                return res.status(400).json({ message: 'User not found' });
            }

            const user = {
                uuid: request.rows[0].uuid,
                username: request.rows[0].username,
                avatar: request.rows[0].avatar
            };

            const avatarURL = user.avatar ? `users/${user.uuid}/avatar` : `Default/avatar`;
            user.avatar = await GetImage(avatarURL);
            if (!user.avatar) {
                await connection.query('ROLLBACK');
                return res.status(400).json({message: "Error fetching avatar"});
            }

            const accessToken = new Token(user.uuid, Token.Type.ACCESS, Token.StorageType.CACHE);
            if (!await accessToken.Save(res, null, true)) {
                await connection.query('ROLLBACK');
                return res.status(400).json({ message: "Couldn't create a token" });
            }
            const refreshToken = new Token(user.uuid, Token.Type.REFRESH, Token.StorageType.DATABASE, { "accessjti": accessToken.content.jti });
            if (!await refreshToken.Save(res, connection, false)) {
                await connection.query('ROLLBACK');
                return res.status(400).json({ message: "Couldn't create a token" });
            }

            res.clearCookie("token_verify", { path: "/auth/verify" });
            try {
                deleteCachedValue(`${user.uuid}/tokens/${Token.Type.VERIFY}/${tokenData.jti}`);
            } catch (err) { err; }

            await connection.query('COMMIT');
            return res.status(200).json({ message: 'Successfully verified your account', user });
        } catch (err) {
            await connection.query('ROLLBACK');
            if (process.env.LOGERRORS === 'true') console.error(err);
            return res.status(500).json({ message: "Internal server error" });
        } finally {
            connection.release();
        }
    });
};