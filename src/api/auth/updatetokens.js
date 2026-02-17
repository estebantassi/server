const db = require("../../config/db/db");
const Token = require("../../helpers/token");

module.exports = (app) => {
    app.get("/auth/refresh/update", async (req, res) => {
        const token = req?.cookies?.token_refresh;

        const data = await Token.GetData(token, Token.Type.REFRESH);
        const authorized = data != null;

        if (authorized) {
            try {
                await db.query(`
                    DELETE FROM tokens
                    WHERE useruuid=$1 AND jti=$2 AND type=$3
                `, [data.useruuid, data.jti, Token.Type.REFRESH]);
            } catch (err) { if (process.env.LOGERRORS === 'true') console.error(err); }

            let accessToken = new Token(data.useruuid, Token.Type.ACCESS, Token.StorageType.CACHE);
            if (!await accessToken.Save(res, db)) return res.status(400).json({ message: "Error creating new token" });

            let refreshToken = new Token(data.useruuid, Token.Type.REFRESH, Token.StorageType.DATABASE);
            if (!await refreshToken.Save(res, db)) return res.status(400).json({ message: "Error creating new token" });
        }

        return res.status(200).json({ authorized });
    });
};