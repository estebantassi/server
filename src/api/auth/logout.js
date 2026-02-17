const { deleteCachedValue } = require("../../config/cache/redis");
const db = require("../../config/db/db");
const Token = require("../../helpers/token");

module.exports = (app) => {
    app.post("/auth/refresh/logout", async (req, res) => {
        const token = req?.cookies?.token_refresh;
        res.clearCookie("token_refresh", { path: "/auth/refresh" });
        
        const data = await Token.GetData(token, Token.Type.REFRESH);
        const authorized = data != null;
        if (authorized)
        {
            try {
                await db.query(`
                    DELETE FROM tokens
                    WHERE useruuid=$1 AND jti=$2 AND type=$3
                `, [data.useruuid, data.jti, Token.Type.REFRESH]);
            } catch (err) { if (process.env.LOGERRORS === 'true') console.error(err); }

            try { await deleteCachedValue(`${data.useruuid}/tokens/${Token.Type.ACCESS}/${data.accessjti}`); }
            catch (err) { if (process.env.LOGERRORS === 'true') console.error(err); }   
        }

        return res.status(200).json({ authorized });
    });
};