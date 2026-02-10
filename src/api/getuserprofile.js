const db = require("../config/db/db");
const { GetImage } = require("../helpers/gcstools");
const { validateUUID } = require("../helpers/validate/validate");

module.exports = (app) => {
    app.get('/getuserprofile', async (req, res) => {
        const uuid = req?.query?.uuid;
        if (!validateUUID(uuid)) return res.status(400).json({message: "Invalid UUID format"});

        try {
            const request = await db.query(`
                SELECT avatar, username, uuid
                FROM users
                WHERE uuid=$1
            `, [uuid]);

            const avatarURL = request.rows[0].avatar ? `users/${uuid}/avatar` : `Default/avatar`;
            const avatar = await GetImage(avatarURL);
            if (!avatar) return res.status(400).json({message: "Error fetching avatar"});

            const user = request.rows[0];
            user.avatar = avatar;

            return res.status(200).json({message: "Successfully fetched user profile", data: user});
        } catch (err) 
        {
            if (process.env.LOGERRORS === 'true') console.error(err);
            return res.status(500).json({message: "Internal server error"});
        }
    });
};