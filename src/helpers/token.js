const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../config/db/db');
const { setCachedValue, getCachedValue } = require('../config/cache/redis');

class Token {
    static Type = Object.freeze({
        ACCESS: "access",
        REFRESH: "refresh",
        LOGIN: "login",
        VERIFY: "verify"
    });

    static StorageType = Object.freeze({
        CACHE: "cache",
        DATABASE: "database",
        BOTH: "both"
    });

    constructor(useruuid, type, storage, extra) {
        const version = process.env['TOKEN_SECRET_' + type.toUpperCase() + '_VERSION'];
        const duration = Number(process.env['TOKEN_EXP_' + type.toUpperCase()]) * 60 * 60 * 1000;
        const expirationDate = new Date(Date.now() + duration);
        const jti = crypto.randomUUID();
        const content = {
            useruuid,
            jti,
            storage,
            ...(extra || {})
        };
        const token = jwt.sign(content, process.env['TOKEN_SECRET_' + type.toUpperCase() + '_V' + version]);

        this.exp = expirationDate;
        this.duration = duration;
        this.token = token;
        this.content = content;
        this.version = version;
        this.type = type;
        this.storage = storage;
    }

    async Save(res, database) {
        try {
            if (this.storage != Token.StorageType.DATABASE)
                await setCachedValue(`${this.content.useruuid}/tokens/${this.type}/${this.content.jti}`, this.duration * 60 * 60 + 10, "1");

            if (this.storage != Token.StorageType.CACHE && database != null)
                await database.query(`
                    INSERT INTO tokens (useruuid, type, jti, expires_at)
                    VALUES ($1, $2, $3, $4)
                `, [this.content.useruuid, this.type, this.content.jti, this.exp]);

            res.cookie('token_' + this.type, this.version + ":" + this.token, {
                httpOnly: true,
                sameSite: 'Strict',
                path: "/auth/" + this.type,
                secure: process.env.SECURE === "true",
                maxAge: this.duration
            });

            return true;
        } catch (err) {
            if (process.env.LOGERRORS === 'true') console.error(err);
            return false;
        }
    }

    static async GetData(encryptedToken, type) {
        try {
            if (encryptedToken == null) return null;

            const tokenSlicer = encryptedToken.indexOf(":");
            if (tokenSlicer === -1) return null;

            //Get version stored in token
            const version = Number(encryptedToken.slice(0, tokenSlicer));
            if (version == null) return null;

            //Get secret of token
            const secret = process.env['TOKEN_SECRET_' + type.toUpperCase() + '_V' + version];
            if (secret == null) return null;

            const token = encryptedToken.slice(tokenSlicer + 1);

            const decode = jwt.verify(token, secret);
            
            if (decode.storage != Token.StorageType.DATABASE)
            {
                const cache = await getCachedValue(`${decode.useruuid}/tokens/${type}/${decode.jti}`);
                if (cache == null && decode.storage == Token.StorageType.CACHE) return null;
            }
            
            if (decode.storage != Token.StorageType.CACHE) {
                const response = await db.query(`
                    SELECT expires_at FROM tokens
                    WHERE useruuid=$1 AND jti=$2 AND type=$3
                `, [decode.useruuid, decode.jti, type]);
                    
                if (response.rowCount == 0) return null;
                if (new Date(response.rows[0].expires_at) < new Date()) 
                {
                    try {
                        await db.query(`
                            DELETE FROM tokens
                            WHERE useruuid=$1 AND jti=$2 AND type=$3
                        `, [decode.useruuid, decode.jti, type]);
                    } catch (err) { if (process.env.LOGERRORS === 'true') console.error(err); }

                    return null;
                }
            }

            //Instead of manually checking user ban, manually remove user tokens from database

            return decode;
        } catch (err) {
            if (process.env.LOGERRORS === 'true') console.error(err);
            return null;
        }
    }
}

module.exports = Token;