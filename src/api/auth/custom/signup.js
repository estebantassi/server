const db = require("../../../config/db/db");
const { Encrypt } = require("../../../helpers/encryption");
const crypto = require('crypto');
const { transporter } = require("../../../config/mail/mailtransport");
const { setCachedValue } = require("../../../config/cache/redis");
const Token = require("../../../helpers/token");
const { validateEmail, validateUsername, validateSRPSalt, validateSRPVerifier } = require("../../../helpers/validate/validate");
const { GetClientIP } = require("../../../helpers/ip");
const { ValidateTurnstile } = require("../../../helpers/validate/turnstile");

const emailHashVersion = process.env.EMAIL_HASH_SECRET_VERSION;
const emailEncryptedVersion = process.env.EMAIL_ENCRYPTION_SECRET_VERSION;
const securityEmail = process.env.SECURITY_EMAIL;

module.exports = (app) => {
    app.post("/auth/signup", async (req, res) => {
        const username = req?.body?.username;
        const email = req?.body?.email?.toLowerCase();
        const emailcheck = req?.body?.emailcheck?.toLowerCase();
        const srpSalt = req?.body?.srpSalt;
        const srpVerifier = req?.body?.srpVerifier;

        if (email !== emailcheck) return res.status(400).json({ message: "Emails don't match" });
        if (!validateEmail(email)) return res.status(400).json({ message: "Invalid email format" });
        if (!validateUsername(username)) return res.status(400).json({ message: "Invalid username format" });
        if (!validateSRPSalt(srpSalt)) return res.status(400).json({ message: "Invalid salt format" });
        if (!validateSRPVerifier(srpVerifier)) return res.status(400).json({ message: "Invalid verifier format" });;

        //TURNSTILE
        const ip = GetClientIP(req);
        const turnstile = ValidateTurnstile(req?.body?.turnstileToken, ip);
        if (!turnstile) return res.status(400).json({ message: "Error resolving CAPTCHA" });

        const connection = await db.connect();
        try {
            const emailHash = crypto.createHmac('sha256', process.env["EMAIL_HASH_SECRET_V" + emailHashVersion]).update(email).digest('hex');
            const emailEncrypted = Encrypt(emailEncryptedVersion + ":" + email, process.env['EMAIL_ENCRYPTION_SECRET_V' + emailEncryptedVersion]);

            const provider = "OpacubeVIP";
            await connection.query('BEGIN');
            const request = await connection.query(`
                INSERT INTO users (created_at, hashed_email, encrypted_email, auth_method, username, avatar, srp_salt, srp_verifier)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (hashed_email)
                DO UPDATE SET hashed_email = users.hashed_email
                RETURNING uuid, username, auth_method, avatar, (xmax = 0) AS inserted;
            `, [new Date().toISOString(), emailHash, emailEncrypted, provider, username, false, srpSalt, srpVerifier]);

            if (provider != request.rows[0].auth_method) {
                await connection.query('ROLLBACK');
                return res.status(400).json({ message: 'You already have an account associated with this email using another service (' + request.rows[0].auth_method + ')' });
            }

            if (!request.rows[0].inserted) {
                await connection.query('ROLLBACK');
                return res.status(400).json({ message: 'An account associated with this email already exists' });
            }

            const uuid = request.rows[0].uuid;

            const code = crypto.randomBytes(3).toString("hex").toUpperCase();
            await setCachedValue(`${uuid}/signup/codes/${code}`, 60 * 30, '1');

            const verifyToken = new Token(uuid, Token.Type.VERIFY, Token.StorageType.CACHE);
            if (!await verifyToken.Save(res, null)) {
                await connection.query('ROLLBACK');
                return res.status(500).json({message: "Couldn't create a token"});
            }

            await transporter.sendMail({
                from: securityEmail,
                to: email,
                subject: "Verification Link",
                text: `Verify your email by using this code:\n\n${code}\n\nIf you didn’t request this, ignore this email.`,
                html: `
                <div style="font-family: Arial, sans-serif; line-height: 1.6; max-width: 500px; margin: 0 auto; padding: 20px;">
                    <h2 style="margin-bottom: 10px;">Email Verification</h2>

                    <p style="margin-top: 0; color: #333;">
                    Use the verification code below to confirm your email address:
                    </p>

                    <div style="
                    background: #f4f4f4;
                    border: 1px solid #ddd;
                    padding: 15px;
                    text-align: center;
                    font-size: 28px;
                    font-weight: bold;
                    letter-spacing: 6px;
                    border-radius: 8px;
                    margin: 20px 0;
                    color: #111;
                    ">
                    ${code}
                    </div>

                    <p style="color: #666; font-size: 14px; margin-top: 20px;">
                    If you did not request this, you can safely ignore this email.
                    </p>
                </div>
                `,
            });

            await connection.query('COMMIT');
            return res.status(200).json({ message: 'Success' });
        } catch (err) {
            await connection.query('ROLLBACK');
            if (process.env.LOGERRORS === 'true') console.error(err);
            return res.status(500).json({ message: "Internal server error" });
        } finally {
            connection.release();
        }
    });
};