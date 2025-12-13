// =======================================================
// Enchanted Hub Backend (Updated for Discord Avatar)
// =======================================================

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
require("dotenv").config();
const cors = require("cors");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const fetch = require("node-fetch"); 
const session = require('express-session'); 

const app = express();
const port = process.env.PORT || 3000;

// Enable trust proxy for Render (required for correct session and IP handling)
app.set('trust proxy', 1);

// --------------------- Payload Limits & CORS ---------------------
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));

// Setup express-session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'a_very_insecure_default_secret_use_env_var', 
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true, 
        httpOnly: true,
        sameSite: 'none', 
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    } 
}));

// CORS setup: Allow credentials and specific origin
app.use(cors({
    origin: 'https://enchantedhub.onrender.com', // Replace with your frontend URL
    credentials: true,
}));

// --------------------- PostgreSQL (Render Compatible) ---------------------
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

pool.connect((err, client, done) => {
    if (err) {
        console.error("DB Connection Failed:", err.stack);
        return;
    }

    console.log("Connected to PostgreSQL (Enchanted Hub).");

    // UPDATED: Added avatar column to the users table
    const tableSQL = `
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(64) PRIMARY KEY,
            script TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- UPDATED: Added avatar column
        CREATE TABLE IF NOT EXISTS users (
            discord_id VARCHAR(32) PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255),
            avatar VARCHAR(128),  -- NEW COLUMN for Discord avatar hash
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS script_users (
            script_key VARCHAR(64) REFERENCES scripts(key) ON DELETE CASCADE,
            user_discord_id VARCHAR(32) REFERENCES users(discord_id) ON DELETE CASCADE,
            PRIMARY KEY (script_key, user_discord_id)
        );

        CREATE TABLE IF NOT EXISTS script_access_log (
            id SERIAL PRIMARY KEY,
            script_key VARCHAR(64) REFERENCES scripts(key) ON DELETE CASCADE,
            ip_address VARCHAR(45) NOT NULL,
            user_agent TEXT,
            access_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;

    client.query(tableSQL, (queryErr) => {
        done();
        if (queryErr) console.error("DB Table Creation Error:", queryErr.stack);
        else console.log("DB Tables Ready (Enchanted Hub).");
    });
});

// --------------------- Static Folder & Constants ---------------------
app.use(express.static("public"));
app.get("/API-SERVICE.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "API-SERVICE.html"));
});

const WATERMARK = "--[[\n\n </> Enchanted Hub Lua Obfuscator\n\n--[[";
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw Lua. Check your syntax. ]] ";

const generateUniqueId = () => crypto.randomBytes(16).toString("hex");
const applyFallback = (raw) => `${FALLBACK_WATERMARK}\n${raw}`;


// --------------------- Discord OAuth2 Configuration ---------------------
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const DISCORD_SCOPES = 'identify email guilds.join'; 

// Guild Join Configuration
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN; 
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;   

// --------------------- Authentication Middleware ---------------------
const requireAuth = (req, res, next) => {
    if (req.session.discord_id) {
        next();
    } else {
        res.status(401).json({ error: "Unauthorized. Please login with Discord." });
    }
};

// --------------------- Discord Guild Join Function ---------------------
const addUserToGuild = async (userId, accessToken, username) => {
    if (!DISCORD_BOT_TOKEN || !DISCORD_GUILD_ID) {
        console.warn("DISCORD_BOT_TOKEN or DISCORD_GUILD_ID is missing. Skipping guild join.");
        return { success: false, message: "Missing server configuration." };
    }

    const apiEndpoint = `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${userId}`;
    
    try {
        const response = await fetch(apiEndpoint, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bot ${DISCORD_BOT_TOKEN}` 
            },
            body: JSON.stringify({
                access_token: accessToken, 
                nick: username 
            })
        });

        if (response.status === 201 || response.status === 204) {
            console.log(`User ${userId} successfully added/already in guild ${DISCORD_GUILD_ID}.`);
            return { success: true };
        } 
        
        const errorData = await response.json();
        console.error(`Failed to add user ${userId} to guild ${DISCORD_GUILD_ID}:`, errorData);
        return { success: false, message: errorData.message || "Discord API error during guild join." };

    } catch (err) {
        console.error("Guild Join Fetch Error:", err);
        return { success: false, message: "Network error during guild join." };
    }
};

// =======================================================
// ======  DISCORD OAUTH2 FLOW (UPDATED) ===================
// =======================================================

// 1. Redirect to Discord
app.get('/auth/discord', (req, res) => {
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent(DISCORD_SCOPES)}`;
    res.redirect(discordAuthUrl);
});

// 2. Discord Callback (Receives the code)
app.get('/auth/discord/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.status(400).send("No code provided.");
    }

    try {
        // Exchange code for token
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: DISCORD_REDIRECT_URI,
                scope: DISCORD_SCOPES,
            })
        });
        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        if (!accessToken) {
            console.error("Token exchange failed:", tokenData);
            return res.status(500).send("Authentication failed. Invalid token or code.");
        }

        // Use token to get user info (includes email and avatar)
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        const userData = await userResponse.json();
        // NOW FETCHING AVATAR HASH
        const { id, username, email, avatar } = userData; 

        // 1. Store or update user in database (including email and avatar)
        await pool.query(
            "INSERT INTO users (discord_id, username, email, avatar) VALUES ($1, $2, $3, $4) ON CONFLICT (discord_id) DO UPDATE SET username = $2, email = $3, avatar = $4",
            [id, username, email, avatar]
        );
        
        // 2. Attempt to add user to the guild (Server)
        await addUserToGuild(id, accessToken, username);

        // 3. Set session (NOW INCLUDING AVATAR)
        req.session.discord_id = id;
        req.session.username = username;
        req.session.avatar = avatar; // Store avatar hash in session

        // Redirect back to the main dashboard/frontend
        res.redirect('/'); 

    } catch (err) {
        console.error("Discord OAuth Error:", err);
        res.status(500).send("Internal Server Error during Discord login.");
    }
});

// 3. Get User Status (for Frontend) - UPDATED
app.get('/api/user/status', async (req, res) => {
    if (req.session.discord_id) {
        // Fetch the latest avatar and username from the DB, just in case the session is stale
        try {
            const result = await pool.query(
                "SELECT username, avatar FROM users WHERE discord_id = $1",
                [req.session.discord_id]
            );
            
            if (result.rows.length > 0) {
                const user = result.rows[0];
                res.json({ 
                    loggedIn: true, 
                    discord_id: req.session.discord_id,
                    username: user.username,
                    avatar: user.avatar // RETURN AVATAR HASH
                });
                return;
            }
        } catch (dbErr) {
            console.error("DB lookup failed for status check:", dbErr);
            // Fallback to session data if DB fails
            res.json({ 
                loggedIn: true, 
                discord_id: req.session.discord_id,
                username: req.session.username,
                avatar: req.session.avatar // Fallback avatar hash
            });
            return;
        }

    } 
    
    // Not logged in or DB lookup failed
    res.json({ loggedIn: false });
});

// 4. Logout
app.post('/api/user/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: "Could not log out." });
        res.clearCookie('connect.sid'); 
        res.json({ success: true, message: "Logged out." });
    });
});

// =======================================================
// === OBFUSCATION, STORAGE, MANAGEMENT ENDPOINTS (No Change) ===
// =======================================================

// ... (Rest of the /v1/obfuscate/auth, /obfuscate-and-store, /api/user/scripts, etc. endpoints remain the same) ...

// Existing logic for obfuscating without storing (no auth required)
app.post("/v1/obfuscate/auth", async (req, res) => {
    const rawLua = req.body.code;
    const preset = "Medium";
    const timestamp = Date.now();

    const tempFile = `/tmp/temp_${timestamp}.lua`;
    const outputFile = `/tmp/obf_${timestamp}.lua`;

    let obfuscated = "";
    let success = false;

    try {
        fs.writeFileSync(tempFile, rawLua, "utf8");

        const cmd = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;

        await new Promise((resolve) => {
            exec(cmd, (err, stdout, stderr) => {
                try {
                    fs.unlinkSync(tempFile);
                } catch (e) {}

                if (err || stderr) {
                    console.error("Obfuscator Error:", err?.message || stderr);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    obfuscated = applyFallback(rawLua);
                    return resolve();
                }

                if (!fs.existsSync(outputFile)) {
                    obfuscated = applyFallback(rawLua);
                    return resolve();
                }

                obfuscated = fs.readFileSync(outputFile, "utf8");
                obfuscated = WATERMARK + obfuscated;
                try {
                    fs.unlinkSync(outputFile);
                } catch (e) {}
                success = true;
                resolve();
            });
        });

    } catch (err) {
        console.error("FS/Exec Error:", err);
        obfuscated = applyFallback(rawLua);
    }

    res.json({ obfuscatedCode: obfuscated, success });
});

// /obfuscate-and-store endpoint
app.post("/obfuscate-and-store", requireAuth, async (req, res) => {
    const rawLua = req.body.script;
    const user_discord_id = req.session.discord_id;
    const preset = "Medium";
    const timestamp = Date.now();

    const tempFile = `/tmp/temp_${timestamp}.lua`;
    const outputFile = `/tmp/obf_${timestamp}.lua`;

    let obfuscated = "";
    let success = false;
    
    // --- [OBFUSCATION EXECUTION LOGIC] ---
    try {
        fs.writeFileSync(tempFile, rawLua, "utf8");
        const cmd = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;

        await new Promise((resolve) => {
            exec(cmd, (err, stdout, stderr) => {
                try {
                    fs.unlinkSync(tempFile);
                } catch (e) {}

                if (err || stderr || !fs.existsSync(outputFile)) {
                    console.error("Obfuscator Error:", err?.message || stderr);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    obfuscated = applyFallback(rawLua);
                    return resolve();
                }

                obfuscated = fs.readFileSync(outputFile, "utf8");
                obfuscated = WATERMARK + obfuscated;
                try {
                    fs.unlinkSync(outputFile);
                } catch (e) {}
                success = true;
                resolve();
            });
        });

    } catch (err) {
        console.error("Error:", err);
        obfuscated = applyFallback(rawLua);
    }
    // --- [END OBFUSCATION EXECUTION LOGIC] ---

    const key = generateUniqueId();

    try {
        await pool.query("BEGIN"); // Start transaction

        // 1. Insert into scripts table
        await pool.query(
            "INSERT INTO scripts(key, script) VALUES($1, $2)",
            [key, obfuscated]
        );
        
        // 2. Link script to user
        await pool.query(
            "INSERT INTO script_users(script_key, user_discord_id) VALUES($1, $2)",
            [key, user_discord_id]
        );

        await pool.query("COMMIT"); // Commit transaction

        res.status(201).json({ key, success });
    } catch (err) {
        await pool.query("ROLLBACK"); // Rollback on error
        console.error("DB Store Error:", err);
        res.status(500).json({ error: "Storage Failure" });
    }
});

// /api/user/scripts endpoint
app.get("/api/user/scripts", requireAuth, async (req, res) => {
    const user_discord_id = req.session.discord_id;

    try {
        const result = await pool.query(
            `SELECT 
                s.key, 
                s.created_at,
                (SELECT COUNT(DISTINCT ip_address) FROM script_access_log WHERE script_key = s.key) AS access_ip_count
            FROM scripts s
            JOIN script_users su ON s.key = su.script_key
            WHERE su.user_discord_id = $1
            ORDER BY s.created_at DESC`,
            [user_discord_id]
        );

        const scripts = result.rows.map(row => ({
            key: row.key,
            created_at: row.created_at,
            suspicious: parseInt(row.access_ip_count) > 5, 
            access_ip_count: parseInt(row.access_ip_count)
        }));

        res.json({ success: true, scripts });
    } catch (err) {
        console.error("DB Fetch User Scripts Error:", err);
        res.status(500).json({ error: "Failed to retrieve scripts." });
    }
});

// DELETE SCRIPT
app.delete("/api/user/scripts/:key", requireAuth, async (req, res) => {
    const key = req.params.key;
    const user_discord_id = req.session.discord_id;

    try {
        const deleteResult = await pool.query(
            "DELETE FROM script_users WHERE script_key = $1 AND user_discord_id = $2 RETURNING script_key",
            [key, user_discord_id]
        );

        if (deleteResult.rowCount === 0) {
            return res.status(404).json({ error: "Script not found or unauthorized." });
        }

        res.json({ success: true, key, message: "Script deleted." });
    } catch (err) {
        console.error("DB Delete Script Error:", err);
        res.status(500).json({ error: "Failed to delete script." });
    }
});

// EDIT SCRIPT
app.put("/api/user/scripts/:key", requireAuth, async (req, res) => {
    const key = req.params.key;
    const rawLua = req.body.script;
    const user_discord_id = req.session.discord_id;

    // First, verify the user owns the script
    const ownershipCheck = await pool.query(
        "SELECT 1 FROM script_users WHERE script_key = $1 AND user_discord_id = $2",
        [key, user_discord_id]
    );

    if (ownershipCheck.rowCount === 0) {
        return res.status(403).json({ error: "Forbidden: You do not own this script." });
    }

    // --- [OBFUSCATION EXECUTION LOGIC (REPEATED)] ---
    const preset = "Medium";
    const timestamp = Date.now();
    const tempFile = `/tmp/temp_${timestamp}.lua`;
    const outputFile = `/tmp/obf_${timestamp}.lua`;
    let obfuscated = "";
    let success = false;
    
    try {
        fs.writeFileSync(tempFile, rawLua, "utf8");
        const cmd = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;

        await new Promise((resolve) => {
            exec(cmd, (err, stdout, stderr) => {
                try {
                    fs.unlinkSync(tempFile);
                } catch (e) {}

                if (err || stderr || !fs.existsSync(outputFile)) {
                    console.error("Obfuscator Error:", err?.message || stderr);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    obfuscated = applyFallback(rawLua);
                    return resolve();
                }

                obfuscated = fs.readFileSync(outputFile, "utf8");
                obfuscated = WATERMARK + obfuscated;
                try {
                    fs.unlinkSync(outputFile);
                } catch (e) {}
                success = true;
                resolve();
            });
        });

    } catch (err) {
        console.error("Error:", err);
        obfuscated = applyFallback(rawLua);
    }
    // --- [END OBFUSCATION EXECUTION LOGIC] ---


    // Update script content
    try {
        const updateResult = await pool.query(
            "UPDATE scripts SET script = $1, created_at = CURRENT_TIMESTAMP WHERE key = $2 RETURNING key",
            [obfuscated, key]
        );

        if (updateResult.rowCount === 0) {
             return res.status(404).json({ error: "Script not found." });
        }

        res.json({ success: true, key, message: "Script updated and re-obfuscated." });
    } catch (err) {
        console.error("DB Update Script Error:", err);
        res.status(500).json({ error: "Failed to update script." });
    }
});


// /v1/api/auth/:key endpoint
app.get("/v1/api/auth/:key", async (req, res) => {
    const key = req.params.key;
    const ua = req.headers["user-agent"];
    const ip = req.ip || req.connection.remoteAddress; 

    // Log the access attempt
    try {
        await pool.query(
            "INSERT INTO script_access_log (script_key, ip_address, user_agent) VALUES ($1, $2, $3)",
            [key, ip, ua]
        );
    } catch (logErr) {
        console.error("Access Log Error:", logErr);
    }

    // Authorization Check (Roblox User-Agent)
    if (!ua || !ua.includes("Roblox")) {
        res.setHeader("Content-Type", "text/plain");
        return res.status(403).send("-- Access Denied.");
    }

    try {
        const result = await pool.query(
            "SELECT script FROM scripts WHERE key = $1",
            [key]
        );

        if (result.rows.length === 0) {
            return res.status(404).send("-- Script Not Found.");
        }

        res.setHeader("Content-Type", "text/plain");
        res.send(result.rows[0].script);

    } catch (err) {
        console.error("DB Retrieve Error:", err);
        res.status(500).send("-- Internal Server Error.");
    }
});


// Root
app.get("/", (req, res) => {
    res.send("Enchanted Hub Backend Running.");
});

// Start Server
app.listen(port, () => {
    console.log(`Enchanted Hub API running on port ${port}`);
});

