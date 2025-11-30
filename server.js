const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
require('dotenv').config();
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require("axios");   // ⭐ REQUIRED for AST reverse-proxy

const app = express();
const port = process.env.PORT || 3000;

/* ---------------- Payload Config ---------------- */
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(cors());
app.use(express.static('public'));

/* ---------------- Database Setup ---------------- */
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Connected to PostgreSQL.');

    client.query(`
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(32) PRIMARY KEY,
            script TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `, (err) => {
        done();
        if (err) console.error('Error creating table:', err.stack);
        else console.log('Table "scripts" ready.');
    });
});

/* ---------------- Constants ---------------- */
const WATERMARK = "-- </> This file has been secured using Nova Hub Protection ";
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";
const SCRIPT_LUA_PATH = path.join(__dirname, 'src', 'cli.lua');

/* ---------------- Helper Functions ---------------- */
const generateId = () => crypto.randomBytes(16).toString("hex");
const applyFallback = (raw) => `${FALLBACK_WATERMARK}\n${raw}`;

/* ======================================================
      FULL OBFUSCATOR FUNCTION (Supports presets)
====================================================== */
async function runObfuscator(rawLua, preset = "Medium") {
    const timestamp = Date.now();
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);

    let success = false;
    let finalCode = "";

    try {
        fs.writeFileSync(tempFile, rawLua, "utf8");

        const command = `lua ${SCRIPT_LUA_PATH} --preset ${preset} --out ${outputFile} ${tempFile}`;

        await new Promise(resolve => {
            exec(command, (error, stdout, stderr) => {
                try { fs.unlinkSync(tempFile); } catch {}

                if (error) {
                    console.error("Lua execution error:", error);
                    finalCode = applyFallback(rawLua);
                    return resolve();
                }

                if (!fs.existsSync(outputFile)) {
                    console.error("Obfuscator output missing.");
                    finalCode = applyFallback(rawLua);
                    return resolve();
                }

                finalCode = fs.readFileSync(outputFile, "utf8");
                finalCode = WATERMARK + finalCode;

                try { fs.unlinkSync(outputFile); } catch {}

                success = true;
                resolve();
            });
        });

    } catch (err) {
        console.error("Internal obfuscator error:", err);
        finalCode = applyFallback(rawLua);
    }

    return { success, code: finalCode };
}

/* =======================================================
       MAIN OBFUSCATION ENDPOINT — /obfuscate
======================================================== */
app.post('/obfuscate', async (req, res) => {
    const rawLuaCode = req.body.code;
    const preset = req.body.preset || "Medium";

    if (!rawLuaCode || typeof rawLuaCode !== "string") {
        return res.status(400).json({ error: 'A "code" field containing Lua script is required.' });
    }

    const result = await runObfuscator(rawLuaCode, preset);

    if (result.success) {
        res.status(200).json({
            obfuscatedCode: result.code,
            success: true
        });
    } else {
        res.status(422).json({
            error: "Obfuscation Failed",
            obfuscatedCode: result.code,
            success: false
        });
    }
});

/* =======================================================
   OBFUSCATE + STORE INTO DATABASE
======================================================== */
app.post("/obfuscate-and-store", async (req, res) => {
    const raw = req.body.script;

    if (!raw)
        return res.status(400).json({ error: "Missing 'script' in request body." });

    const { success, code } = await runObfuscator(raw, "Medium");

    const key = generateId();

    try {
        await pool.query(
            "INSERT INTO scripts(key, script) VALUES($1, $2)",
            [key, code]
        );

        res.status(201).json({
            message: success ? "Obfuscation + storage complete." : "Stored, but obfuscation failed.",
            key
        });

    } catch (err) {
        console.error("DB error:", err);
        res.status(500).json({ error: "Database storage failure." });
    }
});

/* =======================================================
         ROBLOX LOADER — GET STORED OBFUSCATED SCRIPT
======================================================== */
app.get("/retrieve/:key", async (req, res) => {
    const key = req.params.key;

    if (!req.headers["user-agent"]?.includes("Roblox")) {
        res.setHeader("Content-Type", "text/plain");
        return res.status(403).send("-- Access Denied.");
    }

    try {
        const result = await pool.query(
            "SELECT script FROM scripts WHERE key = $1", [key]
        );

        if (result.rows.length === 0)
            return res.status(404).send("-- Script not found.");

        res.setHeader("Content-Type", "text/plain");
        res.send(result.rows[0].script);

    } catch (err) {
        console.error("DB fetch error:", err);
        res.status(500).send("-- Internal Server Error.");
    }
});

/* =======================================================
     ⭐ ADVANCED AST CLEANER REVERSE-PROXY (FINAL)
======================================================== */
app.post("/clean_ast", async (req, res) => {
    try {
        const upstream = await axios.post(
            "http://localhost:5001/clean_ast",
            req.body,
            { headers: { "Content-Type": "application/json" } }
        );

        res.status(200).json(upstream.data);

    } catch (err) {
        console.error("Proxy /clean_ast failed:", err.message);

        res.status(500).json({
            error: "ast_backend_failure",
            message: err.message
        });
    }
});

/* -----------------------------------------------------
                      ROOT
------------------------------------------------------ */
app.get('/', (req, res) => {
    res.redirect('/ast.html');
});

/* -----------------------------------------------------
                    START SERVER
------------------------------------------------------ */
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
