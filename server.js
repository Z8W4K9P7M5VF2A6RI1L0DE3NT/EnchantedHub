// =======================================================
// NovaHub Backend (Obfuscation + Storage)
// Full Updated Version (API-SERVICE.html Added)
// =======================================================

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
require("dotenv").config();
const cors = require("cors");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;

// --------------------- Payload Limits ---------------------
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));

// --------------------- Postgres Connection ---------------------
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

pool.connect((err, client, done) => {
    if (err) {
        console.error("DB Connection Failed:", err.stack);
        return;
    }
    console.log("Connected to PostgreSQL.");

    const tableSQL = `
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(64) PRIMARY KEY,
            script TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;

    client.query(tableSQL, (err) => {
        done();
        if (err) console.error("Table Creation Error:", err.stack);
        else console.log("DB Table Ready.");
    });
});

app.use(cors());

// --------------------- Static Folder ---------------------
app.use(express.static("public"));

// --------------------- Serve API-SERVICE.html ---------------------
app.get("/API-SERVICE.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "API-SERVICE.html"));
});

// --------------------- Constants ---------------------
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] ";
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw Lua. Check your syntax. ]] ";

const generateUniqueId = () => crypto.randomBytes(16).toString("hex");
const applyFallback = (raw) => `${FALLBACK_WATERMARK}\n${raw}`;

// =======================================================
// ===============  /obfuscate (NO STORAGE) ===============
// =======================================================
app.post("/obfuscate", async (req, res) => {
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
                fs.unlinkSync(tempFile);

                if (err || stderr) {
                    console.error("Obfuscator Error:", err?.message || stderr);

                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);

                    obfuscated = applyFallback(rawLua);
                    success = false;
                    return resolve();
                }

                if (!fs.existsSync(outputFile)) {
                    obfuscated = applyFallback(rawLua);
                    success = false;
                    return resolve();
                }

                obfuscated = fs.readFileSync(outputFile, "utf8");
                obfuscated = WATERMARK + obfuscated;
                fs.unlinkSync(outputFile);
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

// =======================================================
// ======  /obfuscate-and-store → RETURN key ==============
// =======================================================
app.post("/obfuscate-and-store", async (req, res) => {
    const rawLua = req.body.script;
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
                fs.unlinkSync(tempFile);

                if (err || stderr) {
                    console.error("Obfuscator Error:", err?.message || stderr);

                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);

                    obfuscated = applyFallback(rawLua);
                    success = false;
                    return resolve();
                }

                if (!fs.existsSync(outputFile)) {
                    obfuscated = applyFallback(rawLua);
                    success = false;
                    return resolve();
                }

                obfuscated = fs.readFileSync(outputFile, "utf8");
                obfuscated = WATERMARK + obfuscated;
                fs.unlinkSync(outputFile);
                success = true;

                resolve();
            });
        });
    } catch (err) {
        console.error("Error:", err);
        obfuscated = applyFallback(rawLua);
    }

    const key = generateUniqueId();

    try {
        await pool.query(
            "INSERT INTO scripts(key, script) VALUES($1, $2)",
            [key, obfuscated]
        );

        res.status(201).json({ key, success });
    } catch (err) {
        console.error("DB Store Error:", err);
        res.status(500).json({ error: "Storage Failure" });
    }
});

// =======================================================
// ======  /retrieve/:key → Roblox Only ===================
// =======================================================
app.get("/retrieve/:key", async (req, res) => {
    const key = req.params.key;
    const ua = req.headers["user-agent"];

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

// =======================================================
// Root
// =======================================================
app.get("/", (req, res) => {
    res.send("NovaHub Backend Running.");
});

// =======================================================
// Start Server
// =======================================================
app.listen(port, () => console.log(`NovaHub API running on port ${port}`));
