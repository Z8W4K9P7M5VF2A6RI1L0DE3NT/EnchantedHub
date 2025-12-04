// =======================================================
// NovaHub Backend + Integrated Linkvertise Bypasser
// Full Combined Version
// =======================================================

require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const cors = require("cors");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3000;

// --------------------- Payload Limits ---------------------
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));
app.use(cors());

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

    client.query(`
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(64) PRIMARY KEY,
            script TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `, (err) => {
        done();
        if (err) console.error("Table Creation Error:", err.stack);
        else console.log("DB Table Ready.");
    });
});

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

/* =======================================================
   ===============  /obfuscate (NO STORAGE) ===============
   ======================================================= */
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

                if (err || stderr || !fs.existsSync(outputFile)) {
                    console.error("Obfuscator Error:", err?.message || stderr);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    obfuscated = applyFallback(rawLua);
                    return resolve();
                }

                obfuscated = WATERMARK + fs.readFileSync(outputFile, "utf8");
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

/* =======================================================
   =========  /obfuscate-and-store → RETURN key ===========
   ======================================================= */
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

                if (err || stderr || !fs.existsSync(outputFile)) {
                    console.error("Obfuscator Error:", err?.message || stderr);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    obfuscated = applyFallback(rawLua);
                    return resolve();
                }

                obfuscated = WATERMARK + fs.readFileSync(outputFile, "utf8");
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

/* =======================================================
   ======  /retrieve/:key → Roblox Only ===================
   ======================================================= */
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

        if (result.rows.length === 0)
            return res.status(404).send("-- Script Not Found.");

        res.setHeader("Content-Type", "text/plain");
        res.send(result.rows[0].script);

    } catch (err) {
        console.error("DB Retrieve Error:", err);
        res.status(500).send("-- Internal Server Error.");
    }
});

/* =======================================================
   ========== LINKVERTISE / LOOT-LINK / PLATOBOOST ========
   =======================  BYPASSER  =====================
   ======================================================= */

// --- Util: Base64 check ---
function isBase64(str) {
    if (!str || typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (trimmed === '') return false;
    try {
        const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
        const reencoded = Buffer.from(decoded, 'utf8').toString('base64');
        return reencoded === trimmed.replace(/=+$/, '');
    } catch { return false; }
}

function randomString() {
    return Math.floor(Math.random() * 1e7).toString();
}

const FAKE_UA =
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1';

function uaGet(url) {
    return axios.get(url, {
        headers: {
            "User-Agent": FAKE_UA,
            "Accept": "application/json, text/plain, */*"
        },
        timeout: 10000
    });
}

function uaPost(url, data, extraHeaders = {}) {
    return axios.post(url, data, {
        headers: {
            "User-Agent": FAKE_UA,
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            ...extraHeaders
        },
        timeout: 10000
    });
}

const cache = new Map();
function cacheSet(key, value, ttl = 600000) {
    cache.set(key, { value, exp: Date.now() + ttl });
}
function cacheGet(key) {
    const entry = cache.get(key);
    if (!entry || Date.now() > entry.exp) return null;
    return entry.value;
}

function axiosErrorDetails(err) {
    if (err?.response?.data) return err.response.data;
    if (err?.message) return err.message;
    return String(err);
}

// --- Linkvertise core bypass ---
async function bypassLinkvertisePath(pathPart, ut = null) {
    const cacheKey = `lv:${pathPart}:${ut || ''}`;
    const cached = cacheGet(cacheKey);
    if (cached) return cached;

    // Warmup (ignore failures)
    ["/captcha", "/countdown_impression?trafficOrigin=network", "/todo_impression?mobile=true&trafficOrigin=network"]
        .forEach(p => uaGet(`https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`).catch(() => {}));

    const staticUrl = `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
    const staticResp = await uaGet(staticUrl).catch(e => {
        throw { status: 502, message: "Failed static", details: axiosErrorDetails(e) };
    });

    const link = staticResp?.data?.data?.link;
    if (!link) throw { status: 502, message: "Unexpected linkvertise static data" };

    const type = link.target_type === "URL"
        ? "target"
        : link.target_type === "PASTE"
        ? "paste"
        : null;

    if (!type) throw { status: 502, message: "Unsupported Linkvertise type" };

    const serial = Buffer
        .from(JSON.stringify({ timestamp: Date.now(), random: randomString(), link_id: link.id }))
        .toString("base64");

    const postUrl =
        `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${type}` +
        (ut ? `?X-Linkvertise-UT=${encodeURIComponent(ut)}` : "");

    const postResp = await uaPost(postUrl, { serial }).catch(e => {
        throw { status: 502, message: "POST failed", details: axiosErrorDetails(e) };
    });

    if (!postResp?.data?.data) throw { status: 502, message: "Invalid Linkvertise response" };

    const result =
        type === "target"
            ? { decodedUrl: postResp.data.data.target }
            : { paste: (postResp.data.data.paste || "").trim() };

    cacheSet(cacheKey, result);
    return result;
}

// ---- Unified bypass endpoint ----
app.get("/api/bypass", async (req, res) => {
    try {
        // ?r=BASE64
        if (req.query.r) {
            if (!isBase64(req.query.r))
                return res.status(400).json({ success: false, error: "Invalid base64" });

            return res.json({
                success: true,
                type: "base64",
                decodedUrl: Buffer.from(req.query.r, "base64").toString("utf8")
            });
        }

        // ?url=
        if (req.query.url) {
            const parsed = new URL(req.query.url);

            // loot-link
            if (parsed.hostname === "loot-link.com" && parsed.searchParams.get("r")) {
                const r = parsed.searchParams.get("r");
                if (!isBase64(r)) return res.status(400).json({ success: false, error: "Invalid Base64" });

                return res.json({
                    success: true,
                    service: "loot-link",
                    decodedUrl: Buffer.from(r, "base64").toString("utf8")
                });
            }

            // platoboost
            if (parsed.hostname === "gateway.platoboost.com" && parsed.searchParams.get("id")) {
                const id = parsed.searchParams.get("id");
                if (!isBase64(id)) return res.status(400).json({ success: false, error: "Invalid Base64" });

                return res.json({
                    success: true,
                    service: "platoboost",
                    decodedUrl: Buffer.from(id, "base64").toString("utf8")
                });
            }

            // generic ?r=
            if (parsed.searchParams.get("r")) {
                const r = parsed.searchParams.get("r");
                if (!isBase64(r)) return res.status(400).json({ success: false, error: "Invalid Base64" });

                return res.json({
                    success: true,
                    service: "generic-r",
                    decodedUrl: Buffer.from(r, "base64").toString("utf8")
                });
            }

            // generic ?id=
            if (parsed.searchParams.get("id")) {
                const id = parsed.searchParams.get("id");
                if (isBase64(id)) {
                    return res.json({
                        success: true,
                        service: "generic-id",
                        decodedUrl: Buffer.from(id, "base64").toString("utf8")
                    });
                }
            }

            // LINKVERTISE
            if (parsed.hostname.includes("linkvertise")) {
                const m = /^(\/[0-9]+\/[^\/]+)/.exec(parsed.pathname);
                if (!m)
                    return res.status(400).json({ success: false, error: "Bad Linkvertise path" });

                try {
                    const data = await bypassLinkvertisePath(m[1], req.query.ut || req.headers["x-linkvertise-ut"]);
                    return res.json({ success: true, service: "linkvertise", ...data });
                } catch (err) {
                    return res.status(err.status || 500).json({
                        success: false,
                        error: err.message || "LV Error",
                        details: err.details
                    });
                }
            }

            return res.status(400).json({ success: false, error: "Unsupported URL" });
        }

        return res.status(400).json({ success: false, error: "Missing ?r= or ?url=" });

    } catch (err) {
        res.status(500).json({ success: false, error: "Internal error", details: axiosErrorDetails(err) });
    }
});

/* =======================================================
   =============== Root ===================
   ======================================================= */
app.get("/", (req, res) => {
    res.send("NovaHub Backend + Bypasser Running.");
});

/* =======================================================
   =============== Start Server ===========================
   ======================================================= */
app.listen(port, () =>
    console.log(`NovaHub API + Bypasser running on port ${port}`)
);
