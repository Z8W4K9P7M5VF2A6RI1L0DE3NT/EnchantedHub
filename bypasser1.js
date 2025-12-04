// bypasser.js
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cors());

// Base64 validator
function isBase64(str) {
    if (!str || typeof str !== "string") return false;
    if (str.trim() === "") return false;

    try {
        const decoded = Buffer.from(str, 'base64').toString('utf8');
        const reencoded = Buffer.from(decoded, 'utf8').toString('base64');
        // allow for missing padding by normalizing
        const norm = str.replace(/=+$/, "");
        return reencoded === norm;
    } catch {
        return false;
    }
}

// Helper: pick a simple pseudo-random string (like userscript used "6548307")
function randomString() {
    return Math.floor(Math.random() * 1e7).toString();
}

// Fake mobile user agent (matches userscript)
const FAKE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) " +
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1";

// Helper: safe axios GET with UA
async function uaGet(url) {
    return axios.get(url, {
        headers: {
            "User-Agent": FAKE_UA,
            "Accept": "application/json, text/plain, */*"
        },
        timeout: 10000
    });
}

// Helper: safe axios POST with UA
async function uaPost(url, data, extraHeaders = {}) {
    return axios.post(url, data, {
        headers: Object.assign({
            "User-Agent": FAKE_UA,
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*"
        }, extraHeaders),
        timeout: 10000
    });
}

// ------------------------------------------
// UNIFIED /api/bypass ENDPOINT (+ Full Linkvertise bypass)
// ------------------------------------------
app.get('/api/bypass', async (req, res) => {
    let encoded = null;

    //
    // MANUAL MODE: /api/bypass?r=BASE64
    //
    if (req.query.r) {
        encoded = req.query.r;
    }

    //
    // AUTO-DETECT MODE
    //
    if (!encoded && req.query.url) {
        const url = req.query.url;

        try {
            const parsed = new URL(url);

            // Lootlink: ?r=BASE64
            if (parsed.hostname === "loot-link.com" && parsed.searchParams.get("r")) {
                encoded = parsed.searchParams.get("r");
            }

            // Platoboost: ?id=BASE64
            else if (parsed.hostname === "gateway.platoboost.com" && parsed.searchParams.get("id")) {
                encoded = parsed.searchParams.get("id");
            }

            // BoostLink or any other ?r=
            else if (parsed.searchParams.get("r")) {
                encoded = parsed.searchParams.get("r");
            }

            // LINKVERTISE BYPASS (server-side)
            // Accepts hostnames containing "linkvertise"
            // We'll detect path like "/12345/slug" and then call publisher.linkvertise.com APIs.
            else if (parsed.hostname.includes("linkvertise")) {
                // Attempt to match regular path like "/12345/slug"
                // Use same regex as the userscript: ^(\/[0-9]+\/[^\/]+)
                const re_regular = /^(\/[0-9]+\/[^\/]+)/;
                const is_regular = re_regular.exec(parsed.pathname);

                if (!is_regular) {
                    // unknown linkvertise path type
                    return res.status(400).json({
                        success: false,
                        error: "Unrecognized Linkvertise path format"
                    });
                }

                const pathPart = is_regular[1]; // e.g. "/12345/slug"
                // Allow client to provide X-Linkvertise-UT token via ?ut= or header x-linkvertise-ut
                const linkvertiseUT = req.query.ut || req.header('x-linkvertise-ut') || null;

                try {
                    // 1) Warm-up requests (fire-and-forget style from userscript)
                    const warmPaths = [
                        "/captcha",
                        "/countdown_impression?trafficOrigin=network",
                        "/todo_impression?mobile=true&trafficOrigin=network"
                    ];

                    // kick off warm requests but don't wait long for them (still await to catch errors if needed)
                    for (let p of warmPaths) {
                        const warmUrl = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`;
                        // don't throw on failure — but await so we don't flood
                        uaGet(warmUrl).catch(() => { /* ignore */ });
                    }

                    // 2) GET static endpoint
                    const staticUrl = `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
                    const staticResp = await uaGet(staticUrl);

                    if (!staticResp || !staticResp.data) {
                        return res.status(502).json({
                            success: false,
                            error: "Linkvertise static endpoint returned empty"
                        });
                    }

                    // Parse JSON:
                    const jsonStatic = staticResp.data;

                    // Validate expected structure
                    if (!jsonStatic.data || !jsonStatic.data.link || !jsonStatic.data.link.id || !jsonStatic.data.link.target_type) {
                        return res.status(502).json({
                            success: false,
                            error: "Unexpected Linkvertise static response structure",
                            details: jsonStatic
                        });
                    }

                    // Determine target type
                    let link_target_type;
                    if (jsonStatic.data.link.target_type === "URL") {
                        link_target_type = "target";
                    } else if (jsonStatic.data.link.target_type === "PASTE") {
                        link_target_type = "paste";
                    } else {
                        return res.status(502).json({
                            success: false,
                            error: `Unsupported Linkvertise link target type: ${jsonStatic.data.link.target_type}`
                        });
                    }

                    // 3) Build serial payload: userscript made an object { timestamp, random, link_id }
                    let o = {
                        timestamp: Date.now(),
                        random: randomString(),
                        link_id: jsonStatic.data.link.id
                    };
                    const serial = Buffer.from(JSON.stringify(o)).toString('base64');
                    const postPayload = { serial };

                    // 4) POST to the target endpoint
                    // allow ut token if provided
                    const targetEndpoint = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` +
                        (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}` : '');

                    const postResp = await uaPost(targetEndpoint, postPayload);

                    if (!postResp || !postResp.data) {
                        return res.status(502).json({
                            success: false,
                            error: "Linkvertise target endpoint returned empty"
                        });
                    }

                    const jsonPost = postResp.data;

                    // If target type is URL, return final URL
                    if (link_target_type === "target") {
                        if (!jsonPost.data || !jsonPost.data.target) {
                            return res.status(502).json({
                                success: false,
                                error: "Linkvertise response missing target"
                            });
                        }
                        return res.json({
                            success: true,
                            service: "linkvertise",
                            detectedBase64: null,
                            decodedUrl: jsonPost.data.target
                        });
                    } else {
                        // paste type: return paste contents
                        if (!jsonPost.data || typeof jsonPost.data.paste === "undefined") {
                            return res.status(502).json({
                                success: false,
                                error: "Linkvertise response missing paste"
                            });
                        }
                        // Return paste content as text field
                        return res.json({
                            success: true,
                            service: "linkvertise",
                            detectedBase64: null,
                            paste: String(jsonPost.data.paste).trim()
                        });
                    }

                } catch (err) {
                    // handle axios errors
                    const details = (err && err.response && err.response.data) ? err.response.data : (err.message || String(err));
                    return res.status(502).json({
                        success: false,
                        error: "Failed to bypass Linkvertise",
                        details
                    });
                }
            }
        } catch (err) {
            return res.status(400).json({
                success: false,
                error: "Invalid URL format",
                details: err.message
            });
        }
    }

    //
    // If we got a Base64 encoded param `r`, decode it as before
    //
    if (encoded) {
        if (!isBase64(encoded)) {
            return res.status(400).json({
                success: false,
                error: "Detected Base64 is invalid"
            });
        }

        try {
            const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');

            return res.json({
                success: true,
                detectedBase64: encoded,
                decodedUrl
            });

        } catch (err) {
            return res.status(500).json({
                success: false,
                error: "Failed to decode Base64",
                details: err.message
            });
        }
    }

    //
    // No encoded and no url-handling triggered
    //
    return res.status(400).json({
        success: false,
        error: "No Base64 detected and no supported URL provided. Use ?r=BASE64 or ?url=<link>"
    });
});

// Start Server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
