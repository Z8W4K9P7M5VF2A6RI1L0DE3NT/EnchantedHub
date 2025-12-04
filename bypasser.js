// bypasser.js
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();

// 🚨 IMPORTANT: separate port so it does NOT conflict with server.js
const BYPASS_PORT = process.env.BYPASS_PORT || 10001;

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
        const norm = str.replace(/=+$/, "");
        return reencoded === norm;
    } catch {
        return false;
    }
}

function randomString() {
    return Math.floor(Math.random() * 1e7).toString();
}

const FAKE_UA =
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1";

async function uaGet(url) {
    return axios.get(url, {
        headers: {
            "User-Agent": FAKE_UA,
            "Accept": "application/json, text/plain, */*"
        },
        timeout: 10000
    });
}

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
// UNIFIED /api/bypass ENDPOINT
// ------------------------------------------
app.get('/api/bypass', async (req, res) => {
    let encoded = null;

    // Manual mode
    if (req.query.r) {
        encoded = req.query.r;
    }

    // Auto-detect mode for ?url=
    if (!encoded && req.query.url) {
        const url = req.query.url;

        try {
            const parsed = new URL(url);

            // Lootlink
            if (parsed.hostname === "loot-link.com" && parsed.searchParams.get("r")) {
                encoded = parsed.searchParams.get("r");
            }

            // Platoboost
            else if (parsed.hostname === "gateway.platoboost.com" && parsed.searchParams.get("id")) {
                encoded = parsed.searchParams.get("id");
            }

            // Boostlink
            else if (parsed.searchParams.get("r")) {
                encoded = parsed.searchParams.get("r");
            }

            // LINKVERTISE
            else if (parsed.hostname.includes("linkvertise")) {
                const re_regular = /^(\/[0-9]+\/[^\/]+)/;
                const is_regular = re_regular.exec(parsed.pathname);

                if (!is_regular) {
                    return res.status(400).json({
                        success: false,
                        error: "Unrecognized Linkvertise path format"
                    });
                }

                const pathPart = is_regular[1];
                const linkvertiseUT = req.query.ut || req.header('x-linkvertise-ut') || null;

                try {
                    // Warmup traffic
                    const warmPaths = [
                        "/captcha",
                        "/countdown_impression?trafficOrigin=network",
                        "/todo_impression?mobile=true&trafficOrigin=network"
                    ];

                    for (let p of warmPaths) {
                        const warmUrl = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`;
                        uaGet(warmUrl).catch(() => { });
                    }

                    // Static
                    const staticUrl =
                        `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
                    const staticResp = await uaGet(staticUrl);

                    if (!staticResp.data || !staticResp.data.data || !staticResp.data.data.link) {
                        return res.status(502).json({
                            success: false,
                            error: "Linkvertise static endpoint returned invalid data"
                        });
                    }

                    const linkData = staticResp.data.data.link;

                    let link_target_type =
                        linkData.target_type === "URL"
                            ? "target"
                            : linkData.target_type === "PASTE"
                                ? "paste"
                                : null;

                    if (!link_target_type) {
                        return res.status(400).json({
                            success: false,
                            error: "Unsupported Linkvertise link type"
                        });
                    }

                    const serialObj = {
                        timestamp: Date.now(),
                        random: randomString(),
                        link_id: linkData.id
                    };

                    const serial = Buffer.from(JSON.stringify(serialObj)).toString('base64');

                    const targetEndpoint =
                        `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` +
                        (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}` : '');

                    const postResp = await uaPost(targetEndpoint, { serial });

                    if (!postResp.data || !postResp.data.data) {
                        return res.status(502).json({
                            success: false,
                            error: "Linkvertise returned no data"
                        });
                    }

                    if (link_target_type === "target") {
                        return res.json({
                            success: true,
                            service: "linkvertise",
                            decodedUrl: postResp.data.data.target
                        });
                    } else {
                        return res.json({
                            success: true,
                            service: "linkvertise",
                            paste: postResp.data.data.paste
                        });
                    }
                } catch (err) {
                    const details =
                        err?.response?.data || err.message || String(err);
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

    // Base64 decode
    if (encoded) {
        if (!isBase64(encoded)) {
            return res.status(400).json({
                success: false,
                error: "Invalid Base64"
            });
        }

        try {
            const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');

            return res.json({
                success: true,
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

    return res.status(400).json({
        success: false,
        error: "Missing ?url= or ?r= parameter"
    });
});

// Start server
app.listen(BYPASS_PORT, () => {
    console.log(`Bypasser running on port ${BYPASS_PORT}`);
});// bypasser.js
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();

// 🚨 IMPORTANT: separate port so it does NOT conflict with server.js
const BYPASS_PORT = process.env.BYPASS_PORT || 10001;

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
        const norm = str.replace(/=+$/, "");
        return reencoded === norm;
    } catch {
        return false;
    }
}

function randomString() {
    return Math.floor(Math.random() * 1e7).toString();
}

const FAKE_UA =
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1";

async function uaGet(url) {
    return axios.get(url, {
        headers: {
            "User-Agent": FAKE_UA,
            "Accept": "application/json, text/plain, */*"
        },
        timeout: 10000
    });
}

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
// UNIFIED /api/bypass ENDPOINT
// ------------------------------------------
app.get('/api/bypass', async (req, res) => {
    let encoded = null;

    // Manual mode
    if (req.query.r) {
        encoded = req.query.r;
    }

    // Auto-detect mode for ?url=
    if (!encoded && req.query.url) {
        const url = req.query.url;

        try {
            const parsed = new URL(url);

            // Lootlink
            if (parsed.hostname === "loot-link.com" && parsed.searchParams.get("r")) {
                encoded = parsed.searchParams.get("r");
            }

            // Platoboost
            else if (parsed.hostname === "gateway.platoboost.com" && parsed.searchParams.get("id")) {
                encoded = parsed.searchParams.get("id");
            }

            // Boostlink
            else if (parsed.searchParams.get("r")) {
                encoded = parsed.searchParams.get("r");
            }

            // LINKVERTISE
            else if (parsed.hostname.includes("linkvertise")) {
                const re_regular = /^(\/[0-9]+\/[^\/]+)/;
                const is_regular = re_regular.exec(parsed.pathname);

                if (!is_regular) {
                    return res.status(400).json({
                        success: false,
                        error: "Unrecognized Linkvertise path format"
                    });
                }

                const pathPart = is_regular[1];
                const linkvertiseUT = req.query.ut || req.header('x-linkvertise-ut') || null;

                try {
                    // Warmup traffic
                    const warmPaths = [
                        "/captcha",
                        "/countdown_impression?trafficOrigin=network",
                        "/todo_impression?mobile=true&trafficOrigin=network"
                    ];

                    for (let p of warmPaths) {
                        const warmUrl = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`;
                        uaGet(warmUrl).catch(() => { });
                    }

                    // Static
                    const staticUrl =
                        `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
                    const staticResp = await uaGet(staticUrl);

                    if (!staticResp.data || !staticResp.data.data || !staticResp.data.data.link) {
                        return res.status(502).json({
                            success: false,
                            error: "Linkvertise static endpoint returned invalid data"
                        });
                    }

                    const linkData = staticResp.data.data.link;

                    let link_target_type =
                        linkData.target_type === "URL"
                            ? "target"
                            : linkData.target_type === "PASTE"
                                ? "paste"
                                : null;

                    if (!link_target_type) {
                        return res.status(400).json({
                            success: false,
                            error: "Unsupported Linkvertise link type"
                        });
                    }

                    const serialObj = {
                        timestamp: Date.now(),
                        random: randomString(),
                        link_id: linkData.id
                    };

                    const serial = Buffer.from(JSON.stringify(serialObj)).toString('base64');

                    const targetEndpoint =
                        `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` +
                        (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}` : '');

                    const postResp = await uaPost(targetEndpoint, { serial });

                    if (!postResp.data || !postResp.data.data) {
                        return res.status(502).json({
                            success: false,
                            error: "Linkvertise returned no data"
                        });
                    }

                    if (link_target_type === "target") {
                        return res.json({
                            success: true,
                            service: "linkvertise",
                            decodedUrl: postResp.data.data.target
                        });
                    } else {
                        return res.json({
                            success: true,
                            service: "linkvertise",
                            paste: postResp.data.data.paste
                        });
                    }
                } catch (err) {
                    const details =
                        err?.response?.data || err.message || String(err);
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

    // Base64 decode
    if (encoded) {
        if (!isBase64(encoded)) {
            return res.status(400).json({
                success: false,
                error: "Invalid Base64"
            });
        }

        try {
            const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');

            return res.json({
                success: true,
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

    return res.status(400).json({
        success: false,
        error: "Missing ?url= or ?r= parameter"
    });
});

// Start server
app.listen(BYPASS_PORT, () => {
    console.log(`Bypasser running on port ${BYPASS_PORT}`);
});
