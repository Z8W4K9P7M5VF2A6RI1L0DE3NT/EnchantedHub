// bypasser.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const BYPASS_PORT = process.env.BYPASS_PORT || 10001;
const REQUEST_TIMEOUT = 10000; // ms

// --- Utilities ---

function isBase64(str) {
    if (!str || typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (trimmed === '') return false;
    try {
        const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
        const reencoded = Buffer.from(decoded, 'utf8').toString('base64');
        return reencoded === trimmed.replace(/=+$/, '');
    } catch {
        return false;
    }
}

function randomString() {
    return Math.floor(Math.random() * 1e7).toString();
}

const FAKE_UA =
    'Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) ' +
    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1';

function uaGet(url) {
    return axios.get(url, {
        headers: {
            'User-Agent': FAKE_UA,
            'Accept': 'application/json, text/plain, */*'
        },
        timeout: REQUEST_TIMEOUT
    });
}

function uaPost(url, data, extraHeaders = {}) {
    return axios.post(url, data, {
        headers: Object.assign({
            'User-Agent': FAKE_UA,
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/plain, */*'
        }, extraHeaders),
        timeout: REQUEST_TIMEOUT
    });
}

// small in-memory cache to reduce repeated expensive calls (optional)
const cache = new Map();
function cacheSet(key, value, ttl = 600_000) { // default 10 minutes
    cache.set(key, { value, exp: Date.now() + ttl });
}
function cacheGet(key) {
    const entry = cache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.exp) {
        cache.delete(key);
        return null;
    }
    return entry.value;
}

// --- Linkvertise bypass (internal full logic) ---
async function bypassLinkvertisePath(pathPart, linkvertiseUT = null) {
    // use a cache key per path+ut
    const cacheKey = `lv:${pathPart}:${linkvertiseUT || ''}`;
    const cached = cacheGet(cacheKey);
    if (cached) return cached;

    // 1. Warmup requests (fire-and-forget)
    const warmPaths = [
        '/captcha',
        '/countdown_impression?trafficOrigin=network',
        '/todo_impression?mobile=true&trafficOrigin=network'
    ];
    for (const p of warmPaths) {
        const warmUrl = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`;
        // intentionally don't await fully — but catch errors to avoid unhandled rejections
        uaGet(warmUrl).catch(() => { /* ignore warmup errors */ });
    }

    // 2. GET static endpoint
    const staticUrl = `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
    let staticResp;
    try {
        staticResp = await uaGet(staticUrl);
    } catch (err) {
        throw { status: 502, message: 'Failed to fetch Linkvertise static endpoint', details: axiosErrorDetails(err) };
    }

    if (!staticResp || !staticResp.data || !staticResp.data.data || !staticResp.data.data.link) {
        throw { status: 502, message: 'Linkvertise static endpoint returned unexpected data', details: staticResp && staticResp.data };
    }

    const linkData = staticResp.data.data.link;
    const targetType = linkData.target_type;
    let link_target_type;
    if (targetType === 'URL') link_target_type = 'target';
    else if (targetType === 'PASTE') link_target_type = 'paste';
    else throw { status: 502, message: `Unsupported Linkvertise link target type: ${targetType}` };

    // 3. Build serial payload
    const serialObj = {
        timestamp: Date.now(),
        random: randomString(),
        link_id: linkData.id
    };
    const serial = Buffer.from(JSON.stringify(serialObj)).toString('base64');
    const postPayload = { serial };

    // 4. POST to target endpoint (append X-Linkvertise-UT if provided)
    const targetEndpoint = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` +
        (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}` : '');

    let postResp;
    try {
        postResp = await uaPost(targetEndpoint, postPayload);
    } catch (err) {
        throw { status: 502, message: 'Failed to POST to Linkvertise target endpoint', details: axiosErrorDetails(err) };
    }

    if (!postResp || !postResp.data || !postResp.data.data) {
        throw { status: 502, message: 'Invalid Linkvertise target response', details: postResp && postResp.data };
    }

    const result = {};
    if (link_target_type === 'target') {
        if (!postResp.data.data.target) throw { status: 502, message: 'Linkvertise response missing target' };
        result.decodedUrl = postResp.data.data.target;
    } else {
        result.paste = (postResp.data.data.paste || '').trim();
    }

    // cache result
    cacheSet(cacheKey, result, 10 * 60 * 1000); // 10 min
    return result;
}

function axiosErrorDetails(err) {
    if (!err) return null;
    if (err.response && err.response.data) return err.response.data;
    if (err.message) return err.message;
    return String(err);
}

// --- Unified endpoint ---
// Supports:
//  - /api/bypass?r=BASE64
//  - /api/bypass?url=<any link> (auto-detect Loot-Link, Platoboost, BoostLink, Linkvertise)
//  - Linkvertise internal bypass with ?ut= or header x-linkvertise-ut
app.get('/api/bypass', async (req, res) => {
    try {
        // 1) Manual Base64 param
        if (req.query.r) {
            const encoded = req.query.r;
            if (!isBase64(encoded)) {
                return res.status(400).json({ success: false, error: 'Invalid Base64 in ?r=' });
            }
            try {
                const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');
                return res.json({ success: true, type: 'base64', decodedUrl });
            } catch (err) {
                return res.status(500).json({ success: false, error: 'Failed to decode Base64', details: err.message || err });
            }
        }

        // 2) Auto-detect via ?url=
        if (req.query.url) {
            const rawUrl = req.query.url;
            let parsed;
            try {
                parsed = new URL(rawUrl);
            } catch (err) {
                return res.status(400).json({ success: false, error: 'Invalid URL format', details: err.message });
            }

            // Loot-Link: ?r=BASE64 on loot-link.com
            if (parsed.hostname === 'loot-link.com' && parsed.searchParams.get('r')) {
                const encoded = parsed.searchParams.get('r');
                if (!isBase64(encoded)) return res.status(400).json({ success: false, error: 'Invalid Base64 detected on loot-link' });
                const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');
                return res.json({ success: true, service: 'loot-link', decodedUrl });
            }

            // Platoboost: ?id=BASE64 on gateway.platoboost.com
            if (parsed.hostname === 'gateway.platoboost.com' && parsed.searchParams.get('id')) {
                const encoded = parsed.searchParams.get('id');
                if (!isBase64(encoded)) return res.status(400).json({ success: false, error: 'Invalid Base64 detected on platoboost' });
                const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');
                return res.json({ success: true, service: 'platoboost', decodedUrl });
            }

            // Generic: any URL that has ?r= (boostlink, others)
            if (parsed.searchParams.get('r')) {
                const encoded = parsed.searchParams.get('r');
                if (!isBase64(encoded)) return res.status(400).json({ success: false, error: 'Invalid Base64 detected in ?r=' });
                const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');
                return res.json({ success: true, service: 'generic-r', decodedUrl });
            }

            // Generic: any URL that has ?id=
            if (parsed.searchParams.get('id')) {
                const encoded = parsed.searchParams.get('id');
                if (isBase64(encoded)) {
                    const decodedUrl = Buffer.from(encoded, 'base64').toString('utf8');
                    return res.json({ success: true, service: 'generic-id', decodedUrl });
                }
            }

            // Linkvertise detection (host contains 'linkvertise')
            if (parsed.hostname.includes('linkvertise')) {
                // attempt to apply regex ^(\/[0-9]+\/[^\/]+)
                const re_regular = /^(\/[0-9]+\/[^\/]+)/;
                const match = re_regular.exec(parsed.pathname);
                if (!match) {
                    return res.status(400).json({ success: false, error: 'Unrecognized Linkvertise path format' });
                }
                const pathPart = match[1]; // e.g. "/12345/slug"
                const linkvertiseUT = req.query.ut || req.header('x-linkvertise-ut') || null;

                try {
                    const lvResult = await bypassLinkvertisePath(pathPart, linkvertiseUT);
                    return res.json(Object.assign({ success: true, service: 'linkvertise' }, lvResult));
                } catch (err) {
                    // err may be an object thrown with status/message/details
                    if (err && err.status) {
                        return res.status(err.status).json({ success: false, error: err.message || 'Linkvertise bypass error', details: err.details || null });
                    }
                    return res.status(502).json({ success: false, error: 'Linkvertise bypass failed', details: axiosErrorDetails(err) });
                }
            }

            // If we reach here, we don't recognize the link format
            return res.status(400).json({ success: false, error: 'No Base64 detected and unsupported URL type. Use ?r=BASE64 or provide a supported ?url=' });
        }

        // Nothing provided
        return res.status(400).json({ success: false, error: 'Missing parameters. Provide ?r=BASE64 or ?url=<link>' });
    } catch (outerErr) {
        return res.status(500).json({ success: false, error: 'Internal server error', details: outerErr && outerErr.message ? outerErr.message : String(outerErr) });
    }
});

// start server
app.listen(BYPASS_PORT, () => {
    console.log(`Bypasser running on port ${BYPASS_PORT}`);
});
