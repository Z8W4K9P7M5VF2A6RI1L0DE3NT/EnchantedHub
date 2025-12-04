// bypasser.js — MAX Aggression Mode Integrated
// Requires (recommended): axios, cloudscraper, express, cors, dotenv, puppeteer
// Install: npm i axios express cors dotenv puppeteer cloudscraper
// Env vars:
//  - BYPASS_PORT (default 10001)
//  - BYPASS_TIMEOUT (ms) default 45000
//  - CHROME_PATH optional full chrome binary path (for non-headless deployments)
//  - BYPASS_MODE optional default mode
//  - PROXY_URL optional (e.g. http://username:pass@host:port) used for Puppeteer launch args as --proxy-server

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');

const cloudscraper = (() => {
  try { return require('cloudscraper'); } catch (e) { return null; }
})();

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

const BYPASS_PORT = process.env.BYPASS_PORT || 10001;
const REQUEST_TIMEOUT = parseInt(process.env.BYPASS_TIMEOUT || '45000', 10);
const PROXY_URL = process.env.PROXY_URL || null;
const CHROME_PATH = process.env.CHROME_PATH || null;

// -----------------------------
// Helper utilities
// -----------------------------
const DESKTOP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const MOBILE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1";

function pickUA() {
  return Math.random() < 0.5 ? DESKTOP_UA : MOBILE_UA;
}

function axiosErrorDetails(err) {
  if (!err) return null;
  if (err.response) return { status: err.response.status, data: err.response.data };
  if (err.message) return err.message;
  return String(err);
}

function randomString() { return Math.floor(Math.random() * 1e7).toString(); }

function isBase64(str) {
  if (!str || typeof str !== 'string') return false;
  try {
    const d = Buffer.from(str, 'base64').toString('utf8');
    return Buffer.from(d, 'utf8').toString('base64') === str.replace(/=+$/, '');
  } catch { return false; }
}

function safeDecodeOnce(s) {
  try { const d = decodeURIComponent(s); return d !== s && d.startsWith('http') ? d : s; } catch { return s; }
}

// -----------------------------
// Axios wrappers
// -----------------------------
function axiosGet(url, { ua = DESKTOP_UA, extraHeaders = {}, timeout = REQUEST_TIMEOUT } = {}) {
  return axios.get(url, {
    headers: Object.assign({ "User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" }, extraHeaders),
    timeout,
    maxRedirects: 10,
    validateStatus: () => true,
    responseType: 'text'
  });
}

function axiosPost(url, data, headers = {}, timeout = REQUEST_TIMEOUT) {
  return axios.post(url, data, { headers: Object.assign({ "Content-Type": "application/json" }, headers), timeout, maxRedirects: 10, validateStatus: () => true });
}

// -----------------------------
// cloudscraper wrappers
// -----------------------------
async function cloudGet(url, opts = {}) {
  if (!cloudscraper) throw new Error('cloudscraper missing');
  return new Promise((resolve, reject) => {
    cloudscraper.get(Object.assign({ uri: url, gzip: true, timeout: REQUEST_TIMEOUT, resolveWithFullResponse: true, followAllRedirects: true }, opts), (err, resp, body) => {
      if (err) return reject(err);
      resolve({ resp, body });
    });
  });
}

async function cloudPost(url, payload, opts = {}) {
  if (!cloudscraper) throw new Error('cloudscraper missing');
  return new Promise((resolve, reject) => {
    cloudscraper.post(Object.assign({ uri: url, json: true, body: payload, timeout: REQUEST_TIMEOUT }, opts), (err, resp, body) => {
      if (err) return reject(err);
      resolve({ resp, body });
    });
  });
}

// -----------------------------
// Puppeteer MAX stealth fetch
// -----------------------------
async function puppeteerFetch(urlStr, { waitFor = 1500, fullPageTimeout = 45000 } = {}) {
  // lazy require so server still runs if puppeteer not installed
  let puppeteer;
  try { puppeteer = require('puppeteer'); } catch (e) {
    throw new Error('Puppeteer is not installed. Install with: npm i puppeteer');
  }

  // Launch args tuned for stealth and Render-like environments
  const launchArgs = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-accelerated-2d-canvas',
    '--disable-gpu',
    '--no-first-run',
    '--no-zygote',
    '--single-process',
    '--disable-background-networking',
    '--disable-background-timer-throttling',
    '--disable-client-side-phishing-detection',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-hang-monitor',
    '--disable-popup-blocking',
    '--disable-prompt-on-repost',
    '--disable-sync',
    '--metrics-recording-only',
    '--mute-audio'
  ];

  if (PROXY_URL) launchArgs.push(`--proxy-server=${PROXY_URL}`);

  const launchOptions = {
    args: launchArgs,
    headless: 'new', // prefer new headless if available
    ignoreHTTPSErrors: true,
    defaultViewport: { width: 1366, height: 768 }
  };

  if (CHROME_PATH) launchOptions.executablePath = CHROME_PATH;

  const browser = await puppeteer.launch(launchOptions);
  try {
    const page = await browser.newPage();

    // Stealth-ish tweaks (manual, not using puppeteer-extra)
    await page.setUserAgent(DESKTOP_UA);
    await page.setJavaScriptEnabled(true);
    await page.setDefaultNavigationTimeout(fullPageTimeout);
    await page.setViewport({ width: 1366, height: 768 });

    // Minimal navigator spoofing
    await page.evaluateOnNewDocument(() => {
      try {
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        // webdriver false
        Object.defineProperty(navigator, 'webdriver', { get: () => false });
      } catch (e) { /* ignore */ }
    });

    // Intercept requests to block analytics & fonts to speed up
    await page.setRequestInterception(true);
    page.on('request', req => {
      const rUrl = req.url();
      if (['image', 'font', 'stylesheet'].includes(req.resourceType()) || rUrl.includes('google-analytics') || rUrl.includes('analytics.js')) {
        return req.abort();
      }
      req.continue();
    });

    // Navigate and wait
    await page.goto(urlStr, { waitUntil: 'networkidle2', timeout: fullPageTimeout }).catch(() => {});
    // allow short time for JS redirects & DOM-mutation-based redirects
    await page.waitForTimeout(waitFor);

    const final = page.url();
    const body = await page.content();

    // Attempt to extract any immediate JS location changes inside the page (some obfuscation uses inline script)
    // Also attempt to read meta-refresh via DOM
    const metaRedirect = await page.evaluate(() => {
      try {
        const meta = document.querySelector('meta[http-equiv="refresh"]');
        if (!meta) return null;
        return meta.getAttribute('content');
      } catch (e) { return null; }
    }).catch(() => null);

    return { finalUrl: final, status: 200, body, metaRedirect };
  } finally {
    await browser.close();
  }
}

// -----------------------------
// Caching
// -----------------------------
const cache = new Map();
function cacheSet(key, value, ttl = 10 * 60 * 1000) { cache.set(key, { value, exp: Date.now() + ttl }); }
function cacheGet(key) { const e = cache.get(key); if (!e) return null; if (Date.now() > e.exp) { cache.delete(key); return null; } return e.value; }

// -----------------------------
// Linkvertise bypass (keeps original approach)
// -----------------------------
async function bypassLinkvertisePath(pathPart, linkvertiseUT = null, aggressive = true) {
  const cacheKey = `lv:${pathPart}:${linkvertiseUT || ''}:${aggressive ? 1 : 0}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  // warmup
  ['/captcha', '/countdown_impression?trafficOrigin=network', '/todo_impression?mobile=true&trafficOrigin=network']
    .forEach(p => {
      (async () => {
        try {
          if (cloudscraper) await cloudGet(`https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`, { headers: { 'User-Agent': pickUA() } });
          else await axiosGet(`https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`, { ua: pickUA() });
        } catch (e) { /* ignore */ }
      })();
    });

  const staticUrl = `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
  let staticResp;
  try {
    if (cloudscraper) {
      const r = await cloudGet(staticUrl);
      staticResp = { data: r.body ? (typeof r.body === 'string' ? JSON.parse(r.body) : r.body) : r.resp };
    } else {
      const r = await axiosGet(staticUrl, { ua: pickUA() });
      staticResp = { data: r.data };
    }
  } catch (err) {
    // fallback to axios desktop
    try {
      const r = await axiosGet(staticUrl, { ua: DESKTOP_UA });
      staticResp = { data: r.data };
    } catch (err2) {
      throw { status: 502, message: 'Failed Linkvertise static endpoint', details: axiosErrorDetails(err2) };
    }
  }

  const linkData = staticResp?.data?.data?.link;
  if (!linkData) throw { status: 502, message: 'Linkvertise static endpoint returned unexpected data', details: staticResp && staticResp.data };

  const targetType = linkData.target_type;
  let link_target_type = targetType === 'URL' ? 'target' : (targetType === 'PASTE' ? 'paste' : null);
  if (!link_target_type) throw { status: 502, message: `Unsupported Linkvertise target type: ${targetType}` };

  const serialObj = { timestamp: Date.now(), random: randomString(), link_id: linkData.id };
  const serial = Buffer.from(JSON.stringify(serialObj)).toString('base64');
  const postPayload = { serial };

  const postEndpoint = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` + (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}` : '');
  let postResp;
  try {
    if (cloudscraper) {
      postResp = await cloudPost(postEndpoint, postPayload, { headers: { 'User-Agent': pickUA() } });
      postResp = { data: postResp.body };
    } else {
      const r = await axiosPost(postEndpoint, postPayload, { "User-Agent": pickUA() });
      postResp = { data: r.data };
    }
  } catch (err) {
    throw { status: 502, message: 'Failed to POST to Linkvertise target endpoint', details: axiosErrorDetails(err) };
  }

  if (!postResp?.data?.data) throw { status: 502, message: 'Invalid Linkvertise target response', details: postResp && postResp.data };

  const result = {};
  if (link_target_type === 'target') result.decodedUrl = postResp.data.data.target;
  else result.paste = (postResp.data.data.paste || '').trim();

  cacheSet(cacheKey, result);
  return result;
}

// -----------------------------
// Simple decoders & heuristics
// -----------------------------
function extractMetaRefresh(html) {
  const m = html.match(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*content=["']?([^"'>]+)["']?[^>]*>/i);
  if (!m) return null;
  const content = m[1];
  const urlMatch = content.match(/url=(.+)/i);
  if (!urlMatch) return null;
  return urlMatch[1].trim();
}

function extractJsLocation(html) {
  const patterns = [
    /window\.location\.href\s*=\s*['"]([^'"]+)['"]/i,
    /window\.location\s*=\s*['"]([^'"]+)['"]/i,
    /top\.location\.href\s*=\s*['"]([^'"]+)['"]/i,
    /location\.href\s*=\s*['"]([^'"]+)['"]/i,
    /window\.location\.replace\(['"]([^'"]+)['"]\)/i
  ];
  for (const p of patterns) {
    const m = html.match(p);
    if (m) return m[1];
  }
  return null;
}

function extractYsmm(html) {
  const m = html.match(/var\s+ysmm\s*=\s*['"]([^'"]+)['"]/i);
  return m ? m[1] : null;
}
function decodeYsmm(ysmm) {
  if (!ysmm) return null;
  try {
    let a = '', b = '';
    for (let i = 0; i < ysmm.length; i++) {
      if (i % 2 === 0) a += ysmm.charAt(i);
      else b = ysmm.charAt(i) + b;
    }
    const merged = a + b;
    const decoded = Buffer.from(merged, 'base64').toString('binary');
    const m = decoded.match(/https?:\/\/.+/);
    if (m) return decodeURIComponent(m[0]);
    return null;
  } catch { return null; }
}

// fetchHtml fallback (cloudscraper -> axios)
async function fetchHtmlWithFallback(urlStr, aggressive = true) {
  if (cloudscraper) {
    try {
      const r = await cloudGet(urlStr, { headers: { 'User-Agent': pickUA() } });
      const body = typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
      const finalUrl = (r.resp && r.resp.request && r.resp.request.href) ? r.resp.request.href : urlStr;
      return { finalUrl, status: r.resp && r.resp.statusCode ? r.resp.statusCode : 200, body };
    } catch (e) {
      // continue to axios
    }
  }

  try {
    const r = await axiosGet(urlStr, { ua: pickUA(), extraHeaders: {} });
    const finalUrl = (r.request && r.request.res && r.request.res.responseUrl) ? r.request.res.responseUrl : urlStr;
    return { finalUrl, status: r.status, body: r.data };
  } catch (err) {
    throw new Error('HTML fetch failed or blocked (Cloudflare/JS challenge likely)');
  }
}

// extract raw tail in case url param is extremely long & not URL-encoded
function extractRawUrlFromOriginalRequest(req) {
  if (req.query && typeof req.query.url === 'string') {
    try { new URL(req.query.url); return req.query.url; } catch {}
  }
  const orig = req.originalUrl || req.url || '';
  const idx = orig.indexOf('url=');
  if (idx === -1) return null;
  const tail = orig.slice(idx + 4);
  try { return decodeURIComponent(tail); } catch { return tail; }
}

// -----------------------------
// Supported patterns quick list (not exhaustive)
// -----------------------------
const SUPPORTED_PATTERNS = [
  'linkvertise', 'loot-link', 'platoboost', 'adf.ly', 'boost.ink', 'shorte.st', 'sub2unlock', 'rekonise', 'tinyurl.com', 'bit.ly'
];

// -----------------------------
// /api/bypass endpoint — MAX mode integrated
// -----------------------------
app.get('/api/bypass', async (req, res) => {
  try {
    // modes: max | hybrid | medium
    const requestedMode = (req.query.mode || process.env.BYPASS_MODE || 'max').toLowerCase();
    const MODE_MAX = requestedMode === 'max';
    const MODE_HYBRID = requestedMode === 'hybrid';
    const methodPref = (req.query.method || '').toLowerCase(); // puppeteer | cloudscraper | axios

    // Support legacy ?r= base64
    if (req.query.r) {
      if (!isBase64(req.query.r)) return res.status(400).json({ success: false, error: 'Invalid Base64 in ?r=' });
      try {
        const decoded = Buffer.from(req.query.r, 'base64').toString('utf8');
        return res.json({ success: true, type: 'base64', decodedUrl: decoded });
      } catch (err) {
        return res.status(500).json({ success: false, error: 'Failed to decode base64', details: err.message || err });
      }
    }

    // get target robustly
    let target = null;
    if (req.query.url && typeof req.query.url === 'string') target = req.query.url;
    else target = extractRawUrlFromOriginalRequest(req);

    if (!target) return res.status(400).json({ success: false, error: 'Missing ?url parameter. Provide URL or use URL-encoding for nested URLs.' });

    target = safeDecodeOnce(target).trim();

    // normalize
    let parsed;
    try { parsed = new URL(target); } catch (err) {
      try { parsed = new URL(encodeURI(target)); target = parsed.href; } catch (err2) { return res.status(400).json({ success: false, error: 'Invalid URL', details: err2.message }); }
    }

    // quick cache
    const cacheKey = `final:${target}:${requestedMode}`;
    const cached = cacheGet(cacheKey);
    if (cached) return res.json(Object.assign({ success: true, cached: true }, cached));

    // Linkvertise special case (prefer to run Linkvertise flow first)
    if (parsed.hostname.includes('linkvertise')) {
      const re = /^(\/[0-9]+\/[^\/]+)/;
      const match = re.exec(parsed.pathname);
      if (!match) return res.status(400).json({ success: false, error: 'Invalid Linkvertise path format' });
      const pathPart = match[1];
      const ut = req.query.ut || req.header('x-linkvertise-ut') || null;
      try {
        const lvRes = await bypassLinkvertisePath(pathPart, ut, true);
        const final = lvRes.decodedUrl || lvRes.paste;
        cacheSet(cacheKey, { service: 'linkvertise', finalUrl: final });
        return res.json({ success: true, service: 'linkvertise', finalUrl: final });
      } catch (err) {
        return res.status(err.status || 502).json({ success: false, error: err.message || 'Linkvertise bypass failed', details: err.details || axiosErrorDetails(err) });
      }
    }

    // resolution strategy for MAX:
    // 1) If methodPref == puppeteer -> puppeteer first
    // 2) If MODE_MAX -> puppeteer first, then cloud/axios fallback
    // 3) MODE_HYBRID -> cloudscraper/axios then puppeteer
    // 4) Otherwise -> cloudscraper/axios

    async function attemptResolve() {
      // puppeteer first when explicitly asked or in MAX
      if (methodPref === 'puppeteer' || MODE_MAX) {
        try {
          const p = await puppeteerFetch(target, { waitFor: 1500, fullPageTimeout: REQUEST_TIMEOUT });
          // if puppeteer reports metaRedirect, handle it
          if (p.metaRedirect) {
            // meta content might be like "3; url=https://..."
            const m = p.metaRedirect.match(/url=(.+)/i);
            if (m && m[1]) {
              const resolved = new URL(m[1].trim(), p.finalUrl).href;
              return { finalUrl: resolved, status: p.status, method: 'puppeteer-meta', body: p.body };
            }
          }
          return { finalUrl: p.finalUrl, status: p.status, method: 'puppeteer', body: p.body };
        } catch (err) {
          // fallthrough to cloudscraper/axios
        }
      }

      // try cloudscraper if available
      if (cloudscraper) {
        try {
          const cr = await cloudGet(target, { headers: { 'User-Agent': pickUA() } });
          const body = typeof cr.body === 'string' ? cr.body : JSON.stringify(cr.body);
          const finalUrl = (cr.resp && cr.resp.request && cr.resp.request.href) ? cr.resp.request.href : target;
          return { finalUrl, status: cr.resp && cr.resp.statusCode ? cr.resp.statusCode : 200, method: 'cloudscraper', body };
        } catch (err) {
          // fallthrough
        }
      }

      // try axios
      try {
        const r = await axiosGet(target, { ua: pickUA() });
        const finalUrl = (r.request && r.request.res && r.request.res.responseUrl) ? r.request.res.responseUrl : target;
        return { finalUrl, status: r.status, method: 'axios', body: r.data };
      } catch (err) {
        // fallthrough
      }

      // last-resort: puppeteer if not tried yet (hybrid & fallback)
      if (!MODE_MAX) {
        try {
          const p = await puppeteerFetch(target, { waitFor: 1500, fullPageTimeout: REQUEST_TIMEOUT });
          return { finalUrl: p.finalUrl, status: p.status, method: 'puppeteer', body: p.body };
        } catch (err) {
          // give up
        }
      }

      throw new Error('All resolution attempts failed');
    }

    let resolved;
    try {
      resolved = await attemptResolve();
    } catch (err) {
      return res.status(502).json({ success: false, error: 'Failed to fetch/resolve target URL', details: axiosErrorDetails(err), hint: 'Try ?mode=hybrid or ensure Puppeteer is installed and CHROME_PATH/PROXY_URL set as needed' });
    }

    const rawBody = resolved.body || '';
    // attempt adf.ly
    if (rawBody && (parsed.hostname.includes('adf') || rawBody.includes('ysmm'))) {
      const ysmm = extractYsmm(rawBody);
      if (ysmm) {
        const decoded = decodeYsmm(ysmm);
        if (decoded) {
          cacheSet(cacheKey, { service: 'adf.ly', finalUrl: decoded });
          return res.json({ success: true, service: 'adf.ly', finalUrl: decoded, method: resolved.method });
        }
      }
    }

    // check meta-refresh or JS location in raw HTML
    const meta = rawBody ? extractMetaRefresh(rawBody) : null;
    const jsloc = rawBody ? extractJsLocation(rawBody) : null;
    if (meta || jsloc) {
      try {
        const redirectRaw = meta || jsloc;
        const resolvedUrl = new URL(redirectRaw, resolved.finalUrl).href;
        cacheSet(cacheKey, { service: 'redirect', finalUrl: resolvedUrl });
        return res.json({ success: true, service: 'redirect', finalUrl: resolvedUrl, method: resolved.method });
      } catch (e) {
        // ignore and continue
      }
    }

    // If fetcher returned a finalUrl different from target (redirects)
    if (resolved.finalUrl && resolved.finalUrl !== target) {
      cacheSet(cacheKey, { service: 'resolved', finalUrl: resolved.finalUrl });
      return res.json({ success: true, service: 'resolved', finalUrl: resolved.finalUrl, method: resolved.method, preview: String(resolved.body || '').slice(0, 2000) });
    }

    // last: return HTML preview and finalUrl (client can inspect)
    cacheSet(cacheKey, { service: 'preview', finalUrl: resolved.finalUrl || target, preview: String(resolved.body || '').slice(0, 2000) });
    return res.json({ success: true, service: 'preview', finalUrl: resolved.finalUrl || target, method: resolved.method, preview: String(resolved.body || '').slice(0, 2000) });

  } catch (outer) {
    console.error('Bypasser (MAX) error:', outer);
    return res.status(500).json({ success: false, error: 'Internal server error', details: outer && outer.message ? outer.message : String(outer) });
  }
});

// -----------------------------
// start server
// -----------------------------
app.listen(BYPASS_PORT, () => {
  console.log(`Bypasser (MAX mode supported) running on port ${BYPASS_PORT}`);
});
