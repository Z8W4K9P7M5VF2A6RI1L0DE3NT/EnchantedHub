// bypasser.js — Full Mode (Legit / Hybrid / Aggressive)
// Requires: axios, cloudscraper, express, cors, dotenv, puppeteer (optional)
// Put in your project root or /web as needed.

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cloudscraper = (() => {
  try { return require('cloudscraper'); } catch(e){ return null; }
})();
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

const BYPASS_PORT = process.env.BYPASS_PORT || 10001;
const REQUEST_TIMEOUT = parseInt(process.env.BYPASS_TIMEOUT || '20000', 10);

/* ===========================
   Headers, UA lists, helpers
   =========================== */
const MOBILE_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1";

const DESKTOP_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const EXTRA_AGGRESSIVE_HEADERS = {
  "DNT": "1",
  "Upgrade-Insecure-Requests": "1",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Dest": "document"
};

// small UA pool for variety
const UA_POOL = [
  DESKTOP_UA,
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
  MOBILE_UA
];

function pickUA(aggressive=false) {
  if(aggressive) return UA_POOL[Math.floor(Math.random()*UA_POOL.length)];
  return (Math.random() < 0.5) ? DESKTOP_UA : MOBILE_UA;
}

function axiosErrorDetails(err) {
  if(!err) return null;
  if(err.response) return { status: err.response.status, data: err.response.data };
  if(err.message) return err.message;
  return String(err);
}

function randomString(){ return Math.floor(Math.random()*1e7).toString(); }

function safeDecodeOnce(s){
  try { const d = decodeURIComponent(s); return d !== s && d.startsWith('http') ? d : s; } catch { return s; }
}

function isBase64(str) {
  if (!str || typeof str !== 'string') return false;
  try {
    const d = Buffer.from(str, 'base64').toString('utf8');
    return Buffer.from(d, 'utf8').toString('base64') === str.replace(/=+$/,'');
  } catch { return false; }
}

/* ===========================
   Axios wrappers
   =========================== */
function axiosGet(url, { ua=null, extraHeaders={}, timeout=REQUEST_TIMEOUT } = {}) {
  return axios.get(url, {
    headers: Object.assign({
      "User-Agent": ua || DESKTOP_UA,
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }, extraHeaders),
    timeout,
    maxRedirects: 10,
    validateStatus: ()=>true,
    responseType: 'text'
  });
}
function axiosPost(url, data, headers={}, timeout=REQUEST_TIMEOUT) {
  return axios.post(url, data, { headers: Object.assign({ "Content-Type": "application/json" }, headers), timeout, maxRedirects: 10, validateStatus: ()=>true });
}

/* ===========================
   Optional cloudscraper wrappers (if installed)
   =========================== */
async function cloudGet(url, opts = {}) {
  if (!cloudscraper) throw new Error('cloudscraper missing');
  return new Promise((resolve, reject) => {
    cloudscraper.get(Object.assign({ uri: url, gzip: true, timeout: REQUEST_TIMEOUT, resolveWithFullResponse: true, followAllRedirects: true }, opts), (err, resp, body) => {
      if (err) return reject(err);
      // cloudscraper 'resp' sometimes is the body; but when resolveWithFullResponse true it returns resp
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

/* ===========================
   Puppeteer fallback (lazy require)
   =========================== */
async function puppeteerFetch(urlStr) {
  let puppeteer;
  try { puppeteer = require('puppeteer'); } catch (e) {
    throw new Error('Puppeteer is not installed. Install with: npm i puppeteer');
  }
  const browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'] });
  try {
    const page = await browser.newPage();
    await page.setUserAgent(DESKTOP_UA);
    await page.goto(urlStr, { waitUntil: 'networkidle2', timeout: 45000 }).catch(()=>{});
    // short wait for JS redirects
    await page.waitForTimeout(1000);
    const final = page.url();
    const body = await page.content();
    return { finalUrl: final, status: 200, body };
  } finally {
    await browser.close();
  }
}

/* ===========================
   Cache
   =========================== */
const cache = new Map();
function cacheSet(key, value, ttl=10*60*1000){ cache.set(key, { value, exp: Date.now()+ttl }); }
function cacheGet(key){ const e = cache.get(key); if(!e) return null; if(Date.now()>e.exp){ cache.delete(key); return null; } return e.value; }

/* ===========================
   Linkvertise bypass (keeps your logic)
   =========================== */
async function bypassLinkvertisePath(pathPart, linkvertiseUT=null, aggressive=false) {
  const cacheKey = `lv:${pathPart}:${linkvertiseUT||''}:${aggressive?1:0}`;
  const cached = cacheGet(cacheKey);
  if(cached) return cached;

  // warmup endpoints
  ['/captcha','/countdown_impression?trafficOrigin=network','/todo_impression?mobile=true&trafficOrigin=network']
    .forEach(p => {
      // fire & forget
      (async ()=> {
        try {
          if (cloudscraper) await cloudGet(`https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`);
          else await axiosGet(`https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`, { ua: pickUA(aggressive) });
        } catch(e){}
      })();
    });

  const staticUrl = `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
  let staticResp;
  try {
    if (cloudscraper) {
      const r = await cloudGet(staticUrl);
      staticResp = { data: r.body ? (typeof r.body === 'string' ? JSON.parse(r.body) : r.body) : r.resp };
    } else {
      const r = await axiosGet(staticUrl, { ua: pickUA(aggressive), extraHeaders: aggressive ? EXTRA_AGGRESSIVE_HEADERS : {} });
      staticResp = { data: r.data };
    }
  } catch (err) {
    // fallback attempt with axios desktop
    try {
      const r = await axiosGet(staticUrl, { ua: DESKTOP_UA, extraHeaders: aggressive ? EXTRA_AGGRESSIVE_HEADERS : {} });
      staticResp = { data: r.data };
    } catch (err2) {
      throw { status: 502, message: 'Failed Linkvertise static endpoint', details: axiosErrorDetails(err2) };
    }
  }

  const linkData = staticResp?.data?.data?.link;
  if (!linkData) throw { status: 502, message: 'Linkvertise static endpoint returned unexpected data', details: staticResp && staticResp.data };

  const targetType = linkData.target_type;
  let link_target_type = (targetType === 'URL') ? 'target' : (targetType === 'PASTE' ? 'paste' : null);
  if (!link_target_type) throw { status: 502, message: `Unsupported Linkvertise link target type: ${targetType}` };

  const serial = Buffer.from(JSON.stringify({ timestamp: Date.now(), random: randomString(), link_id: linkData.id })).toString('base64');
  const postPayload = { serial };
  const targetEndpoint = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` + (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}` : '');

  let postResp;
  try {
    if (cloudscraper) {
      postResp = await cloudPost(targetEndpoint, postPayload);
      postResp = { data: postResp.body };
    } else {
      const r = await axiosPost(targetEndpoint, postPayload, Object.assign({ "User-Agent": pickUA(aggressive) }, aggressive ? EXTRA_AGGRESSIVE_HEADERS : {}));
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

/* ===========================
   HTML heuristics & decoders
   =========================== */
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
  if(!ysmm) return null;
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

/* ===========================
   HTML fetch with fallbacks
   =========================== */
async function fetchHtmlWithFallback(urlStr, aggressive=false) {
  // 1) Try cloudscraper first (if installed)
  if (cloudscraper) {
    try {
      const r = await cloudGet(urlStr, { headers: { 'User-Agent': pickUA(aggressive) } });
      // r.body may be string or object
      const body = typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
      const finalUrl = (r.resp && r.resp.request && r.resp.request.href) ? r.resp.request.href : urlStr;
      return { finalUrl, status: r.resp && r.resp.statusCode ? r.resp.statusCode : 200, body };
    } catch (err) {
      // fall through
    }
  }

  // 2) axios with desktop UA
  try {
    const r = await axiosGet(urlStr, { ua: pickUA(aggressive), extraHeaders: aggressive ? EXTRA_AGGRESSIVE_HEADERS : {} });
    const finalUrl = r.request && r.request.res && r.request.res.responseUrl ? r.request.res.responseUrl : urlStr;
    return { finalUrl, status: r.status, body: r.data };
  } catch (err) {
    // continue
  }

  // 3) give up — signal Cloudflare/JS required
  throw new Error('HTML fetch failed or blocked (Cloudflare/JS challenge likely)');
}

/* ===========================
   Extraction of raw url param (unencoded long tails)
   =========================== */
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

/* ===========================
   Domain lists (40+ patterns)
   =========================== */
const SUPPORTED_PATTERNS = [
  // linkvertise / publisher
  'linkvertise', 'publisher.linkvertise.com',

  // loot-link family
  'loot-link.com', 'loot-link',

  // platoboost family
  'platoboost', 'gateway.platoboost.com', 'auth.platoboost.app', 'go.platoboost.com',

  // ad networks & shorteners
  'adf.ly', 'adf', 'boost.ink', 'shorte.st', 'shst', 'sh.st', 'shortly', 'mboost', 'mboost.me', 'sub2unlock',

  // rekonise / rekonise.io etc
  'rekonise',

  // common shorteners
  'tinyurl.com', 'bit.ly', 'is.gd', 't.co', 'ow.ly',

  // other suspects
  'rekonise', 'shrinkearn', 'shrinke.me', 'vcshort', 'celeb.link', 'linktr.ee'
  // add more as needed...
];

/* ===========================
   Main endpoint
   =========================== */
app.get('/api/bypass', async (req, res) => {
  try {
    // mode: 'legit' | 'aggressive' | 'hybrid' (default hybrid)
    const mode = (req.query.mode || process.env.BYPASS_MODE || 'hybrid').toLowerCase();
    const aggressiveMode = mode === 'aggressive';
    const hybrid = mode === 'hybrid';
    const methodPref = (req.query.method || '').toLowerCase(); // cloudscraper | axios | puppeteer

    // Legacy base64 param
    if (req.query.r) {
      if (!isBase64(req.query.r)) return res.status(400).json({ success:false, error:'Invalid Base64 in ?r=' });
      try {
        const decoded = Buffer.from(req.query.r, 'base64').toString('utf8');
        return res.json({ success:true, type:'base64', decodedUrl: decoded });
      } catch (err) { return res.status(500).json({ success:false, error:'Failed to decode Base64', details: err.message || err }); }
    }

    // Determine target URL robustly
    let target = null;
    if (req.query.url && typeof req.query.url === 'string') target = req.query.url;
    else target = extractRawUrlFromOriginalRequest(req);

    if (!target) return res.status(400).json({ success:false, error:'Missing ?url parameter. URL must be provided (URL-encoding recommended).' });

    target = safeDecodeOnce(target).trim();

    // Normalize parse
    let parsed;
    try { parsed = new URL(target); }
    catch (err) {
      try { parsed = new URL(encodeURI(target)); target = parsed.href; } catch (err2) { return res.status(400).json({ success:false, error:'Invalid URL', details: err2.message }); }
    }

    // Quick cache check (exact URL)
    const cached = cacheGet(`final:${target}:${mode}`);
    if (cached) return res.json(Object.assign({ success:true, cached:true }, cached));

    // Linkvertise special path (keep your logic)
    if (parsed.hostname.includes('linkvertise')) {
      const re = /^(\/[0-9]+\/[^\/]+)/;
      const match = re.exec(parsed.pathname);
      if (!match) return res.status(400).json({ success:false, error:'Bad Linkvertise path format' });
      const pathPart = match[1];
      const ut = req.query.ut || req.header('x-linkvertise-ut') || null;
      try {
        const lv = await bypassLinkvertisePath(pathPart, ut, aggressiveMode);
        cacheSet(`final:${target}:${mode}`, { service:'linkvertise', finalUrl: lv.decodedUrl || lv.paste });
        return res.json({ success:true, service:'linkvertise', finalUrl: lv.decodedUrl || lv.paste });
      } catch (err) {
        return res.status(err.status || 502).json({ success:false, error: err.message || 'Linkvertise bypass failed', details: err.details || axiosErrorDetails(err) });
      }
    }

    // If host matches known shorteners/aggregators — try HTML heuristics first
    const hostMatched = SUPPORTED_PATTERNS.some(p => parsed.hostname.includes(p));

    // Execution order based on mode & methodPref:
    //  - legit: try cloudscraper/axios (no puppeteer) -> heuristics
    //  - aggressive: try puppeteer first or if cloudscraper fails
    //  - hybrid: try cloudscraper -> axios -> puppeteer last-resort

    // Helper to attempt methods in order
    async function attemptResolve() {
      // 1) If methodPref == puppeteer -> use puppeteer directly (aggressive)
      if (methodPref === 'puppeteer') {
        try {
          const p = await puppeteerFetch(target);
          return { finalUrl: p.finalUrl, status: p.status, preview: String(p.body).slice(0,3000), method: 'puppeteer' };
        } catch (err) {
          throw err;
        }
      }

      // 2) Try cloudscraper (if available)
      if (cloudscraper && (mode !== 'legit' ? true : true)) {
        try {
          const cr = await cloudGet(target, { headers: { 'User-Agent': pickUA(aggressiveMode) } });
          const body = typeof cr.body === 'string' ? cr.body : JSON.stringify(cr.body);
          const finalUrl = cr.resp && cr.resp.request && cr.resp.request.href ? cr.resp.request.href : target;
          return { finalUrl, status: cr.resp && cr.resp.statusCode ? cr.resp.statusCode : 200, preview: body.slice(0,3000), method: 'cloudscraper', body };
        } catch (err) {
          // fallback to axios next
        }
      }

      // 3) Try axios desktop/mobile (legit & hybrid)
      try {
        const r = await axiosGet(target, { ua: pickUA(aggressiveMode), extraHeaders: aggressiveMode ? EXTRA_AGGRESSIVE_HEADERS : {} });
        const finalUrl = r.request && r.request.res && r.request.res.responseUrl ? r.request.res.responseUrl : target;
        return { finalUrl, status: r.status, preview: String(r.data || '').slice(0,3000), method: 'axios', body: r.data };
      } catch (err) {
        // fallthrough
      }

      // 4) If aggressive or hybrid fallback -> try puppeteer as last resort
      if (mode === 'aggressive' || mode === 'hybrid') {
        try {
          const p = await puppeteerFetch(target);
          return { finalUrl: p.finalUrl, status: p.status, preview: String(p.body).slice(0,3000), method: 'puppeteer' };
        } catch (err) {
          throw err;
        }
      }

      throw new Error('All resolution attempts failed');
    }

    // ------------- Execute attemptResolve and then apply heuristics -------------
    let resolved;
    try {
      resolved = await attemptResolve();
    } catch (err) {
      // If we get an error and mode is legit, return helpful hint
      return res.status(502).json({ success:false, error:'Failed to fetch/resolve target URL', details: axiosErrorDetails(err), hint: 'Try ?mode=hybrid or ?mode=aggressive or ?method=puppeteer' });
    }

    // If we have a body (HTML), try heuristics (meta-refresh, JS redirects, adf.ly ysmm)
    const rawBody = resolved.body || '';
    const meta = rawBody ? extractMetaRefresh(rawBody) : null;
    const jsloc = rawBody ? extractJsLocation(rawBody) : null;

    // adf.ly handling
    if (rawBody && (parsed.hostname.includes('adf') || rawBody.includes('ysmm'))) {
      const ysmm = extractYsmm(rawBody);
      if (ysmm) {
        const decoded = decodeYsmm(ysmm);
        if (decoded) {
          cacheSet(`final:${target}:${mode}`, { service:'adf.ly', finalUrl: decoded });
          return res.json({ success:true, service:'adf.ly', finalUrl: decoded, method: resolved.method });
        }
      }
    }

    // if meta or js redirect found — resolve it relative
    if (meta || jsloc) {
      try {
        const redirectRaw = meta || jsloc;
        const resolvedUrl = new URL(redirectRaw, resolved.finalUrl).href;
        cacheSet(`final:${target}:${mode}`, { service:'redirect', finalUrl: resolvedUrl });
        return res.json({ success:true, service:'redirect', finalUrl: resolvedUrl, method: resolved.method });
      } catch (err) {
        // continue to return finalUrl below
      }
    }

    // If resolved.finalUrl changed (axios/cloudscraper/pup gave a redirect) — return it
    if (resolved.finalUrl && resolved.finalUrl !== target) {
      cacheSet(`final:${target}:${mode}`, { service:'resolved', finalUrl: resolved.finalUrl });
      return res.json({ success:true, service:'resolved', finalUrl: resolved.finalUrl, method: resolved.method, preview: resolved.preview });
    }

    // Last fallback — return the HTML preview so the client can inspect
    cacheSet(`final:${target}:${mode}`, { service:'preview', finalUrl: resolved.finalUrl, preview: resolved.preview });
    return res.json({ success:true, service:'preview', finalUrl: resolved.finalUrl, method: resolved.method, preview: resolved.preview });

  } catch (outer) {
    console.error('Bypasser error:', outer);
    return res.status(500).json({ success:false, error:'Internal server error', details: outer && outer.message ? outer.message : String(outer) });
  }
});

/* ===========================
   Start server
   =========================== */
app.listen(BYPASS_PORT, () => {
  console.log(`Bypasser (Full Mode) running on port ${BYPASS_PORT}`);
});
