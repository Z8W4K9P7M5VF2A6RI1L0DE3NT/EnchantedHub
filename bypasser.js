// bypasser.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

const BYPASS_PORT = process.env.BYPASS_PORT || 10001;
const REQUEST_TIMEOUT = 20000; // ms

/* ---------------------------
   Headers & helpers
----------------------------*/
const MOBILE_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1";

const BROWSER_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.9",
  "Cache-Control": "no-cache",
  "Pragma": "no-cache",
  "Upgrade-Insecure-Requests": "1",
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-User": "?1"
};

function axiosErrorDetails(err) {
  if (!err) return null;
  if (err.response) return { status: err.response.status, data: err.response.data };
  if (err.message) return err.message;
  return String(err);
}
function randomString(){ return Math.floor(Math.random()*1e7).toString(); }
function isBase64(str) {
  if(!str || typeof str !== 'string') return false;
  try {
    const d = Buffer.from(str, 'base64').toString('utf8');
    return Buffer.from(d, 'utf8').toString('base64') === str.replace(/=+$/,'');
  } catch { return false; }
}

/* ---------------------------
   Axios wrappers
----------------------------*/
function mobileGet(url, opts = {}) {
  return axios.get(url, Object.assign({
    headers: { "User-Agent": MOBILE_UA, "Accept": "application/json, text/plain, */*" },
    timeout: REQUEST_TIMEOUT,
    maxRedirects: 10,
    responseType: 'text',
    validateStatus: ()=>true
  }, opts));
}
function desktopGet(url, opts = {}) {
  return axios.get(url, Object.assign({
    headers: BROWSER_HEADERS,
    timeout: REQUEST_TIMEOUT,
    maxRedirects: 10,
    responseType: 'text',
    validateStatus: ()=>true
  }, opts));
}
function mobilePost(url, data, extraHeaders = {}) {
  return axios.post(url, data, {
    headers: Object.assign({ "User-Agent": MOBILE_UA, "Content-Type": "application/json" }, extraHeaders),
    timeout: REQUEST_TIMEOUT, maxRedirects: 10, validateStatus: ()=>true
  });
}

/* ---------------------------
   Cache
----------------------------*/
const cache = new Map();
function cacheSet(k,v,ttl=600000){ cache.set(k,{value:v,exp:Date.now()+ttl}); }
function cacheGet(k){ const e = cache.get(k); if(!e) return null; if(Date.now()>e.exp){ cache.delete(k); return null; } return e.value; }

/* ====================================================
   Linkvertise bypass (keeps your previous logic)
   (unchanged semantics but integrated)
   ==================================================== */
async function bypassLinkvertisePath(pathPart, linkvertiseUT = null) {
  const cacheKey = `lv:${pathPart}:${linkvertiseUT||''}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  // warm-up endpoints (fire & forget)
  ['/captcha','/countdown_impression?trafficOrigin=network','/todo_impression?mobile=true&trafficOrigin=network']
    .forEach(p => mobileGet(`https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}${p}`).catch(()=>{}));

  const staticUrl = `https://publisher.linkvertise.com/api/v1/redirect/link/static${pathPart}`;
  let staticResp;
  try { staticResp = await mobileGet(staticUrl); }
  catch (err) {
    // fallback to desktop headers
    try { staticResp = await desktopGet(staticUrl); }
    catch (err2) { throw { status:502, message:'Failed Linkvertise static endpoint', details: axiosErrorDetails(err2) }; }
  }

  if(!staticResp?.data?.data?.link) {
    throw { status:502, message:'Linkvertise static endpoint returned unexpected data', details: staticResp && staticResp.data };
  }
  const linkData = staticResp.data.data.link;
  const targetType = linkData.target_type;
  let link_target_type;
  if (targetType === 'URL') link_target_type = 'target';
  else if (targetType === 'PASTE') link_target_type = 'paste';
  else throw { status:502, message:`Unsupported Linkvertise link target type: ${targetType}` };

  const serial = Buffer.from(JSON.stringify({ timestamp: Date.now(), random: randomString(), link_id: linkData.id })).toString('base64');
  const postPayload = { serial };
  const targetEndpoint = `https://publisher.linkvertise.com/api/v1/redirect/link${pathPart}/${link_target_type}` + (linkvertiseUT ? `?X-Linkvertise-UT=${encodeURIComponent(linkvertiseUT)}`:'');

  let postResp;
  try { postResp = await mobilePost(targetEndpoint, postPayload); }
  catch (err) {
    try {
      postResp = await axios.post(targetEndpoint, postPayload, { headers: Object.assign({ "Content-Type":"application/json" }, BROWSER_HEADERS), timeout: REQUEST_TIMEOUT, maxRedirects: 10, validateStatus: ()=>true });
    } catch (err2) {
      throw { status:502, message:'Failed to POST to Linkvertise target endpoint', details: axiosErrorDetails(err2) };
    }
  }

  if (!postResp?.data?.data) throw { status:502, message:'Invalid Linkvertise target response', details: postResp && postResp.data };

  const result = {};
  if (link_target_type === 'target') result.decodedUrl = postResp.data.data.target;
  else result.paste = (postResp.data.data.paste || '').trim();

  cacheSet(cacheKey, result, 10*60*1000);
  return result;
}

/* ====================================================
   Common shortener heuristics: adf.ly 'ysmm' decoder,
   meta refresh, window.location in HTML, meta-refresh tags
   ==================================================== */

// adf.ly ysmm deobfuscation (common pattern)
function decodeAdflyYsmm(ysmm) {
  // lightweight implementation adapted from known open-source decoders
  if(!ysmm || ysmm.length === 0) return null;
  let a = '', b = '';
  for (let i = 0; i < ysmm.length; i++) {
    if (i % 2 === 0) a += ysmm.charAt(i);
    else b = ysmm.charAt(i) + b;
  }
  const merged = a + b;
  const decoded = atob ? atob(merged) : Buffer.from(merged, 'base64').toString('binary');
  // result often contains URL with prefix 'http'
  const m = decoded.match(/go\.php\?u=(.+)/) || decoded.match(/https?:\/\/.+/);
  if (!m) return decoded;
  return decodeURIComponent(m[1] || m[0]);
}

// utility: try meta refresh
function extractMetaRefresh(html) {
  const m = html.match(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*content=["']?([^"'>]+)["']?[^>]*>/i);
  if (!m) return null;
  const content = m[1];
  const urlMatch = content.match(/url=(.+)/i);
  if (!urlMatch) return null;
  return urlMatch[1].trim();
}

// utility: try window.location or top.location or location.href in scripts
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

// search for adf.ly ysmm var
function extractYsmm(html) {
  const m = html.match(/var\s+ysmm\s*=\s*['"]([^'"]+)['"]/i);
  return m ? m[1] : null;
}

/* ====================================================
   HTML fetch fallback - desktop then mobile
   returns { finalUrl, status, body }
   ==================================================== */
async function fetchHtmlWithFallback(url) {
  // first try desktop headers (better vs Cloudflare)
  let resp = await desktopGet(url).catch(()=>null);
  if (resp && resp.status && resp.status < 500) return { finalUrl: resp.request?.res?.responseUrl || url, status: resp.status, body: resp.data };

  // otherwise try mobile UA
  resp = await mobileGet(url).catch(()=>null);
  if (resp && resp.status && resp.status < 500) return { finalUrl: resp.request?.res?.responseUrl || url, status: resp.status, body: resp.data };

  // failed
  throw new Error('HTML fetch failed or blocked (Cloudflare/JS challenge likely)');
}

/* ====================================================
   Robust extraction when user didn't URL-encode their inner URL.
   This reads req.originalUrl and returns everything after url= (not splitting on &),
   then tries decodeURIComponent once.
   ==================================================== */
function extractRawUrlFromOriginalRequest(req) {
  if (req.query && typeof req.query.url === 'string') {
    // sometimes framework already parsed it correctly
    try { new URL(req.query.url); return req.query.url; } catch {}
  }
  const orig = req.originalUrl || req.url || '';
  const idx = orig.indexOf('url=');
  if (idx === -1) return null;
  let tail = orig.slice(idx + 4);
  // If there are further params intended for the bypass endpoint they often follow '&method=' or '&something='
  // But to be safe for long encrypted tokens we return entire tail (decode if needed)
  try { return decodeURIComponent(tail); } catch { return tail; }
}

/* ====================================================
   Main handler: supports:
   - Base64 ?r=
   - Linkvertise (special flow)
   - Loot-link (fetch html & return final)
   - Platoboost (auth/gateway/go)
   - adf.ly (try ysmm decoding, meta refresh, js redirect)
   - shorte.st / boost.ink / mboost / sub2unlock / rekonise etc via HTML fetch & heuristics
   - Generic fallback (HTML fetch)
   ==================================================== */
app.get('/api/bypass', async (req, res) => {
  try {
    // 1) manual base64 ?r= support (legacy)
    if (req.query.r) {
      if (!isBase64(req.query.r)) return res.status(400).json({ success:false, error:'Invalid Base64 in ?r=' });
      try {
        const decodedUrl = Buffer.from(req.query.r, 'base64').toString('utf8');
        return res.json({ success:true, type:'base64', decodedUrl });
      } catch (err) {
        return res.status(500).json({ success:false, error:'Failed to decode Base64', details: err.message || err });
      }
    }

    // 2) Determine target URL robustly
    let targetUrl = null;
    if (req.query.url && typeof req.query.url === 'string') targetUrl = req.query.url;
    else targetUrl = extractRawUrlFromOriginalRequest(req);

    if (!targetUrl) return res.status(400).json({ success:false, error:'Missing ?url parameter. Make sure inner URL is URL-encoded or send as raw and the server will attempt to parse.' });

    targetUrl = targetUrl.trim();

    // try one decode step if it looks encoded
    try {
      const once = decodeURIComponent(targetUrl);
      if (once !== targetUrl && once.startsWith('http')) targetUrl = once;
    } catch {}

    // normalize
    let parsed;
    try { parsed = new URL(targetUrl); }
    catch (err) {
      try { parsed = new URL(encodeURI(targetUrl)); targetUrl = parsed.href; }
      catch (err2) { return res.status(400).json({ success:false, error:'Invalid URL format', details: err2.message }); }
    }

    // Service-specific branches

    // -----------------------
    // Linkvertise (special bypass)
    // -----------------------
    if (parsed.hostname.includes('linkvertise')) {
      const re = /^(\/[0-9]+\/[^\/]+)/;
      const match = re.exec(parsed.pathname);
      if (!match) return res.status(400).json({ success:false, error:'Unrecognized Linkvertise path format' });
      const pathPart = match[1];
      const ut = req.query.ut || req.header('x-linkvertise-ut') || null;
      try {
        const result = await bypassLinkvertisePath(pathPart, ut);
        return res.json(Object.assign({ success:true, service:'linkvertise' }, result));
      } catch (err) {
        if (err && err.status) return res.status(err.status).json({ success:false, error: err.message, details: err.details || null });
        return res.status(502).json({ success:false, error: 'Linkvertise bypass failed', details: axiosErrorDetails(err) });
      }
    }

    // -----------------------
    // Loot-link
    // -----------------------
    if (parsed.hostname === 'loot-link.com' || parsed.hostname.endsWith('.loot-link.com')) {
      try {
        const htmlResp = await fetchHtmlWithFallback(targetUrl);
        // try to find meta refresh or js redirect or direct anchor
        const meta = extractMetaRefresh(htmlResp.body) || extractJsLocation(htmlResp.body);
        if (meta) {
          try {
            const resolved = new URL(meta, htmlResp.finalUrl).href;
            return res.json({ success:true, service:'loot-link', finalUrl: resolved, status: htmlResp.status, method:'html-redirect' });
          } catch {}
        }
        // otherwise return html content for client to parse
        return res.json({ success:true, service:'loot-link', finalUrl: htmlResp.finalUrl, status: htmlResp.status, content: htmlResp.body.slice(0, 2000) });
      } catch (err) {
        return res.status(502).json({ success:false, service:'loot-link', error: err.message, hint:'If blocked by Cloudflare, use Puppeteer/Playwright with stealth + proxies.' });
      }
    }

    // -----------------------
    // Platoboost variants (auth/gateway/go)
    // -----------------------
    if (parsed.hostname.includes('platoboost') || parsed.hostname.includes('platoboost.app')) {
      try {
        const htmlResp = await fetchHtmlWithFallback(targetUrl);
        const meta = extractMetaRefresh(htmlResp.body) || extractJsLocation(htmlResp.body);
        if (meta) {
          try {
            const resolved = new URL(meta, htmlResp.finalUrl).href;
            return res.json({ success:true, service:'platoboost', finalUrl: resolved, status: htmlResp.status, method:'html-redirect' });
          } catch {}
        }
        return res.json({ success:true, service:'platoboost', finalUrl: htmlResp.finalUrl, status: htmlResp.status, content: htmlResp.body.slice(0,2000) });
      } catch (err) {
        return res.status(502).json({ success:false, service:'platoboost', error: err.message, hint:'If blocked by Cloudflare, use Puppeteer/Playwright with stealth + proxies.' });
      }
    }

    // -----------------------
    // adf.ly (try ysmm decoding, meta/js)
    // -----------------------
    if (parsed.hostname.includes('adf.ly') || parsed.hostname.includes('adf')) {
      try {
        const htmlResp = await fetchHtmlWithFallback(targetUrl);
        const ysmm = extractYsmm(htmlResp.body);
        if (ysmm) {
          try {
            const decoded = decodeAdflyYsmm(ysmm);
            if (decoded) return res.json({ success:true, service:'adf.ly', finalUrl: decoded });
          } catch {}
        }
        const meta = extractMetaRefresh(htmlResp.body) || extractJsLocation(htmlResp.body);
        if (meta) {
          try { const resolved = new URL(meta, htmlResp.finalUrl).href; return res.json({ success:true, service:'adf.ly', finalUrl: resolved }); } catch {}
        }
        return res.json({ success:true, service:'adf.ly', finalUrl: htmlResp.finalUrl, status: htmlResp.status, content: htmlResp.body.slice(0,2000) });
      } catch (err) {
        return res.status(502).json({ success:false, service:'adf.ly', error: err.message });
      }
    }

    // -----------------------
    // shorte.st / boost.ink / mboost / sub2unlock / rekonise / others:
    // generally HTML fetch + heuristics
    // -----------------------
    const shortenerHosts = ['shorte.st','boost.ink','mboost.me','mboost','sub2unlock','rekonise','go.platoboost.com','shortly','tinyurl.com'];
    if (shortenerHosts.some(h => parsed.hostname.includes(h))) {
      try {
        const htmlResp = await fetchHtmlWithFallback(targetUrl);
        // try meta/js detection
        const meta = extractMetaRefresh(htmlResp.body) || extractJsLocation(htmlResp.body);
        if (meta) {
          try { const resolved = new URL(meta, htmlResp.finalUrl).href; return res.json({ success:true, service:'shortener', finalUrl: resolved }); } catch {}
        }
        // fallback: return HTML for client parsing
        return res.json({ success:true, service:'shortener', finalUrl: htmlResp.finalUrl, status: htmlResp.status, content: htmlResp.body.slice(0,2000) });
      } catch (err) {
        return res.status(502).json({ success:false, service:'shortener', error: err.message });
      }
    }

    // -----------------------
    // Fallback: generic HTML fetch & return content/finalUrl
    // -----------------------
    try {
      const htmlResp = await fetchHtmlWithFallback(targetUrl);
      const bodyLower = (htmlResp.body || '').toLowerCase();
      if (bodyLower.includes('attention required') || bodyLower.includes('please enable javascript') || bodyLower.includes('cf-chl-bypass')) {
        return res.status(403).json({ success:false, error:'Cloudflare/JS challenge detected', hint:'This target needs a real browser (Puppeteer/Playwright) or a JS-challenge solving proxy.' });
      }

      // try quick heuristics for meta/js redirect
      const meta = extractMetaRefresh(htmlResp.body) || extractJsLocation(htmlResp.body);
      if (meta) {
        try { const resolved = new URL(meta, htmlResp.finalUrl).href; return res.json({ success:true, service:'generic-redirect', finalUrl: resolved, status: htmlResp.status }); } catch {}
      }

      return res.json({ success:true, service:'generic-html', finalUrl: htmlResp.finalUrl, status: htmlResp.status, content: htmlResp.body.slice(0,2000) });
    } catch (err) {
      return res.status(502).json({ success:false, error:'Failed to fetch target URL', details: axiosErrorDetails(err) });
    }

  } catch (outer) {
    console.error('Bypass internal error', outer);
    return res.status(500).json({ success:false, error:'Internal server error', details: outer && outer.message ? outer.message : String(outer) });
  }
});

/* ---------------------------
   Server start
----------------------------*/
app.listen(BYPASS_PORT, () => {
  console.log(`Bypasser running on port ${BYPASS_PORT}`);
});
