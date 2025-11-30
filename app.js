// app.js
// Advanced AST Cleaner (A+B+C) — integrated into app.js (mode A/B/C) for internal service
// - Serves public/ast.html
// - POST /clean_ast -> modes A (fallback-friendly), B (strict), C (max-repair; default)
// - POST /clean      -> hybrid (tries C then regex fallback)
// - GET  /health
// - LISTENS on internal port 5001 (keep server.js proxy to forward /clean_ast -> localhost:5001)
// - Requirements: express, body-parser, luaparse
// Install: npm install express body-parser luaparse
// Usage: node app.js

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const luaparse = require("luaparse");

const app = express();

// Configuration
const INTERNAL_PORT = 5001;
const BODY_LIMIT = "150mb"; // large-file safe
const DEFAULT_ARG_PREFIX = "arg";
const DEFAULT_MAX_ARGS = 10;
const MAX_PARSE_ATTEMPTS = 4;

app.use(bodyParser.json({ limit: BODY_LIMIT }));
app.use(bodyParser.urlencoded({ extended: true, limit: BODY_LIMIT }));
app.use(express.static(path.join(__dirname, "public")));

// ---------- Utilities ----------
function safeSlice(s, a, b) {
  a = Math.max(0, Math.min(s.length, a || 0));
  b = Math.max(0, Math.min(s.length, b || 0));
  if (a >= b) return "";
  return s.slice(a, b);
}
function srcOf(node, code) {
  if (!node || !Array.isArray(node.range) || node.range.length < 2) return "";
  return safeSlice(code, node.range[0], node.range[1]);
}
function walkSafe(node, visitor) {
  try {
    (function rec(n) {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) { for (const x of n) rec(x); return; }
      try { visitor(n); } catch (e) { /* ignore visitor errors */ }
      for (const k of Object.keys(n)) {
        if (k === "range") continue;
        const c = n[k];
        if (c && typeof c === "object") rec(c);
      }
    })(node);
  } catch (e) {}
}
function uniqueName(base, used) {
  base = String(base || "v").replace(/[^A-Za-z0-9_]/g, "");
  if (!/^[A-Za-z_]/.test(base)) base = "_" + base;
  let name = base;
  let i = 1;
  while (used.has(name) || /^var\d+$/i.test(name)) name = base + String(i++);
  used.add(name);
  return name;
}
function inferNameFromInit(initSrc) {
  if (!initSrc || typeof initSrc !== "string") return null;
  const s = initSrc;
  const m = s.match(/GetService\s*\(\s*["']([\w\s-]+)["']\s*\)/i);
  if (m && m[1]) return m[1].replace(/\s+/g, "") + "Service";
  if (/\bgame:HttpGet\b/i.test(s) || /https?:\/\//i.test(s)) return "httpGetResult";
  if (/\bloadstring\b/i.test(s)) return "loaded";
  if (/\bMakeWindow\b/i.test(s)) return "window";
  if (/\bMakeTab\b/i.test(s)) return "tab";
  if (/\bAddSection\b/i.test(s)) return "section";
  if (/\bAddButton\b/i.test(s)) return "button";
  if (/\bLocalPlayer\b/i.test(s)) return "localPlayer";
  const token = s.match(/([A-Za-z_][A-Za-z0-9_]*)\s*$/);
  if (token) return token[1];
  return null;
}

// ---------- Regex fallback (conservative) ----------
function regexFallbackClean(code, options = {}) {
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : DEFAULT_ARG_PREFIX;
  const maxArgs = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : DEFAULT_MAX_ARGS;
  let out = String(code);

  out = out.replace(/\(\{\s*\.{3}\s*\}\)\s*\[\s*(\d+)\s*\]/g, (m, n) => {
    const idx = Number(n);
    if (Number.isFinite(idx) && idx >= 1 && idx <= maxArgs) return `${argPrefix}${idx}`;
    return `${argPrefix}${idx}`;
  });

  out = out.replace(/local\s+([A-Za-z0-9_,\s]+)\s*=\s*\.{3}/g, (m, p1) => {
    const ids = p1.replace(/\s+/g, "").split(",").filter(Boolean);
    if (ids.length === 0) return `local = `;
    const rhs = ids.map((_, i) => `${argPrefix}${i + 1}`).join(", ");
    return `local ${ids.join(", ")} = ${rhs}`;
  });

  out = out.replace(/function\s*\(\s*\.{3}\s*\)/g, "function()");

  out = out.replace(/,\s*([\]\}])/g, "$1");
  out = out.replace(/^\s*\)\s*$/gm, "");

  return out;
}

// ---------- Sanitizers & Repair Helpers ----------
function sanitizeBasic(code) {
  if (!code) return code;
  let out = String(code);
  out = out.replace(/\)\s*end\s*\)/g, ")");
  out = out.replace(/end\s*\)/g, "end");
  out = out.replace(/^\s*\)\s*$/gm, "");
  out = out.replace(/end\s+end/g, "end");
  out = out.replace(/,\s*([\]\}])/g, "$1");
  out = out.replace(/\bend,\b/g, "end");
  return out;
}
function sanitizeBalanceEnds(code) {
  if (!code) return code;
  const s = String(code);
  const functionCount = (s.match(/\bfunction\b/g) || []).length;
  const endCount = (s.match(/\bend\b/g) || []).length;
  if (endCount <= functionCount) return s;
  let diff = endCount - functionCount;
  const lines = s.split("\n");
  for (let i = lines.length - 1; i >= 0 && diff > 0; --i) {
    if (/^\s*end\s*$/.test(lines[i])) { lines.splice(i, 1); diff--; }
  }
  return lines.join("\n");
}
function wrapInFunctionIfNeeded(code, argPrefix = DEFAULT_ARG_PREFIX, maxArgs = DEFAULT_MAX_ARGS) {
  const s = String(code);
  const usesVarargIndex = /\(\{\s*\.{3}\s*\}\)\s*\[\s*\d+\s*\]/.test(s);
  const hasFunction = /\bfunction\b/.test(s);
  const hasTopLevelVarargAssign = /local\s+[A-Za-z0-9_,\s]+\s*=\s*\.{3}/.test(s);
  if ((usesVarargIndex || hasTopLevelVarargAssign) && !hasFunction) {
    const wrapperStart = `local __wrap = function(${Array.from({ length: maxArgs }, (_, i) => argPrefix + (i + 1)).join(", ")})\n`;
    const wrapperEnd = `\nend\n__wrap()`;
    return { code: wrapperStart + s + wrapperEnd, wrapped: true };
  }
  return { code: s, wrapped: false };
}
function sanitizeAggressive(code) {
  if (!code) return code;
  let out = String(code);
  out = out.replace(/^\uFEFF/, "");
  out = out.replace(/\r\n/g, "\n");
  out = out.replace(/[\u200B-\u200D\uFEFF]/g, "");
  out = out.replace(/^\s*<[^>]+>\s*$/gm, "");
  out = out.replace(/\{\s*,/g, "{");
  out = out.replace(/,\s*\}/g, "}");
  out = out.replace(/\bend\)\s*$/g, "end");
  out = sanitizeBasic(out);
  out = sanitizeBalanceEnds(out);
  return out;
}

// ---------- Parse wrapper ----------
function tryParse(code, options = {}) {
  try {
    const ast = luaparse.parse(code, {
      luaVersion: "5.1",
      ranges: true,
      locations: false,
      scope: true,
      comments: false,
      tolerant: !!options.tolerant
    });
    return { ok: true, ast, error: null };
  } catch (err) {
    return { ok: false, ast: null, error: err };
  }
}

// ---------- AST Cleaner (robust) ----------
function cleanWithAST(code, options = {}) {
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : DEFAULT_ARG_PREFIX;
  const maxArgsPerFn = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : DEFAULT_MAX_ARGS;
  const enableRenaming = options.enableRenaming === true;

  const parsed = tryParse(code, { tolerant: true });
  if (!parsed.ok) {
    return { cleaned: code, warnings: ["parse_failed: " + (parsed.error && parsed.error.message)], renameMap: {} };
  }
  const ast = parsed.ast;

  const replacements = [];
  const funcHeaderMap = new Map();

  // 1) detect vararg functions & compute argCounts
  walkSafe(ast, (node) => {
    if (!node) return;
    if ((node.type === "FunctionDeclaration" || node.type === "FunctionExpression") && node.is_vararg) {
      let maxIdx = 0;
      walkSafe(node.body, (n) => {
        if (!n) return;
        if (n.type === "IndexExpression" && n.base && n.base.type === "TableConstructorExpression" && n.index && n.index.type === "NumericLiteral") {
          const hasVararg = (n.base.fields || []).some(f => f && f.type === "TableValue" && f.value && f.value.type === "VarargLiteral");
          if (hasVararg && Number.isFinite(n.index.value)) maxIdx = Math.max(maxIdx, n.index.value);
        }
        if (n.type === "LocalStatement" && Array.isArray(n.init) && n.init.length > 0) {
          for (let i = 0; i < n.init.length; ++i) {
            const initNode = n.init[i];
            if (initNode && initNode.type === "VarargLiteral") {
              const leftCount = Array.isArray(n.variables) ? n.variables.length : 0;
              maxIdx = Math.max(maxIdx, leftCount);
            }
          }
        }
      });
      const argCount = Math.max(0, Math.min(maxArgsPerFn, Math.floor(maxIdx)));
      const argNames = [];
      for (let i = 1; i <= argCount; ++i) argNames.push(`${argPrefix}${i}`);
      funcHeaderMap.set(node, { argCount, argNames });
    }
  });

  // 2) replace IndexExpression occurrences
  walkSafe(ast, (node) => {
    if (!node || node.type !== "IndexExpression") return;
    let enclosing = null;
    for (const fnNode of funcHeaderMap.keys()) {
      if (!fnNode.range || !node.range) continue;
      if (fnNode.range[0] <= node.range[0] && fnNode.range[1] >= node.range[1]) {
        if (!enclosing || (fnNode.range[1] - fnNode.range[0] < enclosing.range[1] - enclosing.range[0])) enclosing = fnNode;
      }
    }
    if (!enclosing) return;
    const hdr = funcHeaderMap.get(enclosing);
    if (!hdr || hdr.argCount <= 0) return;
    const base = node.base;
    const index = node.index;
    if (!base || base.type !== "TableConstructorExpression" || !index || index.type !== "NumericLiteral") return;
    const hasVararg = (base.fields || []).some(f => f && f.type === "TableValue" && f.value && f.value.type === "VarargLiteral");
    if (!hasVararg) return;
    const idx = Number(index.value);
    if (!Number.isFinite(idx) || idx < 1 || idx > hdr.argCount) return;
    if (typeof node.range[0] === "number" && typeof node.range[1] === "number") {
      replacements.push({ start: node.range[0], end: node.range[1], text: hdr.argNames[idx - 1] });
    }
  });

  // 3) replace local a,b = ...
  walkSafe(ast, (node) => {
    if (!node || node.type !== "LocalStatement" || !Array.isArray(node.init) || node.init.length === 0) return;
    for (let i = 0; i < node.init.length; ++i) {
      const initNode = node.init[i];
      if (!initNode || initNode.type !== "VarargLiteral") continue;
      let enclosing = null;
      for (const fnNode of funcHeaderMap.keys()) {
        if (!fnNode.range || !node.range) continue;
        if (fnNode.range[0] <= node.range[0] && fnNode.range[1] >= node.range[1]) {
          if (!enclosing || (fnNode.range[1] - fnNode.range[0] < enclosing.range[1] - enclosing.range[0])) enclosing = fnNode;
        }
      }
      const hdr = funcHeaderMap.get(enclosing);
      const leftVars = (node.variables || []).map(v => (v && v.name) || "").filter(Boolean);
      if (hdr && hdr.argCount > 0 && leftVars.length > 0) {
        const needed = Math.min(leftVars.length, hdr.argCount);
        const rhs = [];
        for (let k = 0; k < needed; ++k) rhs.push(hdr.argNames[k]);
        const newText = `local ${leftVars.join(", ")} = ${rhs.join(", ")}`;
        if (typeof node.range[0] === "number" && typeof node.range[1] === "number") replacements.push({ start: node.range[0], end: node.range[1], text: newText });
      } else if (leftVars.length > 0) {
        const left = leftVars.join(", ");
        if (typeof node.range[0] === "number" && typeof node.range[1] === "number") replacements.push({ start: node.range[0], end: node.range[1], text: `local ${left} = ` });
      }
    }
  });

  // 4) local x = ({...})[N] -> local x = argN
  walkSafe(ast, (node) => {
    if (!node || node.type !== "LocalStatement" || !Array.isArray(node.init) || node.init.length !== 1) return;
    const initNode = node.init[0];
    if (!initNode || initNode.type !== "IndexExpression") return;
    const base = initNode.base;
    if (!base || base.type !== "TableConstructorExpression") return;
    const indexNode = initNode.index;
    if (!indexNode || indexNode.type !== "NumericLiteral") return;
    const hasVararg = (base.fields || []).some(f => f && f.type === "TableValue" && f.value && f.value.type === "VarargLiteral");
    if (!hasVararg) return;
    let enclosing = null;
    for (const fnNode of funcHeaderMap.keys()) {
      if (!fnNode.range || !node.range) continue;
      if (fnNode.range[0] <= node.range[0] && fnNode.range[1] >= node.range[1]) {
        if (!enclosing || (fnNode.range[1] - fnNode.range[0] < enclosing.range[1] - enclosing.range[0])) enclosing = fnNode;
      }
    }
    const hdr = funcHeaderMap.get(enclosing);
    const idxVal = Number(indexNode.value);
    if (hdr && idxVal >= 1 && idxVal <= hdr.argCount) {
      const argName = hdr.argNames[idxVal - 1];
      const leftVar = (node.variables && node.variables[0] && node.variables[0].name) || null;
      if (leftVar) {
        if (typeof node.range[0] === "number" && typeof node.range[1] === "number") replacements.push({ start: node.range[0], end: node.range[1], text: `local ${leftVar} = ${argName}` });
      } else if (typeof node.range[0] === "number" && typeof node.range[1] === "number") {
        replacements.push({ start: node.range[0], end: node.range[1], text: argName });
      }
    }
  });

  // 5) replace function header "(...)" -> "(arg1,...)" 
  for (const [fnNode, hdr] of funcHeaderMap.entries()) {
    try {
      if (!fnNode || !fnNode.range) continue;
      const fnSrc = srcOf(fnNode, code);
      if (!fnSrc) continue;
      const paramMatch = fnSrc.match(/\(\s*\.\.\.\s*\)/);
      const argText = hdr.argCount && hdr.argCount > 0 ? `(${hdr.argNames.join(", ")})` : "()";
      if (paramMatch && typeof paramMatch.index === "number") {
        const absStart = fnNode.range[0] + paramMatch.index;
        const absEnd = absStart + paramMatch[0].length;
        replacements.push({ start: absStart, end: absEnd, text: argText });
      } else {
        const fallbackPos = code.indexOf("(...)", fnNode.range[0]);
        if (fallbackPos >= 0 && fallbackPos + 4 < fnNode.range[1]) replacements.push({ start: fallbackPos, end: fallbackPos + 5, text: argText });
      }
    } catch (e) {}
  }

  // 6) single-element table flattening
  try {
    const tableDefs = [];
    walkSafe(ast, (node) => {
      if (!node || node.type !== "LocalStatement" || !Array.isArray(node.init) || node.init.length !== 1) return;
      const init = node.init[0];
      if (!init || init.type !== "TableConstructorExpression") return;
      const fields = init.fields || [];
      if (fields.length !== 1) return;
      const tv = fields[0];
      if (!tv || tv.type !== "TableValue") return;
      const inner = tv.value;
      if (!inner) return;
      const allowed = new Set(["Identifier", "StringLiteral", "NumericLiteral", "BooleanLiteral", "NilLiteral", "CallExpression", "MemberExpression", "IndexExpression"]);
      if (!allowed.has(inner.type)) return;
      const tblNameNode = node.variables && node.variables[0];
      if (!tblNameNode || !tblNameNode.name) return;
      tableDefs.push({ tblName: tblNameNode.name, exprSrc: srcOf(inner, code) });
    });
    if (tableDefs.length > 0) {
      walkSafe(ast, (node) => {
        if (!node || node.type !== "LocalStatement" || !Array.isArray(node.init) || node.init.length !== 1) return;
        const init = node.init[0];
        if (!init || init.type !== "IndexExpression") return;
        if (!init.index || init.index.type !== "NumericLiteral" || Number(init.index.value) !== 1) return;
        if (!init.base || init.base.type !== "Identifier") return;
        const baseName = init.base.name;
        const found = tableDefs.find(t => t.tblName === baseName);
        if (!found) return;
        const leftVar = (node.variables && node.variables[0] && node.variables[0].name) || null;
        if (leftVar) replacements.push({ start: node.range[0], end: node.range[1], text: `local ${leftVar} = ${found.exprSrc}` });
      });
    }
  } catch (e) {}

  // 7) conservative renaming
  const renameMap = new Map();
  try {
    const usedNames = new Set();
    walkSafe(ast, (n) => { if (n && n.type === "Identifier" && typeof n.name === "string") usedNames.add(n.name); });

    const localDecls = [];
    walkSafe(ast, (n) => {
      if (!n || n.type !== "LocalStatement" || !Array.isArray(n.variables) || n.variables.length === 0) return;
      const inits = Array.isArray(n.init) ? n.init : [];
      for (let vi = 0; vi < n.variables.length; ++vi) {
        const idNode = n.variables[vi];
        const idName = idNode && idNode.name;
        const initNode = inits[vi] || inits[0] || null;
        const initSrc = initNode ? srcOf(initNode, code) : "";
        if (idName) localDecls.push({ idName, initSrc, idNode });
      }
    });

    for (const d of localDecls) {
      if (!d.idName) continue;
      if (!/^var\d+$/i.test(d.idName) && !/^_[A-Za-z0-9]+$/.test(d.idName)) continue;
      const guess = inferNameFromInit(d.initSrc);
      if (!guess) continue;
      const newName = uniqueName(guess, usedNames);
      renameMap.set(d.idName, newName);
    }

    if (enableRenaming && renameMap.size > 0) {
      walkSafe(ast, (n) => {
        if (n && n.type === "Identifier" && typeof n.name === "string" && n.range && renameMap.has(n.name)) {
          replacements.push({ start: n.range[0], end: n.range[1], text: renameMap.get(n.name) });
        }
      });
    }
  } catch (e) {}

  // 8) apply replacements descending
  replacements.sort((a, b) => {
    if (a.start !== b.start) return b.start - a.start;
    return (a.end - a.start) - (b.end - b.start);
  });

  let out = code;
  const appliedRanges = [];
  for (const r of replacements) {
    try {
      if (!r || typeof r.start !== "number" || typeof r.end !== "number" || r.start >= r.end) continue;
      if (r.start < 0 || r.end > code.length) continue;
      let overlap = false;
      for (const a of appliedRanges) {
        if (!(r.end <= a.start || r.start >= a.end)) { overlap = true; break; }
      }
      if (overlap) continue;
      out = out.slice(0, r.start) + r.text + out.slice(r.end);
      appliedRanges.push({ start: r.start, end: r.start + (r.text ? r.text.length : 0) });
    } catch (e) { /* skip faulty replacement */ }
  }

  out = out.replace(/\t/g, "  ").replace(/[ \t]+$/gm, "");
  const renameObj = {};
  for (const [k, v] of renameMap) renameObj[k] = v;
  return { cleaned: out, warnings: [], renameMap: renameObj };
}

// ---------- Modes ----------

async function runModeA(code, options = {}) {
  const parsed = tryParse(code, { tolerant: true });
  if (parsed.ok) {
    const r = cleanWithAST(code, options);
    return { cleaned: r.cleaned, mode: "A", warnings: r.warnings || [], renameMap: r.renameMap || {} };
  } else {
    const fallback = regexFallbackClean(code, options);
    return { cleaned: fallback, mode: "A", warnings: ["parse_failed: " + (parsed.error && parsed.error.message)], renameMap: {} };
  }
}

async function runModeB(code, options = {}) {
  const parsedStrict = tryParse(code, { tolerant: false });
  if (parsedStrict.ok) {
    const r = cleanWithAST(code, options);
    return { cleaned: r.cleaned, mode: "B", warnings: r.warnings || [], renameMap: r.renameMap || {} };
  } else {
    return { cleaned: regexFallbackClean(code, options), mode: "B", warnings: ["strict_parse_failed: " + (parsedStrict.error && parsedStrict.error.message)], renameMap: {} };
  }
}

async function runModeC(code, options = {}) {
  let attempt = 0;
  let current = String(code);
  const warnings = [];

  while (attempt < MAX_PARSE_ATTEMPTS) {
    attempt++;
    const label = ["original", "basic", "balanced", "aggressive-wrapper"][Math.min(attempt - 1, 3)];
    const parsed = tryParse(current, { tolerant: true });
    if (parsed.ok) {
      try {
        const r = cleanWithAST(current, options);
        const meta = [];
        if (attempt > 1) meta.push(`repaired_via:${label}`);
        return { cleaned: r.cleaned, mode: "C", warnings: meta.concat(warnings), renameMap: r.renameMap || {} };
      } catch (e) {
        warnings.push("ast_transform_error:" + (e && e.message));
        break;
      }
    } else {
      const em = parsed.error && parsed.error.message ? parsed.error.message : String(parsed.error);
      warnings.push(`parse_failed_attempt_${attempt}:[${em}]`);
    }

    if (attempt === 1) current = sanitizeBasic(current);
    else if (attempt === 2) current = sanitizeBalanceEnds(current);
    else {
      current = sanitizeAggressive(current);
      const wrap = wrapInFunctionIfNeeded(current, options.argPrefix, options.maxArgsPerFn);
      if (wrap.wrapped) current = wrap.code;
    }
  }

  const fallback = regexFallbackClean(code, options);
  return { cleaned: fallback, mode: "C", warnings: warnings.length ? warnings : ["all_parse_attempts_failed"], renameMap: {} };
}

// ---------- Endpoints ----------

app.post("/clean_ast", async (req, res) => {
  try {
    const code = typeof req.body.code === "string" ? req.body.code : (req.body && req.body.code ? String(req.body.code) : "");
    const opts = req.body.options || {};
    const mode = (opts.mode || "C").toUpperCase();
    if (!code) return res.status(400).json({ success: false, error: "no_code_provided" });

    const runOpts = {
      argPrefix: typeof opts.argPrefix === "string" ? opts.argPrefix : DEFAULT_ARG_PREFIX,
      maxArgsPerFn: typeof opts.maxArgsPerFn === "number" ? opts.maxArgsPerFn : DEFAULT_MAX_ARGS,
      enableRenaming: opts.enableRenaming === true
    };

    let result;
    if (mode === "A") result = await runModeA(code, runOpts);
    else if (mode === "B") result = await runModeB(code, runOpts);
    else result = await runModeC(code, runOpts);

    return res.json({
      success: true,
      cleaned: result.cleaned,
      mode: result.mode,
      warnings: result.warnings || [],
      renameMap: result.renameMap || {}
    });
  } catch (err) {
    console.error("clean_ast error:", err && err.stack || err);
    res.status(500).json({ success: false, error: "internal_error", detail: String(err && err.message) });
  }
});

app.post("/clean", async (req, res) => {
  try {
    const code = typeof req.body.code === "string" ? req.body.code : (req.body && req.body.code ? String(req.body.code) : "");
    const opts = req.body.options || {};
    if (!code) return res.status(400).json({ success: false, error: "no_code_provided" });

    const runOpts = {
      argPrefix: typeof opts.argPrefix === "string" ? opts.argPrefix : DEFAULT_ARG_PREFIX,
      maxArgsPerFn: typeof opts.maxArgsPerFn === "number" ? opts.maxArgsPerFn : DEFAULT_MAX_ARGS,
      enableRenaming: opts.enableRenaming === true
    };
    const astResult = await runModeC(code, runOpts);
    return res.json({ success: true, cleaned: astResult.cleaned, mode: astResult.mode, warnings: astResult.warnings || [] });
  } catch (err) {
    console.error("clean error:", err && err.stack || err);
    res.status(500).json({ success: false, error: "internal_error", detail: String(err && err.message) });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/", (req, res) => {
  const file = path.join(__dirname, "public", "ast.html");
  res.sendFile(file, function (err) {
    if (err) res.status(err.status || 500).send("ast.html not found");
  });
});

// Start internal server
app.listen(INTERNAL_PORT, () => {
  console.log(`Advanced AST Cleaner (A/B/C) running on internal port ${INTERNAL_PORT}`);
});
