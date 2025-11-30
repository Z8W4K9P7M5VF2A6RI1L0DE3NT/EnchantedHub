// app.js - Full Advanced AST Cleaner (Render-safe & Large-file safe)
// - Serves public/ast.html from ./public
// - POST /clean_ast -> advanced AST-based cleaning (tolerant parsing, safe transforms)
// - POST /clean     -> hybrid: try AST then fallback to regex
// - GET /health     -> health check
// - Runs on internal port 5001 (do NOT use process.env.PORT here)
// Requirements: express, body-parser, luaparse
// Install: npm install express body-parser luaparse
// Start (standalone): node app.js
// If you run alongside server.js which uses process.env.PORT, keep this port internal.

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const luaparse = require("luaparse");

const app = express();

// ------ configuration ------
const INTERNAL_PORT = 5001;
const BODY_LIMIT = "50mb"; // large-file safe
const DEFAULT_ARG_PREFIX = "arg";
const DEFAULT_MAX_ARGS = 10;

// ------ middleware ------
app.use(bodyParser.json({ limit: BODY_LIMIT }));
app.use(bodyParser.urlencoded({ extended: true, limit: BODY_LIMIT }));

// Serve static assets from /public (including public/ast.html)
app.use(express.static(path.join(__dirname, "public")));

// ------ utilities ------
function safeSlice(s, a, b) {
  // guard indices
  a = Math.max(0, Math.min(s.length, a));
  b = Math.max(0, Math.min(s.length, b));
  if (a >= b) return "";
  return s.slice(a, b);
}

function srcOf(node, code) {
  if (!node || !node.range || !Array.isArray(node.range) || node.range.length < 2) return "";
  return safeSlice(code, node.range[0], node.range[1]);
}

function walkSafe(node, visitor) {
  // defensive AST walker: never throws on unexpected shapes
  try {
    (function recurse(n) {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) {
        for (let x of n) recurse(x);
        return;
      }
      // call visitor in a try-catch so one visitor bug doesn't break traversal
      try { visitor(n); } catch (e) { /* swallow visitor errors */ }
      for (const k of Object.keys(n)) {
        if (k === "range") continue;
        const child = n[k];
        if (child && typeof child === "object") recurse(child);
      }
    })(node);
  } catch (e) {
    // swallow traversal errors - caller should handle no-op result
  }
}

function uniqueName(base, usedSet) {
  base = String(base || "v").replace(/[^A-Za-z0-9_]/g, "");
  if (!/^[A-Za-z_]/.test(base)) base = "_" + base;
  let name = base;
  let i = 1;
  while (usedSet.has(name) || /^var\d+$/i.test(name)) {
    name = base + String(i++);
  }
  usedSet.add(name);
  return name;
}

function inferNameFromInit(initSrc) {
  if (!initSrc || typeof initSrc !== "string") return null;
  const s = initSrc;
  // common heuristics
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

// ------ regex fallback (conservative) ------
function regexFallbackClean(code, options = {}) {
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : DEFAULT_ARG_PREFIX;
  const maxArgs = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : DEFAULT_MAX_ARGS;

  let out = String(code);

  // Replace ({...})[N] -> argN when N within maxArgs
  out = out.replace(/\(\{\s*\.{3}\s*\}\)\s*\[\s*(\d+)\s*\]/g, (m, n) => {
    const idx = Number(n);
    if (Number.isFinite(idx) && idx >= 1 && idx <= maxArgs) return `${argPrefix}${idx}`;
    return `${argPrefix}${idx}`;
  });

  // Replace local a,b = ... -> local a,b = arg1, arg2, ...
  out = out.replace(/local\s+([A-Za-z0-9_,\s]+)\s*=\s*\.{3}/g, (m, p1) => {
    const ids = p1.replace(/\s+/g, "").split(",").filter(Boolean);
    if (ids.length === 0) return `local = `;
    const rhs = ids.map((_, i) => `${argPrefix}${i+1}`).join(", ");
    return `local ${ids.join(", ")} = ${rhs}`;
  });

  // Replace function(...) -> function()
  out = out.replace(/function\s*\(\s*\.{3}\s*\)/g, "function()");

  // Flatten trivial single-element table inline occurrences (very conservative)
  out = out.replace(/local\s+(\w+)\s*=\s*\{\s*([^\}]+?)\s*\}\s*;\s*local\s+(\w+)\s*=\s*\1\s*\[\s*1\s*\]/g,
    (m, tbl, inner, alias) => `local ${alias} = ${inner}`);

  // whitespace cleanup
  return out;
}

// ------ AST transformation (robust & tolerant) ------
function cleanWithAST(originalCode, options = {}) {
  const code = String(originalCode || "");
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : DEFAULT_ARG_PREFIX;
  const maxArgsPerFn = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : DEFAULT_MAX_ARGS;
  const enableRenaming = options.enableRenaming === true;

  // Prepare result object in case of parse failure
  let ast;
  try {
    // Parse in tolerant mode for large/rough codebases.
    ast = luaparse.parse(code, {
      luaVersion: "5.1",
      ranges: true,
      locations: false,
      scope: true,
      comments: false,
      tolerant: true
    });
  } catch (err) {
    return { cleaned: code, warnings: ["parse_failed: " + (err && err.message)], renameMap: {} };
  }

  // Collect replacements { start, end, text }
  const replacements = [];
  const funcHeaderMap = new Map(); // fnNode -> { argCount, argNames }

  // 1) detect vararg functions and estimate arg counts conservatively
  try {
    walkSafe(ast, (node) => {
      if (!node) return;
      const isFunc = (node.type === "FunctionDeclaration" || node.type === "FunctionExpression");
      if (!isFunc || !node.is_vararg) return;

      let maxIdxDetected = 0;

      // scan body for patterns
      try {
        walkSafe(node.body, (inner) => {
          if (!inner) return;
          // pattern: ({...})[N]
          if (inner.type === "IndexExpression" && inner.base && inner.base.type === "TableConstructorExpression") {
            try {
              const fields = inner.base.fields || [];
              const hasVararg = fields.some(f => f && f.type === "TableValue" && f.value && f.value.type === "VarargLiteral");
              if (hasVararg && inner.index && inner.index.type === "NumericLiteral" && Number.isFinite(inner.index.value)) {
                maxIdxDetected = Math.max(maxIdxDetected, inner.index.value);
              }
            } catch (e) { /* ignore */ }
          }

          // pattern: local a,b = ...
          if (inner.type === "LocalStatement" && Array.isArray(inner.init) && inner.init.length > 0) {
            for (let i = 0; i < inner.init.length; ++i) {
              const initNode = inner.init[i];
              if (initNode && initNode.type === "VarargLiteral") {
                const leftCount = Array.isArray(inner.variables) ? inner.variables.length : 0;
                maxIdxDetected = Math.max(maxIdxDetected, leftCount);
              }
            }
          }
        });
      } catch (e) { /* ignore body scan errors */ }

      const argCount = Math.max(0, Math.min(maxArgsPerFn, Math.floor(maxIdxDetected)));
      const argNames = [];
      for (let i = 1; i <= argCount; ++i) argNames.push(`${argPrefix}${i}`);
      funcHeaderMap.set(node, { argCount, argNames });
    });
  } catch (e) {
    // if detection fails entirely, continue with no func headers
  }

  // 2) replace IndexExpression occurrences like ({...})[N] -> argN when within detected function
  try {
    walkSafe(ast, (node) => {
      if (!node || node.type !== "IndexExpression") return;
      // find enclosing function by range (choose smallest enclosing)
      try {
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

        // schedule replacement
        if (typeof node.range[0] === "number" && typeof node.range[1] === "number") {
          replacements.push({ start: node.range[0], end: node.range[1], text: hdr.argNames[idx - 1] });
        }
      } catch (e) { /* ignore per-node errors */ }
    });
  } catch (e) { /* ignore global errors */ }

  // 3) replace LocalStatement with VarargLiteral init: local a,b = ...
  try {
    walkSafe(ast, (node) => {
      if (!node || node.type !== "LocalStatement" || !Array.isArray(node.init) || node.init.length === 0) return;
      for (let i = 0; i < node.init.length; ++i) {
        const initNode = node.init[i];
        if (!initNode || initNode.type !== "VarargLiteral") continue;

        // find enclosing function for this local
        try {
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
            if (typeof node.range[0] === "number" && typeof node.range[1] === "number") {
              replacements.push({ start: node.range[0], end: node.range[1], text: newText });
            }
          } else if (leftVars.length > 0) {
            const left = leftVars.join(", ");
            if (typeof node.range[0] === "number" && typeof node.range[1] === "number") {
              replacements.push({ start: node.range[0], end: node.range[1], text: `local ${left} = ` });
            }
          }
        } catch (e) { /* ignore per-node */ }
      }
    });
  } catch (e) { /* ignore */ }

  // 4) replace local x = ({...})[N] -> local x = argN
  try {
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

      // find enclosing function
      try {
        let enclosing = null;
        for (const fnNode of funcHeaderMap.keys()) {
          if (!fnNode.range || !node.range) continue;
          if (fnNode.range[0] <= node.range[0] && fnNode.range[1] >= node.range[1]) {
            if (!enclosing || (fnNode.range[1] - fnNode.range[0] < enclosing.range[1] - enclosing.range[0])) enclosing = fnNode;
          }
        }
        const hdr = funcHeaderMap.get(enclosing);
        const idxVal = Number(indexNode.value);
        if (hdr && hdr.argCount > 0 && idxVal >= 1 && idxVal <= hdr.argCount) {
          const argName = hdr.argNames[idxVal - 1];
          const leftVar = (node.variables && node.variables[0] && node.variables[0].name) || null;
          if (leftVar) {
            if (typeof node.range[0] === "number" && typeof node.range[1] === "number") {
              replacements.push({ start: node.range[0], end: node.range[1], text: `local ${leftVar} = ${argName}` });
            }
          } else if (typeof node.range[0] === "number" && typeof node.range[1] === "number") {
            replacements.push({ start: node.range[0], end: node.range[1], text: argName });
          }
        }
      } catch (e) { /* ignore */ }
    });
  } catch (e) { /* ignore */ }

  // 5) replace function header "(...)" -> "(arg1,...)" for detected functions
  try {
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
          // fallback search in code range
          const fallbackPos = code.indexOf("(...)", fnNode.range[0]);
          if (fallbackPos >= 0 && fallbackPos + 4 < fnNode.range[1]) {
            replacements.push({ start: fallbackPos, end: fallbackPos + 5, text: argText });
          }
        }
      } catch (e) { /* ignore per-fn */ }
    }
  } catch (e) { /* ignore */ }

  // 6) single-element table flattening (conservative)
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
      // allowed inner types
      const allow = new Set(["Identifier", "StringLiteral", "NumericLiteral", "BooleanLiteral", "NilLiteral", "CallExpression", "MemberExpression", "IndexExpression"]);
      if (!allow.has(inner.type)) return;
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
        if (leftVar) {
          replacements.push({ start: node.range[0], end: node.range[1], text: `local ${leftVar} = ${found.exprSrc}` });
        }
      });
    }
  } catch (e) { /* ignore */ }

  // 7) variable renaming (conservative): rename var### style locals when we can infer a friendly name
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
      // schedule replacements for identifiers across AST
      walkSafe(ast, (n) => {
        if (n && n.type === "Identifier" && typeof n.name === "string" && n.range && renameMap.has(n.name)) {
          replacements.push({ start: n.range[0], end: n.range[1], text: renameMap.get(n.name) });
        }
      });
    }
  } catch (e) { /* ignore rename errors */ }

  // 8) apply replacements in descending order (non-overlapping guard)
  try {
    // sort descending
    replacements.sort((a, b) => {
      if (a.start !== b.start) return b.start - a.start;
      return (a.end - a.start) - (b.end - b.start);
    });

    let out = code;
    const appliedRanges = [];
    for (const r of replacements) {
      if (!r || typeof r.start !== "number" || typeof r.end !== "number" || r.start >= r.end) continue;
      // ensure positions exist within original code
      if (r.start < 0 || r.end > code.length) continue;
      // check overlap with previously applied replacement (on original coords)
      let overlap = false;
      for (const a of appliedRanges) {
        if (!(r.end <= a.start || r.start >= a.end)) { overlap = true; break; }
      }
      if (overlap) continue;
      // apply on out: because replacements are descending by start, original indices are still valid
      out = out.slice(0, r.start) + r.text + out.slice(r.end);
      appliedRanges.push({ start: r.start, end: r.start + (r.text ? r.text.length : 0) });
    }

    // lightweight trimming
    out = out.replace(/\t/g, "  ").replace(/[ \t]+$/gm, "");
    const renameObj = {};
    for (const [k, v] of renameMap) renameObj[k] = v;
    return { cleaned: out, warnings: [], renameMap: renameObj };
  } catch (e) {
    // if something goes wrong during replacements, return original code with warning
    return { cleaned: code, warnings: ["replace_failed: " + (e && e.message)], renameMap: {} };
  }
}

// ------ endpoints ------

// advanced AST endpoint
app.post("/clean_ast", (req, res) => {
  try {
    const code = typeof req.body.code === "string" ? req.body.code : (req.body && req.body.code ? String(req.body.code) : "");
    const options = req.body.options || {};
    if (!code) return res.status(400).json({ success: false, error: "no_code_provided" });

    // run AST cleaner in safe try-catch wrapper
    let result;
    try {
      result = cleanWithAST(code, options);
    } catch (err) {
      // fallback to regex if transform throws
      const fallback = regexFallbackClean(code, options);
      return res.json({ success: true, cleaned: fallback, fallback: true, warnings: ["ast_transform_crashed: " + (err && err.message)] });
    }

    // if parse failed inside cleaner, fallback to regex
    if (Array.isArray(result.warnings) && result.warnings.some(w => typeof w === "string" && w.startsWith("parse_failed"))) {
      const fallback = regexFallbackClean(code, options);
      return res.json({ success: true, cleaned: fallback, fallback: true, warnings: result.warnings || [] });
    }

    return res.json({ success: true, cleaned: result.cleaned, renameMap: result.renameMap || {}, warnings: result.warnings || [] });
  } catch (err) {
    console.error("clean_ast endpoint error:", err && err.stack || err);
    return res.status(500).json({ success: false, error: "internal_server_error", detail: String(err && err.message) });
  }
});

// hybrid endpoint (try AST then regex)
app.post("/clean", (req, res) => {
  try {
    const code = typeof req.body.code === "string" ? req.body.code : (req.body && req.body.code ? String(req.body.code) : "");
    const options = req.body.options || {};
    if (!code) return res.status(400).json({ success: false, error: "no_code_provided" });

    const astResult = cleanWithAST(code, options);
    if (Array.isArray(astResult.warnings) && astResult.warnings.some(w => typeof w === "string" && w.startsWith("parse_failed"))) {
      const fallback = regexFallbackClean(code, options);
      return res.json({ success: true, cleaned: fallback, fallback: true, warnings: astResult.warnings || [] });
    }
    return res.json({ success: true, cleaned: astResult.cleaned, renameMap: astResult.renameMap || {}, warnings: astResult.warnings || [] });
  } catch (err) {
    console.error("clean endpoint error:", err && err.stack || err);
    return res.status(500).json({ success: false, error: "internal_server_error", detail: String(err && err.message) });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

// default route serve public/ast.html if present
app.get("/", (req, res) => {
  const file = path.join(__dirname, "public", "ast.html");
  res.sendFile(file, function (err) {
    if (err) {
      res.status(err.status || 500).send("ast.html not found");
    }
  });
});

// start server on internal port (do NOT use process.env.PORT to avoid conflicts)
app.listen(INTERNAL_PORT, () => {
  console.log(`Advanced AST Cleaner (robust) running on internal port ${INTERNAL_PORT}`);
});
