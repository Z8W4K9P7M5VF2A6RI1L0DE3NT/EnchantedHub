// app.js - Advanced AST Cleaner (Modes A/B/C: fallback-only, strict, max-repair)
// - Serves public/ast.html
// - POST /clean_ast  -> advanced AST cleaning with mode selection (A/B/C)
// - POST /clean      -> hybrid: try AST then regex fallback
// - GET  /health
// - Port 5001 (internal)
// Requirements: express, body-parser, luaparse
// Install: npm install express body-parser luaparse

const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const luaparse = require("luaparse");

const app = express();

// config
const INTERNAL_PORT = 5001;
const BODY_LIMIT = "100mb";
const DEFAULT_ARG_PREFIX = "arg";
const DEFAULT_MAX_ARGS = 10;
const MAX_PARSE_ATTEMPTS = 4; // for repair mode

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
      try { visitor(n); } catch (e) { /* swallow visitor errors */ }
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
  if (/game:HttpGet/i.test(s) || /https?:\/\//i.test(s)) return "httpGetResult";
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

// ---------- Simple conservative regex fallback ----------
function regexFallbackClean(code, options = {}) {
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : DEFAULT_ARG_PREFIX;
  const maxArgs = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : DEFAULT_MAX_ARGS;

  let out = String(code);

  // ({...})[N] -> argN
  out = out.replace(/\(\{\s*\.{3}\s*\}\)\s*\[\s*(\d+)\s*\]/g, (m, n) => {
    const idx = Number(n);
    if (Number.isFinite(idx) && idx >= 1 && idx <= maxArgs) return `${argPrefix}${idx}`;
    return `${argPrefix}${idx}`;
  });

  // local a,b = ... -> local a,b = arg1, arg2
  out = out.replace(/local\s+([A-Za-z0-9_,\s]+)\s*=\s*\.{3}/g, (m, p1) => {
    const ids = p1.replace(/\s+/g, "").split(",").filter(Boolean);
    if (ids.length === 0) return `local = `;
    const rhs = ids.map((_, i) => `${argPrefix}${i + 1}`).join(", ");
    return `local ${ids.join(", ")} = ${rhs}`;
  });

  // function(...) -> function()
  out = out.replace(/function\s*\(\s*\.{3}\s*\)/g, "function()");

  // whitespace trim
  return out;
}

// ---------- Pre-parsing sanitizers & repair helpers ----------

// Basic sanitizer: remove obvious broken tokens like stray ") end" sequences, fix repeated trailing commas
function sanitizeBasic(code) {
  if (!code) return code;
  let out = String(code);

  // Remove weird ") end" or "end)" combos where a trailing ) follows end or vice versa
  out = out.replace(/\)\s*end\s*\)/g, ")"); // )end) -> )
  out = out.replace(/end\s*\)/g, "end");   // end) -> end

  // Remove stray unmatched ')' on their own lines
  out = out.replace(/^\s*\)\s*$/gm, "");

  // Remove duplicated 'end' sequences like 'endend' or 'end } end' flattening
  out = out.replace(/end\s+end/g, "end");

  // Remove stray leading commas or trailing commas in tables that might confuse parser
  out = out.replace(/,\s*([\]\}])/g, "$1");

  // If there's an isolated 'end,' replace with 'end'
  out = out.replace(/\bend,\b/g, "end");

  return out;
}

// Balance top-level 'end' by removing extra 'end's if there are too many compared to 'function'
function sanitizeBalanceEnds(code) {
  if (!code) return code;
  const s = String(code);
  const functionCount = (s.match(/\bfunction\b/g) || []).length;
  const endCount = (s.match(/\bend\b/g) || []).length;
  if (endCount <= functionCount) return s; // nothing to do
  // remove some trailing 'end' tokens at the end of file first
  let diff = endCount - functionCount;
  let out = s;
  // Try remove `end` occurrences that are alone on a line from the bottom up
  const lines = out.split("\n");
  for (let i = lines.length - 1; i >= 0 && diff > 0; --i) {
    if (/^\s*end\s*$/.test(lines[i])) { lines.splice(i, 1); diff--; }
  }
  return lines.join("\n");
}

// Attempt to wrap orphaned vararg references in a fake function wrapper then strip later.
// This helps when the obfuscator emitted body code without a function header.
function wrapInFunctionIfNeeded(code, argPrefix = DEFAULT_ARG_PREFIX, maxArgs = DEFAULT_MAX_ARGS) {
  const s = String(code);
  // Heuristic: if code contains patterns of ({...})[N] or '...'-based locals but there is no function(...) in the file,
  // then wrap in function(...) end to let parser see varargs.
  const usesVarargIndex = /\(\{\s*\.{3}\s*\}\)\s*\[\s*\d+\s*\]/.test(s);
  const hasFunction = /\bfunction\b/.test(s);
  const hasTopLevelVarargAssign = /local\s+[A-Za-z0-9_,\s]+\s*=\s*\.{3}/.test(s);

  if ((usesVarargIndex || hasTopLevelVarargAssign) && !hasFunction) {
    // create a safe wrapper
    const wrapperStart = `local __wrap = function(${Array.from({ length: maxArgs }, (_, i) => argPrefix + (i + 1)).join(", ")})\n`;
    const wrapperEnd = `\nend\n__wrap()`;
    return { code: wrapperStart + s + wrapperEnd, wrapped: true };
  }
  return { code: s, wrapped: false };
}

// Aggressive repairs: multiple small heuristics (remove byte-order marks, strip trailing illegal tokens, unify quotes)
function sanitizeAggressive(code) {
  if (!code) return code;
  let out = String(code);

  // Remove BOM
  out = out.replace(/^\uFEFF/, "");

  // Replace CRLF with LF
  out = out.replace(/\r\n/g, "\n");

  // Remove invisible zero-width characters
  out = out.replace(/[\u200B-\u200D\uFEFF]/g, "");

  // Remove lines that are obviously not lua (html tags accidentally pasted)
  out = out.replace(/^\s*<[^>]+>\s*$/gm, "");

  // quick bracket/brace cleanup
  out = out.replace(/\{\s*,/g, "{");
  out = out.replace(/,\s*\}/g, "}");

  // attempt to fix "end)" accidental suffixes
  out = out.replace(/\bend\)\s*$/g, "end");

  // combine with basic sanitization
  out = sanitizeBasic(out);
  out = sanitizeBalanceEnds(out);

  return out;
}

// ---------- Parsing attempt wrapper (tolerant with retries) ----------
function tryParse(code, options = {}) {
  // options.tolerant true/false controls luaparse tolerant flag
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

// ---------- AST-driven cleaner (robust & safe) ----------
function cleanWithAST(code, options = {}) {
  const argPrefix = typeof options.argPrefix === "string" ? options.argPrefix : DEFAULT_ARG_PREFIX;
  const maxArgsPerFn = typeof options.maxArgsPerFn === "number" ? options.maxArgsPerFn : DEFAULT_MAX_ARGS;
  const enableRenaming = options.enableRenaming === true;

  // parse tolerant mode (we expect ast)
  let parsed = tryParse(code, { tolerant: true });
  if (!parsed.ok) {
    return { cleaned: code, warnings: ["parse_failed: " + (parsed.error && parsed.error.message)], renameMap: {} };
  }
  const ast = parsed.ast;

  // Collect replacements (start,end,text)
  const replacements = [];
  const funcHeaderMap = new Map();

  // 1) detect functions that are vararg and compute argCounts
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

  // 2) replace IndexExpression occurrences ({...})[N] -> argN when inside detected function
  walkSafe(ast, (node) => {
    if (!node || node.type !== "IndexExpression") return;
    // find smallest enclosing function
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

  // 3) replace local a,b = ... (VarargLiteral)
  walkSafe(ast, (node) => {
    if (!node || node.type !== "LocalStatement" || !Array.isArray(node.init) || node.init.length === 0) return;
    for (let i = 0; i < node.init.length; ++i) {
      const initNode = node.init[i];
      if (!initNode || initNode.type !== "VarargLiteral") continue;
      // find enclosing function
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
    // find enclosing function
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

  // 5) replace function header "(...)" -> "(arg1, arg2, ...)"
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
    } catch (e) { /* ignore per-fn */ }
  }

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
  } catch (e) { /* ignore */ }

  // 7) renaming (conservative)
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
  } catch (e) { /* ignore */ }

  // 8) apply replacements descending
  replacements.sort((a, b) => {
    if (a.start !== b.start) return b.start - a.start;
    return (a.end - a.start) - (b.end - b.start);
  });

  let out = code;
  const appliedRanges = [];
  for (const r of replacements) {
    if (!r || typeof r.start !== "number" || typeof r.end !== "number" || r.start >= r.end) continue;
    if (r.start < 0 || r.end > code.length) continue;
    let overlap = false;
    for (const a of appliedRanges) {
      if (!(r.end <= a.start || r.start >= a.end)) { overlap = true; break; }
    }
    if (overlap) continue;
    out = out.slice(0, r.start) + r.text + out.slice(r.end);
    appliedRanges.push({ start: r.start, end: r.start + (r.text ? r.text.length : 0) });
  }

  out = out.replace(/\t/g, "  ").replace(/[ \t]+$/gm, "");
  const renameObj = {};
  for (const [k, v] of renameMap) renameObj[k] = v;
  return { cleaned: out, warnings: [], renameMap: renameObj };
}

// ---------- Mode orchestration ----------

async function runModeA(code, options = {}) {
  // A: fallback-only: we do not try to fix input; try AST once with tolerant parsing; if fails return regex
  const parsed = tryParse(code, { tolerant: true });
  if (parsed.ok) {
    // run AST cleaner (safe)
    const r = cleanWithAST(code, options);
    // if parser reported warnings, we still accept AST result
    return { cleaned: r.cleaned, mode: "A", warnings: r.warnings || [], renameMap: r.renameMap || {} };
  } else {
    // fallback to regex
    const fallback = regexFallbackClean(code, options);
    return { cleaned: fallback, mode: "A", warnings: ["parse_failed: " + (parsed.error && parsed.error.message)], renameMap: {} };
  }
}

async function runModeB(code, options = {}) {
  // B: strict AST: only run AST if code parses cleanly in strict (non-tolerant) mode
  const parsedStrict = tryParse(code, { tolerant: false });
  if (parsedStrict.ok) {
    const r = cleanWithAST(code, options);
    return { cleaned: r.cleaned, mode: "B", warnings: r.warnings || [], renameMap: r.renameMap || {} };
  } else {
    // do not attempt any auto-repair: return parse error and fallback-only response
    return { cleaned: regexFallbackClean(code, options), mode: "B", warnings: ["strict_parse_failed: " + (parsedStrict.error && parsedStrict.error.message)], renameMap: {} };
  }
}

async function runModeC(code, options = {}) {
  // C: maximum repair mode: iterative sanitize + wrap + parse attempts
  let attempt = 0;
  let current = String(code);
  const tried = [];
  const warnings = [];

  // Attempt loop: try original, then basic sanitize, then balance ends, then aggressive sanitize + wrapper
  while (attempt < MAX_PARSE_ATTEMPTS) {
    attempt++;
    const modeLabel = ["original", "basic", "balanced", "aggressive-wrapper"][Math.min(attempt - 1, 3)];
    tried.push(modeLabel);

    const parsed = tryParse(current, { tolerant: attempt === 1 ? true : true }); // always tolerant but repair varies
    if (parsed.ok) {
      // success -> run AST cleaning on current code
      try {
        const r = cleanWithAST(current, options);
        const metaWarnings = [];
        if (attempt > 1) metaWarnings.push(`repaired_via:${modeLabel}`);
        return { cleaned: r.cleaned, mode: "C", warnings: metaWarnings, renameMap: r.renameMap || {} };
      } catch (e) {
        warnings.push("ast_transform_error:" + (e && e.message));
        break;
      }
    } else {
      // capture parse error
      const em = parsed.error && parsed.error.message ? parsed.error.message : String(parsed.error);
      warnings.push(`parse_failed_attempt_${attempt}:${em}`);
    }

    // prepare next attempt transform
    if (attempt === 1) {
      // basic sanitize
      current = sanitizeBasic(current);
    } else if (attempt === 2) {
      current = sanitizeBalanceEnds(current);
    } else if (attempt >= 3) {
      // aggressive: sanitize + try wrapper
      current = sanitizeAggressive(current);
      const wrap = wrapInFunctionIfNeeded(current, options.argPrefix, options.maxArgsPerFn);
      if (wrap.wrapped) current = wrap.code;
    }
  }

  // if we get here, all attempts failed -> fallback regex
  const fallback = regexFallbackClean(code, options);
  return { cleaned: fallback, mode: "C", warnings: warnings.length ? warnings : ["all_parse_attempts_failed"], renameMap: {} };
}

// ---------- Endpoints ----------

// POST /clean_ast
// body: { code: string, options: { argPrefix, maxArgsPerFn, enableRenaming, mode: 'A'|'B'|'C' } }
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
    else result = await runModeC(code, runOpts); // default C

    // Attach meta
    const response = {
      success: true,
      cleaned: result.cleaned,
      mode: result.mode,
      warnings: result.warnings || [],
      renameMap: result.renameMap || {}
    };
    res.json(response);
  } catch (err) {
    console.error("clean_ast error:", err && err.stack || err);
    res.status(500).json({ success: false, error: "internal_error", detail: String(err && err.message) });
  }
});

// POST /clean (hybrid) -> tries AST (default C) then regex fallback
app.post("/clean", async (req, res) => {
  try {
    const code = typeof req.body.code === "string" ? req.body.code : (req.body && req.body.code ? String(req.body.code) : "");
    const opts = req.body.options || {};
    if (!code) return res.status(400).json({ success: false, error: "no_code_provided" });

    // try mode C first (best effort)
    const runOpts = {
      argPrefix: typeof opts.argPrefix === "string" ? opts.argPrefix : DEFAULT_ARG_PREFIX,
      maxArgsPerFn: typeof opts.maxArgsPerFn === "number" ? opts.maxArgsPerFn : DEFAULT_MAX_ARGS,
      enableRenaming: opts.enableRenaming === true
    };

    const astResult = await runModeC(code, runOpts);
    // if astResult warnings indicate complete failure, produce regex fallback (already done inside runModeC)
    res.json({
      success: true,
      cleaned: astResult.cleaned,
      mode: astResult.mode,
      warnings: astResult.warnings || []
    });
  } catch (err) {
    console.error("clean error:", err && err.stack || err);
    res.status(500).json({ success: false, error: "internal_error", detail: String(err && err.message) });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

// Serve public/ast.html by default
app.get("/", (req, res) => {
  const file = path.join(__dirname, "public", "ast.html");
  res.sendFile(file, function (err) {
    if (err) res.status(err.status || 500).send("ast.html not found");
  });
});

// Start server on internal port
app.listen(INTERNAL_PORT, () => {
  console.log(`Advanced AST Cleaner (A/B/C) running on internal port ${INTERNAL_PORT}`);
});
