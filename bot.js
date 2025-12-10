/**
 * MoonSec Opcode Logger Bot (LuaJIT Version for Render)
 *
 * Deploy:
 *   npm init -y
 *   npm install discord.js@14 node-fetch
 *   node bot.js
 *
 * Env Vars Needed:
 *   DISCORD_TOKEN=YOUR_TOKEN
 */

const { Client, GatewayIntentBits } = require("discord.js");
const fs = require("fs/promises");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const fetch = require("node-fetch");

const TOKEN = process.env.DISCORD_TOKEN;
if (!TOKEN) {
  console.error("Missing DISCORD_TOKEN env var");
  process.exit(1);
}

const MAX_FILE_BYTES = 200 * 1024;
const MAX_OUTPUT_CHARS = 30_000;
const LUA_TIMEOUT_MS = 15_000;

// ============================================================
// ✅ FINAL LUA SCRIPT (DECOMPILER + print(n) INJECTOR)
// ============================================================

const LUA_DECOMPILER = `
-- MoonSec V3 Adaptive Observer + Opcode Printer
local MAX_STEPS = 100000
local debug_getlocal = debug.getlocal
local debug_getupvalue = debug.getupvalue
local debug_getinfo = debug.getinfo
local table_concat = table.concat

local function tostring_safe(v)
    if type(v) == "string" then
        return ("%q"):format(v)
    elseif type(v) == "number" or type(v) == "boolean" or type(v) == "nil" then
        return tostring(v)
    elseif type(v) == "table" then
        return "<table@"..tostring(v)..">"
    elseif type(v) == "function" then
        return "<function@"..tostring(v)..">"
    else
        return "<"..type(v)..">"
    end
end

local function snapshot_locals_list(level)
    local out = {}
    local i = 1
    while true do
        local name, value = debug_getlocal(level + 1, i)
        if not name then break end
        out[i] = {name = name, value = value}
        i = i + 1
    end
    return out
end

local function find_changed_between(before, after)
    for k, v in pairs(after) do
        if before[k] ~= v then
            return k, v
        end
    end
end

local function make_instruction_observer()
    local insts = {}
    local function record(idx, varname, val)
        insts[#insts + 1] = { index = idx, var = varname, value = val }
    end
    local function all() return insts end
    return { record = record, all = all }
end

local function reconstruct_from_observed(insts)
    local stmts = {}
    for _, op in ipairs(insts) do
        stmts[#stmts + 1] = string.format("%s = %s", op.var, tostring_safe(op.value))
    end
    return stmts
end

local function attach_decompiler_to_vm(vm_function)
    local observer = make_instruction_observer()
    local stepcount = 0

    while stepcount < MAX_STEPS do
        stepcount = stepcount + 1
        local before = snapshot_locals_list(2)
        local ok, res = pcall(vm_function)
        local after = snapshot_locals_list(2)

        local before_map = {}
        for _, v in ipairs(before) do before_map[v.name] = v.value end

        local after_map = {}
        for _, v in ipairs(after) do after_map[v.name] = v.value end

        local varname, val = find_changed_between(before_map, after_map)
        if varname then observer.record(stepcount, varname, val) end

        if not ok or type(res) == "table" then break end
    end

    local observed = observer.all()
    local stmts = reconstruct_from_observed(observed)

    print("-- RECONSTRUCTED OUTPUT --")
    for _, s in ipairs(stmts) do print(s) end
    print("-- END OUTPUT --")
end

-- ✅ Detector + print(n) injector
local function is_moonsec_constructor_string(code)
    if type(code) ~= "string" then return false, nil end

    local detected = false

    if code:find("#'", 1, true) or code:find("#", 1, true) then
        detected = true
    end

    local var, value = code:match("([%a_][%w_]*)%s*%[%s*t%s*%]%s*=%s*([%a_][%w_]*|%d+)")

    if var and value then
        detected = true
        local injected = ("print(%s)\\n%s[t] = %s"):format(value, var, value)
        code = code:gsub(
            var .. "%s*%[%s*t%s*%]%s*=%s*" .. value,
            injected,
            1
        )
    end

    return detected, code
end

local _G_env = rawget(_G, "env") or _G
local orig_load = _G_env.loadstring or loadstring

local function wrapped_loadstring(code, chunkname, mode, envtable)
    if type(code) ~= "string" then
        return orig_load(code, chunkname, mode, envtable)
    end

    local is_ms, new_code = is_moonsec_constructor_string(code)
    if new_code then code = new_code end

    local loaded_fn = orig_load(code, chunkname, mode, envtable)
    if not is_ms then return loaded_fn end

    local ok, res = pcall(loaded_fn)
    if ok and type(res) == "function" then
        attach_decompiler_to_vm(res)
    end

    return loaded_fn
end

_G_env.loadstring = wrapped_loadstring
if rawget(_G, "loadstring") then _G.loadstring = wrapped_loadstring end

print("[LuaJIT Decompiler] active")
`;

// ============================================================
// ✅ DISCORD BOT SETUP
// ============================================================

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});

function extractLuaBlock(text) {
  const m = text.match(/```(?:lua)?\n([\s\S]*?)```/i);
  return m ? m[1] : null;
}

async function runLuaJIT(payload) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "luajit-"));
  const decPath = path.join(dir, "decomp.lua");
  const payloadPath = path.join(dir, "payload.lua");

  await fs.writeFile(decPath, LUA_DECOMPILER);
  await fs.writeFile(payloadPath, payload);

  const command = `dofile("${decPath.replace(/\\/g, "\\\\")}"); dofile("${payloadPath.replace(/\\/g, "\\\\")}")`;

  return new Promise((resolve) => {
    const proc = spawn("luajit", ["-e", command], {
      cwd: dir,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";

    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      resolve({ out: "Timed out", err: "" });
    }, LUA_TIMEOUT_MS);

    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));

    proc.on("close", () => {
      clearTimeout(timer);
      resolve({ out, err });
    });
  });
}

client.on("messageCreate", async (msg) => {
  if (msg.author.bot) return;
  if (!msg.content.startsWith("!decomp")) return;

  let luaText = null;

  if (msg.attachments.size) {
    const file = msg.attachments.first();
    if (file.size > MAX_FILE_BYTES) {
      msg.reply("File too large.");
      return;
    }

    // Accept only .txt files
    if (!file.name.endsWith(".txt")) {
      msg.reply("Please attach a `.txt` file.");
      return;
    }

    const res = await fetch.default(file.url);
    luaText = Buffer.from(await res.arrayBuffer()).toString();
  } else {
    luaText = extractLuaBlock(msg.content);
  }

  if (!luaText) {
    msg.reply("Attach a `.txt` file or paste code in ```lua``` format.");
    return;
  }

  msg.channel.sendTyping();

  const result = await runLuaJIT(luaText);
  let output = result.out.slice(0, MAX_OUTPUT_CHARS);
  if (!output.trim()) output = "No output.";

  if (output.length > 1800) {
    const tmp = path.join(os.tmpdir(), "result.txt");
    await fs.writeFile(tmp, output);
    await msg.reply({ content: "Output attached:", files: [tmp] });
  } else {
    await msg.reply("```lua\n" + output + "\n```");
  }
});

client.login(TOKEN);
