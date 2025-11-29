const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');
require('dotenv').config();
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000; 

// --- CRITICAL: INCREASED PAYLOAD LIMIT TO 100MB ---
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
// --------------------------------------------------

// --- Database Connection Pool ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Test connection and initialize table
pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Successfully connected to PostgreSQL.');
    
    // Creates the 'scripts' table if it doesn't exist
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS scripts (
            key VARCHAR(32) PRIMARY KEY,
            script TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;
    client.query(createTableQuery, (err, res) => {
        done();
        if (err) {
            console.error('Error creating table:', err.stack);
        } else {
            console.log('Database table "scripts" initialized.');
        }
    });
});

// Define the watermark constant
const WATERMARK = "--[[ v0.1.0 NovaHub Lua Obfuscator ]] "; 
const FALLBACK_WATERMARK = "--[[ OBFUSCATION FAILED: Returning raw script. Check your Lua syntax. ]] ";

// Middleware for static files and CORS
app.use(express.static('public')); 
app.use(cors());

// --- Helper Functions ---
const generateUniqueId = () => {
    return crypto.randomBytes(16).toString('hex');
};

// --- Fallback Obfuscation Function ---
// Wraps the raw code in a message block so the service doesn't outright fail.
const applyFallback = (rawCode) => {
    return `${FALLBACK_WATERMARK}\n${rawCode}`;
};


// =======================================================
// === 1. OBFUSCATE ROUTE (Returns Raw Code) ===========
// =======================================================
app.post('/obfuscate', async (req, res) => {
    const rawLuaCode = req.body.code;
    const preset = 'Medium';
    const timestamp = Date.now();
    
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);
    
    let obfuscatedCode = '';
    let obfuscationSucceeded = false;

    // Step 1: Execute Obfuscator
    try {
        fs.writeFileSync(tempFile, rawLuaCode, 'utf8');

        const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;
        
        await new Promise((resolve) => { // No need to reject here, we handle failure internally
            exec(command, (error, stdout, stderr) => {
                // Clean up the temporary input file immediately
                fs.unlinkSync(tempFile); 
                
                if (error || stderr) {
                    console.error(`Prometheus Execution Failed: ${error ? error.message : stderr}`);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    
                    // --- FALLBACK LOGIC ---
                    obfuscatedCode = applyFallback(rawLuaCode);
                    obfuscationSucceeded = false;
                    resolve();
                    return;
                }
                
                // Success path
                obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
                obfuscatedCode = WATERMARK + obfuscatedCode;
                fs.unlinkSync(outputFile);
                obfuscationSucceeded = true;
                resolve();
            });
        });
        
    } catch (error) {
        // Handle errors during execution or file read (e.g. filesystem issues)
        console.error('Filesystem or Internal Execution Error:', error);
        
        // --- SECONDARY FALLBACK (for catastrophic errors) ---
        obfuscatedCode = applyFallback(rawLuaCode);
        obfuscationSucceeded = false;
    }

    // Step 2: Return Result
    if (!obfuscationSucceeded) {
        // Log that a fallback was used
        console.warn("Obfuscation failed, returning raw code with a warning.");
    }
    
    res.status(200).json({ 
        obfuscatedCode: obfuscatedCode
    });
});


// =======================================================
// === 2. OBFUSCATE-AND-STORE ROUTE (Returns Loader Key) ===
// =======================================================
app.post('/obfuscate-and-store', async (req, res) => {
    const rawLuaCode = req.body.script;
    const preset = 'Medium'; 
    const timestamp = Date.now();
    
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);
    
    let obfuscatedCode = '';
    let obfuscationSucceeded = false;

    // Step 1: Execute Obfuscator
    try {
        fs.writeFileSync(tempFile, rawLuaCode, 'utf8');

        const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;
        
        await new Promise((resolve) => { // No need to reject here, we handle failure internally
            exec(command, (error, stdout, stderr) => {
                fs.unlinkSync(tempFile); 
                
                if (error || stderr) {
                    console.error(`Prometheus Execution Failed: ${error ? error.message : stderr}`);
                    if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                    
                    // --- FALLBACK LOGIC ---
                    obfuscatedCode = applyFallback(rawLuaCode);
                    obfuscationSucceeded = false;
                    resolve();
                    return;
                }
                
                // Success path
                obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
                obfuscatedCode = WATERMARK + obfuscatedCode;
                fs.unlinkSync(outputFile);
                obfuscationSucceeded = true;
                resolve();
            });
        });
        
    } catch (error) {
        console.error('Filesystem or Internal Execution Error:', error);
        
        // --- SECONDARY FALLBACK (for catastrophic errors) ---
        obfuscatedCode = applyFallback(rawLuaCode);
        obfuscationSucceeded = false;
    }

    // Step 2: Store Code to PostgreSQL
    const scriptKey = generateUniqueId();
    
    try {
        await pool.query(
            'INSERT INTO scripts(key, script) VALUES($1, $2)',
            [scriptKey, obfuscatedCode] // Store the code (either obfuscated or fallback)
        );

        // Success: Return the key to the frontend
        if (!obfuscationSucceeded) {
            console.warn("Obfuscation failed, but the raw code with a warning was stored and a key returned.");
        }
        
        res.status(201).json({ 
            message: obfuscationSucceeded ? 'Obfuscation and storage complete.' : 'Storage complete, but obfuscation failed. Check script for warning.',
            key: scriptKey
        });

    } catch (error) {
        console.error('Database error during storage:', error);
        res.status(500).json({ error: 'Internal server error during script storage.' });
    }
});


// ====================================================
// === 3. STORAGE API ENDPOINTS (PostgreSQL Retrieval)===
// ====================================================

// GET /retrieve/:key (Retrieves the Lua script - Roblox only)
app.get('/retrieve/:key', async (req, res) => {
    const scriptKey = req.params.key;
    const userAgent = req.headers['user-agent'];

    // 1. Validate User-Agent (ROBLOX SECURITY CHECK)
    if (!userAgent || !userAgent.includes('Roblox')) {
        res.setHeader('Content-Type', 'text/plain');
        return res.status(403).send('-- Access Denied.');
    }

    try {
        const result = await pool.query(
            'SELECT script FROM scripts WHERE key = $1', 
            [scriptKey]
        );

        if (result.rows.length === 0) {
            res.setHeader('Content-Type', 'text/plain');
            return res.status(404).send('-- Error: Script not found or has expired.');
        }

        const script = result.rows[0].script;

        // 2. Deliver the stored script
        res.setHeader('Content-Type', 'text/plain');
        res.status(200).send(script);
        
    } catch (error) {
        console.error('Database error during retrieval:', error);
        res.setHeader('Content-Type', 'text/plain');
        res.status(500).send('-- Error: Internal Server Failure.');
    }
});


// Basic Health Check
app.get('/', (req, res) => {
    res.send('NovaHub Unified Backend is running and connected to PostgreSQL.');
});


// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
