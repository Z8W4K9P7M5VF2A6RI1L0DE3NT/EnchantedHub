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

// --- CONFIGURATION ---
const MAX_LAYERS = 3; // Updated from 20 to 25
// ---------------------

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

// Middleware for static files and CORS
app.use(express.static('public')); 
app.use(cors());

// --- Helper Functions ---
const generateUniqueId = () => {
    return crypto.randomBytes(16).toString('hex');
};

const runObfuscationStep = (rawLuaCode, preset, timestamp) => {
    const tempFile = path.join(__dirname, `temp_${timestamp}.lua`);
    const outputFile = path.join(__dirname, `obf_${timestamp}.lua`);
    
    fs.writeFileSync(tempFile, rawLuaCode, 'utf8');
    const command = `lua src/cli.lua --preset ${preset} --out ${outputFile} ${tempFile}`;

    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            fs.unlinkSync(tempFile); 
            
            if (error || stderr) {
                if (fs.existsSync(outputFile)) fs.unlinkSync(outputFile);
                return reject({ error: 'Obfuscation execution error.', details: stderr || error.message });
            }
            
            try {
                let obfuscatedCode = fs.readFileSync(outputFile, 'utf8');
                obfuscatedCode = WATERMARK + obfuscatedCode;
                fs.unlinkSync(outputFile);
                resolve(obfuscatedCode);
            } catch (readError) {
                reject({ error: 'Failed to read obfuscated output.', details: readError.message });
            }
        });
    });
};


// =======================================================
// === 1. /OBFUSCATE ROUTE (Returns Raw Code) ===========
// =======================================================
app.post('/obfuscate', async (req, res) => {
    const rawLuaCode = req.body.code;
    const preset = 'Medium';
    const timestamp = Date.now();
    
    try {
        // Runs Prometheus once
        const obfuscatedCode = await runObfuscationStep(rawLuaCode, preset, timestamp);
        
        // Return Raw Obfuscated Code (NO STORAGE)
        res.status(200).json({ 
            obfuscatedCode: obfuscatedCode
        });
    } catch (error) {
        if (typeof error === 'object' && error.error) {
            return res.status(500).json(error);
        }
        return res.status(500).json({ error: 'Internal execution error.', details: error.message });
    }
});


// =======================================================
// === 2. /OBFUSCATE-AND-STORE ROUTE (NESTED CHAIN) ===
// =======================================================
// Used by the API Locker to get the secure key.
app.post('/obfuscate-and-store', async (req, res) => {
    const rawLuaCode = req.body.script; 
    const preset = 'Medium';
    
    if (!rawLuaCode || rawLuaCode.trim() === '') {
        return res.status(400).json({ error: 'Input script cannot be empty.' });
    }

    let currentPayload = rawLuaCode;
    let finalLoaderScript = '';

    try {
        // Loop MAX_LAYERS times (set to 25) to create the nested chain
        for (let i = 1; i <= MAX_LAYERS; i++) {
            const timestamp = Date.now() + i; 
            
            // Step 1: Obfuscate the CURRENT payload
            const obfuscatedPayload = await runObfuscationStep(currentPayload, preset, timestamp);

            // Step 2: Store the Obfuscated Payload
            const scriptKey = generateUniqueId();
            
            await pool.query(
                'INSERT INTO scripts(key, script) VALUES($1, $2)',
                [scriptKey, obfuscatedPayload]
            );

            // Step 3: Prepare the Loader Script for the NEXT iteration
            const retrievalURL = `/retrieve/${scriptKey}`;
            const loaderScript = `loadstring(game:HttpGet('${retrievalURL}'))()`;

            // The input for the next loop iteration is the loader script
            currentPayload = loaderScript;

            // The very last loader generated (i=MAX_LAYERS) is the one we return to the user.
            if (i === MAX_LAYERS) {
                 finalLoaderScript = loaderScript;
            }
        }
        
        // Success: Return the final loadstring to the frontend.
        res.status(201).json({ 
            message: `Obfuscation complete: ${MAX_LAYERS} layers stored.`,
            key: finalLoaderScript.match(/\/retrieve\/([a-f0-9]+)/)[1], 
            loader: finalLoaderScript 
        });

    } catch (error) {
        console.error('Unified Workflow Error:', error);
        if (typeof error === 'object' && error.error) {
             return res.status(500).json(error);
        }
        return res.status(500).json({ error: 'Critical server error during multi-step processing.', details: error.message });
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

        // 2. Deliver the stored script (which is the next loader or the final code)
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
