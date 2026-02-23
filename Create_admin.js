require('dotenv').config();
const mysql = require('mysql2');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Uses the same library as your server

// --- ADMIN CONFIGURATION ---
const ADMIN_EMAIL = 'admin@ehr.com';
const ADMIN_PASSWORD = 'admin123';
const ADMIN_NAME = 'Super Admin';

// --- DATABASE CONNECTION ---
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME
}).promise();

// --- SECURITY HELPERS (Must match server.js exactly) ---
const hmacSecret = process.env.HMAC_SECRET;

if (!hmacSecret) {
    console.error("❌ Error: HMAC_SECRET is missing in your .env file.");
    process.exit(1);
}

function createBlindIndex(data) {
    return crypto.createHmac('sha256', hmacSecret)
                 .update(String(data).toLowerCase().trim())
                 .digest('hex');
}

// --- MAIN LOGIC ---
async function createAdmin() {
    try {
        console.log(`🔐 Creating Admin Account for: ${ADMIN_EMAIL}...`);

        // 1. Encrypt Data
        const emailIndex = createBlindIndex(ADMIN_EMAIL);
        const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);

        // 2. Check if Admin already exists
        const [existing] = await pool.query('SELECT id FROM users WHERE email_index = ?', [emailIndex]);
        if (existing.length > 0) {
            console.log("⚠️  Admin account already exists. You can login now.");
            process.exit();
        }

        // 3. Insert into 'users' table
        const [userResult] = await pool.query(
            'INSERT INTO users (email_index, password, role) VALUES (?, ?, ?)', 
            [emailIndex, hashedPassword, 'admin']
        );

        // 4. Insert into 'admins' table
        await pool.query(
            'INSERT INTO admins (user_id, name) VALUES (?, ?)', 
            [userResult.insertId, ADMIN_NAME]
        );

        console.log(`
        ✅ SUCCESS! Admin created successfully.
        ---------------------------------------
        Login URL: http://localhost:3000/adminlogin.html
        Email:     ${ADMIN_EMAIL}
        Password:  ${ADMIN_PASSWORD}
        ---------------------------------------
        `);

    } catch (err) {
        console.error("❌ Database Error:", err.message);
    } finally {
        pool.end();
    }
}

createAdmin();