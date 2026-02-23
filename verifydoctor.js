require('dotenv').config();
const mysql = require('mysql2');
const crypto = require('crypto');

// --- Helper function from server.js ---
function createBlindIndex(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// --- Main Verification Logic ---
async function verifyDoctor() {
    // Get the email from the command line arguments
    const emailToVerify = process.argv[2];
    if (!emailToVerify) {
        console.error('❌ Please provide an email address to verify.');
        console.log('Usage: node verify-doctor.js doctor-email@example.com');
        return;
    }

    console.log(`Attempting to verify doctor with email: ${emailToVerify}`);

    const pool = mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME
    }).promise();

    const hmacSecret = process.env.HMAC_SECRET;
    if (!hmacSecret) {
        console.error('❌ HMAC_SECRET not found in .env file.');
        pool.end();
        return;
    }

    try {
        const emailIndex = createBlindIndex(emailToVerify, hmacSecret);

        // 1. Find the user in the 'users' table
        const [users] = await pool.query('SELECT id FROM users WHERE email_index = ? AND role = "doctor"', [emailIndex]);

        if (users.length === 0) {
            console.error(`❌ No doctor found with the email: ${emailToVerify}`);
            return;
        }
        const userId = users[0].id;

        // 2. Update the 'is_verified' flag in the 'doctors' table
        const [result] = await pool.query('UPDATE doctors SET is_verified = 1 WHERE user_id = ?', [userId]);

        if (result.affectedRows > 0) {
            console.log(`✅ Successfully verified doctor: ${emailToVerify}`);
        } else {
            console.error('Could not find a matching record in the doctors table to update.');
        }

    } catch (err) {
        console.error('An error occurred:', err);
    } finally {
        await pool.end(); // Close the connection
    }
}

verifyDoctor();