require('dotenv').config();
const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

// ==========================================
// 1. APP CONFIGURATION & SECURITY
// ==========================================
const app = express();
const PORT = process.env.PORT || 3000;

// Security Headers (Helmet)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
            "img-src": ["'self'", "data:", "images.unsplash.com", "helloindia.co", "via.placeholder.com", "ui-avatars.com"],
        },
    },
    // Add this line below to allow cross-origin requests for UI-avatars/CDNs
    crossOriginEmbedderPolicy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    frameguard: { action: 'deny' }
}));

// Rate Limiting (Prevent Brute Force)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// Body Parsing & Static Files
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 2. DATABASE & ENVIRONMENT SETUP
// ==========================================

// Check required .env variables
function assertCryptoEnv() {
    if (!process.env.ENCRYPTION_KEY || Buffer.from(process.env.ENCRYPTION_KEY, 'utf8').length !== 32) {
        throw new Error('ENCRYPTION_KEY must be set in .env and be exactly 32 bytes.');
    }
    if (!process.env.HMAC_SECRET || Buffer.from(process.env.HMAC_SECRET, 'utf8').length < 32) {
        throw new Error('HMAC_SECRET must be set in .env and be at least 32 bytes.');
    }
    if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET must be set in .env for secure authentication.');
    }
}
assertCryptoEnv();

const key = Buffer.from(process.env.ENCRYPTION_KEY, 'utf8');
const hmacSecret = process.env.HMAC_SECRET;
const JWT_SECRET = process.env.JWT_SECRET;

// MySQL Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();

pool.getConnection().then(conn => {
    console.log('✅ Database connected successfully!');
    conn.release();
}).catch(err => {
    console.error('❌ DATABASE CONNECTION FAILED:', err.message);
    process.exit(1);
});

// ==========================================
// 3. HELPER FUNCTIONS (CRYPTO & UTILS)
// ==========================================

// Create Blind Index (for searching encrypted data like emails)
function createBlindIndex(data) {
    if (!data) return null;
    return crypto.createHmac('sha256', hmacSecret).update(String(data).toLowerCase().trim()).digest('hex');
}

// Encrypt Text (AES-256-GCM)
function encrypt(text) {
    if (text === null || text === undefined) return null;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ct]).toString('base64');
}

// Decrypt Text
function decrypt(encryptedText) {
    if (encryptedText === null || encryptedText === undefined) return null;
    try {
        const buff = Buffer.from(encryptedText, 'base64');
        const iv = buff.slice(0, 12);
        const tag = buff.slice(12, 28);
        const ct = buff.slice(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (err) {
        console.error("Decryption failed:", err.message);
        return null;
    }
}

// Helper: Get Doctor ID from User ID
async function getDoctorIdByUserId(userId) {
    const [doctors] = await pool.query('SELECT id FROM doctors WHERE user_id = ? AND is_verified = true', [userId]);
    return doctors.length > 0 ? doctors[0].id : null;
}

// Helper: Get Patient ID from User ID
async function getPatientIdByUserId(userId) {
    const [patients] = await pool.query('SELECT id FROM patients WHERE user_id = ?', [userId]);
    return patients.length > 0 ? patients[0].id : null;
}

// ==========================================
// 4. MIDDLEWARE
// ==========================================

// Middleware: Authenticate JWT Token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ success: false, message: 'Authentication token is required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("JWT verification failed:", err);
            return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
};

// Middleware: Require Admin Role
const requireAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ success: false, message: "Access denied. Admins only." });
    }
};

// ==========================================
// 5. AUTHENTICATION ROUTES
// ==========================================

// Shared Login Logic for Doctor, Patient, Admin
async function loginUser(req, res, expectedRole) {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required.' });

    const emailIndex = createBlindIndex(email);
    const [users] = await pool.query('SELECT id, password, role FROM users WHERE email_index = ?', [emailIndex]);

    if (users.length === 0 || users[0].role !== expectedRole) {
        return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }
    const user = users[0];

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    let name = 'User';

    if (expectedRole === 'doctor') {
        const [docs] = await pool.query('SELECT name, is_verified FROM doctors WHERE user_id = ?', [user.id]);
        if (docs.length === 0 || !docs[0].is_verified) return res.status(403).json({ success: false, message: 'Account not verified.' });
        name = docs[0].name;
    } else if (expectedRole === 'patient') {
        const [pats] = await pool.query('SELECT name FROM patients WHERE user_id = ?', [user.id]);
        if (pats.length > 0) name = pats[0].name;
    } else if (expectedRole === 'admin') {
        const [admins] = await pool.query('SELECT name FROM admins WHERE user_id = ?', [user.id]);
        if (admins.length > 0) name = admins[0].name;
    }

    res.json({ success: true, message: 'Login successful', token, name });
}

// [POST] /api/*/login - Login Endpoints
app.post('/api/doctor/login', (req, res) => loginUser(req, res, 'doctor'));
app.post('/api/patient/login', (req, res) => loginUser(req, res, 'patient'));
app.post('/api/admin/login', (req, res) => loginUser(req, res, 'admin'));

// [POST] /api/doctor/signup - Register a new Doctor with extended profile
app.post('/api/doctor/signup', async (req, res) => {
    // 1. Destructure the new fields from req.body
    const {
        name, email, password, specialization, license,
        experience, aadhar, clinicAddress, fee, phone
    } = req.body;

    // 2. Updated Validation Logic
    if (!name || !email || !password || password.length < 8 || !specialization ||
        !license || !experience || !aadhar || !clinicAddress || !fee || !phone) {
        return res.status(400).json({ success: false, message: "All professional and identity fields are required." });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        // 3. Security: Hash and Index sensitive identifiers
        const emailIndex = createBlindIndex(email);
        const licenseIndex = createBlindIndex(license);
        const aadharIndex = createBlindIndex(aadhar); // New Index for fast identity lookup
        const hashedPassword = await bcrypt.hash(password, 10);

        // Encrypt PII (Personally Identifiable Information)
        const encryptedLicense = encrypt(license);
        const encryptedAadhar = encrypt(aadhar);
        const encryptedPhone = encrypt(phone);

        // 4. Check if Doctor already exists (via Email or Aadhar)
        const [existingUser] = await connection.query(
            'SELECT id FROM users WHERE email_index = ?', [emailIndex]
        );
        if (existingUser.length > 0) {
            await connection.rollback();
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        }

        // 5. Insert into 'users' table (Auth table)
        const [userResult] = await connection.query(
            'INSERT INTO users (email_index, password, role) VALUES (?, ?, ?)',
            [emailIndex, hashedPassword, 'doctor']
        );

        // 6. Insert into 'doctors' table (Profile table)
        // Ensure your database schema has columns for: experience, aadhar_number, aadhar_index, clinic_address, consultation_fee, phone_encrypted
        const doctorSql = `
            INSERT INTO doctors
            (user_id, name, specialization, license_number, license_index,
             experience_years, aadhar_number, aadhar_index, clinic_address,
             consultation_fee, contact_phone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        const doctorValues = [
            userResult.insertId,
            name,
            specialization,
            encryptedLicense,
            licenseIndex,
            experience,
            encryptedAadhar,
            aadharIndex,
            clinicAddress,
            fee,
            encryptedPhone
        ];

        await connection.query(doctorSql, doctorValues);

        await connection.commit();
        res.status(201).json({
            success: true,
            message: 'Doctor profile created. Please upload verification documents in the dashboard.'
        });

    } catch (err) {
        await connection.rollback();
        console.error("Doctor signup failed:", err);
        res.status(500).json({ success: false, message: 'Database error. Profile could not be created.' });
    } finally {
        connection.release();
    }
});

// [POST] /api/patient/signup - Register a new Patient
app.post('/api/patient/signup', async (req, res) => {
    const { name, email, password, contact } = req.body;
    if (!name || !email || !password || password.length < 8) return res.status(400).json({ success: false, message: "Invalid input." });

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const hashedPassword = await bcrypt.hash(password, 10);
        const emailIndex = createBlindIndex(email);
        const encryptedContact = encrypt(contact);

        const [existingUser] = await connection.query('SELECT id FROM users WHERE email_index = ?', [emailIndex]);
        if (existingUser.length > 0) { await connection.rollback(); return res.status(409).json({ success: false, message: 'Email already registered.' }); }

        const [userResult] = await connection.query('INSERT INTO users (email_index, password, role) VALUES (?, ?, ?)', [emailIndex, hashedPassword, 'patient']);
        await connection.query('INSERT INTO patients (user_id, name, contact_phone) VALUES (?, ?, ?)', [userResult.insertId, name, encryptedContact]);

        await connection.commit();
        res.status(201).json({ success: true, message: 'Patient registered successfully.' });
    } catch (err) {
        await connection.rollback();
        console.error("Patient signup failed:", err);
        res.status(500).json({ success: false, message: 'Database error.' });
    } finally { connection.release(); }
});

// ==========================================
// 6. DOCTOR ROUTES
// ==========================================

app.get('/api/doctor/patients-categorized', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: "Unauthorized" });

    try {
        const doctorId = await getDoctorIdByUserId(req.user.id);

        // 1. Admitted Patients (Active, not discharged)
        const [admitted] = await pool.query(
            `SELECT p.id, p.name, p.age, p.gender, p.medical_history_summary, p.contact_phone
             FROM patients p
             JOIN appointments a ON p.id = a.patient_id
             WHERE a.doctor_id = ? AND p.is_discharged = 0
             GROUP BY p.id
             ORDER BY p.name`,
            [doctorId]
        );

        // 2. Appointment Patients (All patients who have ever booked, distinct)
        const [appointmentPatients] = await pool.query(
            `SELECT DISTINCT p.id, p.name, p.contact_phone, MAX(a.appointment_date) as last_visit
             FROM patients p
             JOIN appointments a ON p.id = a.patient_id
             WHERE a.doctor_id = ?
             GROUP BY p.id
             ORDER BY last_visit DESC`,
            [doctorId]
        );

        // Decrypt phones for display
        const decryptedAdmitted = admitted.map(p => ({ ...p, contact_phone: decrypt(p.contact_phone) }));
        const decryptedAppt = appointmentPatients.map(p => ({ ...p, contact_phone: decrypt(p.contact_phone) }));

        res.json({
            success: true,
            admitted: decryptedAdmitted,
            appointmentPatients: decryptedAppt
        });

    } catch (err) {
        console.error("Categorized patients error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});


// [GET] /api/doctor/dashboard-stats - Get counters for the dashboard
app.get('/api/doctor/dashboard-stats', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: "Unauthorized" });
    try {
        const doctorId = await getDoctorIdByUserId(req.user.id);
        const [patientRows] = await pool.query('SELECT COUNT(DISTINCT patient_id) as patientCount FROM appointments WHERE doctor_id = ?', [doctorId]);
        const [appointmentRows] = await pool.query('SELECT COUNT(id) as appointmentCount FROM appointments WHERE doctor_id = ? AND DATE(appointment_date) = CURDATE()', [doctorId]);
        const [reportRows] = await pool.query('SELECT COUNT(id) as reportCount FROM reports WHERE doctor_id = ?', [doctorId]);
        res.json({ success: true, totalPatients: patientRows[0].patientCount, todaysAppointments: appointmentRows[0].appointmentCount, pendingReports: reportRows[0].reportCount });
    } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

// [GET] /api/doctor/appointments - Get appointments for calendar
app.get('/api/doctor/appointments', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: "Unauthorized" });
    try {
        const doctorId = await getDoctorIdByUserId(req.user.id);
        const [rows] = await pool.query(
            `SELECT a.id, p.name as title, a.appointment_date as start, a.notes, a.status
             FROM appointments a JOIN patients p ON a.patient_id = p.id WHERE a.doctor_id = ?`, [doctorId]
        );
        res.json(rows);
    } catch (err) { res.status(500).json([]); }
});

// [PUT] /api/doctor/appointment-status - Update status (e.g. Complete)
app.put('/api/doctor/appointment-status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: "Unauthorized" });
    try {
        const doctorId = await getDoctorIdByUserId(req.user.id);
        const { appointmentId, status } = req.body;
        const [result] = await pool.query('UPDATE appointments SET status = ? WHERE id = ? AND doctor_id = ?', [status, appointmentId, doctorId]);
        if (result.affectedRows > 0) res.json({ success: true, message: "Appointment updated" });
        else res.status(404).json({ success: false, message: "Appointment not found" });
    } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

// [GET] /api/doctor/my-patients - List active patients
app.get('/api/doctor/my-patients', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: "Unauthorized" });
    try {
        const doctorId = await getDoctorIdByUserId(req.user.id);
        const [patients] = await pool.query(
            `SELECT DISTINCT p.id, p.name, p.is_discharged FROM patients p
             JOIN appointments a ON p.id = a.patient_id
             WHERE a.doctor_id = ? AND p.is_discharged = FALSE ORDER BY p.name`, [doctorId]
        );
        res.json({ success: true, patients });
    } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

// [POST] /api/doctor/admit-patient - Add a new patient manually
app.post('/api/doctor/admit-patient', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: "Unauthorized" });
    const { name, email, contact, medical_history_summary } = req.body;

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const emailIndex = createBlindIndex(email);
        const [existing] = await connection.query('SELECT id FROM users WHERE email_index = ?', [emailIndex]);
        if (existing.length > 0) { await connection.rollback(); return res.status(409).json({ success: false, message: "Patient exists." }); }

        const dummyPass = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
        const [uRes] = await connection.query('INSERT INTO users (email_index, password, role) VALUES (?, ?, ?)', [emailIndex, dummyPass, 'patient']);
        await connection.query('INSERT INTO patients (user_id, name, contact_phone, medical_history_summary) VALUES (?, ?, ?, ?)', [uRes.insertId, name, encrypt(contact), medical_history_summary]);

        await connection.commit();
        res.status(201).json({ success: true, message: 'Patient admitted.' });
    } catch (err) {
        await connection.rollback();
        res.status(500).json({ success: false, message: 'Database error.' });
    } finally { connection.release(); }
});

// [PUT] /api/doctor/discharge-patient/:id - Discharge patient
app.put('/api/doctor/discharge-patient/:patientId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: 'Unauthorized.' });
    try {
        await pool.query('UPDATE patients SET is_discharged = TRUE WHERE id = ?', [req.params.patientId]);
        res.json({ success: true, message: 'Patient discharged.' });
    } catch (err) { res.status(500).json({ success: false, message: 'Database error.' }); }
});

// [GET] /api/doctor/patient-profile/:id - Get full patient details
app.get('/api/doctor/patient-profile/:patientId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: "Unauthorized" });
    try {
        const [rows] = await pool.query('SELECT * FROM patients WHERE id = ?', [req.params.patientId]);
        if (rows.length === 0) return res.status(404).json({ success: false, message: "Not found" });
        const p = rows[0];
        res.json({
            success: true,
            profile: { ...p, contact_phone: decrypt(p.contact_phone), emergency_contact_phone: decrypt(p.emergency_contact_phone) }
        });
    } catch (err) { res.status(500).json({ success: false, message: 'Server error.' }); }
});

// [PUT] /api/doctor/patient-profile/:id - Update patient profile
app.put('/api/doctor/patient-profile/:patientId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: 'Unauthorized.' });
    const { profileData } = req.body;
    try {
        await pool.query(
            `UPDATE patients SET name=?, date_of_birth=?, address=?, blood_group=?, allergies=?, medical_history_summary=?, contact_phone=?, next_visit_date=? WHERE id=?`,
            [profileData.name, profileData.date_of_birth, profileData.address, profileData.blood_group, profileData.allergies, profileData.medical_history_summary, encrypt(profileData.contact_phone), profileData.next_visit_date, req.params.patientId]
        );
        res.json({ success: true, message: 'Profile updated.' });
    } catch (err) { res.status(500).json({ success: false, message: 'Database error.' }); }
});

// [POST] /api/doctor/reports - Create a new medical report
app.post('/api/doctor/reports', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: 'Unauthorized.' });
    const { reportData } = req.body;
    const doctorId = await getDoctorIdByUserId(req.user.id);

    try {
            // UPDATED: Added temperature, weight, and spo2 to the INSERT statement
            await pool.query(
                `INSERT INTO reports (
                    patient_id,
                    doctor_id,
                    report_date,
                    \`condition\`,
                    details,
                    temperature,
                    weight,
                    spo2,
                    bp_systolic,
                    bp_diastolic,
                    blood_sugar,
                    hemoglobin,
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    reportData.patient_id,
                    doctorId,
                    reportData.report_date,
                    reportData.condition,
                    encrypt(reportData.details), // Encrypting sensitive details
                    reportData.temperature,      // New Field
                    reportData.weight,           // New Field
                    reportData.spo2,             // New Field
                    reportData.bp_systolic,
                    reportData.bp_diastolic,
                    reportData.blood_sugar,
                    reportData.hemoglobin,
                    'Completed'
                ]
            );
            res.status(201).json({ success: true, message: 'Report created.' });
        } catch (err) {
            console.error("Database Insert Error:", err);
            res.status(500).json({ success: false, message: 'Database error.' });
        }
    });

// [GET] /api/doctor/recent-reports - Get last 5 reports with FULL DETAILS (UPDATED FOR POPUP)
app.get('/api/doctor/recent-reports', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: 'Unauthorized.' });
    try {
        const doctorId = await getDoctorIdByUserId(req.user.id);

        // UPDATED: Added r.temperature, r.weight, r.spo2 to the SELECT statement
        const [reports] = await pool.query(
            `SELECT
                r.id,
                r.report_date,
                r.condition,
                r.details,
                r.temperature,
                r.weight,
                r.spo2,
                r.bp_systolic,
                r.bp_diastolic,
                r.blood_sugar,
                r.hemoglobin,
                p.name as patient_name
             FROM reports r
             JOIN patients p ON r.patient_id = p.id
             WHERE r.doctor_id = ?
             ORDER BY r.id DESC LIMIT 5`,
            [doctorId]
        );

        // Decrypt details before sending to frontend
        const decryptedReports = reports.map(r => ({
            ...r,
            details: decrypt(r.details) || 'No details available.'
        }));

        res.json({ success: true, reports: decryptedReports });

    } catch (err) {
        console.error("Fetch Reports Error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// [POST] /api/doctor/prescriptions - Create a prescription
app.post('/api/doctor/prescriptions', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: 'Unauthorized.' });
    const { prescriptionData } = req.body;
    const doctorId = await getDoctorIdByUserId(req.user.id);

    try {
        await pool.query(
            `INSERT INTO prescriptions (patient_id, doctor_id, medication, dosage, quantity, pharmacy, date_issued, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [prescriptionData.patient_id, doctorId, prescriptionData.medication, prescriptionData.dosage, prescriptionData.quantity, prescriptionData.pharmacy, prescriptionData.date_issued, 'Sent']
        );
        res.status(201).json({ success: true, message: 'Prescription created.' });
    } catch (err) { res.status(500).json({ success: false, message: 'Database error.' }); }
});

// [GET] /api/doctor/recent-prescriptions - Get last 5 prescriptions with FULL DETAILS
app.get('/api/doctor/recent-prescriptions', authenticateToken, async (req, res) => {
    if (req.user.role !== 'doctor') return res.status(403).json({ success: false, message: 'Unauthorized.' });
    try {
        const doctorId = await getDoctorIdByUserId(req.user.id);

        const [prescriptions] = await pool.query(
            `SELECT
                pr.id,
                pr.date_issued,
                pr.medication,
                pr.dosage,
                pr.quantity,
                pr.pharmacy,
                pr.status,
                p.name as patient_name
             FROM prescriptions pr
             JOIN patients p ON pr.patient_id = p.id
             WHERE pr.doctor_id = ?
             ORDER BY pr.id DESC LIMIT 5`,
            [doctorId]
        );
        res.json({ success: true, prescriptions });
    } catch (err) {
        console.error("Fetch Prescriptions Error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// ==========================================
// 7. PATIENT ROUTES
// ==========================================

// [GET] /api/patient/profile - Get own profile
app.get('/api/patient/profile', authenticateToken, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ success: false });
    try {
        const pid = await getPatientIdByUserId(req.user.id);
        const [rows] = await pool.query('SELECT * FROM patients WHERE id = ?', [pid]);
        if (rows.length === 0) return res.status(404).json({ success: false });
        const p = rows[0];
        res.json({ success: true, profile: { ...p, contact_phone: decrypt(p.contact_phone) } });
    } catch (err) { res.status(500).json({ success: false }); }
});

// [GET] /api/patient/reports - Updated for Health Trends (Chart Data)
app.get('/api/patient/reports', authenticateToken, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ success: false });

    try {
        const pid = await getPatientIdByUserId(req.user.id);

        // UPDATED: Added temperature, weight, and spo2 to the query
        const [rows] = await pool.query(
            `SELECT
                DATE_FORMAT(report_date, '%b %d') as label,
                bp_systolic,
                bp_diastolic,
                blood_sugar,
                temperature,
                weight,
                spo2
             FROM reports
             WHERE patient_id = ?
             ORDER BY report_date DESC
             LIMIT 7`,
            [pid]
        );

        // Reverse the data so it reads left-to-right (Oldest to Newest)
        const sortedRows = rows.reverse();

        res.json({
            success: true,
            labels: sortedRows.map(r => r.label),
            bp_systolic: sortedRows.map(r => r.bp_systolic),
            bp_diastolic: sortedRows.map(r => r.bp_diastolic),
            sugar: sortedRows.map(r => r.blood_sugar),
            temp: sortedRows.map(r => r.temperature),
            weight: sortedRows.map(r => r.weight),
            spo2: sortedRows.map(r => r.spo2)
        });

    } catch (err) {
        console.error("Trends Fetch Error:", err);
        res.status(500).json({
            labels: [],
            bp_systolic: [],
            bp_diastolic: [],
            sugar: [],
            temp: [],
            weight: [],
            spo2: []
        });
    }
});

// 4. Reports List (NEW ROUTE FOR MODAL)
app.get('/api/patient/reports-list', authenticateToken, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ success: false });
    try {
        const pid = await getPatientIdByUserId(req.user.id);
        const [rows] = await pool.query(
            `SELECT r.report_date, r.condition, r.bp_systolic, r.bp_diastolic, r.blood_sugar, d.name as doctor_name
             FROM reports r JOIN doctors d ON r.doctor_id = d.id
             WHERE r.patient_id = ? ORDER BY r.report_date DESC`, [pid]);
        res.json({ success: true, reports: rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

// 5. Prescriptions
app.get('/api/patient/prescriptions', authenticateToken, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ success: false });
    try {
        const pid = await getPatientIdByUserId(req.user.id);
        const [rows] = await pool.query(
            `SELECT pr.medication, pr.dosage, d.name as doctor_name, pr.date_issued
             FROM prescriptions pr JOIN doctors d ON pr.doctor_id = d.id
             WHERE pr.patient_id = ? ORDER BY pr.date_issued DESC`, [pid]);
        res.json({ success: true, prescriptions: rows });
    } catch (err) { res.status(500).json({ success: false }); }
});

// 6. Appointments List
app.get('/api/appointments', authenticateToken, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ success: false });
    try {
        const pid = await getPatientIdByUserId(req.user.id);
        const [rows] = await pool.query(
            `SELECT
                a.id,
                d.name as doctor_name,
                d.specialization,
                DATE_FORMAT(a.appointment_date, '%Y-%m-%d') as date,
                DATE_FORMAT(a.appointment_date, '%H:%i') as time,
                a.status,
                a.notes
             FROM appointments a
             JOIN doctors d ON a.doctor_id = d.id
             WHERE a.patient_id = ?
             ORDER BY a.appointment_date DESC`, [pid]);

        res.json({ success: true, appointments: rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

// 7. Book Appointment
app.post('/api/appointments/book', authenticateToken, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).json({ success: false });

    const { doctorId, date, time, notes } = req.body;

    // VALIDATION: Prevent booking in the past
    const appointmentDateTime = new Date(`${date} ${time}`);
    const now = new Date();

    if (isNaN(appointmentDateTime.getTime()) || appointmentDateTime < now) {
        return res.status(400).json({
            success: false,
            message: 'Invalid date or time. Appointments must be scheduled for the future.'
        });
    }

    try {
        const pid = await getPatientIdByUserId(req.user.id);

        // Ensure your DB column 'appointment_date' is type DATETIME to store both date and time
        await pool.query(
            'INSERT INTO appointments (patient_id, doctor_id, appointment_date, notes) VALUES (?, ?, ?, ?)',
            [pid, doctorId, `${date} ${time}`, notes]
        );

        res.status(201).json({ success: true, message: 'Appointment booked successfully!' });
    } catch (err) {
        console.error("Booking Error:", err);
        res.status(500).json({ success: false, message: 'Error booking appointment.' });
    }
});

// 8. Doctors List (Public/Private)
app.get('/api/doctors', async (req, res) => {
    try {
        const [rows] = await pool.query(
            'SELECT id, name, specialization, experience_years, consultation_fee FROM doctors WHERE is_verified = 1 ORDER BY name'
        );
        res.json({ success: true, doctors: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error fetching doctors.' });
    }
});

// ==========================================
// 8. ADMIN ROUTES
// ==========================================

app.get('/api/admin/unverified-doctors', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name, specialization, license_number, created_at FROM doctors WHERE is_verified = 0');
        const doctors = rows.map(doc => ({ ...doc, license_number: decrypt(doc.license_number) }));
        res.json({ success: true, doctors });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/api/admin/verify-doctor', authenticateToken, requireAdmin, async (req, res) => {
    const { doctorId } = req.body;
    try {
        const [result] = await pool.query('UPDATE doctors SET is_verified = 1 WHERE id = ?', [parseInt(doctorId)]);
        if (result.affectedRows > 0) res.json({ success: true, message: "Doctor verified." });
        else res.status(404).json({ success: false, message: "Doctor not found." });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [[{count: docs}]] = await pool.query('SELECT COUNT(*) as count FROM doctors WHERE is_verified = 1');
        const [[{count: pats}]] = await pool.query('SELECT COUNT(*) as count FROM patients');
        const [[{count: pend}]] = await pool.query('SELECT COUNT(*) as count FROM doctors WHERE is_verified = 0');
        res.json({ success: true, stats: { doctors: docs, patients: pats, pending: pend } });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.get('/api/admin/all-users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [doctors] = await pool.query('SELECT name, specialization, is_verified, DATE_FORMAT(created_at, "%Y-%m-%d") as joined FROM doctors');
        const [patients] = await pool.query('SELECT name, DATE_FORMAT(created_at, "%Y-%m-%d") as joined FROM patients');
        res.json({ success: true, doctors, patients });
    } catch (err) { res.status(500).json({ success: false }); }
});
// ==========================================
// 9. PUBLIC ROUTES & SERVER START
// ==========================================

// [GET] /api/doctors - List verified doctors for patients to choose
app.get('/api/doctors', async (req, res) => {
    try {
        const [doctors] = await pool.query('SELECT id, name, specialization FROM doctors WHERE is_verified = true ORDER BY name');
        res.json({ success: true, doctors });
    } catch (err) { res.status(500).json({ success: false, message: 'Database error' }); }
});

// [GET] * - Catch-all for serving frontend
app.get('*', (req, res) => {
    if (req.originalUrl.startsWith('/api/')) return res.status(404).json({ success: false, message: 'API endpoint not found.' });
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`✅ Server running at: http://localhost:${PORT}`);
});