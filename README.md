🏥 ConnectCare — Integrated EHR System

ConnectCare is a privacy-centric, full-stack Electronic Health Record (EHR) platform engineered to securely bridge the gap between patients and healthcare providers.

By combining seamless clinical scheduling, longitudinal health tracking, and advanced cryptographic safeguards, ConnectCare ensures that medical data remains:

✅ Accessible

✅ Actionable

✅ Highly Secure

🚀 Key Features
🗓️ Intelligent Appointment Engine

Patient-centric booking system

Filtering by specialization & consultation fees

Dual-Layer Temporal Validation prevents retroactive scheduling

Server-side conflict resolution using precise DATETIME logic

🔐 Military-Grade Encryption

AES-256-GCM authenticated encryption for:

Medical Reports

Aadhar information

Contact metadata

Secure password hashing with Bcrypt

JWT-based stateless authentication

👨‍⚕️ Verified Provider Profiles

Structured clinician onboarding workflow

Licensure tracking

Experience metrics

Facility management support

📊 Longitudinal Vitals Analytics

Interactive health trend visualization powered by Chart.js:

Tracks:

Blood Pressure (BP)

SPO₂

Blood Glucose

Weight

Body Temperature

Dynamic telemetry charts allow providers to monitor patient progress over time.

💊 Dynamic Digital Prescriptions

JSON-based medication schemas

Multi-drug prescription support

Structured dosage & duration configuration

🛠️ Technical Stack
Component	Technology
Frontend	HTML5, CSS3, JavaScript (ES6+), Chart.js, FontAwesome
Backend	Node.js, Express.js
Database	MySQL (Relational Schema)
Security	JWT, Bcrypt, AES-256-GCM, HMAC Blind Indexing
🔒 Security & Data Integrity

ConnectCare follows a Zero-Trust Architecture to safeguard sensitive health data.

🔎 Blind Indexing

HMAC-SHA256-based blind indices

Enables secure lookup of sensitive identifiers (Email/Aadhar)

No decryption required for search operations

🛡️ Dual-Layer Validation

Client-side UI restrictions

Server-side business logic verification

Prevents manual request tampering

👥 Granular Role-Based Access Control (RBAC)

Strict separation of:

Doctor

Patient

Admin

Cryptographically signed JWT tokens

Fine-grained permission enforcement

📂 Architecture Overview
users          → Centralized authentication & identity provider
doctors        → Professional metadata
patients       → Demographic & medical metadata
appointments   → Scheduling engine with conflict resolution
reports        → Encrypted clinical repository
prescriptions  → Structured JSON medication storage

Relational architecture consists of 8 normalized tables with enforced constraints.

⚙️ Installation & Deployment
1️⃣ Database Initialization

Execute the schema script:

connectcare_schema.sql

Import into your MySQL environment to initialize tables and constraints.

2️⃣ Environment Configuration

Create a .env file in the root directory:

PORT=3000
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_secure_password
JWT_SECRET=your_jwt_signing_key
ENCRYPTION_KEY=32_byte_hex_key_for_aes
HMAC_SECRET=secure_hmac_secret_key

⚠️ Ensure:

ENCRYPTION_KEY is a 32-byte hex string for AES-256

Secrets are never committed to version control

3️⃣ Application Launch
# Install dependencies
npm install

# Start the application
node server.js

Server runs on:

http://localhost:3000
🔐 Security Best Practices

Use HTTPS in production

Store secrets using a secure vault or environment manager

Rotate encryption & JWT keys periodically

Enable database-level access controls

Implement audit logging for clinical access

📌 Future Enhancements

Two-Factor Authentication (2FA)

OAuth2 provider integration

HL7 / FHIR interoperability

Containerized deployment (Docker)

Cloud-native scaling architecture

📜 License

This project is intended for educational and prototype use.
Production deployments must comply with applicable healthcare regulations (HIPAA, GDPR, etc.).

ConnectCare

Your health, securely connected.
