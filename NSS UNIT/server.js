const express = require('express');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS and JSON parsing with high limit for base64 images
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve frontend static files
app.use(express.static(__dirname));

// SQLite database persisted on disk. Supports Render persistent disk or fallback to local project data directory.
const configuredDbPath = process.env.SQLITE_DB_PATH || process.env.SQLITE_PATH;
let dataDir = process.env.DATA_DIR || (configuredDbPath
    ? path.dirname(configuredDbPath)
    : path.join(__dirname, 'data'));
let dbPath = configuredDbPath || path.join(dataDir, 'nss.sqlite');
let db = null;
let isDbConnected = false;
let dbError = null;
function sqliteQuery(sql, params = []) {
    const statement = db.prepare(sql);
    if (/^\s*(SELECT|PRAGMA|WITH)\b/i.test(sql)) return [statement.all(...params), undefined];
    const result = statement.run(...params);
    return [{ insertId: Number(result.lastInsertRowid), affectedRows: result.changes, changes: result.changes, lastInsertRowid: result.lastInsertRowid }, undefined];
}
const pool = {
    query: async (sql, params) => sqliteQuery(sql, params),
    getConnection: async () => ({ query: async (q, p) => sqliteQuery(q, p), beginTransaction: async () => db.exec('BEGIN'), commit: async () => db.exec('COMMIT'), rollback: async () => { if (db.inTransaction) db.exec('ROLLBACK'); }, release: () => {} })
};
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT) || 587, secure: process.env.SMTP_SECURE === 'true', auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } : undefined }) : null;

function connectDatabase() {
    const candidatePaths = [];
    if (configuredDbPath) candidatePaths.push(configuredDbPath);
    candidatePaths.push(path.join(__dirname, 'data', 'nss.sqlite'));
    const os = require('os');
    candidatePaths.push(path.join(os.tmpdir(), 'nss.sqlite'));

    for (const targetPath of candidatePaths) {
        try {
            const dir = path.dirname(targetPath);
            fs.mkdirSync(dir, { recursive: true });
            const testDb = new Database(targetPath);
            testDb.pragma('journal_mode = WAL');
            dbPath = targetPath;
            dataDir = dir;
            return testDb;
        } catch (err) {
            console.warn(`Could not initialize SQLite at ${targetPath}:`, err.message);
        }
    }
    throw new Error('Failed to initialize SQLite in any candidate path');
}

function initDatabase() {
    try {
        db = connectDatabase();
        db.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, roll_number TEXT NOT NULL UNIQUE, date_of_birth TEXT NOT NULL, age INTEGER NOT NULL, aadhaar_number TEXT NOT NULL, mobile_number TEXT NOT NULL, blood_group TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'volunteer', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS password_reset_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, otp_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_password_reset_email ON password_reset_tokens(email);
CREATE TABLE IF NOT EXISTS members (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, role TEXT DEFAULT 'Volunteer', roll_number TEXT, date_of_birth TEXT, age INTEGER, aadhaar_number TEXT, email TEXT NOT NULL, phone TEXT, blood_group TEXT, photo TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, date TEXT, location TEXT, coordinator TEXT, description TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS gallery (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, image TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS announcements (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS achievements (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL, date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS attendance (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, event_name TEXT, member_id TEXT, member_name TEXT, status TEXT DEFAULT 'Present', date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS certificates (id INTEGER PRIMARY KEY AUTOINCREMENT, member_id TEXT, member_name TEXT, event TEXT, title TEXT, file TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS registrations (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, volunteer_email TEXT, volunteer_name TEXT, date TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
        db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP)");
        db.prepare("INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)").run(1);
        const seed = (table, sql) => { if (db.prepare('SELECT COUNT(*) AS count FROM ' + table).get().count === 0) db.exec(sql); };
        seed('users', "INSERT INTO users (id,name,roll_number,date_of_birth,age,aadhaar_number,mobile_number,blood_group,email,password,role) VALUES (1,'NSS Administrator','ADMIN001','2000-01-01',24,'123456789012','9876543210','O+','admin@nss.com','admin123','admin'),(2,'Rahul Kumar','21JR1A0501','2003-05-15',21,'987654321098','9876543210','A+','rahul@nss.com','volunteer123','volunteer')");
        seed('members', "INSERT INTO members (id,name,role,email,phone,photo) VALUES (1,'Rahul Kumar','Volunteer','rahul@nss.com','9876543210','https://images.unsplash.com/photo-1535713875002-d1d0cf377fde'),(2,'Priya Sharma','Volunteer','priya@nss.com','9876543211','https://images.unsplash.com/photo-1494790108377-be9c29b29330')");
        seed('events', "INSERT INTO events (id,title,date,location,coordinator,description) VALUES (1,'Clean India Drive','2026-10-02','Vijayawada','NSS Coordinator','Community cleanliness and awareness activity.'),(2,'Tree Plantation Drive','2026-10-10','College Campus','NSS Coordinator','Plantation of trees inside and around the campus.')");
        seed('gallery', "INSERT INTO gallery (id,title,image) VALUES (1,'Clean India Drive','https://images.unsplash.com/photo-1532996122724-e3c354a0b15b'),(2,'Tree Plantation','https://images.unsplash.com/photo-1416879595882-3373a0480b5b')");
        seed('announcements', "INSERT INTO announcements (id,title,message) VALUES (1,'NSS Meeting','All NSS volunteers are requested to attend the upcoming meeting.'),(2,'Volunteer Registration','Registration is open for upcoming NSS activities.')");
        seed('achievements', "INSERT INTO achievements (id,title,description,date) VALUES (1,'Best NSS Unit Award','Our NSS unit received recognition for outstanding social service.','2026-01-15')");
        isDbConnected = true; dbError = null; console.log('SQLite database ready: ' + dbPath);
    } catch (err) { isDbConnected = false; dbError = err.message; console.error('SQLite initialization failed:', err.message); }
}
// Helper to check DB connection in handlers
function requireDb(res) {
    if (!isDbConnected || !db) {
        res.status(503).json({ error: 'Database not connected. Please check SQLite initialization and configuration.' });
        return false;
    }
    return true;
}

/* =====================================================
   REST API ROUTES
===================================================== */

// 1. Health & Status
app.get('/api/health', (req, res) => {
    res.json({
        status: 'online',
        database: isDbConnected ? 'connected' : 'disconnected',
        error: dbError,
        config: {
            driver: 'sqlite',
            path: dbPath
        }
    });
});

// 2. Authentication
app.post('/api/auth/register', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { name, rollNumber, dateOfBirth, age, aadhaarNumber, mobileNumber, bloodGroup, email, password, role } = req.body;
        if (!name || !rollNumber || !dateOfBirth || !age || !aadhaarNumber || !mobileNumber || !bloodGroup || !email || !password || !['admin', 'volunteer'].includes(role)) {
            return res.status(400).json({ error: 'All registration fields are required.' });
        }
        const normalizedEmail = email.trim().toLowerCase();
        if (!/^\d{12}$/.test(aadhaarNumber) || !/^\d{10}$/.test(mobileNumber)) {
            return res.status(400).json({ error: 'Enter a valid Aadhaar number and mobile number.' });
        }
        const [existing] = await pool.query(
            'SELECT email, roll_number FROM users WHERE email = ? OR roll_number = ?',
            [normalizedEmail, rollNumber.trim()]
        );
        if (existing.some(user => user.email === normalizedEmail)) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }
        if (existing.some(user => user.roll_number === rollNumber.trim())) {
            return res.status(409).json({ error: 'An account with this roll number already exists.' });
        }
        const [result] = await pool.query(
            'INSERT INTO users (name, roll_number, date_of_birth, age, aadhaar_number, mobile_number, blood_group, email, password, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [name.trim(), rollNumber.trim(), dateOfBirth, age, aadhaarNumber, mobileNumber, bloodGroup, normalizedEmail, password, role]
        );
        res.status(201).json({
            success: true,
            user: { id: result.insertId, name: name.trim(), rollNumber, dateOfBirth, age, aadhaarNumber, mobileNumber, bloodGroup, email: normalizedEmail, role }
        });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY' || err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return res.status(409).json({ error: 'Email or roll number is already registered.' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { email, password } = req.body;
        const [rows] = await pool.query('SELECT id, name, roll_number AS rollNumber, date_of_birth AS dateOfBirth, age, aadhaar_number AS aadhaarNumber, mobile_number AS mobileNumber, blood_group AS bloodGroup, email, role FROM users WHERE email = ? AND password = ?', [email, password]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        res.json({ success: true, user: rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/request-password-reset', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        if (!mailer || !process.env.SMTP_FROM) {
            return res.status(503).json({ error: 'Password reset email is not configured on the server.' });
        }

        const email = String(req.body.email || '').trim().toLowerCase();
        if (!email) return res.status(400).json({ error: 'Email is required.' });

        const [users] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (!users.length) {
            return res.status(404).json({ error: 'No account found with this email.' });
        }

        const otp = String(crypto.randomInt(100000, 1000000));
        const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
        await pool.query("UPDATE password_reset_tokens SET used_at = datetime('now') WHERE email = ? AND used_at IS NULL", [email]);
        await pool.query(
            "INSERT INTO password_reset_tokens (email, otp_hash, expires_at) VALUES (?, ?, datetime('now', '+10 minutes'))",
            [email, otpHash]
        );

        await mailer.sendMail({
            from: process.env.SMTP_FROM,
            to: email,
            subject: 'NSS UNIT PSCMR password reset code',
            text: `Your NSS UNIT PSCMR password reset code is ${otp}. It expires in 10 minutes.`
        });

        res.json({ success: true, message: 'A password reset code was sent to your email.' });
    } catch (err) {
        console.error('Password reset email error:', err);
        res.status(500).json({ error: 'Unable to send the password reset email.' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const email = String(req.body.email || '').trim().toLowerCase();
        const otp = String(req.body.otp || '').trim();
        const newPassword = String(req.body.newPassword || '');
        if (!email || !/^\d{6}$/.test(otp) || newPassword.length < 6) {
            return res.status(400).json({ error: 'Email, a valid 6-digit code, and a password of at least 6 characters are required.' });
        }

        const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
        const [tokens] = await pool.query(
            "SELECT id FROM password_reset_tokens WHERE email = ? AND otp_hash = ? AND used_at IS NULL AND expires_at > datetime('now') ORDER BY id DESC LIMIT 1",
            [email, otpHash]
        );
        if (!tokens.length) return res.status(400).json({ error: 'The code is invalid or expired.' });

        await pool.query('UPDATE users SET password = ? WHERE email = ?', [newPassword, email]);
        await pool.query("UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?", [tokens[0].id]);
        res.json({ success: true, message: 'Password reset successful.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Hydrate All Data (Single roundtrip for fast initial loading)
app.get('/api/all-data', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [members] = await pool.query('SELECT * FROM members ORDER BY id DESC');
        const [events] = await pool.query('SELECT * FROM events ORDER BY id DESC');
        const [gallery] = await pool.query('SELECT * FROM gallery ORDER BY id DESC');
        const [announcements] = await pool.query('SELECT * FROM announcements ORDER BY id DESC');
        const [achievements] = await pool.query('SELECT * FROM achievements ORDER BY id DESC');
        const [attendance] = await pool.query('SELECT * FROM attendance ORDER BY id DESC');
        const [certificates] = await pool.query('SELECT * FROM certificates ORDER BY id DESC');
        const [registrations] = await pool.query('SELECT * FROM registrations ORDER BY id DESC');

        res.json({
            members,
            events,
            gallery,
            announcements,
            achievements,
            attendance,
            certificates,
            registrations
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Members CRUD
app.get('/api/members', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM members ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/members', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { name, role, rollNumber, dateOfBirth, age, aadhaarNumber, email, phone, bloodGroup, photo } = req.body;
        const [result] = await pool.query(
            'INSERT INTO members (name, role, roll_number, date_of_birth, age, aadhaar_number, email, phone, blood_group, photo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [name, role || 'Volunteer', rollNumber || null, dateOfBirth || null, age || null, aadhaarNumber || null, email, phone || '', bloodGroup || null, photo || 'https://via.placeholder.com/200']
        );
        res.status(201).json({ id: result.insertId, name, role, email, phone, photo });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/members/:id', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { name, role, rollNumber, dateOfBirth, age, aadhaarNumber, email, phone, bloodGroup, photo } = req.body;
        await pool.query(
            'UPDATE members SET name=?, role=?, roll_number=?, date_of_birth=?, age=?, aadhaar_number=?, email=?, phone=?, blood_group=?, photo=? WHERE id=?',
            [name, role, rollNumber || null, dateOfBirth || null, age || null, aadhaarNumber || null, email, phone, bloodGroup || null, photo, req.params.id]
        );
        res.json({ success: true, id: req.params.id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/members/:id', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        await pool.query('DELETE FROM members WHERE id=?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. Events CRUD
app.get('/api/events', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM events ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/events', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { title, date, location, coordinator, description } = req.body;
        const [result] = await pool.query(
            'INSERT INTO events (title, date, location, coordinator, description) VALUES (?, ?, ?, ?, ?)',
            [title, date, location, coordinator, description]
        );
        res.status(201).json({ id: result.insertId, title, date, location, coordinator, description });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/events/:id', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { title, date, location, coordinator, description } = req.body;
        await pool.query(
            'UPDATE events SET title=?, date=?, location=?, coordinator=?, description=? WHERE id=?',
            [title, date, location, coordinator, description, req.params.id]
        );
        res.json({ success: true, id: req.params.id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/events/:id', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        await pool.query('DELETE FROM events WHERE id=?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. Gallery CRUD
app.get('/api/gallery', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM gallery ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/gallery', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { title, image } = req.body;
        const [result] = await pool.query('INSERT INTO gallery (title, image) VALUES (?, ?)', [title, image]);
        res.status(201).json({ id: result.insertId, title, image });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/gallery/:id', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        await pool.query('DELETE FROM gallery WHERE id=?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. Announcements CRUD
app.get('/api/announcements', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM announcements ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/announcements', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { title, message } = req.body;
        const [result] = await pool.query('INSERT INTO announcements (title, message) VALUES (?, ?)', [title, message]);
        res.status(201).json({ id: result.insertId, title, message });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/announcements/:id', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        await pool.query('DELETE FROM announcements WHERE id=?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 8. Achievements CRUD
app.get('/api/achievements', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM achievements ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/achievements', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { title, description, date } = req.body;
        const [result] = await pool.query('INSERT INTO achievements (title, description, date) VALUES (?, ?, ?)', [title, description, date || new Date().toISOString().split('T')[0]]);
        res.status(201).json({ id: result.insertId, title, description, date });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/achievements/:id', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        await pool.query('DELETE FROM achievements WHERE id=?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 9. Attendance
app.get('/api/attendance', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM attendance ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/attendance', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { event_id, event_name, member_id, member_name, status, date } = req.body;
        const [result] = await pool.query(
            'INSERT INTO attendance (event_id, event_name, member_id, member_name, status, date) VALUES (?, ?, ?, ?, ?, ?)',
            [event_id, event_name, member_id, member_name, status || 'Present', date || new Date().toISOString().split('T')[0]]
        );
        res.status(201).json({ id: result.insertId, event_id, event_name, member_id, member_name, status, date });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 10. Certificates
app.get('/api/certificates', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM certificates ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/certificates', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { member_id, member_name, event, title, file } = req.body;
        const [result] = await pool.query(
            'INSERT INTO certificates (member_id, member_name, event, title, file) VALUES (?, ?, ?, ?, ?)',
            [member_id, member_name, event, title, file]
        );
        res.status(201).json({ id: result.insertId, member_id, member_name, event, title });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 11. Event Registrations
app.get('/api/registrations', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const [rows] = await pool.query('SELECT * FROM registrations ORDER BY id DESC');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/registrations', async (req, res) => {
    if (!requireDb(res)) return;
    try {
        const { event_id, volunteer_email, volunteer_name, date } = req.body;
        const [result] = await pool.query(
            'INSERT INTO registrations (event_id, volunteer_email, volunteer_name, date) VALUES (?, ?, ?, ?)',
            [event_id, volunteer_email, volunteer_name, date || new Date().toISOString().split('T')[0]]
        );
        res.status(201).json({ id: result.insertId, event_id, volunteer_email, volunteer_name });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 12. Collection Sync (Batch saves from frontend)
app.post('/api/sync/:collection', async (req, res) => {
    if (!requireDb(res)) return;
    const { collection } = req.params;
    const items = Array.isArray(req.body) ? req.body : [];

    try {
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();

            if (collection === 'members') {
                await conn.query('DELETE FROM members');
                for (const m of items) {
                    await conn.query(
                        'INSERT INTO members (id, name, role, roll_number, date_of_birth, age, aadhaar_number, email, phone, blood_group, photo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        [m.id || null, m.name || '', m.role || 'Volunteer', m.rollNumber || m.roll_number || null, m.dateOfBirth || m.date_of_birth || null, m.age || null, m.aadhaarNumber || m.aadhaar_number || null, m.email || '', m.phone || '', m.bloodGroup || m.blood_group || null, m.photo || '']
                    );
                }
            } else if (collection === 'events') {
                await conn.query('DELETE FROM events');
                for (const e of items) {
                    await conn.query(
                        'INSERT INTO events (id, title, date, location, coordinator, description) VALUES (?, ?, ?, ?, ?, ?)',
                        [e.id || null, e.title || '', e.date || '', e.location || '', e.coordinator || '', e.description || '']
                    );
                }
            } else if (collection === 'gallery') {
                await conn.query('DELETE FROM gallery');
                for (const g of items) {
                    await conn.query(
                        'INSERT INTO gallery (id, title, image) VALUES (?, ?, ?)',
                        [g.id || null, g.title || '', g.image || '']
                    );
                }
            } else if (collection === 'announcements') {
                await conn.query('DELETE FROM announcements');
                for (const a of items) {
                    await conn.query(
                        'INSERT INTO announcements (id, title, message) VALUES (?, ?, ?)',
                        [a.id || null, a.title || '', a.message || '']
                    );
                }
            } else if (collection === 'achievements') {
                await conn.query('DELETE FROM achievements');
                for (const ac of items) {
                    await conn.query(
                        'INSERT INTO achievements (id, title, description, date) VALUES (?, ?, ?, ?)',
                        [ac.id || null, ac.title || '', ac.description || '', ac.date || '']
                    );
                }
            } else if (collection === 'attendance') {
                await conn.query('DELETE FROM attendance');
                for (const at of items) {
                    await conn.query(
                        'INSERT INTO attendance (id, event_id, event_name, member_id, member_name, status, date) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [at.id || null, at.eventId || at.event_id || '', at.eventName || at.event_name || '', at.memberId || at.member_id || '', at.memberName || at.member_name || '', at.status || 'Present', at.date || '']
                    );
                }
            } else if (collection === 'certificates') {
                await conn.query('DELETE FROM certificates');
                for (const c of items) {
                    await conn.query(
                        'INSERT INTO certificates (id, member_id, member_name, event, title, file) VALUES (?, ?, ?, ?, ?, ?)',
                        [c.id || null, c.memberId || c.member_id || '', c.memberName || c.member_name || '', c.event || '', c.title || '', c.file || '']
                    );
                }
            } else if (collection === 'registrations') {
                await conn.query('DELETE FROM registrations');
                for (const r of items) {
                    await conn.query(
                        'INSERT INTO registrations (id, event_id, volunteer_email, volunteer_name, date) VALUES (?, ?, ?, ?, ?)',
                        [r.id || null, r.eventId || r.event_id || '', r.volunteerEmail || r.volunteer_email || '', r.volunteerName || r.volunteer_name || '', r.date || '']
                    );
                }
            }

            await conn.commit();
            res.json({ success: true, count: items.length });
        } catch (err) {
            await conn.rollback();
            throw err;
        } finally {
            conn.release();
        }
    } catch (err) {
        console.error('Sync error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Default route -> frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start Server & Init DB
app.listen(PORT, '0.0.0.0', async () => {
    console.log(`====================================================`);
    console.log(`🚀 NSS UNIT PSCMR Server running on http://localhost:${PORT}`);
    console.log(`====================================================`);
    await initDatabase();
});
