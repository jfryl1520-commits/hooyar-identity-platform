const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, '..', 'database.sqlite');
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_no TEXT UNIQUE,
    row_number INTEGER,
    name TEXT NOT NULL,
    family_name TEXT,
    father_name TEXT,
    grandfather_name TEXT,
    national_id TEXT,
    birth_date TEXT,
    gender TEXT,
    blood_type TEXT,
    education TEXT,
    language TEXT,
    province TEXT,
    district TEXT,
    ethnicity TEXT,
    religion TEXT,
    document_type TEXT,
    document_number TEXT,
    marital_status TEXT,
    children_count INTEGER DEFAULT 0,
    job TEXT,
    activity_history TEXT,
    service_location TEXT,
    state TEXT,
    address TEXT,
    mobile_phone TEXT UNIQUE NOT NULL,
    phone_secondary TEXT,
    photo TEXT,
    password TEXT NOT NULL,
    status TEXT DEFAULT 'فعال',
    verification TEXT DEFAULT 'در انتظار بررسی',
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT,
    role TEXT DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,
    actor_name TEXT,
    action TEXT NOT NULL,
    target_id INTEGER,
    target_name TEXT,
    detail TEXT,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    status TEXT DEFAULT 'در حال بررسی',
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mobile ON customers(mobile_phone);
CREATE INDEX IF NOT EXISTS idx_status ON customers(status);
CREATE INDEX IF NOT EXISTS idx_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_services_customer ON services(customer_id);
`);

function addColumnIfMissing(table, column, definition) {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    if (!cols.some(c => c.name === column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
}

['grandfather_name TEXT', 'national_id TEXT', 'gender TEXT', 'blood_type TEXT',
 'district TEXT', 'religion TEXT', 'children_count INTEGER DEFAULT 0', 'job TEXT',
 'address TEXT', 'phone_secondary TEXT', 'photo TEXT', 'registration_no TEXT',
 'verification TEXT DEFAULT \'در انتظار بررسی\''].forEach(def => {
    const [column, ...rest] = def.split(' ');
    addColumnIfMissing('customers', column, rest.join(' '));
});

try {
    db.exec('CREATE INDEX IF NOT EXISTS idx_national ON customers(national_id)');
} catch (e) {
    console.warn('Skipping idx_national:', e.message);
}

['mfa_secret TEXT', 'mfa_enabled INTEGER NOT NULL DEFAULT 0',
 'mfa_last_step INTEGER NOT NULL DEFAULT 0', 'mfa_setup_expires_at TEXT'].forEach(def => {
    const [column, ...rest] = def.split(' ');
    addColumnIfMissing('admins', column, rest.join(' '));
});

const bootstrapUsername = process.env.ADMIN_USERNAME;
const bootstrapPassword = process.env.ADMIN_PASSWORD;
if (bootstrapUsername && bootstrapPassword) {
    if (bootstrapPassword.length < 12) {
        throw new Error('ADMIN_PASSWORD must be at least 12 characters long');
    }
    const adminStmt = db.prepare('INSERT OR IGNORE INTO admins (username, password, full_name, role) VALUES (?, ?, ?, ?)');
    adminStmt.run(bootstrapUsername, bcrypt.hashSync(bootstrapPassword, 12), 'مدیر سامانه', 'admin');
}

db.prepare(`UPDATE customers SET registration_no = 'AF-' || printf('%06d', id) WHERE registration_no IS NULL`).run();

module.exports = db;
