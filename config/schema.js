const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, '..', 'database.sqlite');
fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

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

// Partial unique index: a national ID may only appear once, but records without
// one (NULL / empty) are still allowed. Existing databases may still carry the
// older non-unique index under the same name, so it is upgraded explicitly.
// Creation is skipped with a warning if the data already contains duplicates,
// so an upgrade never bricks a live database.
try {
    const existing = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_national'").get();
    if (existing && !/UNIQUE/i.test(existing.sql || '')) db.exec('DROP INDEX idx_national');

    const duplicates = db.prepare(`
        SELECT national_id FROM customers
        WHERE national_id IS NOT NULL AND national_id != ''
        GROUP BY national_id HAVING COUNT(*) > 1
    `).all();
    if (duplicates.length) {
        console.warn(`Skipping unique national_id index: ${duplicates.length} duplicate value(s) already present`);
    } else {
        db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_national ON customers(national_id)
                 WHERE national_id IS NOT NULL AND national_id != ''`);
    }
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

// ---- Demo data seeding (deterministic) ----
// Seeds only when customers table is empty, so every fresh deployment
// (including Railway without a persistent volume) ships with demo data.
function seedDemoDataIfEmpty() {
    const count = db.prepare('SELECT COUNT(*) AS c FROM customers').get().c;
    if (count > 0) return;

    // Demo accounts share one password; it is configurable so a public deployment
    // never ships with a known credential. Never enable seeding with real data.
    const demoPassword = process.env.DEMO_PASSWORD || '123456';
    const demoHash = bcrypt.hashSync(demoPassword, 10);

    const customers = [
        { registration_no: 'AF-000101', row_number: 1, name: 'سید احمد', family_name: 'موسوی', father_name: 'حیدر', grandfather_name: 'محمد تقی', national_id: '0014567890', birth_date: '1379/04/02', gender: 'مرد', blood_type: 'O+', education: 'ابتدایی', language: 'فارسی / ترکی', province: 'تهران', district: 'تهران', ethnicity: 'سادات', religion: 'اسلام', document_type: 'پاسپورت', document_number: '1211448', marital_status: 'مجرد', children_count: 0, job: 'دانش‌آموز', activity_history: 'بدون سابقه', service_location: '__', state: 'دایکندی', address: 'تهران، خیابان ولیعصر', mobile_phone: '09388598197', phone_secondary: '', photo: null, password: demoHash, status: 'فعال', verification: 'تأیید شده', notes: 'نمونه دادهٔ آزمایشی' },
        { registration_no: 'AF-000102', row_number: 2, name: 'سید علی', family_name: 'حسینی', father_name: 'فضل الله', grandfather_name: 'عباس', national_id: '0024567890', birth_date: '1366/01/01', gender: 'مرد', blood_type: 'A+', education: 'دیپلم', language: 'فارسی', province: 'تهران', district: 'دماوند', ethnicity: 'سادات', religion: 'اسلام', document_type: 'تذکره', document_number: '1346814', marital_status: 'متاهل', children_count: 2, job: 'کارمند', activity_history: 'بدون سابقه', service_location: '__', state: 'دایکندی', address: 'دماوند، خیابان انقلاب', mobile_phone: '09905354215', phone_secondary: '', photo: null, password: demoHash, status: 'فعال', verification: 'در انتظار بررسی', notes: 'نمونه دادهٔ آزمایشی' },
        { registration_no: 'AF-000103', row_number: 3, name: 'رحمان', family_name: 'اخلاقی', father_name: 'محمد حسین', grandfather_name: 'حسین', national_id: '0034567890', birth_date: '1379/08/01', gender: 'مرد', blood_type: 'B+', education: 'سیکل', language: 'فارسی', province: 'سمنان', district: 'شاهرود', ethnicity: 'هزاره', religion: 'اسلام', document_type: 'برگه سرشماری', document_number: '507479', marital_status: 'متاهل', children_count: 3, job: 'کشاورز', activity_history: 'بدون سابقه', service_location: '__', state: 'دایکندی', address: 'سمنان، شاهرود', mobile_phone: '09907995403', phone_secondary: '', photo: null, password: demoHash, status: 'فعال', verification: 'رد شده', notes: 'نمونه دادهٔ آزمایشی' },
        { registration_no: 'AF-000104', row_number: 4, name: 'خدا رحیم', family_name: 'نجاتی', father_name: 'حسین', grandfather_name: 'محمد', national_id: '0044567890', birth_date: '1360/01/01', gender: 'مرد', blood_type: 'AB+', education: 'ابتدایی', language: 'فارسی', province: 'تهران / دماوند', district: 'دماوند', ethnicity: 'تاجیک', religion: 'اسلام', document_type: 'پاسپورت', document_number: '892314', marital_status: 'متاهل', children_count: 4, job: 'سرپرست خانواده', activity_history: 'بدون سابقه', service_location: '__', state: 'غور', address: 'تهران، دماوند', mobile_phone: '09912292791', phone_secondary: '', photo: null, password: demoHash, status: 'غیرفعال', verification: 'در انتظار بررسی', notes: 'نمونه دادهٔ آزمایشی' },
        { registration_no: 'AF-000105', row_number: 5, name: 'عوض', family_name: 'حیدی', father_name: 'یوسف علی', grandfather_name: 'یونس', national_id: '0054567890', birth_date: '1372/05/10', gender: 'زن', blood_type: 'O-', education: 'بی سواد', language: 'فارسی', province: 'تهران / دماوند', district: 'دماوند', ethnicity: 'تاجیک', religion: 'اسلام', document_type: 'تذکره', document_number: '551122', marital_status: 'مجرد', children_count: 0, job: 'خانه‌دار', activity_history: 'بدون سابقه', service_location: '__', state: 'دایکندی', address: 'دماوند', mobile_phone: '09905876449', phone_secondary: '', photo: null, password: demoHash, status: 'فعال', verification: 'تأیید شده', notes: 'نمونه دادهٔ آزمایشی' },
        { registration_no: 'AF-000106', row_number: 6, name: 'زهرا', family_name: 'رضایی', father_name: 'محمد', grandfather_name: 'علی', national_id: '0064567890', birth_date: '1385/11/22', gender: 'زن', blood_type: 'A-', education: 'لیسانس', language: 'فارسی / کردی', province: 'آذربایجان شرقی', district: 'تبریز', ethnicity: 'آذری', religion: 'اسلام', document_type: 'کارت ملی', document_number: '66223344', marital_status: 'متاهل', children_count: 1, job: 'استاد', activity_history: 'بدون سابقه', service_location: '__', state: 'بندر', address: 'تبریز، خیابان 29بهمان', mobile_phone: '09123456789', phone_secondary: '', photo: null, password: demoHash, status: 'فعال', verification: 'تأیید شده', notes: 'نمونه دادهٔ آزمایشی' }
    ];

    const insertCustomer = db.prepare(`
        INSERT INTO customers (
            registration_no, row_number, name, family_name, father_name, grandfather_name,
            national_id, birth_date, gender, blood_type, education, language, province, district,
            ethnicity, religion, document_type, document_number, marital_status, children_count,
            job, activity_history, service_location, state, address, mobile_phone, phone_secondary,
            photo, password, status, verification, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const c of customers) {
        insertCustomer.run(
            c.registration_no, c.row_number, c.name, c.family_name, c.father_name, c.grandfather_name,
            c.national_id, c.birth_date, c.gender, c.blood_type, c.education, c.language, c.province, c.district,
            c.ethnicity, c.religion, c.document_type, c.document_number, c.marital_status, c.children_count,
            c.job, c.activity_history, c.service_location, c.state, c.address, c.mobile_phone, c.phone_secondary,
            c.photo, c.password, c.status, c.verification, c.notes
        );
    }

    const services = [
        { title: 'تأیید شناسه ملی و استعلام', description: 'بررسی و تاییدیه Schengen', status: 'در حال بررسی' },
        { title: 'تغییر نام خانوادگی', description: 'ثبت تغییرات وضعیت خانوادگی', status: 'در حال انجام' },
        { title: 'صدور گواهینامه', description: 'درخواست صدور گواهینامه رانندگی', status: 'انجام شده' },
        { title: 'استعلام', description: 'استعلام در ثبت‌نام', status: 'رد شده' },
        { title: 'ثبت درخواست', description: 'ثبت درخواست جدید', status: 'در حال بررسی' }
    ];

    const insertService = db.prepare('INSERT INTO services (customer_id, title, description, status) VALUES (?, ?, ?, ?)');
    for (let i = 0; i < services.length; i++) {
        insertService.run(i + 1, services[i].title, services[i].description, services[i].status);
    }

    console.log('🎯 Demo data seeded (customers + services)');
}

seedDemoDataIfEmpty();

db.prepare(`UPDATE customers SET registration_no = 'AF-' || printf('%06d', id) WHERE registration_no IS NULL`).run();

module.exports = db;
