const db = require('./schema');

class DatabaseWrapper {
    async query(sql, params = []) {
        const head = sql.trim().slice(0, 6).toUpperCase();
        const stmt = db.prepare(sql);

        if (head.startsWith('SELECT') || head.startsWith('PRAGMA') || head.startsWith('WITH')) {
            return [params.length ? stmt.all(...params) : stmt.all()];
        }

        const info = params.length ? stmt.run(...params) : stmt.run();
        return [{ insertId: info.lastInsertRowid, affectedRows: info.changes }];
    }
}

function log(actorType, actorName, action, targetId = null, targetName = null, detail = null, ip = null) {
    db.prepare(
        'INSERT INTO audit_logs (actor_type, actor_name, action, target_id, target_name, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(actorType, actorName, action, targetId, targetName, detail, ip);
}

// Translates an SQLite UNIQUE violation into a field-specific message so the
// client learns which value collided instead of always blaming the mobile number.
function uniqueConstraintMessage(error) {
    const message = String(error?.message || '');
    if (error?.code !== 'SQLITE_CONSTRAINT_UNIQUE' && !message.includes('UNIQUE constraint failed')) return null;
    if (message.includes('national_id')) return 'این کد ملی قبلاً در سامانه ثبت شده است';
    if (message.includes('mobile_phone')) return 'این شماره موبایل قبلاً ثبت شده است';
    if (message.includes('registration_no')) return 'شماره پرونده تکراری است';
    return 'مقدار ورودی یکتا نیست و قبلاً ثبت شده است';
}

module.exports = new DatabaseWrapper();
module.exports.log = log;
module.exports.raw = db;
module.exports.uniqueConstraintMessage = uniqueConstraintMessage;
