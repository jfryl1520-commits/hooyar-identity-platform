const { ready, db } = require('./schema');

function uniqueConstraintMessage(error) {
    const message = String(error?.message || '');
    if (error?.code !== 'SQLITE_CONSTRAINT_UNIQUE' && !message.includes('UNIQUE constraint failed')) return null;
    if (message.includes('national_id')) return 'این کد ملی قبلاً در سامانه ثبت شده است';
    if (message.includes('mobile_phone')) return 'این شماره موبایل قبلاً ثبت شده است';
    if (message.includes('registration_no')) return 'شماره پرونده تکراری است';
    return 'مقدار ورودی یکتا نیست و قبلاً ثبت شده است';
}

class DatabaseWrapper {
    // Awaits schema creation so the first request on a cold serverless
    // container cannot race the CREATE TABLE / seeding steps.
    async query(sql, params = []) {
        await ready;

        const head = sql.trim().slice(0, 6).toUpperCase();
        const reads = /^(SELECT|PRAGMA|WITH)/.test(head);

        if (reads) {
            return [await db.all(sql, params)];
        }
        const info = await db.run(sql, params);
        return [{ insertId: Number(info.lastInsertRowid), affectedRows: Number(info.changes) }];
    }

    async insertLog(actorType, actorName, action, targetId = null, targetName = null, detail = null, ip = null) {
        await this.query(
            'INSERT INTO audit_logs (actor_type, actor_name, action, target_id, target_name, detail, ip) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [actorType, actorName, action, targetId, targetName, detail, ip]);
    }

    async log(actorType, actorName, action, targetId = null, targetName = null, detail = null, ip = null) {
        try {
            await this.insertLog(actorType, actorName, action, targetId, targetName, detail, ip);
        } catch (error) {
            // A failed audit write must never break the operation it records.
            console.error('Audit log write failed:', error.message);
        }
    }
}

module.exports = new DatabaseWrapper();
module.exports.uniqueConstraintMessage = uniqueConstraintMessage;
