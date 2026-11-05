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

module.exports = new DatabaseWrapper();
module.exports.log = log;
module.exports.raw = db;
