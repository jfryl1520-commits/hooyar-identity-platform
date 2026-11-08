const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../config/database');
const { authMiddleware, adminMiddleware } = require('../middleware/auth');

const router = express.Router();
// Public headline numbers for the landing page. Aggregate only — no record
// names, no personal data, no per-record detail.
router.get('/public-summary', async (req, res) => {
    try {
        const one = async (sql) => (await db.query(sql))[0][0].c;
        res.json({
            success: true,
            summary: {
                total: await one('SELECT COUNT(*) AS c FROM customers'),
                verified: await one("SELECT COUNT(*) AS c FROM customers WHERE verification = 'تأیید شده'"),
                servicesOpen: await one("SELECT COUNT(*) AS c FROM services WHERE status != 'انجام شده'")
            }
        });
    } catch (error) {
        console.error('Get public summary error:', error);
        res.status(500).json({ success: false, message: 'خطا در دریافت آمار' });
    }
});

router.use(authMiddleware, adminMiddleware);

const FIELDS = [
    'name', 'family_name', 'father_name', 'grandfather_name', 'national_id', 'birth_date',
    'gender', 'blood_type', 'education', 'language', 'province', 'district', 'ethnicity',
    'religion', 'document_type', 'document_number', 'marital_status', 'children_count',
    'job', 'activity_history', 'service_location', 'state', 'address', 'mobile_phone',
    'phone_secondary', 'photo', 'status', 'verification', 'notes', 'row_number'
];

const NUMERIC_FIELDS = { children_count: 0, row_number: 1 };
const TEXT_LIMITS = {
    name: 100, family_name: 100, father_name: 100, grandfather_name: 100,
    national_id: 30, birth_date: 20, gender: 20, blood_type: 10, education: 80,
    language: 120, province: 80, district: 80, ethnicity: 80, religion: 40,
    document_type: 60, document_number: 60, marital_status: 30, job: 120,
    activity_history: 1000, service_location: 120, state: 80, address: 500,
    phone_secondary: 15, photo: 500, notes: 2000
};
const ALLOWED = {
    status: ['فعال', 'غیرفعال', 'مسدود'],
    verification: ['در انتظار بررسی', 'تأیید شده', 'رد شده']
};

// Returns an error message for invalid input, or null when the payload is fine.
// Fields absent from the payload are not validated (partial updates are legal).
function validateCustomerInput(data) {
    for (const [field, max] of Object.entries(TEXT_LIMITS)) {
        if (!Object.prototype.hasOwnProperty.call(data, field) || data[field] === null) continue;
        if (String(data[field]).length > max) {
            return `مقدار فیلد «${field}» بیش از ${max} نویسه است`;
        }
    }
    for (const [field, min] of Object.entries(NUMERIC_FIELDS)) {
        if (!Object.prototype.hasOwnProperty.call(data, field) || data[field] === null || data[field] === '') continue;
        const value = Number(data[field]);
        if (!Number.isInteger(value) || value < min || value > 100) {
            return `مقدار فیلد «${field}» باید عددی بین ${min} و ۱۰۰ باشد`;
        }
    }
    for (const [field, allowed] of Object.entries(ALLOWED)) {
        if (!Object.prototype.hasOwnProperty.call(data, field) || !data[field]) continue;
        if (!allowed.includes(data[field])) return `مقدار فیلد «${field}» نامعتبر است`;
    }
    if (data.national_id) {
        const digits = String(data.national_id).replace(/[^\d]/g, '');
        if (digits.length < 6 || digits.length > 20) return 'کد ملی معتبر نیست';
    }
    if (Object.prototype.hasOwnProperty.call(data, 'name') && !String(data.name || '').trim()) {
        return 'نام نمی‌تواند خالی باشد';
    }
    return null;
}

function buildFilters(query) {
    const where = [];
    const params = [];

    if (query.search) {
        const q = `%${query.search}%`;
        where.push('(name LIKE ? OR family_name LIKE ? OR mobile_phone LIKE ? OR national_id LIKE ? OR registration_no LIKE ? OR father_name LIKE ?)');
        params.push(q, q, q, q, q, q);
    }
    if (query.status) { where.push('status = ?'); params.push(query.status); }
    if (query.verification) { where.push('verification = ?'); params.push(query.verification); }
    if (query.province) { where.push('province LIKE ?'); params.push(`%${query.province}%`); }
    if (query.ethnicity) { where.push('ethnicity = ?'); params.push(query.ethnicity); }
    if (query.education) { where.push('education = ?'); params.push(query.education); }

    return { clause: where.length ? 'WHERE ' + where.join(' AND ') : '', params };
}

router.get('/customers', async (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 20));
        const sortMap = {
            newest: 'id DESC', oldest: 'id ASC',
            name: 'name ASC', family: 'family_name ASC'
        };
        const order = sortMap[req.query.sort] || 'id DESC';

        const { clause, params } = buildFilters(req.query);

        const [rows] = await db.query(
            `SELECT id, registration_no, row_number, name, family_name, father_name, national_id,
                    birth_date, gender, education, province, ethnicity, mobile_phone, photo,
                    status, verification, created_at
             FROM customers ${clause} ORDER BY ${order} LIMIT ? OFFSET ?`,
            [...params, limit, (page - 1) * limit]
        );

        const [countRows] = await db.query(`SELECT COUNT(*) AS total FROM customers ${clause}`, params);
        const total = countRows[0].total;

        res.json({
            success: true,
            customers: rows,
            pagination: { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) }
        });
    } catch (error) {
        console.error('Get customers error:', error);
        res.status(500).json({ success: false, message: 'خطا در دریافت لیست پرونده‌ها' });
    }
});

router.get('/customers/export', async (req, res) => {
    try {
        const { clause, params } = buildFilters(req.query);
        const [rows] = await db.query(`SELECT * FROM customers ${clause} ORDER BY id`, params);

        const headers = ['کد پرونده', 'نام', 'نام خانوادگی', 'نام پدر', 'کد ملی', 'موبایل',
                         'استان', 'قومیت', 'تحصیلات', 'وضعیت', 'تأیید', 'تاریخ ثبت'];

        const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const lines = [headers.map(escape).join(',')];

        rows.forEach(r => {
            lines.push([
                r.registration_no, r.name, r.family_name, r.father_name, r.national_id,
                r.mobile_phone, r.province, r.ethnicity, r.education, r.status, r.verification,
                r.created_at
            ].map(escape).join(','));
        });

        db.log('admin', req.user.username, 'خروجی اکسل پرونده‌ها', null, null, `${rows.length} رکورد`, req.ip);

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="customers-${Date.now()}.csv"`);
        res.send('﻿' + lines.join('\r\n'));
    } catch (error) {
        console.error('Export error:', error);
        res.status(500).json({ success: false, message: 'خطا در تولید خروجی' });
    }
});

router.get('/customers/:id', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM customers WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'پرونده یافت نشد' });

        const customer = rows[0];
        delete customer.password;

        const [services] = await db.query(
            'SELECT * FROM services WHERE customer_id = ? ORDER BY created_at DESC', [req.params.id]);

        const [logs] = await db.query(
            'SELECT * FROM audit_logs WHERE target_id = ? ORDER BY created_at DESC LIMIT 20', [req.params.id]);

        res.json({ success: true, customer, services, logs });
    } catch (error) {
        console.error('Get customer error:', error);
        res.status(500).json({ success: false, message: 'خطا در دریافت پرونده' });
    }
});

router.post('/customers', async (req, res) => {
    try {
        const data = req.body;
        const name = String(data.name || '').trim();
        const mobile = String(data.mobile_phone || '').replace(/[^\d]/g, '');
        const password = String(data.password || '');

        if (!name || mobile.length < 10 || mobile.length > 15) {
            return res.status(400).json({ success: false, message: 'نام و شماره موبایل معتبر الزامی است' });
        }
        if (password.length < 8) {
            return res.status(400).json({ success: false, message: 'گذرواژه باید حداقل ۸ کاراکتر باشد' });
        }

        const invalid = validateCustomerInput(data);
        if (invalid) return res.status(400).json({ success: false, message: invalid });

        const createFields = FIELDS.filter(field => !['mobile_phone', 'row_number', 'status', 'verification'].includes(field));
        const values = createFields.map(field => {
            const value = data[field] ?? null;
            return field === 'children_count' && value !== null ? Number(value) : value;
        });
        const insertFields = [...createFields, 'mobile_phone', 'password', 'status', 'verification'];
        const hashed = await bcrypt.hash(password, 10);
        const placeholders = insertFields.map(() => '?').join(', ');

        const result = await db.query(
            `INSERT INTO customers (${insertFields.join(', ')}) VALUES (${placeholders})`,
            [...values, mobile, hashed, 'فعال', 'در انتظار بررسی']
        );

        const id = result[0].insertId;
        await db.query('UPDATE customers SET registration_no = ? WHERE id = ?',
            [`AF-${String(id).padStart(6, '0')}`, id]);

        db.log('admin', req.user.username, 'ثبت پرونده جدید', id, name, null, req.ip);

        res.status(201).json({ success: true, message: 'پرونده با موفقیت ثبت شد', id,
            registration_no: `AF-${String(id).padStart(6, '0')}` });
    } catch (error) {
        const uniqueMessage = db.uniqueConstraintMessage(error);
        if (uniqueMessage) {
            return res.status(400).json({ success: false, message: uniqueMessage });
        }
        console.error('Create customer error:', error);
        res.status(500).json({ success: false, message: 'خطا در ثبت پرونده' });
    }
});

router.put('/customers/:id', async (req, res) => {
    try {
        const [existing] = await db.query('SELECT id FROM customers WHERE id = ?', [req.params.id]);
        if (!existing.length) return res.status(404).json({ success: false, message: 'پرونده یافت نشد' });

        const data = req.body;
        const invalid = validateCustomerInput(data);
        if (invalid) return res.status(400).json({ success: false, message: invalid });

        const sets = [];
        const params = [];

        // Only update fields the client actually sent, so a partial payload can
        // never wipe the rest of the record to NULL.
        for (const field of FIELDS) {
            if (!Object.prototype.hasOwnProperty.call(data, field)) continue;
            let value = data[field] ?? null;
            if (field === 'mobile_phone') value = String(value).replace(/[^\d]/g, '');
            if (field === 'children_count' && value !== null) value = Number(value);
            sets.push(`${field} = ?`);
            params.push(value);
        }

        if (data.password) {
            if (String(data.password).length < 8) {
                return res.status(400).json({ success: false, message: 'رمز عبور باید حداقل ۸ کاراکتر باشد' });
            }
            // Setting the password here must not clear the MFA registration:
            // doing so would let an admin strip their own second factor. Disabling
            // MFA happens only through /api/auth/admin/mfa/disable, which needs the
            // current password AND a valid TOTP code.
            sets.push('password = ?');
            params.push(await bcrypt.hash(data.password, 10));
        }

        if (!sets.length) return res.status(400).json({ success: false, message: 'تغییری مشخص نشده' });

        sets.push('updated_at = CURRENT_TIMESTAMP');
        params.push(req.params.id);

        await db.query(`UPDATE customers SET ${sets.join(', ')} WHERE id = ?`, params);
        db.log('admin', req.user.username, 'ویرایش پرونده', req.params.id, data.name || null,
               data.password ? 'شامل تغییر گذرواژه' : null, req.ip);

        res.json({ success: true, message: 'پرونده به‌روزرسانی شد' });
    } catch (error) {
        const uniqueMessage = db.uniqueConstraintMessage(error);
        if (uniqueMessage) {
            return res.status(400).json({ success: false, message: uniqueMessage });
        }
        console.error('Update customer error:', error);
        res.status(500).json({ success: false, message: 'خطا در به‌روزرسانی پرونده' });
    }
});

router.patch('/customers/:id/status', async (req, res) => {
    try {
        const { status, verification } = req.body;
        const allowedStatus = ['فعال', 'غیرفعال', 'مسدود'];
        const allowedVerify = ['در انتظار بررسی', 'تأیید شده', 'رد شده'];

        const sets = [];
        const params = [];

        if (status) {
            if (!allowedStatus.includes(status)) return res.status(400).json({ success: false, message: 'وضعیت نامعتبر' });
            sets.push('status = ?'); params.push(status);
        }
        if (verification) {
            if (!allowedVerify.includes(verification)) return res.status(400).json({ success: false, message: 'وضعیت بررسی نامعتبر' });
            sets.push('verification = ?'); params.push(verification);
        }
        if (!sets.length) return res.status(400).json({ success: false, message: 'تغییری مشخص نشده' });

        sets.push('updated_at = CURRENT_TIMESTAMP');
        params.push(req.params.id);

        await db.query(`UPDATE customers SET ${sets.join(', ')} WHERE id = ?`, params);
        db.log('admin', req.user.username, 'تغییر وضعیت پرونده', req.params.id, null,
               [status, verification].filter(Boolean).join(' / '), req.ip);

        res.json({ success: true, message: 'وضعیت به‌روزرسانی شد' });
    } catch (error) {
        console.error('Patch status error:', error);
        res.status(500).json({ success: false, message: 'خطا در تغییر وضعیت' });
    }
});

router.delete('/customers/:id', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT name, family_name, registration_no FROM customers WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'پرونده یافت نشد' });

        // CASCADE removes the customer's service requests too; the audit trail
        // stays behind on purpose so deletions remain traceable.
        await db.query('DELETE FROM customers WHERE id = ?', [req.params.id]);
        db.log('admin', req.user.username, 'حذف پرونده', req.params.id,
               `${rows[0].name} ${rows[0].family_name}`, rows[0].registration_no, req.ip);

        res.json({ success: true, message: 'پرونده حذف شد' });
    } catch (error) {
        console.error('Delete customer error:', error);
        res.status(500).json({ success: false, message: 'خطا در حذف پرونده' });
    }
});

router.get('/stats', async (req, res) => {
    try {
        const one = async (sql, params = []) => (await db.query(sql, params))[0][0];

        const total = (await one('SELECT COUNT(*) AS c FROM customers')).c;
        const active = (await one("SELECT COUNT(*) AS c FROM customers WHERE status = 'فعال'")).c;
        const blocked = (await one("SELECT COUNT(*) AS c FROM customers WHERE status = 'مسدود'")).c;
        const pending = (await one("SELECT COUNT(*) AS c FROM customers WHERE verification = 'در انتظار بررسی'")).c;
        const verified = (await one("SELECT COUNT(*) AS c FROM customers WHERE verification = 'تأیید شده'")).c;
        const thisMonth = (await one("SELECT COUNT(*) AS c FROM customers WHERE created_at >= date('now','start of month')")).c;
        const servicesOpen = (await one("SELECT COUNT(*) AS c FROM services WHERE status != 'انجام شده'")).c;

        const [byProvince] = await db.query(
            `SELECT province, COUNT(*) AS count FROM customers
             WHERE province IS NOT NULL AND province != '' GROUP BY province ORDER BY count DESC LIMIT 8`);

        const [byEducation] = await db.query(
            `SELECT education, COUNT(*) AS count FROM customers
             WHERE education IS NOT NULL AND education != '' GROUP BY education ORDER BY count DESC LIMIT 8`);

        const [byEthnicity] = await db.query(
            `SELECT ethnicity, COUNT(*) AS count FROM customers
             WHERE ethnicity IS NOT NULL AND ethnicity != '' GROUP BY ethnicity ORDER BY count DESC LIMIT 8`);

        const [byGender] = await db.query(
            `SELECT gender, COUNT(*) AS count FROM customers
             WHERE gender IS NOT NULL AND gender != '' GROUP BY gender`);

        const [recent] = await db.query(
            `SELECT id, registration_no, name, family_name, mobile_phone, province, status, verification, created_at
             FROM customers ORDER BY id DESC LIMIT 8`);

        const [monthly] = await db.query(
            `SELECT strftime('%Y-%m', created_at) AS month, COUNT(*) AS count
             FROM customers GROUP BY month ORDER BY month DESC LIMIT 12`);

        const [marital] = await db.query(
            `SELECT marital_status, COUNT(*) AS count FROM customers
             WHERE marital_status IS NOT NULL AND marital_status != '' GROUP BY marital_status`);

        res.json({
            success: true,
            stats: {
                total, active, blocked, pending, verified, thisMonth, servicesOpen,
                by_province: byProvince,
                by_education: byEducation,
                by_ethnicity: byEthnicity,
                by_gender: byGender,
                by_marital: marital,
                monthly: monthly.reverse(),
                recent
            }
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ success: false, message: 'خطا در دریافت آمار' });
    }
});

router.get('/logs', async (req, res) => {
    try {
        const limit = Math.min(200, parseInt(req.query.limit) || 60);
        const [logs] = await db.query(
            'SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?', [limit]);
        res.json({ success: true, logs });
    } catch (error) {
        console.error('Get logs error:', error);
        res.status(500).json({ success: false, message: 'خطا در دریافت لاگ‌ها' });
    }
});

router.get('/services', async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT s.*, c.name, c.family_name, c.registration_no
             FROM services s JOIN customers c ON c.id = s.customer_id
             ORDER BY s.created_at DESC LIMIT 100`);
        res.json({ success: true, services: rows });
    } catch (error) {
        res.status(500).json({ success: false, message: 'خطا در دریافت درخواست‌ها' });
    }
});

router.post('/services', async (req, res) => {
    try {
        const { customer_id, title, description } = req.body;
        if (!customer_id || !title) {
            return res.status(400).json({ success: false, message: 'پرونده و عنوان خدمت الزامی است' });
        }
        const result = await db.query(
            "INSERT INTO services (customer_id, title, description, status) VALUES (?, ?, ?, 'در حال بررسی')",
            [customer_id, title, description || null]);
        db.log('admin', req.user.username, 'ثبت درخواست خدمت', customer_id, title, null, req.ip);
        res.status(201).json({ success: true, id: result[0].insertId });
    } catch (error) {
        res.status(500).json({ success: false, message: 'خطا در ثبت درخواست' });
    }
});

router.patch('/services/:id', async (req, res) => {
    try {
        const allowed = ['در حال بررسی', 'در حال انجام', 'انجام شده', 'رد شده'];
        if (!allowed.includes(req.body.status)) {
            return res.status(400).json({ success: false, message: 'وضعیت نامعتبر' });
        }
        await db.query('UPDATE services SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
        db.log('admin', req.user.username, 'تغییر وضعیت درخواست', req.params.id, null, req.body.status, req.ip);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'خطا در تغییر وضعیت' });
    }
});

router.get('/meta', async (req, res) => {
    try {
        const distinct = async col =>
            (await db.query(`SELECT DISTINCT ${col} AS v FROM customers WHERE ${col} IS NOT NULL AND ${col} != '' ORDER BY v`))[0]
                .map(r => r.v);
        res.json({
            success: true,
            meta: {
                provinces: await distinct('province'),
                educations: await distinct('education'),
                ethnicities: await distinct('ethnicity')
            }
        });
    } catch {
        res.status(500).json({ success: false, message: 'خطا' });
    }
});

module.exports = router;
