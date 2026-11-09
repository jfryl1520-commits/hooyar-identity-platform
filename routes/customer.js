const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../config/database');
const { authMiddleware, customerMiddleware } = require('../middleware/auth');

const router = express.Router();

// Deliberately narrow: a citizen portal must not expose the analyst's internal
// notes, document scan numbers, or the sensitive classification fields
// (ethnicity, religion, blood type, activity history). Those stay admin-only.
const CUSTOMER_PORTAL_FIELDS = `
    id, registration_no, name, family_name, father_name, grandfather_name, birth_date, gender,
    education, language, province, district, state, job, marital_status, children_count,
    address, mobile_phone, phone_secondary, status, verification, created_at, updated_at
`;

// Simple per-process limiter for the only customer endpoint that writes data on
// its own. Eight requests per ten minutes per IP keeps the queue clean without
// punishing an honest user.
const SERVICE_WINDOW_MS = 10 * 60 * 1000;
const SERVICE_MAX_REQUESTS = 8;
const serviceAttempts = new Map();

function throttleServiceCreation(req, res, next) {
    const key = req.ip;
    const now = Date.now();
    let entry = serviceAttempts.get(key);
    if (!entry || entry.resetAt <= now) entry = { count: 0, resetAt: now + SERVICE_WINDOW_MS };
    if (entry.count >= SERVICE_MAX_REQUESTS) {
        res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
        return res.status(429).json({ success: false, message: 'تعداد درخواست‌ها بیش از حد مجاز است؛ کمی بعد دوباره تلاش کنید' });
    }
    entry.count += 1;
    serviceAttempts.set(key, entry);
    if (serviceAttempts.size > 5000) {
        for (const [candidate, value] of serviceAttempts) if (value.resetAt <= now) serviceAttempts.delete(candidate);
    }
    next();
}

router.get('/profile', authMiddleware, customerMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query(`SELECT ${CUSTOMER_PORTAL_FIELDS} FROM customers WHERE id = ?`, [req.user.id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'پرونده یافت نشد' });

        const [services] = await db.query(
            'SELECT id, title, status, description, created_at FROM services WHERE customer_id = ? ORDER BY created_at DESC',
            [req.user.id]
        );

        res.json({ success: true, customer: rows[0], services });
    } catch (error) {
        console.error('Get customer profile error:', error);
        res.status(500).json({ success: false, message: 'خطا در دریافت اطلاعات' });
    }
});

router.post('/services', authMiddleware, customerMiddleware, throttleServiceCreation, async (req, res) => {
    try {
        const title = String(req.body.title || '').trim().slice(0, 120);
        const description = String(req.body.description || '').trim().slice(0, 1000);
        if (!title) return res.status(400).json({ success: false, message: 'عنوان درخواست الزامی است' });

        const result = await db.query(
            "INSERT INTO services (customer_id, title, description, status) VALUES (?, ?, ?, 'در حال بررسی')",
            [req.user.id, title, description || null]
        );
        db.log('customer', req.user.mobile, 'ثبت درخواست خدمت', result[0].insertId, title, null, req.ip);
        res.status(201).json({ success: true, id: result[0].insertId, message: 'درخواست شما ثبت شد' });
    } catch (error) {
        console.error('Create customer service error:', error);
        res.status(500).json({ success: false, message: 'خطا در ثبت درخواست' });
    }
});

router.put('/profile/contact', authMiddleware, customerMiddleware, async (req, res) => {
    try {
        const address = String(req.body.address || '').slice(0, 500);
        const phone = String(req.body.phone_secondary || '').replace(/[^\d]/g, '').slice(0, 15);

        await db.query('UPDATE customers SET address = ?, phone_secondary = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [address, phone, req.user.id]);

        await db.log('customer', req.user.mobile, 'به‌روزرسانی اطلاعات تماس', req.user.id, null, null, req.ip);

        res.json({ success: true, message: 'اطلاعات تماس به‌روزرسانی شد' });
    } catch (error) {
        console.error('Update contact error:', error);
        res.status(500).json({ success: false, message: 'خطا در ذخیره اطلاعات' });
    }
});

router.post('/change-password', authMiddleware, customerMiddleware, async (req, res) => {
    try {
        const { current_password, new_password } = req.body;

        if (!current_password || !new_password) {
            return res.status(400).json({ success: false, message: 'رمز فعلی و رمز جدید الزامی است' });
        }
        if (String(new_password).length < 6) {
            return res.status(400).json({ success: false, message: 'رمز جدید باید حداقل ۶ کاراکتر باشد' });
        }

        const [rows] = await db.query('SELECT password FROM customers WHERE id = ?', [req.user.id]);
        const ok = await bcrypt.compare(current_password, rows[0].password);
        if (!ok) {
            return res.status(400).json({ success: false, message: 'رمز عبور فعلی اشتباه است' });
        }

        const hashed = await bcrypt.hash(new_password, 10);
        await db.query('UPDATE customers SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [hashed, req.user.id]);

        await db.log('customer', req.user.mobile, 'تغییر رمز عبور', req.user.id, null, null, req.ip);

        res.json({ success: true, message: 'رمز عبور تغییر کرد' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ success: false, message: 'خطا در تغییر رمز عبور' });
    }
});

module.exports = router;
