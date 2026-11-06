const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../config/database');
const { authMiddleware, customerMiddleware } = require('../middleware/auth');

const router = express.Router();

const PUBLIC_FIELDS = `
    id, registration_no, row_number, name, family_name, father_name, grandfather_name,
    national_id, birth_date, gender, blood_type, education, language, province, district,
    ethnicity, religion, document_type, document_number, marital_status, children_count,
    job, activity_history, service_location, state, address, mobile_phone, phone_secondary,
    photo, status, verification, notes, created_at, updated_at
`;

router.get('/profile', authMiddleware, customerMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query(`SELECT ${PUBLIC_FIELDS} FROM customers WHERE id = ?`, [req.user.id]);
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

router.post('/services', authMiddleware, customerMiddleware, async (req, res) => {
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

        db.raw.prepare('INSERT INTO audit_logs (actor_type, actor_name, action, target_id, ip) VALUES (?,?,?,?,?)')
            .run('customer', req.user.mobile, 'به‌روزرسانی اطلاعات تماس', req.user.id, req.ip);

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

        db.raw.prepare('INSERT INTO audit_logs (actor_type, actor_name, action, target_id, ip) VALUES (?,?,?,?,?)')
            .run('customer', req.user.mobile, 'تغییر رمز عبور', req.user.id, req.ip);

        res.json({ success: true, message: 'رمز عبور تغییر کرد' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ success: false, message: 'خطا در تغییر رمز عبور' });
    }
});

module.exports = router;
