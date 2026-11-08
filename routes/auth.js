const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { authMiddleware, adminMiddleware } = require('../middleware/auth');
const { createSetup, encryptSecret, decryptSecret, verifyToken } = require('../lib/totp');

const router = express.Router();
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;

function throttleLogin(req, res, next) {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    let attempt = loginAttempts.get(key);
    if (!attempt || attempt.resetAt <= now) attempt = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
        res.set('Retry-After', String(Math.ceil((attempt.resetAt - now) / 1000)));
        return res.status(429).json({ success: false, message: 'تلاش‌های ورود بیش از حد مجاز است؛ کمی بعد دوباره تلاش کنید' });
    }
    attempt.count += 1;
    loginAttempts.set(key, attempt);
    req.loginAttemptKey = key;
    if (loginAttempts.size > 10000) {
        for (const [candidate, value] of loginAttempts) if (value.resetAt <= now) loginAttempts.delete(candidate);
    }
    next();
}

function issueAdminToken(admin) {
    return jwt.sign(
        { id: admin.id, username: admin.username, role: admin.role, type: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
    );
}

function logAdminAction(admin, action, req) {
    db.raw.prepare('INSERT INTO audit_logs (actor_type, actor_name, action, target_id, ip) VALUES (?,?,?,?,?)')
        .run('admin', admin.username, action, admin.id, req.ip);
}

function safeDecryptSecret(encrypted) {
    try {
        return decryptSecret(encrypted);
    } catch {
        return null;
    }
}

router.post('/customer/login', throttleLogin, async (req, res) => {
    try {
        const mobile = String(req.body.mobile || '').replace(/[^\d]/g, '');
        const { password } = req.body;

        if (!mobile || !password) {
            return res.status(400).json({ success: false, message: 'شماره موبایل و رمز عبور الزامی است' });
        }

        const [rows] = await db.query('SELECT * FROM customers WHERE mobile_phone = ?', [mobile]);
        if (!rows.length) {
            return res.status(401).json({ success: false, message: 'شماره موبایل یا رمز عبور اشتباه است' });
        }

        const customer = rows[0];
        if (customer.status === 'مسدود') {
            return res.status(403).json({ success: false, message: 'حساب کاربری شما مسدود شده است. با پشتیبانی تماس بگیرید' });
        }

        const ok = await bcrypt.compare(password, customer.password);
        if (!ok) {
            return res.status(401).json({ success: false, message: 'شماره موبایل یا رمز عبور اشتباه است' });
        }

        const token = jwt.sign(
            { id: customer.id, mobile: customer.mobile_phone, type: 'customer' },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        db.raw.prepare('INSERT INTO audit_logs (actor_type, actor_name, action, target_id, target_name, ip) VALUES (?,?,?,?,?,?)')
            .run('customer', `${customer.name} ${customer.family_name}`, 'ورود به پورتال', customer.id,
                 customer.registration_no, req.ip);
        loginAttempts.delete(req.loginAttemptKey);

        res.json({
            success: true,
            token,
            customer: { id: customer.id, name: customer.name, registration_no: customer.registration_no }
        });
    } catch (error) {
        console.error('Customer login error:', error);
        res.status(500).json({ success: false, message: 'خطا در ورود به سیستم' });
    }
});

router.post('/admin/login', throttleLogin, async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'نام کاربری و رمز عبور الزامی است' });
        }

        const [rows] = await db.query('SELECT * FROM admins WHERE username = ?', [username]);
        if (!rows.length) {
            return res.status(401).json({ success: false, message: 'نام کاربری یا رمز عبور اشتباه است' });
        }

        const admin = rows[0];
        const ok = await bcrypt.compare(password, admin.password);
        if (!ok) {
            return res.status(401).json({ success: false, message: 'نام کاربری یا رمز عبور اشتباه است' });
        }

        // A manager who has set up TOTP must never reach a full admin session
        // with the password alone: a second database copy, a backup restore, a
        // rotated secret, or any local password change would otherwise become a
        // way around the second factor. Remediation has to go through someone
        // with device access, or through an explicit offline reset procedure.
        if (admin.mfa_enabled) {
            const usableSecret = admin.mfa_secret && safeDecryptSecret(admin.mfa_secret);
            if (!usableSecret) {
                console.error(`MFA secret for admin ${admin.username} could not be decrypted; blocking password-only login`);
                return res.status(409).json({
                    success: false,
                    message: 'کلید ورود دومرحله‌ای این حساب قابل خواندن نیست؛ برای بازیابی با پشتیبانی تماس بگیرید'
                });
            }
        }

        loginAttempts.delete(req.loginAttemptKey);

        if (admin.mfa_enabled) {
            return res.json({
                success: true,
                mfa_required: true,
                challenge_token: jwt.sign({ id: admin.id, type: 'admin_mfa' }, process.env.JWT_SECRET, { expiresIn: '5m' })
            });
        }

        await db.query('UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [admin.id]);
        logAdminAction(admin, 'ورود به پنل مدیریت', req);

        res.json({
            success: true,
            token: issueAdminToken(admin),
            admin: { id: admin.id, username: admin.username, full_name: admin.full_name, role: admin.role }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ success: false, message: 'خطا در ورود به سیستم' });
    }
});

router.post('/admin/verify-mfa', throttleLogin, async (req, res) => {
    try {
        const challenge = jwt.verify(String(req.body.challenge_token || ''), process.env.JWT_SECRET);
        if (challenge.type !== 'admin_mfa') return res.status(401).json({ success: false, message: 'درخواست ورود معتبر نیست' });

        const [rows] = await db.query('SELECT * FROM admins WHERE id = ? AND mfa_enabled = 1', [challenge.id]);
        if (!rows.length) return res.status(401).json({ success: false, message: 'درخواست ورود معتبر نیست' });
        const admin = rows[0];
        const step = verifyToken(decryptSecret(admin.mfa_secret), req.body.code);
        if (step === null || step <= Number(admin.mfa_last_step || 0)) {
            return res.status(401).json({ success: false, message: 'کد یک‌بارمصرف نامعتبر یا استفاده‌شده است' });
        }

        const changed = db.raw.prepare('UPDATE admins SET mfa_last_step = ?, last_login = CURRENT_TIMESTAMP WHERE id = ? AND mfa_last_step < ?')
            .run(step, admin.id, step);
        if (!changed.changes) return res.status(401).json({ success: false, message: 'کد یک‌بارمصرف قبلاً استفاده شده است' });
        loginAttempts.delete(req.loginAttemptKey);
        logAdminAction(admin, 'ورود دومرحله‌ای به پنل مدیریت', req);
        res.json({ success: true, token: issueAdminToken(admin),
            admin: { id: admin.id, username: admin.username, full_name: admin.full_name, role: admin.role } });
    } catch (error) {
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: 'درخواست ورود منقضی شده؛ دوباره وارد شوید' });
        }
        console.error('Admin MFA error:', error);
        res.status(500).json({ success: false, message: 'خطا در بررسی کد یک‌بارمصرف' });
    }
});

router.post('/admin/mfa/setup', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT password, mfa_enabled FROM admins WHERE id = ?', [req.user.id]);
        if (!rows.length || !(await bcrypt.compare(String(req.body.current_password || ''), rows[0].password))) {
            return res.status(401).json({ success: false, message: 'گذرواژه فعلی نادرست است' });
        }
        if (rows[0].mfa_enabled) return res.status(409).json({ success: false, message: 'ورود دومرحله‌ای از قبل فعال است' });
        const setup = createSetup(req.user.username);
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
        await db.query('UPDATE admins SET mfa_secret = ?, mfa_setup_expires_at = ? WHERE id = ?',
            [encryptSecret(setup.secret), expiresAt, req.user.id]);
        res.json({ success: true, secret: setup.secret, uri: setup.uri, expires_at: expiresAt });
    } catch (error) {
        console.error('MFA setup error:', error);
        res.status(500).json({ success: false, message: 'خطا در آغاز راه‌اندازی ورود دومرحله‌ای' });
    }
});

router.get('/admin/mfa/status', authMiddleware, adminMiddleware, async (req, res) => {
    const [rows] = await db.query('SELECT mfa_enabled FROM admins WHERE id = ?', [req.user.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'حساب مدیر پیدا نشد' });
    res.json({ success: true, enabled: Boolean(rows[0].mfa_enabled) });
});

router.post('/admin/mfa/enable', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT mfa_secret, mfa_enabled, mfa_setup_expires_at, mfa_last_step FROM admins WHERE id = ?', [req.user.id]);
        const admin = rows[0];
        if (!admin || admin.mfa_enabled || !admin.mfa_secret || Date.parse(admin.mfa_setup_expires_at || '') < Date.now()) {
            return res.status(400).json({ success: false, message: 'راه‌اندازی ورود دومرحله‌ای منقضی شده؛ دوباره شروع کنید' });
        }
        const step = verifyToken(decryptSecret(admin.mfa_secret), req.body.code);
        if (step === null || step <= Number(admin.mfa_last_step || 0)) {
            return res.status(400).json({ success: false, message: 'کد تأیید نامعتبر است' });
        }
        await db.query('UPDATE admins SET mfa_enabled = 1, mfa_last_step = ?, mfa_setup_expires_at = NULL WHERE id = ?', [step, req.user.id]);
        logAdminAction(req.user, 'فعال‌سازی ورود دومرحله‌ای', req);
        res.json({ success: true, message: 'ورود دومرحله‌ای فعال شد' });
    } catch (error) {
        console.error('MFA enable error:', error);
        res.status(500).json({ success: false, message: 'خطا در فعال‌سازی ورود دومرحله‌ای' });
    }
});

router.post('/admin/mfa/disable', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT password, mfa_secret, mfa_enabled, mfa_last_step FROM admins WHERE id = ?', [req.user.id]);
        const admin = rows[0];
        if (!admin || !(await bcrypt.compare(String(req.body.current_password || ''), admin.password))) {
            return res.status(401).json({ success: false, message: 'گذرواژه فعلی نادرست است' });
        }
        if (admin.mfa_enabled) {
            const step = verifyToken(decryptSecret(admin.mfa_secret), req.body.code);
            if (step === null || step <= Number(admin.mfa_last_step || 0)) {
                return res.status(401).json({ success: false, message: 'کد یک‌بارمصرف نادرست است' });
            }
        }
        await db.query('UPDATE admins SET mfa_secret = NULL, mfa_enabled = 0, mfa_last_step = 0, mfa_setup_expires_at = NULL WHERE id = ?', [req.user.id]);
        logAdminAction(req.user, 'غیرفعال‌سازی ورود دومرحله‌ای', req);
        res.json({ success: true, message: 'ورود دومرحله‌ای غیرفعال شد' });
    } catch (error) {
        console.error('MFA disable error:', error);
        res.status(500).json({ success: false, message: 'خطا در غیرفعال‌سازی ورود دومرحله‌ای' });
    }
});

module.exports = router;
