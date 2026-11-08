const express = require('express');
const path = require('path');
require('dotenv').config();

const SAMPLE_JWT_SECRET = 'replace-with-a-random-secret-of-at-least-32-characters';
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be configured with at least 32 characters');
}
if (process.env.JWT_SECRET === SAMPLE_JWT_SECRET) {
    throw new Error('JWT_SECRET is still the sample value from .env.example; generate a random secret');
}

const authRoutes = require('./routes/auth');
const customerRoutes = require('./routes/customer');
const adminRoutes = require('./routes/admin');

const app = express();

app.disable('x-powered-by');
// Behind Railway/nginx the socket peer is the proxy, so every user would share
// one rate-limit bucket unless the real client address is trusted.
if (process.env.TRUST_PROXY) {
    const value = /^\d+$/.test(process.env.TRUST_PROXY) ? Number(process.env.TRUST_PROXY) : process.env.TRUST_PROXY === 'true' ? 1 : process.env.TRUST_PROXY;
    app.set('trust proxy', value);
}
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => {
    res.json({ success: true, status: 'ok' });
});

app.use('/api/auth', authRoutes);
app.use('/api/customer', customerRoutes);
app.use('/api/admin', adminRoutes);

app.get('/', (req, res) => {
    res.json({
        message: 'هویار | سامانه مدیریت هویت',
        version: '1.1.0',
        endpoints: {
            auth: {
                customer_login: 'POST /api/auth/customer/login',
                admin_login: 'POST /api/auth/admin/login'
            },
            customer: {
                profile: 'GET /api/customer/profile'
            },
            admin: {
                customers: 'GET /api/admin/customers',
                get_customer: 'GET /api/admin/customers/:id',
                create_customer: 'POST /api/admin/customers',
                update_customer: 'PUT /api/admin/customers/:id',
                delete_customer: 'DELETE /api/admin/customers/:id',
                stats: 'GET /api/admin/stats'
            }
        }
    });
});

app.use('/api', (req, res) => {
    res.status(404).json({ success: false, message: 'مسیر مورد نظر یافت نشد' });
});

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    if (res.headersSent) return next(err);
    const status = err.type === 'entity.too.large' || err.status === 413 ? 413 : 500;
    res.status(status).json({
        success: false,
        message: status === 413 ? 'حجم درخواست بیش از حد مجاز است' : 'خطای داخلی سرور'
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, process.env.HOST || '0.0.0.0', () => {
    console.log(`🚀 سرور روی پورت ${PORT} راه‌اندازی شد`);
    console.log(`📍 آدرس: http://localhost:${PORT}`);
});
