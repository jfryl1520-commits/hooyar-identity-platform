const jwt = require('jsonwebtoken');

const requireToken = (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!token) {
        return res.status(401).json({ success: false, message: 'دسترسی غیرمجاز - توکن یافت نشد' });
    }

    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'نشست شما منقضی شده است، دوباره وارد شوید' });
    }
};

const adminMiddleware = (req, res, next) => {
    if (req.user?.type !== 'admin' || req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'دسترسی مدیریتی لازم است' });
    }
    next();
};

const customerMiddleware = (req, res, next) => {
    if (req.user?.type !== 'customer') {
        return res.status(403).json({ success: false, message: 'دسترسی فقط برای مشتریان' });
    }
    next();
};

module.exports = { authMiddleware: requireToken, adminMiddleware, customerMiddleware };
