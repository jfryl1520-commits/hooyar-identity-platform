const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
    let bits = 0;
    let value = 0;
    let output = '';
    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            output += ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits) output += ALPHABET[(value << (5 - bits)) & 31];
    return output;
}

function base32Decode(input) {
    let bits = 0;
    let value = 0;
    const bytes = [];
    for (const char of input.toUpperCase().replace(/=+$/g, '')) {
        const index = ALPHABET.indexOf(char);
        if (index < 0) throw new Error('Invalid TOTP secret');
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return Buffer.from(bytes);
}

function encryptSecret(secret) {
    const key = crypto.createHash('sha256').update(`${process.env.JWT_SECRET}:hooyar-mfa-v1`).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), ciphertext].map(part => part.toString('base64url')).join('.');
}

function decryptSecret(payload) {
    const [ivText, tagText, ciphertextText] = String(payload || '').split('.');
    if (!ivText || !tagText || !ciphertextText) throw new Error('Encrypted TOTP secret is invalid');
    const key = crypto.createHash('sha256').update(`${process.env.JWT_SECRET}:hooyar-mfa-v1`).digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivText, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8');
}

function tokenAt(secret, step) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step));
    const digest = crypto.createHmac('sha1', base32Decode(secret)).update(counter).digest();
    const offset = digest[digest.length - 1] & 0x0f;
    const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
    return String(binary % 1000000).padStart(6, '0');
}

function verifyToken(secret, supplied, now = Date.now()) {
    const code = String(supplied || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(code)) return null;
    const actual = Buffer.from(code);
    const currentStep = Math.floor(now / 30000);
    for (const step of [currentStep - 1, currentStep, currentStep + 1]) {
        if (step < 0) continue;
        const expected = Buffer.from(tokenAt(secret, step));
        if (crypto.timingSafeEqual(actual, expected)) return step;
    }
    return null;
}

function createSetup(username) {
    const secret = base32Encode(crypto.randomBytes(20));
    const label = encodeURIComponent(`هویار:${username}`);
    const issuer = encodeURIComponent('هویار');
    return { secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` };
}

module.exports = { createSetup, encryptSecret, decryptSecret, verifyToken };
