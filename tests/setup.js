"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = require("child_process");
const crypto_1 = require("crypto");
process.env.NODE_ENV = 'test';
const testDbName = `tekparola_test_${(0, crypto_1.randomBytes)(8).toString('hex')}`;
process.env.DATABASE_URL = `postgresql://postgres:postgres123@localhost:5432/${testDbName}`;
process.env.JWT_SECRET = 'test-jwt-secret-key';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.SMTP_HOST = 'smtp.mailtrap.io';
process.env.SMTP_USER = 'test';
process.env.SMTP_PASS = 'test';
process.env.FROM_EMAIL = 'test@tekparola.com';
beforeAll(async () => {
    try {
        (0, child_process_1.execSync)(`createdb ${testDbName}`, { stdio: 'inherit' });
    }
    catch (error) {
    }
    (0, child_process_1.execSync)('npx prisma migrate deploy', { stdio: 'inherit' });
    (0, child_process_1.execSync)('npx prisma db seed', { stdio: 'inherit' });
});
afterAll(async () => {
    try {
        (0, child_process_1.execSync)(`dropdb ${testDbName}`, { stdio: 'inherit' });
    }
    catch (error) {
    }
});
//# sourceMappingURL=setup.js.map