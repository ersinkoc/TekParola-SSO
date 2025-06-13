"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const app_1 = require("../src/app");
const database_1 = require("../src/config/database");
const app = (0, app_1.createApp)();
describe('Authentication API', () => {
    beforeEach(async () => {
        await database_1.prisma.user.deleteMany({
            where: {
                email: {
                    contains: 'test',
                },
            },
        });
    });
    describe('POST /api/v1/auth/register', () => {
        it('should register a new user successfully', async () => {
            const userData = {
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                password: 'TestPass123!',
            };
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send(userData)
                .expect(201);
            expect(response.body.success).toBe(true);
            expect(response.body.data.user.email).toBe(userData.email);
            expect(response.body.data.user.firstName).toBe(userData.firstName);
            expect(response.body.data.user.lastName).toBe(userData.lastName);
            expect(response.body.data.user).not.toHaveProperty('password');
        });
        it('should not register user with invalid email', async () => {
            const userData = {
                email: 'invalid-email',
                firstName: 'Test',
                lastName: 'User',
                password: 'TestPass123!',
            };
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send(userData)
                .expect(400);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('VALIDATION_ERROR');
        });
        it('should not register user with weak password', async () => {
            const userData = {
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                password: 'weak',
            };
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send(userData)
                .expect(400);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('VALIDATION_ERROR');
        });
        it('should not register duplicate email', async () => {
            const userData = {
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                password: 'TestPass123!',
            };
            await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send(userData)
                .expect(201);
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send(userData)
                .expect(409);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('CONFLICT_ERROR');
        });
    });
    describe('POST /api/v1/auth/login', () => {
        beforeEach(async () => {
            await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send({
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                password: 'TestPass123!',
            });
        });
        it('should login successfully with valid credentials', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/login')
                .send({
                email: 'test@example.com',
                password: 'TestPass123!',
            })
                .expect(200);
            expect(response.body.success).toBe(true);
            expect(response.body.data.user.email).toBe('test@example.com');
            expect(response.body.data.tokens.accessToken).toBeDefined();
            expect(response.body.data.tokens.refreshToken).toBeDefined();
            expect(response.body.data.sessionId).toBeDefined();
        });
        it('should not login with invalid email', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/login')
                .send({
                email: 'nonexistent@example.com',
                password: 'TestPass123!',
            })
                .expect(401);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('AUTHENTICATION_ERROR');
        });
        it('should not login with invalid password', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/login')
                .send({
                email: 'test@example.com',
                password: 'WrongPassword123!',
            })
                .expect(401);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('AUTHENTICATION_ERROR');
        });
        it('should not login with malformed email', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/login')
                .send({
                email: 'invalid-email',
                password: 'TestPass123!',
            })
                .expect(400);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('VALIDATION_ERROR');
        });
    });
    describe('POST /api/v1/auth/refresh-token', () => {
        let refreshToken;
        beforeEach(async () => {
            await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send({
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                password: 'TestPass123!',
            });
            const loginResponse = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/login')
                .send({
                email: 'test@example.com',
                password: 'TestPass123!',
            });
            refreshToken = loginResponse.body.data.tokens.refreshToken;
        });
        it('should refresh token successfully', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/refresh-token')
                .send({ refreshToken })
                .expect(200);
            expect(response.body.success).toBe(true);
            expect(response.body.data.tokens.accessToken).toBeDefined();
            expect(response.body.data.tokens.refreshToken).toBeDefined();
            expect(response.body.data.tokens.accessToken).not.toBe(refreshToken);
        });
        it('should not refresh with invalid token', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/refresh-token')
                .send({ refreshToken: 'invalid-token' })
                .expect(400);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('VALIDATION_ERROR');
        });
    });
    describe('GET /api/v1/auth/profile', () => {
        let accessToken;
        beforeEach(async () => {
            await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send({
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                password: 'TestPass123!',
            });
            const loginResponse = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/login')
                .send({
                email: 'test@example.com',
                password: 'TestPass123!',
            });
            accessToken = loginResponse.body.data.tokens.accessToken;
        });
        it('should get profile successfully with valid token', async () => {
            const response = await (0, supertest_1.default)(app)
                .get('/api/v1/auth/profile')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);
            expect(response.body.success).toBe(true);
            expect(response.body.data.user.email).toBe('test@example.com');
            expect(response.body.data.user.firstName).toBe('Test');
            expect(response.body.data.user.lastName).toBe('User');
            expect(response.body.data.user.roles).toBeDefined();
            expect(response.body.data.user.permissions).toBeDefined();
        });
        it('should not get profile without token', async () => {
            const response = await (0, supertest_1.default)(app)
                .get('/api/v1/auth/profile')
                .expect(401);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('AUTHENTICATION_ERROR');
        });
        it('should not get profile with invalid token', async () => {
            const response = await (0, supertest_1.default)(app)
                .get('/api/v1/auth/profile')
                .set('Authorization', 'Bearer invalid-token')
                .expect(401);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('AUTHENTICATION_ERROR');
        });
    });
    describe('POST /api/v1/auth/logout', () => {
        let accessToken;
        beforeEach(async () => {
            await (0, supertest_1.default)(app)
                .post('/api/v1/auth/register')
                .send({
                email: 'test@example.com',
                firstName: 'Test',
                lastName: 'User',
                password: 'TestPass123!',
            });
            const loginResponse = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/login')
                .send({
                email: 'test@example.com',
                password: 'TestPass123!',
            });
            accessToken = loginResponse.body.data.tokens.accessToken;
        });
        it('should logout successfully', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/logout')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);
            expect(response.body.success).toBe(true);
            expect(response.body.message).toBe('Logout successful');
        });
        it('should not logout without token', async () => {
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/auth/logout')
                .expect(401);
            expect(response.body.success).toBe(false);
            expect(response.body.code).toBe('AUTHENTICATION_ERROR');
        });
    });
});
describe('Health Check', () => {
    it('should return health status', async () => {
        const response = await (0, supertest_1.default)(app)
            .get('/health')
            .expect(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe('Service is healthy');
        expect(response.body.uptime).toBeDefined();
    });
});
describe('API Info', () => {
    it('should return API information', async () => {
        const response = await (0, supertest_1.default)(app)
            .get('/api')
            .expect(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toBe('TekParola SSO API');
        expect(response.body.version).toBeDefined();
        expect(response.body.endpoints).toBeDefined();
    });
});
//# sourceMappingURL=auth.test.js.map