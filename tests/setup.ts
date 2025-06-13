import { execSync } from 'child_process';
import { randomBytes } from 'crypto';

// Set test environment
process.env.NODE_ENV = 'test';

// Generate unique test database URL
const testDbName = `tekparola_test_${randomBytes(8).toString('hex')}`;
process.env.DATABASE_URL = `postgresql://postgres:postgres123@localhost:5432/${testDbName}`;

// Set test-specific environment variables
process.env.JWT_SECRET = 'test-jwt-secret-key';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.SMTP_HOST = 'smtp.mailtrap.io';
process.env.SMTP_USER = 'test';
process.env.SMTP_PASS = 'test';
process.env.FROM_EMAIL = 'test@tekparola.com';

// Global test setup
beforeAll(async () => {
  // Create test database
  try {
    execSync(`createdb ${testDbName}`, { stdio: 'inherit' });
  } catch (error) {
    // Database might already exist, ignore error
  }

  // Run migrations
  execSync('npx prisma migrate deploy', { stdio: 'inherit' });
  
  // Seed test data
  execSync('npx prisma db seed', { stdio: 'inherit' });
});

// Cleanup after all tests
afterAll(async () => {
  // Drop test database
  try {
    execSync(`dropdb ${testDbName}`, { stdio: 'inherit' });
  } catch (error) {
    // Ignore errors
  }
});