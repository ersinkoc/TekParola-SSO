import dotenv from 'dotenv';
import Joi from 'joi';

dotenv.config();

const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  API_VERSION: Joi.string().default('v1'),
  
  // Database
  DATABASE_URL: Joi.string().required(),
  
  // JWT
  JWT_SECRET: Joi.string().required(),
  JWT_REFRESH_SECRET: Joi.string().required(),
  JWT_EXPIRES_IN: Joi.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: Joi.string().default('7d'),
  
  // Redis
  REDIS_URL: Joi.string().default('redis://localhost:6379'),
  
  // Email
  SMTP_HOST: Joi.string().required(),
  SMTP_PORT: Joi.number().default(587),
  SMTP_SECURE: Joi.boolean().default(false),
  SMTP_USER: Joi.string().required(),
  SMTP_PASS: Joi.string().required(),
  FROM_EMAIL: Joi.string().email().required(),
  FROM_NAME: Joi.string().default('TekParola SSO'),
  
  // Security
  BCRYPT_ROUNDS: Joi.number().default(12),
  MAX_LOGIN_ATTEMPTS: Joi.number().default(5),
  LOCKOUT_TIME: Joi.number().default(900000), // 15 minutes
  RATE_LIMIT_WINDOW: Joi.number().default(900000), // 15 minutes
  RATE_LIMIT_MAX: Joi.number().default(100),
  
  // Application Settings
  REGISTRATION_ENABLED: Joi.boolean().default(true),
  DEFAULT_ROLE: Joi.string().default('user'),
  COMPANY_NAME: Joi.string().default('TekParola'),
  COMPANY_LOGO: Joi.string().allow('').default(''),
  
  // 2FA
  APP_NAME: Joi.string().default('TekParola SSO'),
  ISSUER: Joi.string().default('TekParola'),
  
  // Session
  SESSION_SECRET: Joi.string().required(),
  SESSION_TIMEOUT: Joi.number().default(86400000), // 24 hours
  
  // File Upload
  MAX_FILE_SIZE: Joi.number().default(5242880), // 5MB
  UPLOAD_PATH: Joi.string().default('./uploads'),
}).unknown();

const { error, value: env } = envSchema.validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

export const config = {
  node_env: env.NODE_ENV,
  port: env.PORT,
  api_version: env.API_VERSION,
  
  database: {
    url: env.DATABASE_URL,
  },
  
  jwt: {
    secret: env.JWT_SECRET,
    refreshSecret: env.JWT_REFRESH_SECRET,
    expiresIn: env.JWT_EXPIRES_IN,
    refreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN,
  },
  
  redis: {
    url: env.REDIS_URL,
  },
  
  email: {
    smtp: {
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_SECURE,
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
    },
    from: {
      email: env.FROM_EMAIL,
      name: env.FROM_NAME,
    },
  },
  
  security: {
    bcryptRounds: env.BCRYPT_ROUNDS,
    maxLoginAttempts: env.MAX_LOGIN_ATTEMPTS,
    lockoutTime: env.LOCKOUT_TIME,
    rateLimit: {
      windowMs: env.RATE_LIMIT_WINDOW,
      max: env.RATE_LIMIT_MAX,
    },
  },
  
  app: {
    registrationEnabled: env.REGISTRATION_ENABLED,
    defaultRole: env.DEFAULT_ROLE,
    companyName: env.COMPANY_NAME,
    companyLogo: env.COMPANY_LOGO,
  },
  
  twoFactor: {
    appName: env.APP_NAME,
    issuer: env.ISSUER,
  },
  
  session: {
    secret: env.SESSION_SECRET,
    timeout: env.SESSION_TIMEOUT,
  },
  
  upload: {
    maxFileSize: env.MAX_FILE_SIZE,
    uploadPath: env.UPLOAD_PATH,
  },
};