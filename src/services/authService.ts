import { v4 as uuidv4 } from 'uuid';
import speakeasy from 'speakeasy';
import { User } from '@prisma/client';
import { prisma } from '../config/database';
import { config } from '../config/env';
import { jwtService, TokenPair } from '../utils/jwt';
import { logger } from '../utils/logger';
import { userService } from './userService';
import { emailService } from './emailService';
import { 
  AuthenticationError, 
  ValidationError, 
  NotFoundError, 
  ConflictError 
} from '../utils/errors';

export interface LoginCredentials {
  email: string;
  password: string;
  twoFactorCode?: string;
  rememberMe?: boolean;
}

export interface RegisterData {
  email: string;
  username?: string;
  firstName: string;
  lastName: string;
  password: string;
  phoneNumber?: string;
}

export interface AuthResult {
  user: Omit<User, 'password'>;
  tokens: TokenPair;
  requiresTwoFactor?: boolean;
  sessionId: string;
}

export interface MagicLinkData {
  email: string;
}

export interface PasswordResetData {
  email: string;
}

export interface PasswordResetConfirmData {
  token: string;
  newPassword: string;
}

export class AuthService {
  async login(credentials: LoginCredentials, ipAddress: string, userAgent: string): Promise<AuthResult> {
    try {
      // Find user by email
      const user = await userService.findByEmail(credentials.email);
      if (!user) {
        throw new AuthenticationError('Invalid credentials');
      }

      // Check if account is locked
      const isLocked = await userService.isAccountLocked(user);
      if (isLocked) {
        throw new AuthenticationError('Account is locked due to too many failed login attempts');
      }

      // Check if account is active
      if (!user.isActive) {
        throw new AuthenticationError('Account is deactivated');
      }

      // Verify password
      const isPasswordValid = await userService.verifyPassword(user, credentials.password);
      if (!isPasswordValid) {
        await userService.recordLoginAttempt(user.id, false, ipAddress);
        throw new AuthenticationError('Invalid credentials');
      }

      // Check 2FA if enabled
      if (user.twoFactorEnabled) {
        if (!credentials.twoFactorCode) {
          return {
            user: this.sanitizeUser(user),
            tokens: { accessToken: '', refreshToken: '', expiresIn: 0 },
            requiresTwoFactor: true,
            sessionId: '',
          };
        }

        const is2FAValid = this.verifyTwoFactorCode(user.twoFactorSecret!, credentials.twoFactorCode);
        if (!is2FAValid) {
          await userService.recordLoginAttempt(user.id, false, ipAddress);
          throw new AuthenticationError('Invalid two-factor authentication code');
        }
      }

      // Create session
      const sessionId = uuidv4();
      const tokens = jwtService.generateTokenPair(user.id, user.email, sessionId);

      // Create session record
      await this.createSession(user.id, sessionId, tokens.refreshToken, ipAddress, userAgent);

      // Record successful login
      await userService.recordLoginAttempt(user.id, true, ipAddress);

      // Create audit log
      await this.createAuditLog(user.id, 'login', 'user', user.id, { ipAddress, userAgent });

      logger.info(`User logged in: ${user.email} from ${ipAddress}`);

      return {
        user: this.sanitizeUser(user),
        tokens,
        sessionId,
      };
    } catch (error) {
      logger.error('Login failed:', error);
      throw error;
    }
  }

  async register(registerData: RegisterData): Promise<User> {
    try {
      // Check if registration is enabled
      const registrationEnabled = await this.getSystemSetting('registration_enabled', true);
      if (!registrationEnabled) {
        throw new ValidationError('Registration is currently disabled');
      }

      // Create user
      const user = await userService.createUser({
        email: registerData.email,
        username: registerData.username,
        firstName: registerData.firstName,
        lastName: registerData.lastName,
        password: registerData.password,
        phoneNumber: registerData.phoneNumber,
      });

      // Send welcome email
      try {
        await emailService.sendWelcomeEmail(user.email, user.firstName);
      } catch (emailError) {
        logger.warn('Failed to send welcome email:', emailError);
      }

      // Create audit log
      await this.createAuditLog(null, 'register', 'user', user.id, { email: user.email });

      logger.info(`User registered: ${user.email}`);
      return user;
    } catch (error) {
      logger.error('Registration failed:', error);
      throw error;
    }
  }

  async logout(sessionId: string, userId: string): Promise<void> {
    try {
      // Invalidate session
      await this.invalidateSession(sessionId);

      // Create audit log
      await this.createAuditLog(userId, 'logout', 'session', sessionId);

      logger.info(`User logged out: ${userId}`);
    } catch (error) {
      logger.error('Logout failed:', error);
      throw error;
    }
  }

  async refreshToken(refreshToken: string): Promise<TokenPair> {
    try {
      // Verify refresh token
      const payload = jwtService.verifyRefreshToken(refreshToken);

      // Check if token is blacklisted
      const isBlacklisted = await jwtService.isTokenBlacklisted(refreshToken);
      if (isBlacklisted) {
        throw new AuthenticationError('Token has been revoked');
      }

      // Check if user tokens are revoked
      const areTokensRevoked = await jwtService.areUserTokensRevoked(payload.userId);
      if (areTokensRevoked) {
        throw new AuthenticationError('User tokens have been revoked');
      }

      // Find session
      const session = await prisma.userSession.findUnique({
        where: { 
          sessionToken: payload.sessionId,
          isActive: true,
        },
        include: { user: true },
      });

      if (!session || session.userId !== payload.userId) {
        throw new AuthenticationError('Invalid session');
      }

      // Check if session has expired
      if (session.expiresAt < new Date()) {
        await this.invalidateSession(session.sessionToken);
        throw new AuthenticationError('Session has expired');
      }

      // Generate new token pair
      const newTokens = jwtService.generateTokenPair(
        session.user.id,
        session.user.email,
        session.sessionToken
      );

      // Blacklist old refresh token
      await jwtService.blacklistToken(refreshToken);

      // Update session with new refresh token
      await prisma.userSession.update({
        where: { id: session.id },
        data: {
          refreshToken: newTokens.refreshToken,
          lastActivityAt: new Date(),
        },
      });

      logger.debug(`Token refreshed for user: ${session.user.email}`);
      return newTokens;
    } catch (error) {
      logger.error('Token refresh failed:', error);
      throw error;
    }
  }

  async requestPasswordReset(data: PasswordResetData): Promise<void> {
    try {
      const user = await userService.findByEmail(data.email);
      if (!user) {
        // Don't reveal if email exists
        logger.info(`Password reset requested for non-existent email: ${data.email}`);
        return;
      }

      // Generate reset token
      const resetToken = await jwtService.generatePasswordResetToken(user.id);

      // Store reset token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetPasswordToken: resetToken,
          resetPasswordExpires: new Date(Date.now() + 3600000), // 1 hour
        },
      });

      // Send reset email
      await emailService.sendPasswordResetEmail(user.email, user.firstName, resetToken);

      // Create audit log
      await this.createAuditLog(user.id, 'password_reset_request', 'user', user.id);

      logger.info(`Password reset requested for: ${user.email}`);
    } catch (error) {
      logger.error('Password reset request failed:', error);
      throw error;
    }
  }

  async confirmPasswordReset(data: PasswordResetConfirmData): Promise<void> {
    try {
      // Verify reset token
      const { userId } = jwtService.verifyPasswordResetToken(data.token);

      // Find user with valid reset token
      const user = await prisma.user.findFirst({
        where: {
          id: userId,
          resetPasswordToken: data.token,
          resetPasswordExpires: { gt: new Date() },
        },
      });

      if (!user) {
        throw new AuthenticationError('Invalid or expired reset token');
      }

      // Update password
      await userService.updatePassword(user.id, data.newPassword);

      // Clear reset token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetPasswordToken: null,
          resetPasswordExpires: null,
        },
      });

      // Revoke all user sessions
      await this.revokeAllUserSessions(user.id);

      // Create audit log
      await this.createAuditLog(user.id, 'password_reset_confirm', 'user', user.id);

      logger.info(`Password reset completed for: ${user.email}`);
    } catch (error) {
      logger.error('Password reset confirmation failed:', error);
      throw error;
    }
  }

  async requestMagicLink(data: MagicLinkData): Promise<void> {
    try {
      const user = await userService.findByEmail(data.email);
      if (!user) {
        // Don't reveal if email exists
        logger.info(`Magic link requested for non-existent email: ${data.email}`);
        return;
      }

      // Generate magic link token
      const magicToken = await jwtService.generateMagicLinkToken(user.id);

      // Store magic link token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          magicLinkToken: magicToken,
          magicLinkExpires: new Date(Date.now() + 900000), // 15 minutes
        },
      });

      // Send magic link email
      await emailService.sendMagicLinkEmail(user.email, user.firstName, magicToken);

      // Create audit log
      await this.createAuditLog(user.id, 'magic_link_request', 'user', user.id);

      logger.info(`Magic link requested for: ${user.email}`);
    } catch (error) {
      logger.error('Magic link request failed:', error);
      throw error;
    }
  }

  async loginWithMagicLink(token: string, ipAddress: string, userAgent: string): Promise<AuthResult> {
    try {
      // Verify magic link token
      const { userId } = jwtService.verifyMagicLinkToken(token);

      // Find user with valid magic link token
      const user = await prisma.user.findFirst({
        where: {
          id: userId,
          magicLinkToken: token,
          magicLinkExpires: { gt: new Date() },
        },
      });

      if (!user) {
        throw new AuthenticationError('Invalid or expired magic link');
      }

      // Check if account is active
      if (!user.isActive) {
        throw new AuthenticationError('Account is deactivated');
      }

      // Clear magic link token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          magicLinkToken: null,
          magicLinkExpires: null,
        },
      });

      // Create session
      const sessionId = uuidv4();
      const tokens = jwtService.generateTokenPair(user.id, user.email, sessionId);

      // Create session record
      await this.createSession(user.id, sessionId, tokens.refreshToken, ipAddress, userAgent);

      // Record successful login
      await userService.recordLoginAttempt(user.id, true, ipAddress);

      // Create audit log
      await this.createAuditLog(user.id, 'magic_link_login', 'user', user.id, { ipAddress, userAgent });

      logger.info(`User logged in via magic link: ${user.email} from ${ipAddress}`);

      return {
        user: this.sanitizeUser(user),
        tokens,
        sessionId,
      };
    } catch (error) {
      logger.error('Magic link login failed:', error);
      throw error;
    }
  }

  async generateTwoFactorSecret(userId: string): Promise<{ secret: string; qrCode: string }> {
    try {
      const user = await userService.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      const secret = speakeasy.generateSecret({
        name: `${config.twoFactor.appName} (${user.email})`,
        issuer: config.twoFactor.issuer,
      });

      // Store secret temporarily (not enabled until verified)
      await prisma.user.update({
        where: { id: userId },
        data: { twoFactorSecret: secret.base32 },
      });

      return {
        secret: secret.base32,
        qrCode: secret.otpauth_url!,
      };
    } catch (error) {
      logger.error('Failed to generate 2FA secret:', error);
      throw error;
    }
  }

  async enableTwoFactor(userId: string, code: string): Promise<void> {
    try {
      const user = await userService.findById(userId);
      if (!user || !user.twoFactorSecret) {
        throw new ValidationError('Two-factor setup not initiated');
      }

      const isValid = this.verifyTwoFactorCode(user.twoFactorSecret, code);
      if (!isValid) {
        throw new ValidationError('Invalid verification code');
      }

      await prisma.user.update({
        where: { id: userId },
        data: { twoFactorEnabled: true },
      });

      // Create audit log
      await this.createAuditLog(userId, 'enable_2fa', 'user', userId);

      logger.info(`2FA enabled for user: ${user.email}`);
    } catch (error) {
      logger.error('Failed to enable 2FA:', error);
      throw error;
    }
  }

  async disableTwoFactor(userId: string, code: string): Promise<void> {
    try {
      const user = await userService.findById(userId);
      if (!user || !user.twoFactorEnabled) {
        throw new ValidationError('Two-factor authentication is not enabled');
      }

      const isValid = this.verifyTwoFactorCode(user.twoFactorSecret!, code);
      if (!isValid) {
        throw new ValidationError('Invalid verification code');
      }

      await prisma.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: false,
          twoFactorSecret: null,
          twoFactorBackupCodes: [],
        },
      });

      // Create audit log
      await this.createAuditLog(userId, 'disable_2fa', 'user', userId);

      logger.info(`2FA disabled for user: ${user.email}`);
    } catch (error) {
      logger.error('Failed to disable 2FA:', error);
      throw error;
    }
  }

  private verifyTwoFactorCode(secret: string, code: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: code,
      window: 2, // Allow 2 time steps of variance
    });
  }

  private async createSession(
    userId: string,
    sessionId: string,
    refreshToken: string,
    ipAddress: string,
    userAgent: string
  ): Promise<void> {
    await prisma.userSession.create({
      data: {
        userId,
        sessionToken: sessionId,
        refreshToken,
        ipAddress,
        userAgent,
        expiresAt: new Date(Date.now() + config.session.timeout),
      },
    });
  }

  private async invalidateSession(sessionId: string): Promise<void> {
    await prisma.userSession.updateMany({
      where: { sessionToken: sessionId },
      data: { isActive: false },
    });
  }

  private async revokeAllUserSessions(userId: string): Promise<void> {
    await prisma.userSession.updateMany({
      where: { userId },
      data: { isActive: false },
    });

    // Revoke all JWT tokens for the user
    await jwtService.revokeAllUserTokens(userId);
  }

  private async createAuditLog(
    userId: string | null,
    action: string,
    resource: string,
    resourceId: string,
    details?: Record<string, any>
  ): Promise<void> {
    try {
      await prisma.auditLog.create({
        data: {
          userId,
          action,
          resource,
          resourceId,
          details: details || {},
          ipAddress: details?.ipAddress || 'unknown',
          userAgent: details?.userAgent || 'unknown',
        },
      });
    } catch (error) {
      logger.error('Failed to create audit log:', error);
    }
  }

  private sanitizeUser(user: User): Omit<User, 'password'> {
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
  }

  private async getSystemSetting(key: string, defaultValue: any): Promise<any> {
    try {
      const setting = await prisma.systemSetting.findUnique({
        where: { key },
      });

      if (!setting) {
        return defaultValue;
      }

      switch (setting.type) {
        case 'boolean':
          return setting.value === 'true';
        case 'number':
          return parseInt(setting.value, 10);
        case 'json':
          return JSON.parse(setting.value);
        default:
          return setting.value;
      }
    } catch (error) {
      logger.error(`Failed to get system setting ${key}:`, error);
      return defaultValue;
    }
  }
}

export const authService = new AuthService();