import { Router } from 'express';
import { authController } from '../controllers/authController';
import { authenticate, optionalAuth } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import {
  authLimiter,
  registrationLimiter,
  passwordResetLimiter,
  magicLinkLimiter,
  twoFactorLimiter,
} from '../middleware/rateLimiter';
import {
  validateRegister,
  validateLogin,
  validatePasswordResetRequest,
  validatePasswordResetConfirm,
  validateMagicLinkRequest,
  validateMagicLinkLogin,
  validateRefreshToken,
  validateTwoFactorSetup,
  validateChangePassword,
  validateUpdateProfile,
} from '../validators/authValidators';

const router = Router();

// Public routes
router.post(
  '/register',
  registrationLimiter,
  validateRegister,
  validateRequest,
  authController.register
);

router.post(
  '/login',
  authLimiter,
  validateLogin,
  validateRequest,
  authController.login
);

router.post(
  '/refresh-token',
  authLimiter,
  validateRefreshToken,
  validateRequest,
  authController.refreshToken
);

router.post(
  '/password-reset/request',
  passwordResetLimiter,
  validatePasswordResetRequest,
  validateRequest,
  authController.requestPasswordReset
);

router.post(
  '/password-reset/confirm',
  passwordResetLimiter,
  validatePasswordResetConfirm,
  validateRequest,
  authController.confirmPasswordReset
);

router.post(
  '/magic-link/request',
  magicLinkLimiter,
  validateMagicLinkRequest,
  validateRequest,
  authController.requestMagicLink
);

router.post(
  '/magic-link/login',
  magicLinkLimiter,
  validateMagicLinkLogin,
  validateRequest,
  authController.loginWithMagicLink
);

// Check availability endpoints (optional auth for better UX)
router.post(
  '/check-email',
  optionalAuth,
  authController.checkEmailAvailability
);

router.post(
  '/check-username',
  optionalAuth,
  authController.checkUsernameAvailability
);

// Protected routes
router.post(
  '/logout',
  authenticate,
  authController.logout
);

router.get(
  '/profile',
  authenticate,
  authController.getProfile
);

router.put(
  '/profile',
  authenticate,
  validateUpdateProfile,
  validateRequest,
  authController.updateProfile
);

router.post(
  '/change-password',
  authenticate,
  validateChangePassword,
  validateRequest,
  authController.changePassword
);

// Two-factor authentication routes
router.post(
  '/2fa/generate',
  authenticate,
  authController.generate2FASecret
);

router.post(
  '/2fa/enable',
  authenticate,
  twoFactorLimiter,
  validateTwoFactorSetup,
  validateRequest,
  authController.enable2FA
);

router.post(
  '/2fa/disable',
  authenticate,
  twoFactorLimiter,
  validateTwoFactorSetup,
  validateRequest,
  authController.disable2FA
);

// Email verification
router.get(
  '/verify-email/:token',
  authenticate,
  authController.verifyEmail
);

export default router;