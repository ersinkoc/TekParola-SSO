import { sessionService } from '../../src/services/sessionService';
import { prisma } from '../../src/config/database';
import { redis } from '../../src/config/redis';
import { AuthenticationError, ValidationError } from '../../src/utils/errors';
import * as jwt from 'jsonwebtoken';

// Mock dependencies
jest.mock('../../src/config/database');
jest.mock('../../src/config/redis');
jest.mock('jsonwebtoken');

const mockPrisma = prisma as jest.Mocked<typeof prisma>;
const mockRedis = redis as jest.Mocked<typeof redis>;
const mockJwt = jwt as jest.Mocked<typeof jwt>;

describe('SessionService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('createSession', () => {
    const sessionData = {
      userId: 'user-123',
      ipAddress: '127.0.0.1',
      userAgent: 'Test Browser',
      remember: false,
    };

    it('should create session successfully', async () => {
      const mockSession = {
        id: 'session-123',
        userId: sessionData.userId,
        ipAddress: sessionData.ipAddress,
        userAgent: sessionData.userAgent,
        isActive: true,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        lastActivityAt: new Date(),
      };

      mockPrisma.session.create.mockResolvedValue(mockSession as any);
      mockRedis.setex.mockResolvedValue('OK');

      const result = await sessionService.createSession(sessionData);

      expect(result).toEqual(mockSession);
      expect(mockPrisma.session.create).toHaveBeenCalledWith({
        data: {
          userId: sessionData.userId,
          ipAddress: sessionData.ipAddress,
          userAgent: sessionData.userAgent,
          isActive: true,
          expiresAt: expect.any(Date),
          lastActivityAt: expect.any(Date),
        },
      });
      expect(mockRedis.setex).toHaveBeenCalled();
    });

    it('should create extended session when remember is true', async () => {
      const rememberSessionData = { ...sessionData, remember: true };
      const mockSession = {
        id: 'session-123',
        userId: sessionData.userId,
        ipAddress: sessionData.ipAddress,
        userAgent: sessionData.userAgent,
        isActive: true,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        createdAt: new Date(),
        lastActivityAt: new Date(),
      };

      mockPrisma.session.create.mockResolvedValue(mockSession as any);
      mockRedis.setex.mockResolvedValue('OK');

      const result = await sessionService.createSession(rememberSessionData);

      expect(result).toEqual(mockSession);
      // Expect longer expiration time for remember sessions
      const createCall = mockPrisma.session.create.mock.calls[0][0];
      const expiresAt = createCall.data.expiresAt as Date;
      const expectedMinTime = Date.now() + 25 * 24 * 60 * 60 * 1000; // At least 25 days
      expect(expiresAt.getTime()).toBeGreaterThan(expectedMinTime);
    });
  });

  describe('findById', () => {
    it('should find session by id', async () => {
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        userId: 'user-123',
        isActive: true,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      mockPrisma.session.findUnique.mockResolvedValue(mockSession as any);

      const result = await sessionService.findById(sessionId);

      expect(result).toEqual(mockSession);
      expect(mockPrisma.session.findUnique).toHaveBeenCalledWith({
        where: { id: sessionId },
      });
    });

    it('should return null for non-existent session', async () => {
      const sessionId = 'non-existent';
      mockPrisma.session.findUnique.mockResolvedValue(null);

      const result = await sessionService.findById(sessionId);

      expect(result).toBeNull();
    });
  });

  describe('validateSession', () => {
    it('should validate active session successfully', async () => {
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        userId: 'user-123',
        isActive: true,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        lastActivityAt: new Date(),
      };

      mockPrisma.session.findUnique.mockResolvedValue(mockSession as any);
      mockPrisma.session.update.mockResolvedValue(mockSession as any);
      mockRedis.setex.mockResolvedValue('OK');

      const result = await sessionService.validateSession(sessionId);

      expect(result).toEqual(mockSession);
      expect(mockPrisma.session.update).toHaveBeenCalledWith({
        where: { id: sessionId },
        data: { lastActivityAt: expect.any(Date) },
      });
    });

    it('should return null for expired session', async () => {
      const sessionId = 'session-123';
      const expiredSession = {
        id: sessionId,
        userId: 'user-123',
        isActive: true,
        expiresAt: new Date(Date.now() - 60 * 60 * 1000), // Expired 1 hour ago
      };

      mockPrisma.session.findUnique.mockResolvedValue(expiredSession as any);

      const result = await sessionService.validateSession(sessionId);

      expect(result).toBeNull();
      expect(mockPrisma.session.update).not.toHaveBeenCalled();
    });

    it('should return null for inactive session', async () => {
      const sessionId = 'session-123';
      const inactiveSession = {
        id: sessionId,
        userId: 'user-123',
        isActive: false,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      mockPrisma.session.findUnique.mockResolvedValue(inactiveSession as any);

      const result = await sessionService.validateSession(sessionId);

      expect(result).toBeNull();
    });
  });

  describe('generateTokens', () => {
    it('should generate access and refresh tokens', async () => {
      const sessionData = {
        sessionId: 'session-123',
        userId: 'user-123',
        roles: ['user'],
        permissions: ['read:profile'],
      };

      const mockAccessToken = 'mock-access-token';
      const mockRefreshToken = 'mock-refresh-token';

      mockJwt.sign
        .mockReturnValueOnce(mockAccessToken) // Access token
        .mockReturnValueOnce(mockRefreshToken); // Refresh token

      mockRedis.setex.mockResolvedValue('OK');

      const result = await sessionService.generateTokens(sessionData);

      expect(result).toEqual({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });

      expect(mockJwt.sign).toHaveBeenCalledTimes(2);
      expect(mockRedis.setex).toHaveBeenCalledWith(
        `refresh_token:${sessionData.sessionId}`,
        expect.any(Number),
        mockRefreshToken
      );
    });
  });

  describe('validateRefreshToken', () => {
    it('should validate refresh token successfully', async () => {
      const refreshToken = 'valid-refresh-token';
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        userId: 'user-123',
        isActive: true,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      const mockDecoded = {
        sessionId,
        userId: 'user-123',
        type: 'refresh',
      };

      mockJwt.verify.mockReturnValue(mockDecoded as any);
      mockRedis.get.mockResolvedValue(refreshToken);
      mockPrisma.session.findUnique.mockResolvedValue(mockSession as any);

      const result = await sessionService.validateRefreshToken(refreshToken);

      expect(result).toEqual(mockSession);
      expect(mockJwt.verify).toHaveBeenCalledWith(
        refreshToken,
        process.env.JWT_REFRESH_SECRET
      );
      expect(mockRedis.get).toHaveBeenCalledWith(`refresh_token:${sessionId}`);
    });

    it('should return null for invalid token signature', async () => {
      const invalidToken = 'invalid-token';
      mockJwt.verify.mockImplementation(() => {
        throw new Error('Invalid signature');
      });

      const result = await sessionService.validateRefreshToken(invalidToken);

      expect(result).toBeNull();
      expect(mockRedis.get).not.toHaveBeenCalled();
    });

    it('should return null for token not in Redis', async () => {
      const refreshToken = 'valid-but-revoked-token';
      const sessionId = 'session-123';
      const mockDecoded = {
        sessionId,
        userId: 'user-123',
        type: 'refresh',
      };

      mockJwt.verify.mockReturnValue(mockDecoded as any);
      mockRedis.get.mockResolvedValue(null); // Token not in Redis

      const result = await sessionService.validateRefreshToken(refreshToken);

      expect(result).toBeNull();
      expect(mockPrisma.session.findUnique).not.toHaveBeenCalled();
    });
  });

  describe('invalidateSession', () => {
    it('should invalidate session successfully', async () => {
      const sessionId = 'session-123';
      mockPrisma.session.update.mockResolvedValue({} as any);
      mockRedis.del.mockResolvedValue(1);

      await sessionService.invalidateSession(sessionId);

      expect(mockPrisma.session.update).toHaveBeenCalledWith({
        where: { id: sessionId },
        data: { isActive: false },
      });
      expect(mockRedis.del).toHaveBeenCalledWith(`refresh_token:${sessionId}`);
    });
  });

  describe('invalidateAllUserSessions', () => {
    it('should invalidate all user sessions', async () => {
      const userId = 'user-123';
      const mockSessions = [
        { id: 'session-1', userId },
        { id: 'session-2', userId },
      ];

      mockPrisma.session.findMany.mockResolvedValue(mockSessions as any);
      mockPrisma.session.updateMany.mockResolvedValue({ count: 2 });
      mockRedis.del.mockResolvedValue(2);

      await sessionService.invalidateAllUserSessions(userId);

      expect(mockPrisma.session.findMany).toHaveBeenCalledWith({
        where: { userId, isActive: true },
        select: { id: true },
      });
      expect(mockPrisma.session.updateMany).toHaveBeenCalledWith({
        where: { userId, isActive: true },
        data: { isActive: false },
      });
      expect(mockRedis.del).toHaveBeenCalledWith([
        'refresh_token:session-1',
        'refresh_token:session-2',
      ]);
    });
  });

  describe('getUserSessions', () => {
    it('should get active user sessions', async () => {
      const userId = 'user-123';
      const mockSessions = [
        {
          id: 'session-1',
          userId,
          ipAddress: '127.0.0.1',
          userAgent: 'Browser 1',
          isActive: true,
          createdAt: new Date(),
          lastActivityAt: new Date(),
        },
        {
          id: 'session-2',
          userId,
          ipAddress: '192.168.1.1',
          userAgent: 'Browser 2',
          isActive: true,
          createdAt: new Date(),
          lastActivityAt: new Date(),
        },
      ];

      mockPrisma.session.findMany.mockResolvedValue(mockSessions as any);

      const result = await sessionService.getUserSessions(userId);

      expect(result).toEqual(mockSessions);
      expect(mockPrisma.session.findMany).toHaveBeenCalledWith({
        where: { userId, isActive: true },
        orderBy: { lastActivityAt: 'desc' },
      });
    });

    it('should return empty array for user with no sessions', async () => {
      const userId = 'user-with-no-sessions';
      mockPrisma.session.findMany.mockResolvedValue([]);

      const result = await sessionService.getUserSessions(userId);

      expect(result).toEqual([]);
    });
  });

  describe('cleanupExpiredSessions', () => {
    it('should cleanup expired sessions', async () => {
      const expiredSessions = [
        { id: 'session-1' },
        { id: 'session-2' },
      ];

      mockPrisma.session.findMany.mockResolvedValue(expiredSessions as any);
      mockPrisma.session.deleteMany.mockResolvedValue({ count: 2 });
      mockRedis.del.mockResolvedValue(2);

      const result = await sessionService.cleanupExpiredSessions();

      expect(result).toBe(2);
      expect(mockPrisma.session.findMany).toHaveBeenCalledWith({
        where: {
          OR: [
            { expiresAt: { lt: expect.any(Date) } },
            { isActive: false },
          ],
        },
        select: { id: true },
      });
      expect(mockPrisma.session.deleteMany).toHaveBeenCalledWith({
        where: {
          OR: [
            { expiresAt: { lt: expect.any(Date) } },
            { isActive: false },
          ],
        },
      });
      expect(mockRedis.del).toHaveBeenCalledWith([
        'refresh_token:session-1',
        'refresh_token:session-2',
      ]);
    });

    it('should handle no expired sessions', async () => {
      mockPrisma.session.findMany.mockResolvedValue([]);
      mockPrisma.session.deleteMany.mockResolvedValue({ count: 0 });

      const result = await sessionService.cleanupExpiredSessions();

      expect(result).toBe(0);
      expect(mockRedis.del).not.toHaveBeenCalled();
    });
  });

  describe('updateSessionActivity', () => {
    it('should update session last activity', async () => {
      const sessionId = 'session-123';
      const mockSession = {
        id: sessionId,
        lastActivityAt: new Date(),
      };

      mockPrisma.session.update.mockResolvedValue(mockSession as any);
      mockRedis.setex.mockResolvedValue('OK');

      await sessionService.updateSessionActivity(sessionId);

      expect(mockPrisma.session.update).toHaveBeenCalledWith({
        where: { id: sessionId },
        data: { lastActivityAt: expect.any(Date) },
      });
      expect(mockRedis.setex).toHaveBeenCalled();
    });
  });
});
