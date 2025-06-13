import bcrypt from 'bcrypt';
import { User, Prisma } from '@prisma/client';
import { prisma } from '../config/database';
import { config } from '../config/env';
import { logger } from '../utils/logger';
import { NotFoundError, ConflictError, ValidationError, AuthenticationError } from '../utils/errors';

export interface CreateUserData {
  email: string;
  username?: string;
  firstName: string;
  lastName: string;
  password: string;
  phoneNumber?: string;
  isEmailVerified?: boolean;
  createdBy?: string;
}

export interface UpdateUserData {
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
  avatar?: string;
  timezone?: string;
  language?: string;
  dateFormat?: string;
  timeFormat?: string;
  updatedBy?: string;
}

export interface UserWithRoles extends User {
  roles: Array<{
    role: {
      id: string;
      name: string;
      displayName: string;
      permissions: Array<{
        permission: {
          id: string;
          name: string;
          resource: string;
          action: string;
          scope: string | null;
        };
      }>;
    };
  }>;
}

export class UserService {
  async createUser(userData: CreateUserData): Promise<User> {
    try {
      // Check if user already exists
      const existingUser = await this.findByEmailOrUsername(userData.email, userData.username);
      if (existingUser) {
        throw new ConflictError('User with this email or username already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(userData.password, config.security.bcryptRounds);

      // Get default role
      const defaultRole = await prisma.role.findUnique({
        where: { name: config.app.defaultRole },
      });

      if (!defaultRole) {
        throw new ValidationError('Default role not found');
      }

      // Create user with role assignment in transaction
      const user = await prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: {
            email: userData.email,
            username: userData.username,
            firstName: userData.firstName,
            lastName: userData.lastName,
            password: hashedPassword,
            phoneNumber: userData.phoneNumber,
            isEmailVerified: userData.isEmailVerified || false,
            createdBy: userData.createdBy,
          },
        });

        // Assign default role
        await tx.userRole.create({
          data: {
            userId: newUser.id,
            roleId: defaultRole.id,
            assignedBy: userData.createdBy,
          },
        });

        return newUser;
      });

      logger.info(`User created: ${user.id} (${user.email})`);
      return user;
    } catch (error) {
      logger.error('Failed to create user:', error);
      throw error;
    }
  }

  async findById(id: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { id },
      });
    } catch (error) {
      logger.error('Failed to find user by ID:', error);
      throw error;
    }
  }

  async findByEmail(email: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { email },
      });
    } catch (error) {
      logger.error('Failed to find user by email:', error);
      throw error;
    }
  }

  async findByUsername(username: string): Promise<User | null> {
    try {
      return await prisma.user.findUnique({
        where: { username },
      });
    } catch (error) {
      logger.error('Failed to find user by username:', error);
      throw error;
    }
  }

  async findByEmailOrUsername(email: string, username?: string): Promise<User | null> {
    try {
      const whereConditions: Prisma.UserWhereInput[] = [{ email }];
      
      if (username) {
        whereConditions.push({ username });
      }

      return await prisma.user.findFirst({
        where: {
          OR: whereConditions,
        },
      });
    } catch (error) {
      logger.error('Failed to find user by email or username:', error);
      throw error;
    }
  }

  async findWithRoles(id: string): Promise<UserWithRoles | null> {
    try {
      return await prisma.user.findUnique({
        where: { id },
        include: {
          roles: {
            include: {
              role: {
                include: {
                  permissions: {
                    include: {
                      permission: true,
                    },
                  },
                },
              },
            },
          },
        },
      });
    } catch (error) {
      logger.error('Failed to find user with roles:', error);
      throw error;
    }
  }

  async updateUser(id: string, updateData: UpdateUserData): Promise<User> {
    try {
      const user = await this.findById(id);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      const updatedUser = await prisma.user.update({
        where: { id },
        data: {
          ...updateData,
          updatedAt: new Date(),
        },
      });

      logger.info(`User updated: ${updatedUser.id} (${updatedUser.email})`);
      return updatedUser;
    } catch (error) {
      logger.error('Failed to update user:', error);
      throw error;
    }
  }

  async updatePassword(id: string, newPassword: string, updatedBy?: string): Promise<void> {
    try {
      const hashedPassword = await bcrypt.hash(newPassword, config.security.bcryptRounds);

      await prisma.user.update({
        where: { id },
        data: {
          password: hashedPassword,
          updatedBy,
          updatedAt: new Date(),
        },
      });

      logger.info(`Password updated for user: ${id}`);
    } catch (error) {
      logger.error('Failed to update password:', error);
      throw error;
    }
  }

  async verifyPassword(user: User, password: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, user.password);
    } catch (error) {
      logger.error('Failed to verify password:', error);
      return false;
    }
  }

  async deactivateUser(id: string, updatedBy?: string): Promise<User> {
    try {
      const user = await this.updateUser(id, { updatedBy });
      
      const deactivatedUser = await prisma.user.update({
        where: { id },
        data: {
          isActive: false,
          updatedBy,
          updatedAt: new Date(),
        },
      });

      logger.info(`User deactivated: ${deactivatedUser.id} (${deactivatedUser.email})`);
      return deactivatedUser;
    } catch (error) {
      logger.error('Failed to deactivate user:', error);
      throw error;
    }
  }

  async activateUser(id: string, updatedBy?: string): Promise<User> {
    try {
      const user = await this.findById(id);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      const activatedUser = await prisma.user.update({
        where: { id },
        data: {
          isActive: true,
          updatedBy,
          updatedAt: new Date(),
        },
      });

      logger.info(`User activated: ${activatedUser.id} (${activatedUser.email})`);
      return activatedUser;
    } catch (error) {
      logger.error('Failed to activate user:', error);
      throw error;
    }
  }

  async verifyEmail(id: string): Promise<User> {
    try {
      const user = await prisma.user.update({
        where: { id },
        data: {
          isEmailVerified: true,
          emailVerifiedAt: new Date(),
          updatedAt: new Date(),
        },
      });

      logger.info(`Email verified for user: ${user.id} (${user.email})`);
      return user;
    } catch (error) {
      logger.error('Failed to verify email:', error);
      throw error;
    }
  }

  async recordLoginAttempt(id: string, success: boolean, ipAddress?: string): Promise<void> {
    try {
      if (success) {
        await prisma.user.update({
          where: { id },
          data: {
            lastLoginAt: new Date(),
            lastLoginIp: ipAddress,
            failedLoginAttempts: 0,
            lockedAt: null,
            lockedUntil: null,
          },
        });
      } else {
        const user = await this.findById(id);
        if (!user) return;

        const failedAttempts = user.failedLoginAttempts + 1;
        const shouldLock = failedAttempts >= config.security.maxLoginAttempts;

        await prisma.user.update({
          where: { id },
          data: {
            failedLoginAttempts: failedAttempts,
            lockedAt: shouldLock ? new Date() : null,
            lockedUntil: shouldLock ? new Date(Date.now() + config.security.lockoutTime) : null,
          },
        });

        if (shouldLock) {
          logger.warn(`User account locked due to failed login attempts: ${user.email}`);
        }
      }
    } catch (error) {
      logger.error('Failed to record login attempt:', error);
    }
  }

  async isAccountLocked(user: User): Promise<boolean> {
    if (!user.lockedUntil) return false;
    
    if (user.lockedUntil > new Date()) {
      return true;
    }

    // Unlock account if lockout period has expired
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedAt: null,
        lockedUntil: null,
      },
    });

    return false;
  }

  async getUserPermissions(userId: string): Promise<string[]> {
    try {
      const userWithRoles = await this.findWithRoles(userId);
      if (!userWithRoles) {
        return [];
      }

      const permissions = new Set<string>();
      
      for (const userRole of userWithRoles.roles) {
        for (const rolePermission of userRole.role.permissions) {
          permissions.add(rolePermission.permission.name);
        }
      }

      return Array.from(permissions);
    } catch (error) {
      logger.error('Failed to get user permissions:', error);
      return [];
    }
  }

  async hasPermission(userId: string, permission: string): Promise<boolean> {
    try {
      const permissions = await this.getUserPermissions(userId);
      return permissions.includes(permission);
    } catch (error) {
      logger.error('Failed to check user permission:', error);
      return false;
    }
  }

  async searchUsers(query: string, limit = 10, offset = 0): Promise<{ users: User[]; total: number }> {
    try {
      const where: Prisma.UserWhereInput = {
        OR: [
          { email: { contains: query, mode: 'insensitive' } },
          { username: { contains: query, mode: 'insensitive' } },
          { firstName: { contains: query, mode: 'insensitive' } },
          { lastName: { contains: query, mode: 'insensitive' } },
        ],
      };

      const [users, total] = await Promise.all([
        prisma.user.findMany({
          where,
          take: limit,
          skip: offset,
          orderBy: { createdAt: 'desc' },
        }),
        prisma.user.count({ where }),
      ]);

      return { users, total };
    } catch (error) {
      logger.error('Failed to search users:', error);
      throw error;
    }
  }

  async getUserStats(): Promise<{
    total: number;
    active: number;
    inactive: number;
    emailVerified: number;
    lockedAccounts: number;
  }> {
    try {
      const [total, active, inactive, emailVerified, lockedAccounts] = await Promise.all([
        prisma.user.count(),
        prisma.user.count({ where: { isActive: true } }),
        prisma.user.count({ where: { isActive: false } }),
        prisma.user.count({ where: { isEmailVerified: true } }),
        prisma.user.count({ where: { lockedUntil: { gt: new Date() } } }),
      ]);

      return {
        total,
        active,
        inactive,
        emailVerified,
        lockedAccounts,
      };
    } catch (error) {
      logger.error('Failed to get user stats:', error);
      throw error;
    }
  }
}

export const userService = new UserService();