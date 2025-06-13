import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main(): Promise<void> {
  // Create system permissions
  const permissions = [
    // User management
    { name: 'users.create', displayName: 'Create Users', resource: 'users', action: 'create', scope: 'all' },
    { name: 'users.read', displayName: 'Read Users', resource: 'users', action: 'read', scope: 'all' },
    { name: 'users.update', displayName: 'Update Users', resource: 'users', action: 'update', scope: 'all' },
    { name: 'users.delete', displayName: 'Delete Users', resource: 'users', action: 'delete', scope: 'all' },
    { name: 'users.read.own', displayName: 'Read Own Profile', resource: 'users', action: 'read', scope: 'own' },
    { name: 'users.update.own', displayName: 'Update Own Profile', resource: 'users', action: 'update', scope: 'own' },
    
    // Role management
    { name: 'roles.create', displayName: 'Create Roles', resource: 'roles', action: 'create', scope: 'all' },
    { name: 'roles.read', displayName: 'Read Roles', resource: 'roles', action: 'read', scope: 'all' },
    { name: 'roles.update', displayName: 'Update Roles', resource: 'roles', action: 'update', scope: 'all' },
    { name: 'roles.delete', displayName: 'Delete Roles', resource: 'roles', action: 'delete', scope: 'all' },
    
    // Permission management
    { name: 'permissions.create', displayName: 'Create Permissions', resource: 'permissions', action: 'create', scope: 'all' },
    { name: 'permissions.read', displayName: 'Read Permissions', resource: 'permissions', action: 'read', scope: 'all' },
    { name: 'permissions.update', displayName: 'Update Permissions', resource: 'permissions', action: 'update', scope: 'all' },
    { name: 'permissions.delete', displayName: 'Delete Permissions', resource: 'permissions', action: 'delete', scope: 'all' },
    
    // Application management
    { name: 'applications.create', displayName: 'Create Applications', resource: 'applications', action: 'create', scope: 'all' },
    { name: 'applications.read', displayName: 'Read Applications', resource: 'applications', action: 'read', scope: 'all' },
    { name: 'applications.update', displayName: 'Update Applications', resource: 'applications', action: 'update', scope: 'all' },
    { name: 'applications.delete', displayName: 'Delete Applications', resource: 'applications', action: 'delete', scope: 'all' },
    
    // System settings
    { name: 'settings.read', displayName: 'Read Settings', resource: 'settings', action: 'read', scope: 'all' },
    { name: 'settings.update', displayName: 'Update Settings', resource: 'settings', action: 'update', scope: 'all' },
    
    // Audit logs
    { name: 'audit.read', displayName: 'Read Audit Logs', resource: 'audit', action: 'read', scope: 'all' },
    
    // Sessions
    { name: 'sessions.read', displayName: 'Read Sessions', resource: 'sessions', action: 'read', scope: 'all' },
    { name: 'sessions.delete', displayName: 'Delete Sessions', resource: 'sessions', action: 'delete', scope: 'all' },
    { name: 'sessions.read.own', displayName: 'Read Own Sessions', resource: 'sessions', action: 'read', scope: 'own' },
    { name: 'sessions.delete.own', displayName: 'Delete Own Sessions', resource: 'sessions', action: 'delete', scope: 'own' },
  ];

  console.log('Creating permissions...');
  for (const permission of permissions) {
    await prisma.permission.upsert({
      where: { name: permission.name },
      update: {},
      create: {
        ...permission,
        isSystem: true,
      },
    });
  }

  // Create system roles
  const superAdminRole = await prisma.role.upsert({
    where: { name: 'super_admin' },
    update: {},
    create: {
      name: 'super_admin',
      displayName: 'Super Administrator',
      description: 'Full system access with all permissions',
      isSystem: true,
    },
  });

  const adminRole = await prisma.role.upsert({
    where: { name: 'admin' },
    update: {},
    create: {
      name: 'admin',
      displayName: 'Administrator',
      description: 'Administrative access to manage users and applications',
      isSystem: true,
    },
  });

  const userRole = await prisma.role.upsert({
    where: { name: 'user' },
    update: {},
    create: {
      name: 'user',
      displayName: 'User',
      description: 'Standard user with basic permissions',
      isSystem: true,
    },
  });

  // Assign all permissions to super admin
  console.log('Assigning permissions to super admin...');
  const allPermissions = await prisma.permission.findMany();
  for (const permission of allPermissions) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: superAdminRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: superAdminRole.id,
        permissionId: permission.id,
      },
    });
  }

  // Assign admin permissions to admin role
  console.log('Assigning permissions to admin...');
  const adminPermissions = await prisma.permission.findMany({
    where: {
      OR: [
        { resource: 'users' },
        { resource: 'roles' },
        { resource: 'applications' },
        { resource: 'sessions' },
        { resource: 'audit' },
        { name: 'settings.read' },
      ],
    },
  });
  
  for (const permission of adminPermissions) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: adminRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: adminRole.id,
        permissionId: permission.id,
      },
    });
  }

  // Assign basic permissions to user role
  console.log('Assigning permissions to user...');
  const userPermissions = await prisma.permission.findMany({
    where: {
      scope: 'own',
    },
  });
  
  for (const permission of userPermissions) {
    await prisma.rolePermission.upsert({
      where: {
        roleId_permissionId: {
          roleId: userRole.id,
          permissionId: permission.id,
        },
      },
      update: {},
      create: {
        roleId: userRole.id,
        permissionId: permission.id,
      },
    });
  }

  // Create default super admin user
  const hashedPassword = await bcrypt.hash('Admin123!', 12);
  const superAdminUser = await prisma.user.upsert({
    where: { email: 'admin@tekparola.com' },
    update: {},
    create: {
      email: 'admin@tekparola.com',
      username: 'superadmin',
      firstName: 'Super',
      lastName: 'Admin',
      password: hashedPassword,
      isEmailVerified: true,
      emailVerifiedAt: new Date(),
    },
  });

  // Assign super admin role to the user
  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: superAdminUser.id,
        roleId: superAdminRole.id,
      },
    },
    update: {},
    create: {
      userId: superAdminUser.id,
      roleId: superAdminRole.id,
    },
  });

  // Create system settings
  const systemSettings = [
    { key: 'registration_enabled', value: 'true', type: 'boolean', description: 'Allow new user registration', category: 'auth', isPublic: true },
    { key: 'default_role', value: 'user', type: 'string', description: 'Default role for new users', category: 'auth' },
    { key: 'company_name', value: 'TekParola', type: 'string', description: 'Company name', category: 'branding', isPublic: true },
    { key: 'max_login_attempts', value: '5', type: 'number', description: 'Maximum login attempts before lockout', category: 'security' },
    { key: 'lockout_duration', value: '900', type: 'number', description: 'Lockout duration in seconds', category: 'security' },
    { key: 'session_timeout', value: '86400', type: 'number', description: 'Session timeout in seconds', category: 'security' },
    { key: 'password_min_length', value: '8', type: 'number', description: 'Minimum password length', category: 'security', isPublic: true },
    { key: 'password_require_uppercase', value: 'true', type: 'boolean', description: 'Require uppercase letters in password', category: 'security', isPublic: true },
    { key: 'password_require_lowercase', value: 'true', type: 'boolean', description: 'Require lowercase letters in password', category: 'security', isPublic: true },
    { key: 'password_require_numbers', value: 'true', type: 'boolean', description: 'Require numbers in password', category: 'security', isPublic: true },
    { key: 'password_require_symbols', value: 'true', type: 'boolean', description: 'Require symbols in password', category: 'security', isPublic: true },
  ];

  console.log('Creating system settings...');
  for (const setting of systemSettings) {
    await prisma.systemSetting.upsert({
      where: { key: setting.key },
      update: {},
      create: setting,
    });
  }

  // Create email templates
  const emailTemplates = [
    {
      name: 'welcome',
      subject: 'Welcome to {{company_name}}',
      htmlContent: `
        <h1>Welcome to {{company_name}}!</h1>
        <p>Hello {{firstName}},</p>
        <p>Welcome to our platform. Your account has been successfully created.</p>
        <p>You can now log in using your email address: {{email}}</p>
        <p>If you have any questions, please don't hesitate to contact us.</p>
        <p>Best regards,<br>The {{company_name}} Team</p>
      `,
      textContent: `Welcome to {{company_name}}!\n\nHello {{firstName}},\n\nWelcome to our platform. Your account has been successfully created.\n\nYou can now log in using your email address: {{email}}\n\nIf you have any questions, please don't hesitate to contact us.\n\nBest regards,\nThe {{company_name}} Team`,
      variables: { firstName: 'string', email: 'string', company_name: 'string' },
    },
    {
      name: 'password_reset',
      subject: 'Password Reset Request',
      htmlContent: `
        <h1>Password Reset Request</h1>
        <p>Hello {{firstName}},</p>
        <p>We received a request to reset your password. Click the link below to reset it:</p>
        <p><a href="{{resetLink}}">Reset Password</a></p>
        <p>This link will expire in {{expirationTime}} minutes.</p>
        <p>If you didn't request this password reset, please ignore this email.</p>
        <p>Best regards,<br>The {{company_name}} Team</p>
      `,
      textContent: `Password Reset Request\n\nHello {{firstName}},\n\nWe received a request to reset your password. Use the link below to reset it:\n\n{{resetLink}}\n\nThis link will expire in {{expirationTime}} minutes.\n\nIf you didn't request this password reset, please ignore this email.\n\nBest regards,\nThe {{company_name}} Team`,
      variables: { firstName: 'string', resetLink: 'string', expirationTime: 'number', company_name: 'string' },
    },
    {
      name: 'magic_link',
      subject: 'Your Magic Login Link',
      htmlContent: `
        <h1>Magic Login Link</h1>
        <p>Hello {{firstName}},</p>
        <p>Click the link below to log in to your account:</p>
        <p><a href="{{magicLink}}">Login to {{company_name}}</a></p>
        <p>This link will expire in {{expirationTime}} minutes.</p>
        <p>If you didn't request this login link, please ignore this email.</p>
        <p>Best regards,<br>The {{company_name}} Team</p>
      `,
      textContent: `Magic Login Link\n\nHello {{firstName}},\n\nUse the link below to log in to your account:\n\n{{magicLink}}\n\nThis link will expire in {{expirationTime}} minutes.\n\nIf you didn't request this login link, please ignore this email.\n\nBest regards,\nThe {{company_name}} Team`,
      variables: { firstName: 'string', magicLink: 'string', expirationTime: 'number', company_name: 'string' },
    },
  ];

  console.log('Creating email templates...');
  for (const template of emailTemplates) {
    await prisma.emailTemplate.upsert({
      where: { name: template.name },
      update: {},
      create: template,
    });
  }

  console.log('Seed data created successfully!');
  console.log('Super Admin Login:');
  console.log('Email: admin@tekparola.com');
  console.log('Password: Admin123!');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });