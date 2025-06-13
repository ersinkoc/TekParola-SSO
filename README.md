# TekParola - Enterprise Single Sign-On System

TekParola is a comprehensive, enterprise-grade Single Sign-On (SSO) system built with Node.js, TypeScript, and PostgreSQL. It provides centralized authentication and authorization with role-based access control (RBAC), perfect for managing access across multiple applications.

## ✨ Features

### 🔐 Authentication & Security
- **JWT-based Authentication** with refresh tokens
- **Two-Factor Authentication (2FA)** using TOTP
- **Magic Link Authentication** for passwordless login
- **Password Reset** with secure token validation
- **Account Lockout** protection against brute force attacks
- **Rate Limiting** on all sensitive endpoints
- **Session Management** with concurrent session control

### 👥 User Management
- **User Registration** (admin-controlled)
- **User Profiles** with customizable fields
- **Email Verification** system
- **Account Status Management** (active, inactive, suspended)
- **User Import/Export** functionality

### 🛡️ Role & Permission System
- **Hierarchical Role System** with inheritance
- **Granular Permissions** with resource-based control
- **Dynamic Role Assignment** at runtime
- **Application-Specific Permissions**
- **Permission Templates** for common roles

### 🏢 Application Management
- **Application Registration** for client apps
- **API Key Management** with scoped permissions
- **OAuth2-like Flow** for secure integrations
- **Application-Specific Configurations**

### 📊 Admin Features
- **Comprehensive Dashboard** with analytics
- **User Management Interface**
- **Role & Permission Management**
- **System Settings Configuration**
- **Audit Logging** for all activities
- **Security Monitoring** and alerts

### 📧 Email System
- **Template-Based Emails** with variables
- **Email Queue** with retry mechanism
- **Multiple Email Types** (welcome, reset, alerts)
- **SMTP Integration** with popular providers

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- PostgreSQL 14+
- Redis 6+
- SMTP email service

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd tekparola
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start services with Docker (recommended)**
   ```bash
   # Start PostgreSQL and Redis
   docker-compose -f docker-compose.dev.yml up -d
   ```

5. **Set up the database**
   ```bash
   # Generate Prisma client
   npm run db:generate
   
   # Run migrations
   npm run migrate
   
   # Seed database with initial data
   npm run db:seed
   ```

6. **Start the development server**
   ```bash
   npm run dev
   ```

The API will be available at `http://localhost:3000`

### Default Admin Account
After seeding the database, you can login with:
- **Email:** admin@tekparola.com
- **Password:** Admin123!

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `JWT_SECRET` | Secret for JWT tokens | Required |
| `JWT_REFRESH_SECRET` | Secret for refresh tokens | Required |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `SMTP_HOST` | SMTP server hostname | Required |
| `SMTP_USER` | SMTP username | Required |
| `SMTP_PASS` | SMTP password | Required |
| `FROM_EMAIL` | Sender email address | Required |
| `REGISTRATION_ENABLED` | Allow new registrations | `true` |
| `MAX_LOGIN_ATTEMPTS` | Max failed login attempts | `5` |
| `LOCKOUT_TIME` | Account lockout duration (ms) | `900000` |

See `.env.example` for all available configuration options.

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "password": "SecurePass123!"
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "twoFactorCode": "123456"
}
```

#### Refresh Token
```http
POST /api/v1/auth/refresh-token
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Password Reset
```http
POST /api/v1/auth/password-reset/request
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Magic Link
```http
POST /api/v1/auth/magic-link/request
Content-Type: application/json

{
  "email": "user@example.com"
}
```

### Protected Endpoints

All protected endpoints require the `Authorization` header:
```http
Authorization: Bearer <access_token>
```

#### Get Profile
```http
GET /api/v1/auth/profile
```

#### Update Profile
```http
PUT /api/v1/auth/profile
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+1234567890"
}
```

#### Enable 2FA
```http
POST /api/v1/auth/2fa/generate
POST /api/v1/auth/2fa/enable
Content-Type: application/json

{
  "code": "123456"
}
```

## 🏗️ Architecture

### Project Structure
```
tekparola/
├── src/
│   ├── controllers/     # Route controllers
│   ├── middleware/      # Express middleware
│   ├── models/          # Prisma models
│   ├── services/        # Business logic
│   ├── utils/           # Utility functions
│   ├── validators/      # Input validation
│   ├── config/          # Configuration files
│   └── routes/          # API routes
├── prisma/              # Database schema & migrations
├── tests/               # Test files
├── docker/              # Docker configurations
└── docs/                # Documentation
```

### Database Schema

The system uses PostgreSQL with the following main entities:
- **Users** - User accounts and profiles
- **Roles** - Hierarchical role system
- **Permissions** - Granular permissions
- **Applications** - Registered client applications
- **Sessions** - User session management
- **Audit Logs** - Activity tracking

## 🔐 Security Features

### Authentication Security
- **Bcrypt** password hashing with configurable rounds
- **JWT** tokens with short expiration and refresh rotation
- **Rate limiting** on all authentication endpoints
- **Account lockout** after failed login attempts
- **IP-based tracking** for suspicious activities

### Authorization
- **Role-based access control** (RBAC)
- **Permission inheritance** through role hierarchy
- **Resource-level permissions** with actions and scopes
- **Session validation** on every request

### Data Protection
- **Input validation** on all endpoints
- **SQL injection prevention** via Prisma ORM
- **XSS protection** with input sanitization
- **CORS** configuration for cross-origin requests
- **Helmet** for security headers

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
```

## 🚀 Deployment

### Docker Deployment

1. **Build the image**
   ```bash
   docker build -t tekparola .
   ```

2. **Run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

### Production Environment

1. **Set production environment variables**
2. **Run database migrations**
   ```bash
   npm run migrate:deploy
   ```
3. **Start the application**
   ```bash
   npm start
   ```

### Health Checks

The application provides a health check endpoint at `/health` for monitoring:

```http
GET /health
```

## 📊 Monitoring & Logging

### Logging
- **Structured logging** with Winston
- **Request/response logging** for audit trails
- **Error tracking** with stack traces
- **Security event logging** for monitoring

### Metrics
- **User activity** metrics
- **Authentication success/failure** rates
- **API response times**
- **System health** indicators

## 🔧 Development

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- Redis 6+

### Development Workflow

1. **Start development services**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

2. **Run in development mode**
   ```bash
   npm run dev
   ```

3. **Run linting**
   ```bash
   npm run lint
   npm run lint:fix
   ```

4. **Format code**
   ```bash
   npm run format
   ```

### Database Operations

```bash
# Generate Prisma client
npm run db:generate

# Create migration
npm run migrate

# Reset database
npx prisma migrate reset

# Open Prisma Studio
npm run db:studio
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the API endpoints at `/api`

## 🗺️ Roadmap

- [ ] OAuth2/OpenID Connect support
- [ ] SAML integration
- [ ] Multi-tenant support
- [ ] Advanced analytics dashboard
- [ ] Mobile app SDKs
- [ ] Kubernetes deployment manifests
- [ ] Advanced audit reporting
- [ ] Integration with popular identity providers

---

**TekParola** - Secure, scalable, and enterprise-ready SSO solution.