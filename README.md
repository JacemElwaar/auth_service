# 🔐 Auth Service

A complete authentication and identity service for LinkedIn-style meetup applications, built with Go, ORY Hydra (OAuth2/OIDC), and ORY Kratos (identity management).

## Features

- **Local Authentication**: Email/password registration and login
- **Social Login**: Google, LinkedIn, Twitter OAuth integration
- **Email Verification**: Automated email verification workflow
- **Password Reset**: Secure password reset via email
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA with backup codes
- **JWT Tokens**: Short-lived access tokens with refresh token rotation
- **Database Support**: SQLite for development, PostgreSQL for production
- **Email Service**: SMTP integration with MailHog for development
- **Observability**: Prometheus metrics, health checks, structured logging
- **Production Ready**: Docker Compose for dev, Kubernetes manifests for prod

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Auth Service  │    │   Database      │
│   (React/Vue)   │◄──►│   (Go/Gin)      │◄──►│   (SQLite/PG)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ORY Hydra     │    │   Email Service │    │   ORY Kratos    │
│   (OAuth2/OIDC) │    │   (SMTP/MailHog)│    │   (Identity)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Database Models

### Users
- `id` (UUID, Primary Key)
- `email` (String, Unique)
- `password_hash` (String)
- `email_verified` (Boolean)
- `mfa_enabled` (Boolean)
- `mfa_secret` (String)
- `profile_data` (JSONB)
- `created_at`, `updated_at` (Timestamps)

### Social Providers
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key)
- `provider` (String: google, linkedin, twitter)
- `provider_user_id` (String)
- `access_token`, `refresh_token` (String)
- `token_expires_at` (Timestamp)

### OAuth Clients
- `id` (UUID, Primary Key)
- `client_name` (String)
- `client_secret` (String)
- `redirect_uris` (JSON Array)
- `scopes` (JSON Array)

### Refresh Tokens
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key)
- `token` (String, Unique)
- `revoked` (Boolean)
- `expires_at` (Timestamp)

### Email Tokens
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key)
- `token` (String, Unique)
- `type` (Enum: verification, password_reset)
- `expires_at` (Timestamp)
- `used` (Boolean)

## Quick Start

### Development Setup

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd auth-service
   cp .env.example .env
   ```

2. **Start with Docker Compose**
   ```bash
   docker-compose up -d
   ```

   This starts:
   - Auth Service (port 8080)
   - PostgreSQL (port 5432)
   - Redis (port 6379)
   - MailHog Web UI (port 8025)
   - ORY Hydra (ports 4444, 4445)
   - ORY Kratos (ports 4433, 4434)
   - Prometheus (port 9090)
   - Grafana (port 3001)

3. **Access Services**
   - Auth Service API: http://localhost:8080
   - MailHog UI: http://localhost:8025
   - Prometheus: http://localhost:9090
   - Grafana: http://localhost:3001 (admin/admin)

### Local Development

1. **Install Dependencies**
   ```bash
   go mod download
   ```

2. **Setup Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run the Service**
   ```bash
   go run main.go
   ```

## API Endpoints

### Authentication

#### Register User
```http
POST /api/v1/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123",
  "profile_data": {
    "first_name": "John",
    "last_name": "Doe",
    "display_name": "John Doe"
  }
}
```

#### Login
```http
POST /api/v1/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123",
  "mfa_code": "123456"  // Optional, required if MFA enabled
}
```

#### Forgot Password
```http
POST /api/v1/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Reset Password
```http
POST /api/v1/reset-password
Content-Type: application/json

{
  "token": "reset-token-from-email",
  "new_password": "newsecurepassword123"
}
```

#### Verify Email
```http
POST /api/v1/verify-email
Content-Type: application/json

{
  "token": "verification-token-from-email"
}
```

#### Refresh Token
```http
POST /api/v1/refresh-token
Content-Type: application/json

{
  "refresh_token": "your-refresh-token"
}
```

### MFA (Multi-Factor Authentication)

#### Setup MFA
```http
POST /api/v1/mfa/setup
Authorization: Bearer <access-token>
```

#### Verify MFA Setup
```http
POST /api/v1/mfa/verify
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "secret": "mfa-secret-from-setup",
  "code": "123456"
}
```

#### Disable MFA
```http
POST /api/v1/mfa/disable
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "password": "currentpassword",
  "code": "123456"
}
```

### Profile Management

#### Get Profile
```http
GET /api/v1/profile
Authorization: Bearer <access-token>
```

#### Update Profile
```http
PUT /api/v1/profile
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe",
  "bio": "Software Developer",
  "location": "San Francisco, CA"
}
```

#### Delete Account
```http
DELETE /api/v1/profile
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "password": "currentpassword"
}
```

### Health & Monitoring

#### Health Check
```http
GET /health
```

#### Metrics (Prometheus)
```http
GET /metrics
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DATABASE_URL` | Database connection string | `auth_service.db` | Yes |
| `DATABASE_DRIVER` | Database driver (sqlite/postgres) | `sqlite` | Yes |
| `JWT_SECRET` | JWT signing secret | - | Yes |
| `SMTP_HOST` | SMTP server host | `localhost` | Yes |
| `SMTP_PORT` | SMTP server port | `1025` | Yes |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - | No |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - | No |

See `.env.example` for complete list.

### OAuth Provider Setup

#### Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add redirect URI: `http://localhost:8080/api/v1/social-login/google/callback`
6. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`

#### LinkedIn OAuth
1. Go to [LinkedIn Developer Portal](https://developer.linkedin.com/)
2. Create a new app
3. Add redirect URI: `http://localhost:8080/api/v1/social-login/linkedin/callback`
4. Set `LINKEDIN_CLIENT_ID` and `LINKEDIN_CLIENT_SECRET`

## Production Deployment

### Kubernetes

1. **Create Namespace**
   ```bash
   kubectl apply -f k8s/namespace.yaml
   ```

2. **Create Secrets**
   ```bash
   kubectl create secret generic auth-service-secrets \
     --from-literal=DATABASE_URL="postgres://user:pass@host:5432/db" \
     --from-literal=JWT_SECRET="your-production-jwt-secret" \
     --namespace=auth-service
   ```

3. **Deploy Application**
   ```bash
   kubectl apply -f k8s/
   ```

### Database Migration

#### SQLite to PostgreSQL

1. **Export SQLite Data**
   ```bash
   sqlite3 auth_service.db .dump > backup.sql
   ```

2. **Convert and Import to PostgreSQL**
   ```bash
   # Install sqlite3-to-postgres tool
   pip install sqlite3-to-postgres
   
   # Convert and import
   sqlite3-to-postgres -f auth_service.db -d "postgresql://user:pass@host:5432/auth_service"
   ```

3. **Update Configuration**
   ```bash
   export DATABASE_DRIVER=postgres
   export DATABASE_URL="postgres://user:pass@host:5432/auth_service?sslmode=disable"
   ```

## Security Considerations

### Production Checklist

- [ ] Change default JWT secret
- [ ] Use strong database passwords
- [ ] Enable HTTPS/TLS
- [ ] Configure rate limiting
- [ ] Set up proper CORS policies
- [ ] Use secure session cookies
- [ ] Enable database connection encryption
- [ ] Configure proper firewall rules
- [ ] Set up monitoring and alerting
- [ ] Regular security updates

### Best Practices

1. **Password Security**
   - Minimum 8 characters
   - BCrypt hashing with cost 12+
   - Password strength validation

2. **Token Security**
   - Short-lived access tokens (15 minutes)
   - Secure refresh token rotation
   - Proper token revocation

3. **Email Security**
   - Token expiration (24h for verification, 1h for reset)
   - Rate limiting on email sending
   - Secure token generation

## Monitoring & Observability

### Prometheus Metrics

- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request duration
- `auth_attempts_total` - Authentication attempts
- `emails_sent_total` - Emails sent
- `active_tokens_count` - Active refresh tokens

### Health Checks

The `/health` endpoint provides:
- Service status
- Database connectivity
- Connection pool stats
- System timestamp

### Logging

Structured JSON logging with:
- Request/response logging
- Error tracking
- Authentication events
- Email delivery status

## Development

### Project Structure

```
auth-service/
├── config/          # Configuration management
├── database/        # Database connection and migrations
├── handlers/        # HTTP request handlers
├── middleware/      # HTTP middleware (auth, CORS, metrics)
├── models/          # Database models (GORM)
├── services/        # Business logic services
├── k8s/            # Kubernetes manifests
├── docker-compose.yml
├── Dockerfile
├── go.mod
├── go.sum
├── main.go
└── README.md
```

### Adding New Features

1. **Database Models**: Add to `models/`
2. **Business Logic**: Add to `services/`
3. **HTTP Handlers**: Add to `handlers/`
4. **Routes**: Register in `main.go`
5. **Tests**: Add corresponding test files

### Testing

```bash
# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test
go test ./services -run TestAuthService
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check `DATABASE_URL` format
   - Verify database server is running
   - Check network connectivity

2. **Email Not Sending**
   - Verify SMTP configuration
   - Check MailHog is running (development)
   - Validate email credentials (production)

3. **JWT Token Invalid**
   - Check `JWT_SECRET` configuration
   - Verify token hasn't expired
   - Ensure consistent secret across instances

4. **MFA Not Working**
   - Verify time synchronization
   - Check TOTP secret generation
   - Validate authenticator app setup

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=debug
go run main.go
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check existing documentation
- Review troubleshooting section
