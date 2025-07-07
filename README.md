# Library - Go Microservices Shared Library

A comprehensive Go library providing essential building blocks for microservices development, including authentication, database management, HTTP utilities, logging, configuration, and error handling.

## 🚀 Features

- **🔐 Authentication & Authorization**: JWT token management with refresh tokens, password hashing, and middleware
- **🗄️ Database Management**: PostgreSQL connection handling, migrations, and transaction utilities
- **🌐 HTTP Utilities**: Middleware stack, CORS, rate limiting, request/response helpers, and HTTP client
- **📝 Structured Logging**: JSON-based logging with context propagation and error sanitization
- **⚙️ Configuration Management**: Environment-based configuration with validation
- **❌ Error Handling**: Structured error types with proper HTTP status mapping
- **🧪 Testing Framework**: Comprehensive testing utilities and integration test helpers
- **🔄 Models**: Common data structures and validation

## 📦 Installation

```bash
go get github.com/facuhernandez99/library
```

## 🏗️ Architecture

```
pkg/
├── auth/           # JWT authentication, password hashing, middleware
├── config/         # Environment configuration management
├── database/       # PostgreSQL connection and migration utilities
├── errors/         # Structured error handling
├── http/           # HTTP middleware, client, and utilities
├── logging/        # Structured JSON logging with context
├── models/         # Common data models and validation
└── testing/        # Testing utilities and helpers

integration/        # Integration tests and examples
scripts/           # Test automation scripts
```

## 🚀 Quick Start

### Basic Setup

```go
package main

import (
    "context"
    "log"
    
    "github.com/facuhernandez99/library/pkg/config"
    "github.com/facuhernandez99/library/pkg/database"
    "github.com/facuhernandez99/library/pkg/logging"
    "github.com/gin-gonic/gin"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }
    
    // Setup logging
    logger := logging.NewLogger(&logging.Config{
        Level:      logging.LevelInfo,
        Service:    "my-service",
        Production: cfg.IsProduction(),
    })
    
    // Connect to database
    db, err := database.Connect(cfg)
    if err != nil {
        logger.Fatal(context.Background(), "Database connection failed", err)
    }
    defer db.Close()
    
    // Setup HTTP server
    router := gin.New()
    // Add your routes here
    
    router.Run(":" + fmt.Sprintf("%d", cfg.Port))
}
```

### Environment Configuration

Create a `.env` file or set environment variables:

```bash
# Required
DATABASE_URL=postgres://user:password@localhost:5432/dbname
JWT_SECRET=your-super-secret-jwt-key-at-least-32-chars

# Optional
PORT=8080
ENVIRONMENT=development
LOG_LEVEL=info
REDIS_URL=redis://localhost:6379
```

## 📚 Package Documentation

### 🔐 Authentication (`pkg/auth`)

Comprehensive JWT authentication with refresh tokens and password security.

```go
import "github.com/facuhernandez99/library/pkg/auth"

// Generate JWT tokens
tokenResponse, err := auth.GenerateJWT(user, jwtSecret, 24) // 24 hours
refreshToken, err := auth.GenerateRefreshToken(user, jwtSecret)

// Validate tokens
claims, err := auth.ValidateJWT(tokenString, jwtSecret)
refreshClaims, err := auth.ValidateRefreshToken(refreshToken, jwtSecret)

// Password hashing
hashedPassword, err := auth.HashPassword("plaintext")
isValid := auth.CheckPasswordHash("plaintext", hashedPassword)

// Middleware for Gin
router.Use(auth.AuthMiddleware(jwtSecret))

// Token blacklisting (logout)
auth.SetTokenStorage(redisStorage) // Implement TokenStorage interface
err := auth.LogoutToken(tokenString, jwtSecret)
```

**Features:**
- JWT token generation and validation
- Refresh token support
- Password hashing with bcrypt
- Token blacklisting for logout
- Gin middleware for route protection
- User context extraction

### 🗄️ Database (`pkg/database`)

PostgreSQL database management with connection pooling and migrations.

```go
import "github.com/facuhernandez99/library/pkg/database"

// Connect using shared config
db, err := database.Connect(cfg)

// Or connect with custom DSN
db, err := database.ConnectWithDSN("postgres://...")

// Transaction handling
err = db.WithTransaction(ctx, func(tx *sql.Tx) error {
    // Your transactional operations
    return nil
})

// Health checks
isHealthy := db.IsHealthy(ctx)
stats := db.Stats()

// Utility functions
exists, err := db.TableExists(ctx, "users")
exists, err := db.ColumnExists(ctx, "users", "email")
```

**Features:**
- Connection pooling configuration
- Transaction helpers with automatic rollback
- Health check utilities
- Database introspection
- Migration support
- Context-aware operations

### 🌐 HTTP (`pkg/http`)

HTTP utilities including middleware, client, and response helpers.

```go
import httpPkg "github.com/facuhernandez99/library/pkg/http"

// Middleware stack
router.Use(httpPkg.RequestIDMiddleware())
router.Use(httpPkg.DefaultStructuredLoggingMiddleware())
router.Use(httpPkg.CORSMiddleware(nil))
router.Use(httpPkg.SecurityHeadersMiddleware())

// Rate limiting
rateLimiter := httpPkg.NewRateLimiter(100, time.Minute) // 100 req/min
router.Use(rateLimiter.RateLimitMiddleware())

// HTTP Client
client := httpPkg.NewClient(&httpPkg.ClientConfig{
    BaseURL: "https://api.example.com",
    Timeout: 30 * time.Second,
    AuthConfig: &httpPkg.AuthConfig{
        JWTSecret: jwtSecret,
        ServiceToken: token,
    },
})

response, err := client.Get(ctx, "/users")
response, err := client.Post(ctx, "/users", userData)

// Response helpers
httpPkg.RespondWithSuccess(c, data)
httpPkg.RespondWithError(c, http.StatusBadRequest, "Invalid input")
httpPkg.RespondWithCreated(c, newUser)
```

**Features:**
- Request ID tracking
- Structured HTTP logging
- CORS with security controls
- Rate limiting with cleanup
- Security headers
- Timeout handling
- HTTP client with authentication
- Standardized response formats

### 📝 Logging (`pkg/logging`)

Structured JSON logging with context propagation and error sanitization.

```go
import "github.com/facuhernandez99/library/pkg/logging"

// Setup logger
logger := logging.NewLogger(&logging.Config{
    Level:      logging.LevelInfo,
    Service:    "user-service",
    Version:    "1.0.0",
    Production: true,
})

// Basic logging
logger.Info(ctx, "User created successfully")
logger.Error(ctx, "Database connection failed", err)

// Structured logging with fields
logger.WithFields(map[string]interface{}{
    "user_id": 123,
    "action":  "login",
}).Info(ctx, "User action performed")

// Context-aware logging
ctx = logging.WithRequestAndUserID(ctx, requestID, userID)
logger.Info(ctx, "Processing request") // Automatically includes IDs

// HTTP middleware logging
router.Use(logging.HTTPLoggingMiddleware(nil))
```

**Features:**
- Structured JSON output
- Context propagation (request ID, user ID)
- Error sanitization for production
- Multiple log levels
- Field-based logging
- HTTP request/response logging
- Stack traces for errors

### ⚙️ Configuration (`pkg/config`)

Environment-based configuration with validation.

```go
import "github.com/facuhernandez99/library/pkg/config"

// Load configuration
cfg, err := config.Load()

// Access configuration
fmt.Println("Port:", cfg.Port)
fmt.Println("Database URL:", cfg.DatabaseURL)
fmt.Println("Environment:", cfg.Environment)

// Environment checks
if cfg.IsDevelopment() {
    // Development-specific logic
}

if cfg.IsProduction() {
    // Production-specific logic
}

// Database configuration
dbConfig := cfg.GetDatabaseConfig()
```

**Configuration Fields:**
- `PORT`: Server port (default: 8080)
- `DATABASE_URL`: PostgreSQL connection string (required)
- `JWT_SECRET`: JWT signing secret (required, min 32 chars)
- `ENVIRONMENT`: development/staging/production (default: development)
- `LOG_LEVEL`: debug/info/warn/error (default: info)
- `REDIS_URL`: Redis connection string (default: redis://localhost:6379)

### ❌ Error Handling (`pkg/errors`)

Structured error handling with HTTP status mapping.

```go
import "github.com/facuhernandez99/library/pkg/errors"

// Create structured errors
err := errors.New(errors.ErrCodeValidation, "Invalid email format")
err := errors.Wrap(originalErr, errors.ErrCodeDatabaseError, "Failed to save user")

// Error codes
errors.ErrCodeValidation      // 400 Bad Request
errors.ErrCodeUnauthorized    // 401 Unauthorized
errors.ErrCodeNotFound        // 404 Not Found
errors.ErrCodeUserExists      // 409 Conflict
errors.ErrCodeDatabaseError   // 500 Internal Server Error
errors.ErrCodeInternal        // 500 Internal Server Error

// Check error types
if appErr, ok := errors.IsAppError(err); ok {
    switch appErr.Code {
    case errors.ErrCodeValidation:
        // Handle validation error
    case errors.ErrCodeUnauthorized:
        // Handle auth error
    }
}

// HTTP status mapping
statusCode := errors.GetHTTPStatus(err)
```

### 🧪 Testing (`pkg/testing`)

Comprehensive testing utilities for integration tests.

```go
import "github.com/facuhernandez99/library/pkg/testing"

// Database testing
func TestUserService(t *testing.T) {
    if !testing.IsPostgreSQLAvailable() {
        t.Skip("PostgreSQL not available")
    }
    
    dbHelper := testing.NewDatabaseTestHelper(t)
    dbHelper.Setup()
    defer dbHelper.Teardown()
    
    // Use dbHelper.DB for testing
}

// HTTP testing
httpHelper := testing.NewHTTPTestHelper(t)
response := httpHelper.MakeRequest("POST", "/users", userData)
httpHelper.AssertStatusCode(response, http.StatusCreated)

// Integration framework
framework := testing.NewIntegrationFramework(t, &testing.IntegrationConfig{
    DatabaseURL: "postgres://...",
    JWTSecret:   "test-secret",
})
defer framework.Cleanup()
```

## 🔧 Development

### Prerequisites

- Go 1.23+
- PostgreSQL 15+
- Redis (optional, for token blacklisting)

### Running Tests

```bash
# Unit tests
go test ./pkg/...

# Integration tests (requires PostgreSQL)
go test ./integration/...

# Specific integration test
go test ./integration/user_registration_login_flow_integration_test.go

# All tests with coverage
go test -cover ./...
```

### Test Scripts

```bash
# Run all tests
./scripts/run_all_tests.sh

# Run specific integration tests
./scripts/run_auth_integration_test.sh
./scripts/run_database_integration_test.sh
./scripts/run_user_registration_login_flow_test.sh

# Setup test database
./scripts/setup_database_for_tests.sh
```

### Docker Development

```bash
# Start PostgreSQL for testing
docker-compose up -d user-db

# Run tests against Docker database
DATABASE_URL="postgres://postgres:postgres@localhost:5432/users" go test ./integration/...
```

## 📋 Examples

### Complete User Authentication Service

```go
package main

import (
    "context"
    "net/http"
    
    "github.com/facuhernandez99/library/pkg/auth"
    "github.com/facuhernandez99/library/pkg/config"
    "github.com/facuhernandez99/library/pkg/database"
    httpPkg "github.com/facuhernandez99/library/pkg/http"
    "github.com/facuhernandez99/library/pkg/logging"
    "github.com/facuhernandez99/library/pkg/models"
    "github.com/gin-gonic/gin"
)

func main() {
    // Load configuration
    cfg, _ := config.Load()
    
    // Setup logging
    logger := logging.NewLogger(&logging.Config{
        Level:   logging.LevelInfo,
        Service: "auth-service",
    })
    
    // Connect to database
    db, _ := database.Connect(cfg)
    defer db.Close()
    
    // Setup router with middleware
    router := gin.New()
    router.Use(httpPkg.RequestIDMiddleware())
    router.Use(httpPkg.DefaultStructuredLoggingMiddleware())
    router.Use(httpPkg.CORSMiddleware(nil))
    router.Use(httpPkg.SecurityHeadersMiddleware())
    
    // Public routes
    router.POST("/auth/login", loginHandler(cfg.JWTSecret))
    router.POST("/auth/register", registerHandler(db, cfg.JWTSecret))
    
    // Protected routes
    protected := router.Group("/api")
    protected.Use(auth.AuthMiddleware(cfg.JWTSecret))
    protected.GET("/profile", profileHandler())
    
    router.Run(":8080")
}

func loginHandler(jwtSecret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req models.UserLoginRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            httpPkg.RespondWithError(c, http.StatusBadRequest, "Invalid request")
            return
        }
        
        // Authenticate user (implement your logic)
        user := &models.User{ID: 1, Username: req.Username}
        
        // Generate tokens
        tokenResponse, err := auth.GenerateJWT(user, jwtSecret, 24)
        if err != nil {
            httpPkg.RespondWithError(c, http.StatusInternalServerError, "Token generation failed")
            return
        }
        
        httpPkg.RespondWithSuccess(c, tokenResponse)
    }
}
```

### Database Operations with Transactions

```go
func CreateUserWithProfile(ctx context.Context, db *database.DB, userData UserData) error {
    return db.WithTransaction(ctx, func(tx *sql.Tx) error {
        // Create user
        userID, err := createUser(tx, userData.User)
        if err != nil {
            return err
        }
        
        // Create profile
        userData.Profile.UserID = userID
        return createProfile(tx, userData.Profile)
    })
}
```

### HTTP Client with Authentication

```go
func callExternalAPI(ctx context.Context, token string) (*APIResponse, error) {
    client := httpPkg.NewClient(&httpPkg.ClientConfig{
        BaseURL: "https://api.external.com",
        Timeout: 30 * time.Second,
        AuthConfig: &httpPkg.AuthConfig{
            ServiceToken: token,
        },
    })
    
    response, err := client.Get(ctx, "/data")
    if err != nil {
        return nil, err
    }
    
    var apiResponse APIResponse
    if err := json.Unmarshal(response.Body, &apiResponse); err != nil {
        return nil, err
    }
    
    return &apiResponse, nil
}
```