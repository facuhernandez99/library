# Context-Aware Logging Package

The `pkg/logging` package provides a comprehensive, structured logging solution with context propagation, error sanitization, and HTTP middleware support for the blog service.

## Features

- **Structured JSON Logging**: All logs are output in structured JSON format for easy parsing and analysis
- **Context Propagation**: Automatically propagate request IDs and user IDs through the application context
- **Error Sanitization**: Automatically sanitize sensitive information from errors in production environments
- **HTTP Middleware**: Comprehensive HTTP request/response logging with configurable options
- **Log Level Filtering**: Support for different log levels (DEBUG, INFO, WARN, ERROR, FATAL)
- **Production Safety**: Intelligent error sanitization to prevent sensitive data leaks
- **Thread-Safe**: All operations are thread-safe and can be used concurrently

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "github.com/facuhernandez99/blog/pkg/logging"
)

func main() {
    ctx := context.Background()
    
    // Simple logging
    logging.Info(ctx, "Application started")
    logging.Error(ctx, "Something went wrong", err)
    
    // Logging with fields
    logging.WithFields(map[string]interface{}{
        "user_id": "123",
        "action": "login",
    }).Info(ctx, "User logged in")
}
```

### Custom Logger Configuration

```go
package main

import (
    "os"
    "github.com/facuhernandez99/blog/pkg/logging"
)

func main() {
    // Create custom logger
    config := &logging.Config{
        Level:      logging.LevelDebug,
        Output:     os.Stdout,
        Service:    "my-service",
        Version:    "1.0.0",
        Production: true, // Enable production mode for sanitization
    }
    
    logger := logging.NewLogger(config)
    
    // Set as default logger
    logging.SetDefault(logger)
}
```

## Core Components

### Logger

The main logger provides structured logging with different levels:

```go
logger := logging.NewLogger(config)

ctx := context.Background()

// Different log levels
logger.Debug(ctx, "Debug message")
logger.Info(ctx, "Info message")
logger.Warn(ctx, "Warning message")
logger.Error(ctx, "Error occurred", err)
logger.Fatal(ctx, "Fatal error", err) // Calls os.Exit(1)

// Formatted logging
logger.Infof(ctx, "User %s logged in with ID %d", username, userID)
logger.Errorf(ctx, err, "Failed to process request %s", requestID)
```

### Context Propagation

The package provides utilities for propagating request and user IDs through the application context:

```go
// Add request ID to context
ctx := logging.WithRequestID(context.Background(), "req-123")

// Add user ID to context
ctx = logging.WithUserID(ctx, "user-456")

// Add both at once
ctx = logging.WithRequestAndUserID(context.Background(), "req-123", "user-456")

// Extract from context
requestID := logging.GetRequestIDFromContext(ctx)
userID := logging.GetUserIDFromContext(ctx)

// All logs will automatically include these IDs
logging.Info(ctx, "Processing request") 
// Output: {"timestamp":"2024-01-01T12:00:00Z","level":"INFO","message":"Processing request","request_id":"req-123","user_id":"user-456",...}
```

### Structured Logging with Fields

Add structured fields to logs for better observability:

```go
// Single field
logger.WithField("component", "auth").Info(ctx, "Authentication successful")

// Multiple fields
logger.WithFields(map[string]interface{}{
    "component": "database",
    "operation": "query",
    "duration_ms": 45.2,
    "rows_affected": 1,
}).Info(ctx, "Database operation completed")

// Chain fields
contextLogger := logger.
    WithField("service", "user-service").
    WithField("version", "1.2.3")

contextLogger.Info(ctx, "Service started")
```

## HTTP Middleware

### Comprehensive HTTP Logging

The package provides advanced HTTP middleware for request/response logging:

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/facuhernandez99/blog/pkg/logging"
)

func main() {
    router := gin.New()
    
    // Use comprehensive HTTP logging middleware
    config := &logging.HTTPLoggingConfig{
        Logger:              logging.GetDefault(),
        SkipPaths:          []string{"/health", "/metrics"},
        LogRequestBody:     false, // Set to true to log request bodies
        LogResponseBody:    false, // Set to true to log response bodies
        MaxBodySize:        1024 * 1024, // 1MB limit for body logging
        SanitizeHeaders:    true,  // Remove sensitive headers
        SkipSuccessfulGETs: true,  // Skip logging successful GET requests
        RequestIDHeader:    "X-Request-ID",
        UserIDExtractor:    logging.DefaultUserIDExtractor,
    }
    
    router.Use(logging.HTTPLoggingMiddleware(config))
    
    // Your routes here
    router.GET("/api/users", getUsersHandler)
}
```

### Simple Request Logging

For simpler use cases, use the basic request logging middleware:

```go
router.Use(logging.RequestLoggingMiddleware(logging.GetDefault()))
```

### Recovery Middleware

Use the recovery middleware to log panics with structured context:

```go
router.Use(logging.RecoveryLoggingMiddleware(logging.GetDefault()))
```

## Error Sanitization

The package automatically sanitizes sensitive information from errors in production mode:

### Production Mode

```go
config := &logging.Config{
    Production: true, // Enable production mode
}
logger := logging.NewLogger(config)

// Sensitive information will be automatically redacted
err := errors.New("database connection failed with password: secret123")
logger.Error(ctx, "Database error", err)
// Output: {"level":"ERROR","message":"Database error","error":"database connection failed with password: [REDACTED]",...}
```

### Sensitive Data Patterns

The sanitizer automatically detects and redacts:

- **Credentials**: passwords, tokens, API keys, secrets
- **Personal Information**: email addresses, credit card numbers, SSNs
- **Network Information**: IP addresses (partial redaction)
- **JWT Tokens**: Complete redaction
- **Database Connection Strings**: Credential parts redacted

### Custom Sanitization

```go
sanitizer := logging.NewErrorSanitizer(true) // production mode

// Check if error contains sensitive data
if sanitizer.IsSensitiveError(err) {
    // Handle sensitive error specially
}

// Sanitize data maps (useful for request/response logging)
sanitizedData := sanitizer.SanitizeMap(requestData)
```

## Configuration

### Logger Configuration

```go
type Config struct {
    Level      LogLevel    // Minimum log level to output
    Output     io.Writer   // Where to write logs (default: os.Stdout)
    Service    string      // Service name for all log entries
    Version    string      // Service version for all log entries
    Production bool        // Enable production mode (affects sanitization)
}
```

### HTTP Middleware Configuration

```go
type HTTPLoggingConfig struct {
    Logger               *Logger                    // Logger instance to use
    SkipPaths           []string                   // Paths to skip logging
    LogRequestBody      bool                       // Whether to log request bodies
    LogResponseBody     bool                       // Whether to log response bodies
    MaxBodySize         int64                      // Maximum body size to log
    SanitizeHeaders     bool                       // Whether to sanitize headers
    SkipSuccessfulGETs  bool                       // Skip logging successful GET requests
    RequestIDHeader     string                     // Header name for request ID
    UserIDExtractor     func(*gin.Context) string  // Function to extract user ID
}
```

## Log Output Format

All logs are output in structured JSON format:

```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "INFO",
  "message": "User authentication successful",
  "request_id": "req-123",
  "user_id": "user-456",
  "service": "blog-service",
  "version": "1.0.0",
  "fields": {
    "component": "auth",
    "method": "password",
    "duration_ms": 45.2
  }
}
```

### Error Log Format

When logging errors, additional fields are included:

```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "ERROR",
  "message": "Database operation failed",
  "request_id": "req-123",
  "error": "connection timeout",
  "stack": "goroutine 1 [running]:\n...",
  "service": "blog-service",
  "version": "1.0.0"
}
```

## Best Practices

### 1. Use Context Propagation

Always pass context with request and user IDs:

```go
// In HTTP middleware (handled automatically by provided middleware)
ctx := logging.WithRequestAndUserID(c.Request.Context(), requestID, userID)
c.Request = c.Request.WithContext(ctx)

// In service functions
func (s *UserService) GetUser(ctx context.Context, userID string) (*User, error) {
    logger := logging.WithFields(map[string]interface{}{
        "operation": "get_user",
        "target_user_id": userID,
    })
    
    logger.Info(ctx, "Getting user")
    // ... implementation
}
```

### 2. Use Structured Fields

Instead of embedding data in messages, use structured fields:

```go
// ❌ Don't do this
logging.Infof(ctx, "User %s performed action %s at %v", userID, action, timestamp)

// ✅ Do this
logging.WithFields(map[string]interface{}{
    "user_id": userID,
    "action": action,
    "timestamp": timestamp,
}).Info(ctx, "User performed action")
```

### 3. Choose Appropriate Log Levels

- **DEBUG**: Detailed information for debugging
- **INFO**: General information about application flow
- **WARN**: Something unexpected happened, but application can continue
- **ERROR**: Error occurred, but application can continue
- **FATAL**: Error occurred, application cannot continue

### 4. Enable Production Mode

Always enable production mode in production environments:

```go
config := &logging.Config{
    Production: os.Getenv("ENV") == "production",
}
```

### 5. Use Package-Level Functions for Convenience

For simple logging, use package-level functions:

```go
// These use the default logger
logging.Info(ctx, "Application started")
logging.WithField("component", "auth").Error(ctx, "Authentication failed", err)
```

## Testing

The package includes comprehensive tests covering all functionality. Run tests with:

```bash
go test ./pkg/logging/...
```

### Testing with Custom Logger

For testing, you can capture log output:

```go
func TestMyFunction(t *testing.T) {
    var buf bytes.Buffer
    
    logger := logging.NewLogger(&logging.Config{
        Level:  logging.LevelDebug,
        Output: &buf,
    })
    logging.SetDefault(logger)
    
    // Run your function
    myFunction()
    
    // Check log output
    output := buf.String()
    assert.Contains(t, output, "expected log message")
}
```

## Integration Examples

### With Existing HTTP Middleware

```go
// Integrate with existing middleware stack
router := gin.New()

// Request ID middleware (if not using the logging middleware)
router.Use(func(c *gin.Context) {
    requestID := uuid.New().String()
    ctx := logging.WithRequestID(c.Request.Context(), requestID)
    c.Request = c.Request.WithContext(ctx)
    c.Header("X-Request-ID", requestID)
    c.Next()
})

// Logging middleware
router.Use(logging.RequestLoggingMiddleware(nil))

// Recovery middleware
router.Use(logging.RecoveryLoggingMiddleware(nil))
```

### With Authentication Middleware

```go
func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // ... authentication logic
        
        // Add user ID to context for logging
        if userID := extractUserID(c); userID != "" {
            ctx := logging.WithUserID(c.Request.Context(), userID)
            c.Request = c.Request.WithContext(ctx)
        }
        
        c.Next()
    }
}
```

### Service Layer Integration

```go
type UserService struct {
    logger *logging.Logger
}

func NewUserService() *UserService {
    return &UserService{
        logger: logging.GetDefault(),
    }
}

func (s *UserService) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
    serviceLogger := s.logger.WithFields(map[string]interface{}{
        "operation": "create_user",
        "email": req.Email, // This will be sanitized automatically
    })
    
    serviceLogger.Info(ctx, "Creating new user")
    
    // ... implementation
    
    if err != nil {
        serviceLogger.Error(ctx, "Failed to create user", err)
        return nil, err
    }
    
    serviceLogger.WithField("user_id", user.ID).Info(ctx, "User created successfully")
    return user, nil
}
```

## Performance Considerations

- Log level filtering happens early to avoid expensive operations
- JSON marshaling is only done for logs that will actually be output
- Context values are cached to avoid repeated type assertions
- Sanitization patterns are compiled once at startup
- Thread-safe operations use read-write mutexes for optimal performance

## Security

- Production mode automatically sanitizes sensitive information
- Configurable sanitization patterns for different environments
- Headers containing authentication information are automatically redacted
- Stack traces are only included for internal errors or in development mode
- Request/response body logging is disabled by default and should be used carefully 