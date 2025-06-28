# Shared Packages Documentation

This document provides a comprehensive overview of all structs, functions, and constants implemented in the shared packages (`pkg/`) for the blog microservices architecture.

---

## 📦 `pkg/models` - Data Models and Common Types

### Structs

#### `User`
Represents a user in the system.
```go
type User struct {
    ID        int64     `json:"id" db:"id"`
    Username  string    `json:"username" db:"username" validate:"required,min=3,max=50"`
    Email     string    `json:"email" db:"email" validate:"required,email"`
    Password  string    `json:"-" db:"password_hash"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
    UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
```
**Purpose:** Core user model with validation tags for JSON serialization and database mapping.

#### `UserCreateRequest`
Request payload for user registration.
```go
type UserCreateRequest struct {
    Username string `json:"username" validate:"required,min=3,max=50"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8,max=100"`
}
```
**Purpose:** Structured input validation for user creation endpoints.

#### `UserLoginRequest`
Request payload for user authentication.
```go
type UserLoginRequest struct {
    Username string `json:"username" validate:"required"`
    Password string `json:"password" validate:"required"`
}
```
**Purpose:** Login credential validation.

#### `UserResponse`
Public user data for API responses.
```go
type UserResponse struct {
    ID        int64     `json:"id"`
    Username  string    `json:"username"`
    Email     string    `json:"email"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```
**Purpose:** Safe user representation without sensitive data (password excluded).

#### `APIResponse`
Standard wrapper for all API responses.
```go
type APIResponse struct {
    Success bool        `json:"success"`
    Message string      `json:"message,omitempty"`
    Data    interface{} `json:"data,omitempty"`
    Error   string      `json:"error,omitempty"`
}
```
**Purpose:** Consistent response format across all services.

#### `Pagination`
Pagination metadata for listing endpoints.
```go
type Pagination struct {
    Page       int `json:"page"`
    Limit      int `json:"limit"`
    Total      int `json:"total"`
    TotalPages int `json:"total_pages"`
}
```
**Purpose:** Standardized pagination information.

#### `PaginatedResponse`
Wrapper for paginated data responses.
```go
type PaginatedResponse struct {
    Data       interface{} `json:"data"`
    Pagination Pagination  `json:"pagination"`
}
```
**Purpose:** Consistent format for paginated API responses.

#### `HealthCheck`
Service health status information.
```go
type HealthCheck struct {
    Status    string    `json:"status"`
    Timestamp time.Time `json:"timestamp"`
    Version   string    `json:"version,omitempty"`
    Service   string    `json:"service"`
}
```
**Purpose:** Standardized health check responses across services.

#### `TokenResponse`
JWT token response format.
```go
type TokenResponse struct {
    Token     string    `json:"token"`
    ExpiresAt time.Time `json:"expires_at"`
    TokenType string    `json:"token_type"`
}
```
**Purpose:** Consistent token response format for authentication endpoints.

### Functions

#### `ToResponse() *UserResponse`
**Purpose:** Converts a User model to UserResponse, excluding sensitive data.
**Usage:** Safe user data serialization for API responses.

### Constants

```go
const (
    MaxUsernameLength = 50
    MinUsernameLength = 3
    MaxPasswordLength = 100
    MinPasswordLength = 8
)
```
**Purpose:** Validation constraints used across services.

---

## 🔐 `pkg/auth` - Authentication and Security

### Structs

#### `Claims`
JWT token claims structure.
```go
type Claims struct {
    UserID   int64  `json:"user_id"`
    Username string `json:"username"`
    jwt.RegisteredClaims
}
```
**Purpose:** Custom JWT claims with user identification and standard JWT fields.

### Functions

#### Password Management (`password.go`)

##### `HashPassword(password string) (string, error)`
**Purpose:** Generates bcrypt hash of a password with cost 12.
**Returns:** Hashed password string or error.

##### `CheckPasswordHash(password, hash string) bool`
**Purpose:** Verifies a password against its bcrypt hash.
**Returns:** True if password matches hash.

##### `ValidatePasswordStrength(password string) error`
**Purpose:** Comprehensive password strength validation (length, complexity, common patterns).
**Returns:** Detailed error if password is weak.

##### `ValidatePasswordBasic(password string) error`
**Purpose:** Basic password length validation.
**Returns:** Error if password doesn't meet minimum requirements.

#### JWT Management (`jwt.go`)

##### `GenerateJWT(userID int64, username, secret string) (string, error)`
**Purpose:** Creates a JWT token with user claims and 24-hour expiration.
**Returns:** Signed JWT token string or error.

##### `ValidateJWT(tokenString, secret string) (*Claims, error)`
**Purpose:** Validates and parses a JWT token.
**Returns:** Extracted claims or specific error (expired, malformed, invalid signature).

##### `ExtractUserID(tokenString, secret string) (int64, error)`
**Purpose:** Quick extraction of user ID from JWT token.
**Returns:** User ID or error.

##### `ExtractUsername(tokenString, secret string) (string, error)`
**Purpose:** Quick extraction of username from JWT token.
**Returns:** Username or error.

##### `IsTokenExpired(tokenString, secret string) bool`
**Purpose:** Checks if a JWT token has expired.
**Returns:** True if token is expired.

##### `RefreshToken(tokenString, secret string) (string, error)`
**Purpose:** Generates a new token with same claims but extended expiration.
**Returns:** New JWT token or error.

#### Middleware (`middleware.go`)

##### `AuthMiddleware(jwtSecret string) gin.HandlerFunc`
**Purpose:** Gin middleware requiring valid JWT authentication.
**Behavior:** Validates token, sets user context, aborts on invalid/missing token.

##### `OptionalAuthMiddleware(jwtSecret string) gin.HandlerFunc`
**Purpose:** Gin middleware that extracts JWT info if present but doesn't require it.
**Behavior:** Sets user context if valid token exists, continues regardless.

##### `RequireUserID(paramName string) gin.HandlerFunc`
**Purpose:** Middleware ensuring authenticated user matches URL parameter user ID.
**Behavior:** Prevents users from accessing other users' resources.

##### `CORSMiddleware() gin.HandlerFunc`
**Purpose:** Adds CORS headers for cross-origin requests.
**Behavior:** Sets standard CORS headers and handles preflight OPTIONS requests.

##### `GetUserID(c *gin.Context) (int64, bool)`
**Purpose:** Extracts user ID from Gin context.
**Returns:** User ID and existence flag.

##### `GetUsername(c *gin.Context) (string, bool)`
**Purpose:** Extracts username from Gin context.
**Returns:** Username and existence flag.

##### `GetClaims(c *gin.Context) (*Claims, bool)`
**Purpose:** Extracts full JWT claims from Gin context.
**Returns:** Claims struct and existence flag.

##### `IsAuthenticated(c *gin.Context) bool`
**Purpose:** Checks if current request is authenticated.
**Returns:** True if user is authenticated.

### Constants

```go
const (
    UserIDKey   = "user_id"
    UsernameKey = "username"
    ClaimsKey   = "claims"
)
```
**Purpose:** Context keys for storing user information in Gin requests.

### Error Variables

```go
var (
    ErrInvalidToken     = errors.New("invalid token")
    ErrTokenExpired     = errors.New("token has expired")
    ErrTokenMalformed   = errors.New("token is malformed")
    ErrInvalidSignature = errors.New("invalid token signature")
    // ... more auth-specific errors
)
```
**Purpose:** Predefined errors for authentication scenarios.

---

## ⚠️ `pkg/errors` - Error Handling and Response Management

### Types

#### `ErrorCode`
String type for error classification.
```go
type ErrorCode string
```
**Purpose:** Strongly-typed error codes for consistent error categorization.

#### `AppError`
Custom application error with metadata.
```go
type AppError struct {
    Code       ErrorCode `json:"code"`
    Message    string    `json:"message"`
    Details    string    `json:"details,omitempty"`
    StatusCode int       `json:"-"`
    Err        error     `json:"-"`
}
```
**Purpose:** Rich error information with HTTP status mapping and error wrapping.

### Error Codes

```go
const (
    // General errors
    ErrCodeInternal      ErrorCode = "INTERNAL_ERROR"
    ErrCodeNotFound      ErrorCode = "NOT_FOUND"
    ErrCodeValidation    ErrorCode = "VALIDATION_ERROR"
    ErrCodeUnauthorized  ErrorCode = "UNAUTHORIZED"
    ErrCodeForbidden     ErrorCode = "FORBIDDEN"
    ErrCodeConflict      ErrorCode = "CONFLICT"
    ErrCodeBadRequest    ErrorCode = "BAD_REQUEST"
    
    // User-related errors
    ErrCodeUserNotFound     ErrorCode = "USER_NOT_FOUND"
    ErrCodeUserExists       ErrorCode = "USER_ALREADY_EXISTS"
    ErrCodeInvalidPassword  ErrorCode = "INVALID_PASSWORD"
    // ... more error codes
)
```
**Purpose:** Comprehensive error code catalog for all business scenarios.

### Functions

#### Error Creation

##### `New(code ErrorCode, message string) *AppError`
**Purpose:** Creates a new AppError with automatic HTTP status mapping.

##### `Newf(code ErrorCode, format string, args ...interface{}) *AppError`
**Purpose:** Creates a new AppError with formatted message.

##### `Wrap(err error, code ErrorCode, message string) *AppError`
**Purpose:** Wraps an existing error with application context.

##### `Wrapf(err error, code ErrorCode, format string, args ...interface{}) *AppError`
**Purpose:** Wraps an existing error with formatted message.

#### Error Methods

##### `WithDetails(details string) *AppError`
**Purpose:** Adds additional details to an existing error.

##### `WithStatusCode(statusCode int) *AppError`
**Purpose:** Overrides the default HTTP status code.

##### `Error() string`
**Purpose:** Implements error interface with formatted string representation.

##### `Unwrap() error`
**Purpose:** Returns the underlying wrapped error for error chain inspection.

#### Response Helpers

##### `RespondWithError(c *gin.Context, err *AppError)`
**Purpose:** Sends structured error response using Gin context.

##### `RespondWithErrorCode(c *gin.Context, code ErrorCode, message string)`
**Purpose:** Quick error response with code and message.

##### `RespondWithInternalError(c *gin.Context)`
**Purpose:** Sends generic internal server error response.

##### `RespondWithValidationError(c *gin.Context, details string)`
**Purpose:** Sends validation error with detailed feedback.

##### `RespondWithNotFound(c *gin.Context, resource string)`
**Purpose:** Sends formatted "not found" error for specific resource.

##### `RespondWithUnauthorized(c *gin.Context, message string)`
**Purpose:** Sends unauthorized error response.

##### `RespondWithConflict(c *gin.Context, message string)`
**Purpose:** Sends conflict error response.

#### Utility Functions

##### `IsAppError(err error) (*AppError, bool)`
**Purpose:** Type assertion to check if error is an AppError.

##### `HandleError(c *gin.Context, err error)`
**Purpose:** Converts any error to AppError and sends appropriate response.

#### Validation Helpers

##### `ValidateRequired(value interface{}, fieldName string) *AppError`
**Purpose:** Validates that a field is present and non-empty.

##### `ValidateLength(value string, fieldName string, minLen, maxLen int) *AppError`
**Purpose:** Validates string length constraints.

##### `ValidateUsernameFormat(username string) *AppError`
**Purpose:** Comprehensive username format validation (length, character constraints).

### Predefined Errors

```go
var (
    ErrInternal      = New(ErrCodeInternal, "Internal server error")
    ErrNotFound      = New(ErrCodeNotFound, "Resource not found")
    ErrUnauthorized  = New(ErrCodeUnauthorized, "Unauthorized access")
    // ... more predefined errors
)
```
**Purpose:** Common errors ready for immediate use.

---

## 🗄️ `pkg/database` - Database Connection and Migration Management

### Structs

#### `Config`
Database connection configuration.
```go
type Config struct {
    Host            string        `json:"host"`
    Port            int           `json:"port"`
    Username        string        `json:"username"`
    Password        string        `json:"password"`
    Database        string        `json:"database"`
    SSLMode         string        `json:"ssl_mode"`
    MaxOpenConns    int           `json:"max_open_conns"`
    MaxIdleConns    int           `json:"max_idle_conns"`
    ConnMaxLifetime time.Duration `json:"conn_max_lifetime"`
    ConnMaxIdleTime time.Duration `json:"conn_max_idle_time"`
}
```
**Purpose:** Comprehensive database configuration with connection pooling settings.

#### `DB`
Enhanced database wrapper.
```go
type DB struct {
    *sql.DB
    config *Config
}
```
**Purpose:** Wraps sql.DB with additional functionality and configuration tracking.

#### `Migration`
Database migration representation.
```go
type Migration struct {
    Version     int       `json:"version"`
    Name        string    `json:"name"`
    UpSQL       string    `json:"up_sql"`
    DownSQL     string    `json:"down_sql"`
    AppliedAt   time.Time `json:"applied_at"`
    ChecksumUp  string    `json:"checksum_up"`
    ChecksumDown string   `json:"checksum_down"`
}
```
**Purpose:** Complete migration metadata with versioning and rollback support.

#### `MigrationFile`
Migration file representation.
```go
type MigrationFile struct {
    Version  int
    Name     string
    FilePath string
    IsUp     bool
}
```
**Purpose:** File-based migration parsing and loading.

#### `Migrator`
Migration management system.
```go
type Migrator struct {
    db        *DB
    tableName string
}
```
**Purpose:** Handles database schema evolution with version tracking.

#### `MigrationStatus`
Migration status information.
```go
type MigrationStatus struct {
    Version   int       `json:"version"`
    Name      string    `json:"name"`
    Applied   bool      `json:"applied"`
    AppliedAt time.Time `json:"applied_at,omitempty"`
}
```
**Purpose:** Reports migration application status for monitoring.

### Functions

#### Connection Management (`connection.go`)

##### `DefaultConfig() *Config`
**Purpose:** Returns sensible default database configuration.

##### `DSN() string`
**Purpose:** Generates PostgreSQL data source name from configuration.

##### `Connect(config *Config) (*DB, error)`
**Purpose:** Establishes database connection with pooling and health check.

##### `ConnectWithDSN(dsn string) (*DB, error)`
**Purpose:** Direct connection using DSN string.

##### `Close() error`
**Purpose:** Gracefully closes database connection.

##### `HealthCheck(ctx context.Context) error`
**Purpose:** Performs database connectivity health check with timeout.

##### `Stats() sql.DBStats`
**Purpose:** Returns database connection pool statistics.

##### `IsHealthy(ctx context.Context) bool`
**Purpose:** Simple boolean health check.

#### Transaction Management

##### `WithTransaction(ctx context.Context, fn func(*sql.Tx) error) error`
**Purpose:** Executes function within database transaction with automatic rollback on error.

##### `WithTransactionTimeout(ctx context.Context, timeout time.Duration, fn func(*sql.Tx) error) error`
**Purpose:** Transaction execution with explicit timeout.

#### Query Helpers

##### `QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row`
**Purpose:** Context-aware single row query execution.

##### `Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)`
**Purpose:** Context-aware multi-row query with error wrapping.

##### `Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)`
**Purpose:** Context-aware query execution without result rows.

##### `Prepare(ctx context.Context, query string) (*sql.Stmt, error)`
**Purpose:** Context-aware prepared statement creation.

#### Utility Functions

##### `TableExists(ctx context.Context, tableName string) (bool, error)`
**Purpose:** Checks if a table exists in the database schema.

##### `ColumnExists(ctx context.Context, tableName, columnName string) (bool, error)`
**Purpose:** Checks if a column exists in a specific table.

##### `GetDatabaseVersion(ctx context.Context) (string, error)`
**Purpose:** Retrieves PostgreSQL version information.

##### `GetConnectionInfo() *Config`
**Purpose:** Returns current connection configuration.

#### Migration Management (`migration.go`)

##### `NewMigrator(db *DB) *Migrator`
**Purpose:** Creates migration manager with default table name.

##### `NewMigratorWithTable(db *DB, tableName string) *Migrator`
**Purpose:** Creates migration manager with custom tracking table.

##### `Initialize(ctx context.Context) error`
**Purpose:** Creates schema_migrations table if it doesn't exist.

##### `GetAppliedMigrations(ctx context.Context) ([]Migration, error)`
**Purpose:** Retrieves list of all applied migrations.

##### `GetCurrentVersion(ctx context.Context) (int, error)`
**Purpose:** Gets the highest applied migration version.

##### `IsMigrationApplied(ctx context.Context, version int) (bool, error)`
**Purpose:** Checks if specific migration version is applied.

##### `ApplyMigration(ctx context.Context, migration *Migration) error`
**Purpose:** Applies a single migration within transaction.

##### `RollbackMigration(ctx context.Context, migration *Migration) error`
**Purpose:** Rolls back a single migration within transaction.

##### `MigrateUp(ctx context.Context, migrations []Migration) error`
**Purpose:** Applies all pending migrations in version order.

##### `MigrateDown(ctx context.Context, targetVersion int, migrations []Migration) error`
**Purpose:** Rolls back migrations to target version.

##### `Status(ctx context.Context, migrations []Migration) ([]MigrationStatus, error)`
**Purpose:** Reports status of all available migrations.

##### `LoadMigrationsFromFS(fsys fs.FS, migrationDir string) ([]Migration, error)`
**Purpose:** Loads migrations from embedded filesystem.

---

## 🌐 `pkg/http` - HTTP Utilities and Inter-Service Communication

### Structs

#### `Client`
Inter-service HTTP client.
```go
type Client struct {
    httpClient    *http.Client
    baseURL       string
    defaultHeaders map[string]string
    timeout       time.Duration
    retryAttempts int
}
```
**Purpose:** Enhanced HTTP client with authentication, retry logic, and service integration.

#### `ClientConfig`
HTTP client configuration.
```go
type ClientConfig struct {
    BaseURL       string            `json:"base_url"`
    Timeout       time.Duration     `json:"timeout"`
    RetryAttempts int               `json:"retry_attempts"`
    Headers       map[string]string `json:"headers"`
}
```
**Purpose:** Configurable HTTP client settings.

#### `Request`
HTTP request representation.
```go
type Request struct {
    Method  string                 `json:"method"`
    Path    string                 `json:"path"`
    Body    interface{}            `json:"body,omitempty"`
    Headers map[string]string      `json:"headers,omitempty"`
    Query   map[string]string      `json:"query,omitempty"`
}
```
**Purpose:** Structured request building with JSON body marshaling.

#### `Response`
HTTP response representation.
```go
type Response struct {
    StatusCode int                    `json:"status_code"`
    Headers    map[string][]string    `json:"headers"`
    Body       []byte                 `json:"body"`
    Success    bool                   `json:"success"`
    Data       interface{}            `json:"data,omitempty"`
    Error      string                 `json:"error,omitempty"`
}
```
**Purpose:** Rich response parsing with APIResponse integration.

### Functions

#### Response Helpers (`response.go`)

##### `RespondWithSuccess(c *gin.Context, data interface{})`
**Purpose:** Sends 200 OK response with data.

##### `RespondWithSuccessAndStatus(c *gin.Context, statusCode int, data interface{})`
**Purpose:** Sends success response with custom status code.

##### `RespondWithCreated(c *gin.Context, data interface{})`
**Purpose:** Sends 201 Created response.

##### `RespondWithNoContent(c *gin.Context)`
**Purpose:** Sends 204 No Content response.

##### `RespondWithPagination(c *gin.Context, data interface{}, pagination models.Pagination)`
**Purpose:** Sends paginated response with metadata.

##### `RespondWithError(c *gin.Context, statusCode int, message string)`
**Purpose:** Sends error response with custom status.

##### `RespondWithErrorAndData(c *gin.Context, statusCode int, message string, data interface{})`
**Purpose:** Sends error response with additional data.

##### `RespondWithValidationErrors(c *gin.Context, errors map[string]string)`
**Purpose:** Sends structured validation error response.

##### `RespondWithBadRequest(c *gin.Context, message string)`
**Purpose:** Sends 400 Bad Request response.

##### `RespondWithUnauthorized(c *gin.Context, message string)`
**Purpose:** Sends 401 Unauthorized response.

##### `RespondWithForbidden(c *gin.Context, message string)`
**Purpose:** Sends 403 Forbidden response.

##### `RespondWithNotFound(c *gin.Context, message string)`
**Purpose:** Sends 404 Not Found response.

##### `RespondWithConflict(c *gin.Context, message string)`
**Purpose:** Sends 409 Conflict response.

##### `RespondWithInternalError(c *gin.Context, message string)`
**Purpose:** Sends 500 Internal Server Error response.

##### `RespondWithHealthCheck(c *gin.Context, health models.HealthCheck)`
**Purpose:** Sends health check response with appropriate status.

#### Pagination Helpers

##### `GetPaginationFromQuery(c *gin.Context) models.Pagination`
**Purpose:** Extracts and validates pagination parameters from query string.

##### `SetTotalCount(pagination *models.Pagination, totalCount int)`
**Purpose:** Updates pagination with total count and calculates pages.

#### Validation Helpers

##### `ValidateContentType(c *gin.Context, expectedType string) bool`
**Purpose:** Checks if request has expected Content-Type header.

##### `ValidateJSONContentType(c *gin.Context) bool`
**Purpose:** Validates JSON Content-Type specifically.

#### Security and Caching

##### `SetSecurityHeaders(c *gin.Context)`
**Purpose:** Adds standard security headers (XSS protection, content type options, etc.).

##### `AddCacheHeaders(c *gin.Context, maxAge int)`
**Purpose:** Adds cache control headers with specified max age.

##### `AddNoCacheHeaders(c *gin.Context)`
**Purpose:** Disables caching with appropriate headers.

#### HTTP Client (`client.go`)

##### `DefaultClientConfig() *ClientConfig`
**Purpose:** Returns default HTTP client configuration.

##### `NewClient(config *ClientConfig) *Client`
**Purpose:** Creates configured HTTP client with retry and authentication support.

##### `SetAuthToken(token string)`
**Purpose:** Sets Bearer token for all requests.

##### `SetHeader(key, value string)`
**Purpose:** Sets default header for all requests.

##### `Do(ctx context.Context, req *Request) (*Response, error)`
**Purpose:** Executes HTTP request with retry logic and error handling.

#### HTTP Method Conveniences

##### `Get(ctx context.Context, path string) (*Response, error)`
**Purpose:** Performs GET request.

##### `GetWithQuery(ctx context.Context, path string, query map[string]string) (*Response, error)`
**Purpose:** Performs GET request with query parameters.

##### `Post(ctx context.Context, path string, body interface{}) (*Response, error)`
**Purpose:** Performs POST request with JSON body.

##### `Put(ctx context.Context, path string, body interface{}) (*Response, error)`
**Purpose:** Performs PUT request with JSON body.

##### `Patch(ctx context.Context, path string, body interface{}) (*Response, error)`
**Purpose:** Performs PATCH request with JSON body.

##### `Delete(ctx context.Context, path string) (*Response, error)`
**Purpose:** Performs DELETE request.

#### Service Integration

##### `HealthCheck(ctx context.Context) (*models.HealthCheck, error)`
**Purpose:** Performs health check request to service.

##### `IsHealthy(ctx context.Context) bool`
**Purpose:** Simple boolean health check.

##### `ParseError(response *Response) error`
**Purpose:** Extracts error information from response.

##### `UnmarshalResponse(response *Response, target interface{}) error`
**Purpose:** Unmarshals successful response data into target struct.

---

## 🔧 Dependencies Added

The shared packages automatically added these dependencies to `go.mod`:

- **`github.com/gin-gonic/gin`** - Web framework for HTTP middleware and routing
- **`github.com/golang-jwt/jwt/v5`** - JWT token generation and validation  
- **`golang.org/x/crypto`** - Bcrypt password hashing
- **`github.com/lib/pq`** - PostgreSQL database driver

---

## 📋 Usage Summary

These shared packages provide a complete foundation for microservices with:

- **Consistent data models** and validation
- **Secure authentication** with JWT and bcrypt
- **Comprehensive error handling** with HTTP status mapping  
- **Database connectivity** with migrations and transactions
- **HTTP utilities** for responses and inter-service communication

All packages are designed to work together seamlessly and follow Go best practices for modularity, testability, and maintainability. 