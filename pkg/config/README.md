# Configuration Package

This package provides centralized configuration management for the blog microservice with environment variable support, validation, and sensible defaults.

## Features

- **Environment Variable Loading**: Load configuration from environment variables with fallback defaults
- **Validation**: Comprehensive validation of all configuration values
- **Type Safety**: Proper type conversion for integer values
- **Environment Detection**: Helper methods to detect development/production environments
- **Database Integration**: Built-in support for database configuration

## Usage

### Basic Usage

```go
package main

import (
    "log"
    "github.com/facuhernandez99/blog/pkg/config"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load configuration:", err)
    }

    // Use configuration
    fmt.Printf("Server starting on port %d\n", cfg.Port)
    fmt.Printf("Environment: %s\n", cfg.Environment)
    
    // Check environment
    if cfg.IsDevelopment() {
        fmt.Println("Running in development mode")
    }
}
```

### Integration with Database Package

```go
func setupDatabase() {
    cfg, _ := config.Load()
    dbConfig := cfg.GetDatabaseConfig()
    
    // Use with your database connection
    // db := database.Connect(dbConfig)
}
```

## Environment Variables

### Required Variables

- `DATABASE_URL`: PostgreSQL connection string (e.g., `postgres://user:pass@localhost/db`)
- `JWT_SECRET`: JWT signing secret (minimum 32 characters)

### Optional Variables

- `PORT`: Server port (default: 8080)
- `ENVIRONMENT`: Runtime environment - `development`, `staging`, `production` (default: development)
- `LOG_LEVEL`: Logging level - `debug`, `info`, `warn`, `error` (default: info)
- `REDIS_URL`: Redis connection string (default: redis://localhost:6379)

## Environment File

Copy `environment.example` to `.env` and modify as needed:

```bash
cp pkg/config/environment.example .env
# Edit .env with your values
```

## Validation Rules

- **Port**: Must be between 1 and 65535
- **Database URL**: Cannot be empty
- **JWT Secret**: Must be at least 32 characters long
- **Environment**: Must be one of: development, staging, production
- **Log Level**: Must be one of: debug, info, warn, error

## Testing

Run the test suite:

```bash
go test ./pkg/config/
```

The package includes comprehensive tests covering:
- Environment variable loading
- Validation scenarios
- Default value handling
- Error conditions
- Helper functions 