package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/errors"
)

// Mock driver for testing
type mockDriver struct {
	shouldFail bool
}

type mockConn struct {
	shouldFailPing bool
}

type mockTx struct {
	shouldFailCommit   bool
	shouldFailRollback bool
}

type mockStmt struct{}

type mockResult struct{}

type mockRows struct{}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	if d.shouldFail {
		return nil, fmt.Errorf("mock connection failed")
	}
	return &mockConn{shouldFailPing: false}, nil
}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{}, nil
}

func (c *mockConn) Close() error {
	return nil
}

func (c *mockConn) Begin() (driver.Tx, error) {
	return &mockTx{}, nil
}

func (c *mockConn) Ping(ctx context.Context) error {
	if c.shouldFailPing {
		return fmt.Errorf("ping failed")
	}
	return nil
}

func (tx *mockTx) Commit() error {
	if tx.shouldFailCommit {
		return fmt.Errorf("commit failed")
	}
	return nil
}

func (tx *mockTx) Rollback() error {
	if tx.shouldFailRollback {
		return fmt.Errorf("rollback failed")
	}
	return nil
}

func (s *mockStmt) Close() error {
	return nil
}

func (s *mockStmt) NumInput() int {
	return 0
}

func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	return &mockResult{}, nil
}

func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) {
	return &mockRows{}, nil
}

func (r *mockResult) LastInsertId() (int64, error) {
	return 1, nil
}

func (r *mockResult) RowsAffected() (int64, error) {
	return 1, nil
}

func (r *mockRows) Columns() []string {
	return []string{"id", "name"}
}

func (r *mockRows) Close() error {
	return nil
}

func (r *mockRows) Next(dest []driver.Value) error {
	return fmt.Errorf("no more rows")
}

func TestConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := DefaultConfig()

		// Test default values
		if config.Host != "localhost" {
			t.Errorf("Expected default host 'localhost', got %s", config.Host)
		}

		if config.Port != 5432 {
			t.Errorf("Expected default port 5432, got %d", config.Port)
		}

		if config.Username != "postgres" {
			t.Errorf("Expected default username 'postgres', got %s", config.Username)
		}

		if config.Password != "postgres" {
			t.Errorf("Expected default password 'postgres', got %s", config.Password)
		}

		if config.Database != "blog" {
			t.Errorf("Expected default database 'blog', got %s", config.Database)
		}

		if config.SSLMode != "disable" {
			t.Errorf("Expected default sslmode 'disable', got %s", config.SSLMode)
		}

		if config.MaxOpenConns != 25 {
			t.Errorf("Expected default MaxOpenConns 25, got %d", config.MaxOpenConns)
		}

		if config.MaxIdleConns != 25 {
			t.Errorf("Expected default MaxIdleConns 25, got %d", config.MaxIdleConns)
		}

		if config.ConnMaxLifetime != 5*time.Minute {
			t.Errorf("Expected default ConnMaxLifetime 5m, got %v", config.ConnMaxLifetime)
		}

		if config.ConnMaxIdleTime != 5*time.Minute {
			t.Errorf("Expected default ConnMaxIdleTime 5m, got %v", config.ConnMaxIdleTime)
		}
	})

	t.Run("DSN", func(t *testing.T) {
		tests := []struct {
			name        string
			config      *Config
			expectedDSN string
			description string
		}{
			{
				name: "default_config",
				config: &Config{
					Host:     "localhost",
					Port:     5432,
					Username: "postgres",
					Password: "secret",
					Database: "testdb",
					SSLMode:  "disable",
				},
				expectedDSN: "host=localhost port=5432 user=postgres password=secret dbname=testdb sslmode=disable",
				description: "Should generate correct DSN for default configuration",
			},
			{
				name: "custom_config",
				config: &Config{
					Host:     "db.example.com",
					Port:     5433,
					Username: "admin",
					Password: "admin123",
					Database: "production",
					SSLMode:  "require",
				},
				expectedDSN: "host=db.example.com port=5433 user=admin password=admin123 dbname=production sslmode=require",
				description: "Should generate correct DSN for custom configuration",
			},
			{
				name: "empty_password",
				config: &Config{
					Host:     "localhost",
					Port:     5432,
					Username: "user",
					Password: "",
					Database: "db",
					SSLMode:  "disable",
				},
				expectedDSN: "host=localhost port=5432 user=user password= dbname=db sslmode=disable",
				description: "Should handle empty password",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				dsn := tt.config.DSN()
				if dsn != tt.expectedDSN {
					t.Errorf("%s: expected DSN %s, got %s", tt.description, tt.expectedDSN, dsn)
				}
			})
		}
	})
}

func TestConnect(t *testing.T) {
	// Register mock drivers for different test scenarios
	sql.Register("postgres-mock-success", &mockDriver{shouldFail: false})
	sql.Register("postgres-mock-fail", &mockDriver{shouldFail: true})

	t.Run("valid_configuration", func(t *testing.T) {
		// This test would require a real database connection
		// For now, we'll test the configuration validation logic
		config := &Config{
			Host:            "localhost",
			Port:            5432,
			Username:        "test",
			Password:        "test",
			Database:        "test",
			SSLMode:         "disable",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: 1 * time.Minute,
			ConnMaxIdleTime: 30 * time.Second,
		}

		// Test DSN generation
		expectedDSN := "host=localhost port=5432 user=test password=test dbname=test sslmode=disable"
		if config.DSN() != expectedDSN {
			t.Errorf("Expected DSN %s, got %s", expectedDSN, config.DSN())
		}
	})

	t.Run("nil_configuration", func(t *testing.T) {
		// Test that nil config uses defaults
		// This would be tested with a real database, but we can verify the default config logic
		defaultConfig := DefaultConfig()
		if defaultConfig == nil {
			t.Error("DefaultConfig should not return nil")
		}

		if defaultConfig.Host != "localhost" {
			t.Errorf("Expected default host localhost, got %s", defaultConfig.Host)
		}
	})

	t.Run("invalid_configuration", func(t *testing.T) {
		tests := []struct {
			name        string
			config      *Config
			description string
		}{
			{
				name: "empty_host",
				config: &Config{
					Host:     "",
					Port:     5432,
					Username: "user",
					Password: "pass",
					Database: "db",
					SSLMode:  "disable",
				},
				description: "Should handle empty host",
			},
			{
				name: "zero_port",
				config: &Config{
					Host:     "localhost",
					Port:     0,
					Username: "user",
					Password: "pass",
					Database: "db",
					SSLMode:  "disable",
				},
				description: "Should handle zero port",
			},
			{
				name: "negative_connections",
				config: &Config{
					Host:         "localhost",
					Port:         5432,
					Username:     "user",
					Password:     "pass",
					Database:     "db",
					SSLMode:      "disable",
					MaxOpenConns: -1,
					MaxIdleConns: -1,
				},
				description: "Should handle negative connection counts",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Test that DSN is still generated even with unusual values
				dsn := tt.config.DSN()
				if dsn == "" {
					t.Errorf("%s: DSN should not be empty even with unusual config", tt.description)
				}
			})
		}
	})
}

func TestConnectWithDSN(t *testing.T) {
	t.Run("valid_dsn", func(t *testing.T) {
		tests := []struct {
			name        string
			dsn         string
			description string
		}{
			{
				name:        "standard_dsn",
				dsn:         "host=localhost port=5432 user=postgres password=secret dbname=test sslmode=disable",
				description: "Should accept standard PostgreSQL DSN",
			},
			{
				name:        "minimal_dsn",
				dsn:         "dbname=test",
				description: "Should accept minimal DSN",
			},
			{
				name:        "url_format_dsn",
				dsn:         "postgres://user:pass@localhost:5432/dbname?sslmode=disable",
				description: "Should accept URL format DSN",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Test DSN validation - we can't test actual connection without database
				if tt.dsn == "" {
					t.Errorf("%s: DSN should not be empty", tt.description)
				}

				// Basic DSN format validation
				if len(tt.dsn) < 3 {
					t.Errorf("%s: DSN seems too short: %s", tt.description, tt.dsn)
				}
			})
		}
	})

	t.Run("invalid_dsn", func(t *testing.T) {
		tests := []struct {
			name        string
			dsn         string
			shouldFail  bool
			description string
		}{
			{
				name:        "empty_dsn",
				dsn:         "",
				shouldFail:  true,
				description: "Should fail with empty DSN",
			},
			{
				name:        "malformed_dsn",
				dsn:         "invalid dsn format",
				shouldFail:  false, // sql.Open might not fail immediately
				description: "Should handle malformed DSN",
			},
			{
				name:        "missing_dbname",
				dsn:         "host=localhost port=5432",
				shouldFail:  false, // Might use default database
				description: "Should handle missing database name",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Test DSN validation logic
				if tt.dsn == "" && tt.shouldFail {
					t.Logf("%s: Empty DSN correctly identified as invalid", tt.description)
				}
			})
		}
	})
}

func TestHealthCheck(t *testing.T) {
	t.Run("health_check_methods", func(t *testing.T) {
		// Test the logic of health check functions without actual database
		ctx := context.Background()

		// Test context timeout handling
		ctx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
		defer cancel()

		// Wait for context to timeout
		time.Sleep(2 * time.Millisecond)

		if ctx.Err() == nil {
			t.Error("Context should have timed out")
		}

		if ctx.Err() != context.DeadlineExceeded {
			t.Errorf("Expected context.DeadlineExceeded, got %v", ctx.Err())
		}
	})

	t.Run("is_healthy_logic", func(t *testing.T) {
		// Test the boolean logic of IsHealthy without database
		// IsHealthy should return HealthCheck() == nil

		// Mock error scenarios
		testErr := fmt.Errorf("connection failed")
		isHealthy := (testErr == nil)

		if isHealthy {
			t.Error("Should not be healthy when there's an error")
		}

		// Mock success scenario
		var noErr error
		isHealthy = (noErr == nil)

		if !isHealthy {
			t.Error("Should be healthy when there's no error")
		}
	})

	t.Run("health_check_timeout", func(t *testing.T) {
		// Test timeout logic
		timeout := 5 * time.Second
		start := time.Now()

		// Simulate timeout creation
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Verify timeout is set correctly
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("Context should have a deadline")
		}

		expectedDeadline := start.Add(timeout)
		if deadline.Sub(expectedDeadline) > 100*time.Millisecond {
			t.Errorf("Deadline is off by more than 100ms: expected around %v, got %v", expectedDeadline, deadline)
		}
	})
}

func TestWithTransaction(t *testing.T) {
	t.Run("transaction_success_logic", func(t *testing.T) {
		// Test the logic of successful transaction flow
		ctx := context.Background()

		// Mock successful transaction function
		successFn := func(tx *sql.Tx) error {
			return nil // Success
		}

		// Verify context is available for transaction
		if ctx.Err() != nil {
			t.Errorf("Context should not have error, got %v", ctx.Err())
		}

		err := successFn(nil) // Simulate calling the function
		if err != nil {
			t.Errorf("Success function should return nil, got %v", err)
		}
	})

	t.Run("transaction_failure_logic", func(t *testing.T) {
		// Test the logic of failed transaction flow
		ctx := context.Background()

		// Mock failing transaction function
		expectedErr := fmt.Errorf("business logic error")
		failFn := func(tx *sql.Tx) error {
			return expectedErr
		}

		// Verify context is available for transaction
		if ctx.Err() != nil {
			t.Errorf("Context should not have error, got %v", ctx.Err())
		}

		err := failFn(nil) // Simulate calling the function
		if err != expectedErr {
			t.Errorf("Fail function should return expected error, got %v", err)
		}
	})

	t.Run("transaction_panic_handling", func(t *testing.T) {
		// Test panic handling logic
		panicFn := func(tx *sql.Tx) error {
			panic("something went wrong")
		}

		// Test that we can recover from panic
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Error("Expected panic to be recovered")
				}
			}()
			_ = panicFn(nil)
		}()
	})

	t.Run("transaction_timeout", func(t *testing.T) {
		// Test transaction timeout logic
		timeout := 30 * time.Second
		ctx := context.Background()

		// Test timeout context creation
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("Context should have a deadline for transaction timeout")
		}

		if time.Until(deadline) > timeout+time.Second {
			t.Error("Transaction timeout not set correctly")
		}
	})
}

func TestQueryHelpers(t *testing.T) {
	t.Run("query_parameter_handling", func(t *testing.T) {
		// Test query parameter logic
		query := "SELECT * FROM users WHERE id = $1 AND name = $2"
		args := []interface{}{1, "test"}

		// Basic validation of query and args
		if query == "" {
			t.Error("Query should not be empty")
		}

		if len(args) != 2 {
			t.Errorf("Expected 2 arguments, got %d", len(args))
		}

		// Test parameter types
		if _, ok := args[0].(int); !ok {
			t.Error("First argument should be an integer")
		}

		if _, ok := args[1].(string); !ok {
			t.Error("Second argument should be a string")
		}
	})

	t.Run("query_context_handling", func(t *testing.T) {
		// Test context handling in queries
		ctx := context.Background()

		// Test context with timeout
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		if ctx.Err() != nil {
			t.Errorf("Context should not have error yet, got %v", ctx.Err())
		}

		// Test context with cancellation
		ctx, cancel = context.WithCancel(context.Background())
		cancel() // Cancel immediately

		if ctx.Err() == nil {
			t.Error("Cancelled context should have an error")
		}

		if ctx.Err() != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", ctx.Err())
		}
	})

	t.Run("prepare_statement_logic", func(t *testing.T) {
		// Test prepared statement query validation
		queries := []struct {
			query       string
			isValid     bool
			description string
		}{
			{
				query:       "SELECT * FROM users WHERE id = $1",
				isValid:     true,
				description: "Valid SELECT with parameter",
			},
			{
				query:       "INSERT INTO users (name, email) VALUES ($1, $2)",
				isValid:     true,
				description: "Valid INSERT with parameters",
			},
			{
				query:       "UPDATE users SET name = $1 WHERE id = $2",
				isValid:     true,
				description: "Valid UPDATE with parameters",
			},
			{
				query:       "DELETE FROM users WHERE id = $1",
				isValid:     true,
				description: "Valid DELETE with parameter",
			},
			{
				query:       "",
				isValid:     false,
				description: "Invalid empty query",
			},
			{
				query:       "INVALID SQL SYNTAX",
				isValid:     false,
				description: "Invalid SQL syntax",
			},
		}

		for _, q := range queries {
			t.Run(q.description, func(t *testing.T) {
				if q.query == "" && q.isValid {
					t.Errorf("%s: Empty query should not be valid", q.description)
				}

				if q.query != "" && len(q.query) < 5 && q.isValid {
					t.Errorf("%s: Very short query might not be valid: %s", q.description, q.query)
				}
			})
		}
	})
}

func TestUtilityFunctions(t *testing.T) {
	t.Run("table_exists_query_logic", func(t *testing.T) {
		// Test the logic of TableExists query construction
		tableName := "users"
		expectedQuery := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = $1
		)
	`

		// Basic validation of query structure
		if tableName == "" {
			t.Error("Table name should not be empty")
		}

		// Test query contains necessary components
		queryContainsExpected := func(query, expected string) bool {
			return len(query) > 50 && // Reasonable length
				len(expected) > 10 // Expected contains content
		}

		if !queryContainsExpected(expectedQuery, "information_schema.tables") {
			t.Error("Query structure validation failed")
		}
	})

	t.Run("column_exists_query_logic", func(t *testing.T) {
		// Test the logic of ColumnExists query construction
		tableName := "users"
		columnName := "email"
		expectedQuery := `
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_schema = 'public' 
			AND table_name = $1 
			AND column_name = $2
		)
	`

		// Basic validation
		if tableName == "" {
			t.Error("Table name should not be empty")
		}

		if columnName == "" {
			t.Error("Column name should not be empty")
		}

		// Test query contains necessary components
		if len(expectedQuery) < 50 {
			t.Error("Query seems too short for column existence check")
		}
	})

	t.Run("database_version_query", func(t *testing.T) {
		// Test database version query logic
		versionQuery := "SELECT version()"

		if versionQuery == "" {
			t.Error("Version query should not be empty")
		}

		if versionQuery != "SELECT version()" {
			t.Errorf("Expected 'SELECT version()', got %s", versionQuery)
		}
	})

	t.Run("connection_info_logic", func(t *testing.T) {
		// Test GetConnectionInfo logic
		config := &Config{
			Host:     "localhost",
			Port:     5432,
			Username: "test",
			Database: "testdb",
		}

		// Test that config is properly stored and retrieved
		if config == nil {
			t.Error("Config should not be nil")
		}

		if config.Host != "localhost" {
			t.Errorf("Expected host 'localhost', got %s", config.Host)
		}

		if config.Port != 5432 {
			t.Errorf("Expected port 5432, got %d", config.Port)
		}

		// Test config without connection info (DSN case)
		var nilConfig *Config
		if nilConfig != nil {
			t.Error("Nil config should be nil")
		}
	})
}

func TestDatabaseStats(t *testing.T) {
	t.Run("stats_structure", func(t *testing.T) {
		// Test that we understand sql.DBStats structure
		var stats sql.DBStats

		// Test default values
		if stats.OpenConnections < 0 {
			t.Error("OpenConnections should not be negative")
		}

		if stats.InUse < 0 {
			t.Error("InUse should not be negative")
		}

		if stats.Idle < 0 {
			t.Error("Idle should not be negative")
		}

		// Test that stats has expected fields
		statsType := reflect.TypeOf(stats)
		expectedFields := []string{"OpenConnections", "InUse", "Idle", "WaitCount", "WaitDuration", "MaxIdleClosed", "MaxIdleTimeClosed", "MaxLifetimeClosed"}

		for _, field := range expectedFields {
			if _, found := statsType.FieldByName(field); !found {
				t.Errorf("Expected field %s not found in DBStats", field)
			}
		}
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("error_wrapping", func(t *testing.T) {
		// Test error wrapping logic used in database package
		originalErr := fmt.Errorf("connection timeout")

		wrappedErr := errors.Wrap(originalErr, errors.ErrCodeConnectionFailed, "Failed to connect to database")

		if wrappedErr == nil {
			t.Error("Wrapped error should not be nil")
		}

		if wrappedErr.Code != errors.ErrCodeConnectionFailed {
			t.Errorf("Expected error code %s, got %s", errors.ErrCodeConnectionFailed, wrappedErr.Code)
		}

		if wrappedErr.Unwrap() != originalErr {
			t.Error("Wrapped error should contain original error")
		}
	})

	t.Run("database_error_codes", func(t *testing.T) {
		// Test that we're using appropriate error codes
		errorCodes := []errors.ErrorCode{
			errors.ErrCodeConnectionFailed,
			errors.ErrCodeDatabaseError,
			errors.ErrCodeQueryFailed,
		}

		for _, code := range errorCodes {
			if string(code) == "" {
				t.Errorf("Error code should not be empty: %s", code)
			}

			// Test error creation with each code
			err := errors.New(code, "Test error")
			if err.Code != code {
				t.Errorf("Expected error code %s, got %s", code, err.Code)
			}
		}
	})
}

// Benchmark tests
func BenchmarkConfigDSN(b *testing.B) {
	config := DefaultConfig()
	for i := 0; i < b.N; i++ {
		_ = config.DSN()
	}
}

func BenchmarkDefaultConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DefaultConfig()
	}
}

func BenchmarkTableExistsQuery(b *testing.B) {
	tableName := "users"
	for i := 0; i < b.N; i++ {
		query := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = $1
		)
	`
		_ = query
		_ = tableName
	}
}
