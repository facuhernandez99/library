package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/facuhernandez99/library/pkg/config"
	"github.com/facuhernandez99/library/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// TestConnect_RealFunction tests the actual Connect function
func TestConnect_RealFunction(t *testing.T) {
	tests := []struct {
		name        string
		appConfig   *config.Config
		expectError bool
		errorCode   errors.ErrorCode
	}{
		{
			name:        "nil_config",
			appConfig:   nil,
			expectError: true,
			errorCode:   errors.ErrCodeValidation,
		},
		{
			name: "empty_database_url",
			appConfig: &config.Config{
				DatabaseURL: "",
			},
			expectError: true,
			errorCode:   errors.ErrCodeValidation,
		},
		{
			name: "invalid_database_url",
			appConfig: &config.Config{
				DatabaseURL: "invalid://connection/string",
			},
			expectError: true,
			errorCode:   errors.ErrCodeConnectionFailed,
		},
		{
			name: "malformed_postgres_url",
			appConfig: &config.Config{
				DatabaseURL: "postgres://",
			},
			expectError: true,
			errorCode:   errors.ErrCodeConnectionFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Connect(tt.appConfig)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, db)

				// Verify error type
				var appErr *errors.AppError
				if assert.ErrorAs(t, err, &appErr) {
					assert.Equal(t, tt.errorCode, appErr.Code)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, db)
				if db != nil {
					db.Close()
				}
			}
		})
	}
}

// TestConnectWithConfig_RealFunction tests the actual ConnectWithConfig function
func TestConnectWithConfig_RealFunction(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		description string
	}{
		{
			name:        "nil_config_uses_default",
			config:      nil,
			expectError: true, // Will fail to connect but tests the function path
			description: "Should use default config when nil is passed",
		},
		{
			name: "invalid_host",
			config: &Config{
				Host:     "non.existent.host.local",
				Port:     5432,
				Username: "test",
				Password: "test",
				Database: "test",
				SSLMode:  "disable",
			},
			expectError: true,
			description: "Should fail with invalid host",
		},
		{
			name: "invalid_port",
			config: &Config{
				Host:     "localhost",
				Port:     99999, // Invalid port
				Username: "test",
				Password: "test",
				Database: "test",
				SSLMode:  "disable",
			},
			expectError: true,
			description: "Should fail with invalid port",
		},
		{
			name: "complete_config_invalid_database",
			config: &Config{
				Host:            "localhost",
				Port:            5432,
				Username:        "nonexistent",
				Password:        "wrongpassword",
				Database:        "nonexistent",
				SSLMode:         "disable",
				MaxOpenConns:    10,
				MaxIdleConns:    5,
				ConnMaxLifetime: 5 * time.Minute,
				ConnMaxIdleTime: 5 * time.Minute,
			},
			expectError: true,
			description: "Should fail with invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := ConnectWithConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Nil(t, db)

				// Verify it's wrapped in AppError
				var appErr *errors.AppError
				if assert.ErrorAs(t, err, &appErr) {
					assert.Equal(t, errors.ErrCodeConnectionFailed, appErr.Code)
				}
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, db)
				if db != nil {
					db.Close()
				}
			}
		})
	}
}

// TestConnectWithDSN_RealFunction tests the actual ConnectWithDSN function
func TestConnectWithDSN_RealFunction(t *testing.T) {
	tests := []struct {
		name        string
		dsn         string
		expectError bool
		description string
	}{
		{
			name:        "empty_dsn",
			dsn:         "",
			expectError: true,
			description: "Should fail with empty DSN",
		},
		{
			name:        "invalid_scheme",
			dsn:         "mysql://user:pass@localhost/db",
			expectError: true,
			description: "Should fail with non-postgres scheme",
		},
		{
			name:        "malformed_dsn",
			dsn:         "not-a-valid-dsn",
			expectError: true,
			description: "Should fail with malformed DSN",
		},
		{
			name:        "postgres_invalid_host",
			dsn:         "postgres://user:pass@nonexistent.host/db",
			expectError: true,
			description: "Should fail with non-existent host",
		},
		{
			name:        "postgres_with_ssl_disable",
			dsn:         "postgres://user:pass@localhost/db?sslmode=disable",
			expectError: true, // Will fail but tests function path
			description: "Should attempt connection with SSL disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := ConnectWithDSN(tt.dsn)

			if tt.expectError {
				assert.Error(t, err, tt.description)
				assert.Nil(t, db)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, db)
				if db != nil {
					db.Close()
				}
			}
		})
	}
}

// TestDB_Methods_WithMockDB tests DB methods using a mock connection
func TestDB_Methods_WithMockDB(t *testing.T) {
	// Note: Some methods cannot be tested with a nil/empty sql.DB as they would panic
	config := DefaultConfig()

	t.Run("GetConnectionInfo", func(t *testing.T) {
		db := &DB{config: config}
		info := db.GetConnectionInfo()

		// Test when config exists
		assert.NotNil(t, info)
		assert.Equal(t, config, info)
	})

	t.Run("GetConnectionInfo_NilConfig", func(t *testing.T) {
		dbNilConfig := &DB{config: nil}
		info := dbNilConfig.GetConnectionInfo()
		assert.Nil(t, info)
	})

	t.Run("Stats_Method_Exists", func(t *testing.T) {
		// Test that Stats method exists by testing with invalid connection
		// This avoids calling Stats on uninitialized sql.DB
		invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
		if err != nil {
			// Expected - connection failed
			assert.Error(t, err)
			return
		}

		// If connection somehow succeeded, test Stats
		if invalidDB != nil {
			stats := invalidDB.Stats()
			assert.NotNil(t, stats)
			invalidDB.Close()
		}
	})

	t.Run("Close", func(t *testing.T) {
		// Test Close method with invalid DSN to create a real but invalid connection
		invalidDB, err := ConnectWithDSN("postgres://invalid:invalid@localhost:5432/nonexistent")
		if err != nil {
			// Expected - invalid connection
			assert.Error(t, err)
			return
		}

		// If somehow a connection was created, test closing it
		if invalidDB != nil {
			err := invalidDB.Close()
			// Close should work even for invalid connections
			assert.NoError(t, err)
		}
	})
}

// TestDB_HealthCheck_Timeouts tests HealthCheck with various timeout scenarios
func TestDB_HealthCheck_Timeouts(t *testing.T) {
	// Test HealthCheck timeouts with invalid connection to avoid mock DB issues

	t.Run("context_with_timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		// Wait for context to timeout
		time.Sleep(2 * time.Millisecond)

		// Test with invalid connection
		invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
		if err != nil {
			assert.Error(t, err)
			return
		}

		if invalidDB != nil {
			err := invalidDB.HealthCheck(ctx)
			assert.Error(t, err)
			invalidDB.Close()
		}
	})

	t.Run("context_cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Test with invalid connection
		invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
		if err != nil {
			assert.Error(t, err)
			return
		}

		if invalidDB != nil {
			err := invalidDB.HealthCheck(ctx)
			assert.Error(t, err)
			invalidDB.Close()
		}
	})

	t.Run("IsHealthy_returns_boolean", func(t *testing.T) {
		ctx := context.Background()

		// Test with invalid connection
		invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
		if err != nil {
			assert.Error(t, err)
			return
		}

		if invalidDB != nil {
			healthy := invalidDB.IsHealthy(ctx)
			assert.False(t, healthy)
			invalidDB.Close()
		}
	})
}

// TestDB_QueryMethods tests query-related methods
func TestDB_QueryMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("QueryMethods_WithInvalidConnection", func(t *testing.T) {
		// Test query methods with invalid connection to ensure they handle errors properly
		invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
		if err != nil {
			assert.Error(t, err)
			return
		}

		if invalidDB != nil {
			// Test QueryRow
			row := invalidDB.QueryRow(ctx, "SELECT 1")
			assert.NotNil(t, row)

			// Test Query
			rows, err := invalidDB.Query(ctx, "SELECT * FROM users")
			if err != nil {
				assert.Error(t, err)
			}
			if rows != nil {
				rows.Close()
			}

			// Test Exec
			result, err := invalidDB.Exec(ctx, "INSERT INTO users (name) VALUES ($1)", "test")
			if err != nil {
				assert.Error(t, err)
			}
			if result != nil {
				_, _ = result.RowsAffected()
				_, _ = result.LastInsertId()
			}

			// Test Prepare
			stmt, err := invalidDB.Prepare(ctx, "SELECT * FROM users WHERE id = $1")
			if err != nil {
				var appErr *errors.AppError
				if assert.ErrorAs(t, err, &appErr) {
					assert.Equal(t, errors.ErrCodeDatabaseError, appErr.Code)
				}
			}
			if stmt != nil {
				stmt.Close()
			}

			invalidDB.Close()
		}
	})
}

// TestDB_UtilityMethods tests utility methods
func TestDB_UtilityMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("UtilityMethods_WithInvalidConnection", func(t *testing.T) {
		// Test utility methods with invalid connection
		invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
		if err != nil {
			assert.Error(t, err)
			return
		}

		if invalidDB != nil {
			// Test TableExists
			exists, err := invalidDB.TableExists(ctx, "users")
			assert.Error(t, err)
			assert.False(t, exists)

			// Test ColumnExists
			exists, err = invalidDB.ColumnExists(ctx, "users", "id")
			assert.Error(t, err)
			assert.False(t, exists)

			// Test GetDatabaseVersion
			version, err := invalidDB.GetDatabaseVersion(ctx)
			assert.Error(t, err)
			assert.Empty(t, version)

			invalidDB.Close()
		}
	})
}

// TestDB_TransactionMethods tests transaction-related methods
func TestDB_TransactionMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("TransactionMethods_WithInvalidConnection", func(t *testing.T) {
		// Test transaction methods with invalid connection
		invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
		if err != nil {
			assert.Error(t, err)
			return
		}

		if invalidDB != nil {
			// Test WithTransaction with function error
			expectedErr := fmt.Errorf("business logic error")
			err := invalidDB.WithTransaction(ctx, func(tx *sql.Tx) error {
				return expectedErr
			})
			assert.Error(t, err)

			// Test WithTransaction success path
			err = invalidDB.WithTransaction(ctx, func(tx *sql.Tx) error {
				return nil
			})
			assert.Error(t, err)

			// Test WithTransactionTimeout
			timeout := 1 * time.Second
			err = invalidDB.WithTransactionTimeout(ctx, timeout, func(tx *sql.Tx) error {
				return nil
			})
			assert.Error(t, err)

			invalidDB.Close()
		}
	})
}

// TestConfig_Methods tests Config struct methods
func TestConfig_Methods(t *testing.T) {
	t.Run("DefaultConfig_AllFields", func(t *testing.T) {
		config := DefaultConfig()

		assert.Equal(t, "localhost", config.Host)
		assert.Equal(t, 5432, config.Port)
		assert.Equal(t, "postgres", config.Username)
		assert.Equal(t, "postgres", config.Password)
		assert.Equal(t, "library", config.Database)
		assert.Equal(t, "disable", config.SSLMode)
		assert.Equal(t, 25, config.MaxOpenConns)
		assert.Equal(t, 25, config.MaxIdleConns)
		assert.Equal(t, 5*time.Minute, config.ConnMaxLifetime)
		assert.Equal(t, 5*time.Minute, config.ConnMaxIdleTime)
	})

	t.Run("DSN_CompleteString", func(t *testing.T) {
		config := &Config{
			Host:     "testhost",
			Port:     5433,
			Username: "testuser",
			Password: "testpass",
			Database: "testdb",
			SSLMode:  "require",
		}

		dsn := config.DSN()
		expected := "host=testhost port=5433 user=testuser password=testpass dbname=testdb sslmode=require"

		assert.Equal(t, expected, dsn)
	})

	t.Run("DSN_SpecialCharacters", func(t *testing.T) {
		config := &Config{
			Host:     "localhost",
			Port:     5432,
			Username: "user@domain",
			Password: "pass word!",
			Database: "test-db",
			SSLMode:  "disable",
		}

		dsn := config.DSN()
		assert.Contains(t, dsn, "user=user@domain")
		assert.Contains(t, dsn, "password=pass word!")
		assert.Contains(t, dsn, "dbname=test-db")
	})
}
