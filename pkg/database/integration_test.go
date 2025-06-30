//go:build integration
// +build integration

/*
Package database integration tests

These tests require a running PostgreSQL instance and test actual database operations.
They demonstrate:
- Real database connections and configuration
- Transaction management with commit/rollback
- Query operations with real data
- Database utility functions (table/column existence, version info)

To run these tests:
1. Start PostgreSQL: bash scripts/setup_database_for_tests.sh
2. Run tests: go test -tags=integration ./pkg/database -v

These tests complement the unit tests by validating actual database behavior
rather than mocked interactions.
*/

package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealDatabaseConnection(t *testing.T) {
	// Skip if PostgreSQL not available
	if !isPostgreSQLAvailable() {
		t.Skip("PostgreSQL not available for integration testing")
	}

	// Test actual database connection
	cfg := getTestConfig()
	db, err := ConnectWithConfig(cfg)
	require.NoError(t, err, "Should connect to real database")
	defer db.Close()

	// Test basic operations
	ctx := context.Background()

	// Test health check
	err = db.HealthCheck(ctx)
	assert.NoError(t, err, "Health check should pass")

	// Test stats
	stats := db.Stats()
	assert.NotNil(t, stats, "Should return database stats")
	assert.True(t, stats.OpenConnections >= 0, "Should have valid connection count")
}

func TestBasicQueryOperations(t *testing.T) {
	if !isPostgreSQLAvailable() {
		t.Skip("PostgreSQL not available for integration testing")
	}

	cfg := getTestConfig()
	db, err := ConnectWithConfig(cfg)
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Test simple query
	var version string
	err = db.QueryRow(ctx, "SELECT version()").Scan(&version)
	require.NoError(t, err, "Should execute simple query")
	assert.Contains(t, version, "PostgreSQL", "Should return PostgreSQL version")

	// Test current time query
	var now time.Time
	err = db.QueryRow(ctx, "SELECT NOW()").Scan(&now)
	require.NoError(t, err, "Should get current time")
	assert.WithinDuration(t, time.Now(), now, 5*time.Second, "Time should be recent")
}

func TestTransactionOperations(t *testing.T) {
	if !isPostgreSQLAvailable() {
		t.Skip("PostgreSQL not available for integration testing")
	}

	cfg := getTestConfig()
	db, err := ConnectWithConfig(cfg)
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	// Create a temporary test table
	_, err = db.Exec(ctx, `
		CREATE TEMPORARY TABLE test_users (
			id SERIAL PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL
		)
	`)
	require.NoError(t, err, "Should create temporary table")

	t.Run("Successful Transaction", func(t *testing.T) {
		err := db.WithTransaction(ctx, func(tx *sql.Tx) error {
			// Insert test data
			_, err := tx.Exec(`
				INSERT INTO test_users (name, email) 
				VALUES ($1, $2)
			`, "John Doe", "john@example.com")
			return err
		})
		require.NoError(t, err, "Transaction should succeed")

		// Verify data was inserted
		var count int
		err = db.QueryRow(ctx, "SELECT COUNT(*) FROM test_users").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "Should have one user")
	})

	t.Run("Failed Transaction Rollback", func(t *testing.T) {
		err := db.WithTransaction(ctx, func(tx *sql.Tx) error {
			// Insert valid data
			_, err := tx.Exec(`
				INSERT INTO test_users (name, email) 
				VALUES ($1, $2)
			`, "Jane Doe", "jane@example.com")
			if err != nil {
				return err
			}

			// Try to insert duplicate email (should fail)
			_, err = tx.Exec(`
				INSERT INTO test_users (name, email) 
				VALUES ($1, $2)
			`, "Jane Smith", "jane@example.com")
			return err // This will cause rollback
		})
		require.Error(t, err, "Transaction should fail due to duplicate email")

		// Verify rollback - should still have only 1 user
		var count int
		err = db.QueryRow(ctx, "SELECT COUNT(*) FROM test_users").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "Should still have only one user after rollback")
	})
}

func TestDatabaseUtilities(t *testing.T) {
	if !isPostgreSQLAvailable() {
		t.Skip("PostgreSQL not available for integration testing")
	}

	cfg := getTestConfig()
	db, err := ConnectWithConfig(cfg)
	require.NoError(t, err)
	defer db.Close()

	ctx := context.Background()

	t.Run("Table Operations", func(t *testing.T) {
		// Create a test table (not temporary so it appears in public schema)
		tableName := "integration_test_table"
		_, err := db.Exec(ctx, fmt.Sprintf(`
			CREATE TABLE %s (
				id SERIAL PRIMARY KEY,
				data TEXT
			)
		`, tableName))
		require.NoError(t, err)

		// Clean up the table at the end
		defer func() {
			db.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName))
		}()

		// Test TableExists
		exists, err := db.TableExists(ctx, tableName)
		require.NoError(t, err)
		assert.True(t, exists, "Table should exist")

		// Test with non-existent table
		exists, err = db.TableExists(ctx, "non_existent_table")
		require.NoError(t, err)
		assert.False(t, exists, "Non-existent table should not exist")
	})

	t.Run("Column Operations", func(t *testing.T) {
		// Create a test table with known columns (not temporary so it appears in public schema)
		tableName := "column_test_table"
		_, err := db.Exec(ctx, fmt.Sprintf(`
			CREATE TABLE %s (
				id SERIAL PRIMARY KEY,
				name VARCHAR(100),
				created_at TIMESTAMP DEFAULT NOW()
			)
		`, tableName))
		require.NoError(t, err)

		// Clean up the table at the end
		defer func() {
			db.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName))
		}()

		// Test ColumnExists for existing column
		exists, err := db.ColumnExists(ctx, tableName, "name")
		require.NoError(t, err)
		assert.True(t, exists, "Column 'name' should exist")

		// Test ColumnExists for non-existent column
		exists, err = db.ColumnExists(ctx, tableName, "non_existent_column")
		require.NoError(t, err)
		assert.False(t, exists, "Non-existent column should not exist")
	})

	t.Run("Database Information", func(t *testing.T) {
		// Test GetDatabaseVersion
		version, err := db.GetDatabaseVersion(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, version, "Should return database version")
		assert.Contains(t, version, "PostgreSQL", "Should be PostgreSQL")

		// Test GetConnectionInfo
		info := db.GetConnectionInfo()
		assert.NotNil(t, info, "Should return connection info")
		assert.Equal(t, "postgres", info.Database, "Should show correct database name")
		assert.Equal(t, "localhost", info.Host, "Should show correct host")
		assert.Equal(t, 5432, info.Port, "Should show correct port")
	})
}

// Helper functions
func isPostgreSQLAvailable() bool {
	cfg := getTestConfig()
	db, err := ConnectWithConfig(cfg)
	if err != nil {
		return false
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return db.HealthCheck(ctx) == nil
}

func getTestConfig() *Config {
	return &Config{
		Host:            "localhost",
		Port:            5432,
		Username:        "postgres",
		Password:        "postgres",
		Database:        "postgres",
		SSLMode:         "disable",
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}
}
