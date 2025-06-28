package testing

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/database"
	"github.com/facuhernandez99/blog/pkg/models"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/stretchr/testify/require"
)

// DatabaseTestHelper provides utilities for database testing
type DatabaseTestHelper struct {
	DB             *sql.DB
	Config         *database.Config
	TestDBName     string
	MasterDBName   string
	OriginalDBName string
	t              *testing.T
}

// NewDatabaseTestHelper creates a new database test helper
func NewDatabaseTestHelper(t *testing.T) *DatabaseTestHelper {
	config := getTestDatabaseConfig()

	helper := &DatabaseTestHelper{
		Config:         config,
		MasterDBName:   "postgres", // Default PostgreSQL admin database
		OriginalDBName: config.Database,
		t:              t,
	}

	// Generate unique test database name
	helper.TestDBName = fmt.Sprintf("test_%s_%d_%d",
		strings.ToLower(t.Name()),
		time.Now().Unix(),
		rand.Intn(10000))

	return helper
}

// Setup creates a test database and establishes connection
func (h *DatabaseTestHelper) Setup() {
	// Connect to master database to create test database
	masterConfig := *h.Config
	masterConfig.Database = h.MasterDBName

	masterDB, err := database.Connect(&masterConfig)
	require.NoError(h.t, err, "Failed to connect to master database")
	defer masterDB.Close()

	// Create test database
	_, err = masterDB.Exec(context.Background(), fmt.Sprintf("CREATE DATABASE %s", h.TestDBName))
	require.NoError(h.t, err, "Failed to create test database")

	// Connect to test database
	h.Config.Database = h.TestDBName
	dbWrapper, err := database.Connect(h.Config)
	require.NoError(h.t, err, "Failed to connect to test database")
	h.DB = dbWrapper.DB
	require.NoError(h.t, err, "Failed to connect to test database")

	// Run migrations if available
	h.runMigrations()
}

// Teardown cleans up the test database
func (h *DatabaseTestHelper) Teardown() {
	if h.DB != nil {
		h.DB.Close()
	}

	// Connect to master database to drop test database
	masterConfig := *h.Config
	masterConfig.Database = h.MasterDBName

	masterDB, err := database.Connect(&masterConfig)
	if err != nil {
		h.t.Logf("Failed to connect to master database for cleanup: %v", err)
		return
	}
	defer masterDB.Close()

	// Terminate connections to test database
	_, err = masterDB.Exec(context.Background(), fmt.Sprintf(`
		SELECT pg_terminate_backend(pid) 
		FROM pg_stat_activity 
		WHERE datname = '%s' AND pid <> pg_backend_pid()`, h.TestDBName))
	if err != nil {
		h.t.Logf("Failed to terminate connections: %v", err)
	}

	// Drop test database
	_, err = masterDB.Exec(context.Background(), fmt.Sprintf("DROP DATABASE IF EXISTS %s", h.TestDBName))
	if err != nil {
		h.t.Logf("Failed to drop test database: %v", err)
	}
}

// Exec executes a SQL statement
func (h *DatabaseTestHelper) Exec(query string, args ...interface{}) sql.Result {
	result, err := h.DB.Exec(query, args...)
	require.NoError(h.t, err, "Failed to execute query: %s", query)
	return result
}

// Query executes a SQL query
func (h *DatabaseTestHelper) Query(query string, args ...interface{}) *sql.Rows {
	rows, err := h.DB.Query(query, args...)
	require.NoError(h.t, err, "Failed to execute query: %s", query)
	return rows
}

// QueryRow executes a SQL query that returns a single row
func (h *DatabaseTestHelper) QueryRow(query string, args ...interface{}) *sql.Row {
	return h.DB.QueryRow(query, args...)
}

// Truncate truncates specified tables
func (h *DatabaseTestHelper) Truncate(tables ...string) {
	for _, table := range tables {
		h.Exec(fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table))
	}
}

// TruncateAll truncates all tables in the database
func (h *DatabaseTestHelper) TruncateAll() {
	// Get all table names
	rows := h.Query(`
		SELECT tablename 
		FROM pg_tables 
		WHERE schemaname = 'public'
		AND tablename NOT LIKE 'schema_migrations%'
	`)
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		require.NoError(h.t, rows.Scan(&tableName))
		tables = append(tables, tableName)
	}

	if len(tables) > 0 {
		h.Truncate(tables...)
	}
}

// SeedData provides methods for seeding test data
type SeedData struct {
	helper *DatabaseTestHelper
}

// Seed returns a SeedData instance for seeding test data
func (h *DatabaseTestHelper) Seed() *SeedData {
	return &SeedData{helper: h}
}

// User creates a test user
func (s *SeedData) User(overrides ...map[string]interface{}) *models.User {
	user := &models.User{
		Username:     fmt.Sprintf("testuser_%d", rand.Intn(10000)),
		PasswordHash: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // "password"
	}

	// Apply overrides
	if len(overrides) > 0 {
		for key, value := range overrides[0] {
			switch key {
			case "username":
				user.Username = value.(string)
			case "password_hash":
				user.PasswordHash = value.(string)
			}
		}
	}

	// Insert user into database
	err := s.helper.QueryRow(`
		INSERT INTO users (username, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at
	`, user.Username, user.PasswordHash, time.Now(), time.Now()).Scan(
		&user.ID, &user.CreatedAt, &user.UpdatedAt)

	require.NoError(s.helper.t, err, "Failed to create test user")

	return user
}

// Users creates multiple test users
func (s *SeedData) Users(count int) []*models.User {
	users := make([]*models.User, count)
	for i := 0; i < count; i++ {
		users[i] = s.User()
	}
	return users
}

// Transaction provides utilities for testing database transactions
type TransactionTestHelper struct {
	*DatabaseTestHelper
	tx *sql.Tx
}

// BeginTransaction starts a new transaction for testing
func (h *DatabaseTestHelper) BeginTransaction() *TransactionTestHelper {
	tx, err := h.DB.Begin()
	require.NoError(h.t, err, "Failed to begin transaction")

	return &TransactionTestHelper{
		DatabaseTestHelper: h,
		tx:                 tx,
	}
}

// Exec executes a query within the transaction
func (th *TransactionTestHelper) Exec(query string, args ...interface{}) sql.Result {
	result, err := th.tx.Exec(query, args...)
	require.NoError(th.t, err, "Failed to execute query in transaction: %s", query)
	return result
}

// Query executes a query within the transaction
func (th *TransactionTestHelper) Query(query string, args ...interface{}) *sql.Rows {
	rows, err := th.tx.Query(query, args...)
	require.NoError(th.t, err, "Failed to execute query in transaction: %s", query)
	return rows
}

// QueryRow executes a query within the transaction
func (th *TransactionTestHelper) QueryRow(query string, args ...interface{}) *sql.Row {
	return th.tx.QueryRow(query, args...)
}

// Commit commits the transaction
func (th *TransactionTestHelper) Commit() {
	err := th.tx.Commit()
	require.NoError(th.t, err, "Failed to commit transaction")
}

// Rollback rolls back the transaction
func (th *TransactionTestHelper) Rollback() {
	err := th.tx.Rollback()
	require.NoError(th.t, err, "Failed to rollback transaction")
}

// AssertRowCount validates the number of rows in a table
func (h *DatabaseTestHelper) AssertRowCount(tableName string, expectedCount int) {
	var count int
	err := h.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&count)
	require.NoError(h.t, err, "Failed to count rows in table %s", tableName)
	require.Equal(h.t, expectedCount, count, "Unexpected row count in table %s", tableName)
}

// AssertTableExists validates that a table exists
func (h *DatabaseTestHelper) AssertTableExists(tableName string) {
	var exists bool
	err := h.DB.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = $1
		)
	`, tableName).Scan(&exists)
	require.NoError(h.t, err, "Failed to check if table exists")
	require.True(h.t, exists, "Table %s should exist", tableName)
}

// AssertColumnExists validates that a column exists in a table
func (h *DatabaseTestHelper) AssertColumnExists(tableName, columnName string) {
	var exists bool
	err := h.DB.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_schema = 'public' 
			AND table_name = $1 
			AND column_name = $2
		)
	`, tableName, columnName).Scan(&exists)
	require.NoError(h.t, err, "Failed to check if column exists")
	require.True(h.t, exists, "Column %s should exist in table %s", columnName, tableName)
}

// getTestDatabaseConfig returns database configuration for testing
func getTestDatabaseConfig() *database.Config {
	config := database.DefaultConfig()

	// Override with test environment variables if available
	if host := os.Getenv("TEST_DB_HOST"); host != "" {
		config.Host = host
	}
	if port := os.Getenv("TEST_DB_PORT"); port != "" {
		// Simple conversion, in real code you'd want proper error handling
		if port == "5433" {
			config.Port = 5433
		}
	}
	if username := os.Getenv("TEST_DB_USERNAME"); username != "" {
		config.Username = username
	}
	if password := os.Getenv("TEST_DB_PASSWORD"); password != "" {
		config.Password = password
	}
	if database := os.Getenv("TEST_DB_DATABASE"); database != "" {
		config.Database = database
	} else {
		config.Database = "blog_test"
	}

	// Set test-specific connection settings
	config.MaxOpenConns = 5
	config.MaxIdleConns = 2
	config.ConnMaxLifetime = 1 * time.Minute

	return config
}

// runMigrations runs database migrations if available
func (h *DatabaseTestHelper) runMigrations() {
	// This is a simplified version. In a real application, you might:
	// 1. Use the migration system from pkg/database/migration.go
	// 2. Load migrations from embedded files
	// 3. Run specific test migrations

	// For now, we'll create basic tables that are commonly used in tests
	h.createBasicTables()
}

// createBasicTables creates basic tables for testing
func (h *DatabaseTestHelper) createBasicTables() {
	// Users table
	h.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)

	// Posts table (example)
	h.Exec(`
		CREATE TABLE IF NOT EXISTS posts (
			id SERIAL PRIMARY KEY,
			title VARCHAR(200) NOT NULL,
			content TEXT,
			author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
			published BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)

	// Comments table (example)
	h.Exec(`
		CREATE TABLE IF NOT EXISTS comments (
			id SERIAL PRIMARY KEY,
			content TEXT NOT NULL,
			post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
			author_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
}

// WithTransaction executes a function within a database transaction and rolls it back
func (h *DatabaseTestHelper) WithTransaction(fn func(*TransactionTestHelper)) {
	txHelper := h.BeginTransaction()
	defer txHelper.Rollback()
	fn(txHelper)
}

// CleanupFunction represents a cleanup function
type CleanupFunction func()

// SetupTestDatabase sets up a test database and returns a cleanup function
func SetupTestDatabase(t *testing.T) (*DatabaseTestHelper, CleanupFunction) {
	helper := NewDatabaseTestHelper(t)
	helper.Setup()

	cleanup := func() {
		helper.Teardown()
	}

	return helper, cleanup
}
