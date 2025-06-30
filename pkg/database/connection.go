package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/facuhernandez99/blog/pkg/config"
	"github.com/facuhernandez99/blog/pkg/errors"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// Config holds database configuration
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

// DefaultConfig returns a default database configuration
func DefaultConfig() *Config {
	return &Config{
		Host:            "localhost",
		Port:            5432,
		Username:        "postgres",
		Password:        "postgres",
		Database:        "blog",
		SSLMode:         "disable",
		MaxOpenConns:    25,
		MaxIdleConns:    25,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}
}

// DSN returns the data source name for PostgreSQL
func (c *Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.Username, c.Password, c.Database, c.SSLMode,
	)
}

// DB wraps sql.DB with additional functionality
type DB struct {
	*sql.DB
	config *Config
}

// Connect establishes a connection to the database using shared config
func Connect(appConfig *config.Config) (*DB, error) {
	if appConfig == nil {
		return nil, errors.New(errors.ErrCodeValidation, "Application config is required")
	}

	// Use the DATABASE_URL from the shared config
	dsn := appConfig.DatabaseURL
	if dsn == "" {
		return nil, errors.New(errors.ErrCodeValidation, "DATABASE_URL is required in configuration")
	}

	return ConnectWithDSN(dsn)
}

// ConnectWithConfig establishes a connection using the legacy Config struct for backward compatibility
func ConnectWithConfig(config *Config) (*DB, error) {
	if config == nil {
		config = DefaultConfig()
	}

	sqlDB, err := sql.Open("postgres", config.DSN())
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConnectionFailed, "Failed to open database connection")
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(config.ConnMaxLifetime)
	sqlDB.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	db := &DB{
		DB:     sqlDB,
		config: config,
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		sqlDB.Close()
		return nil, errors.Wrap(err, errors.ErrCodeConnectionFailed, "Failed to ping database")
	}

	return db, nil
}

// ConnectWithDSN establishes a connection using a DSN string
func ConnectWithDSN(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeConnectionFailed, "Failed to open database connection")
	}

	db := &DB{
		DB:     sqlDB,
		config: nil, // No config when using DSN directly
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		sqlDB.Close()
		return nil, errors.Wrap(err, errors.ErrCodeConnectionFailed, "Failed to ping database")
	}

	return db, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	if err := db.DB.Close(); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to close database connection")
	}
	return nil
}

// HealthCheck performs a health check on the database
func (db *DB) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "Database health check failed")
	}

	return nil
}

// Stats returns database statistics
func (db *DB) Stats() sql.DBStats {
	return db.DB.Stats()
}

// IsHealthy checks if the database is healthy
func (db *DB) IsHealthy(ctx context.Context) bool {
	return db.HealthCheck(ctx) == nil
}

// Transaction helpers

// WithTransaction executes a function within a database transaction
func (db *DB) WithTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to begin transaction")
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Re-throw panic after Rollback
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Wrapf(err, errors.ErrCodeDatabaseError, "Transaction failed and rollback failed: %v", rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to commit transaction")
	}

	return nil
}

// WithTransactionTimeout executes a function within a database transaction with timeout
func (db *DB) WithTransactionTimeout(ctx context.Context, timeout time.Duration, fn func(*sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return db.WithTransaction(ctx, fn)
}

// Query helpers

// QueryRow executes a query that returns a single row with error handling
func (db *DB) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return db.DB.QueryRowContext(ctx, query, args...)
}

// Query executes a query that returns multiple rows with error handling
func (db *DB) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	rows, err := db.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeQueryFailed, "Query execution failed")
	}
	return rows, nil
}

// Exec executes a query without returning rows
func (db *DB) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	result, err := db.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeQueryFailed, "Query execution failed")
	}
	return result, nil
}

// Prepare creates a prepared statement
func (db *DB) Prepare(ctx context.Context, query string) (*sql.Stmt, error) {
	stmt, err := db.DB.PrepareContext(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to prepare statement")
	}
	return stmt, nil
}

// Utility functions

// TableExists checks if a table exists in the database
func (db *DB) TableExists(ctx context.Context, tableName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_name = $1
		)
	`

	var exists bool
	err := db.QueryRow(ctx, query, tableName).Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, errors.ErrCodeQueryFailed, "Failed to check table existence")
	}

	return exists, nil
}

// ColumnExists checks if a column exists in a table
func (db *DB) ColumnExists(ctx context.Context, tableName, columnName string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT FROM information_schema.columns 
			WHERE table_schema = 'public' 
			AND table_name = $1 
			AND column_name = $2
		)
	`

	var exists bool
	err := db.QueryRow(ctx, query, tableName, columnName).Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, errors.ErrCodeQueryFailed, "Failed to check column existence")
	}

	return exists, nil
}

// GetDatabaseVersion returns the PostgreSQL version
func (db *DB) GetDatabaseVersion(ctx context.Context) (string, error) {
	var version string
	err := db.QueryRow(ctx, "SELECT version()").Scan(&version)
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCodeQueryFailed, "Failed to get database version")
	}
	return version, nil
}

// GetConnectionInfo returns information about the current connection
func (db *DB) GetConnectionInfo() *Config {
	return db.config
}
