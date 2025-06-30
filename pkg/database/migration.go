package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/facuhernandez99/library/pkg/errors"
	"github.com/facuhernandez99/library/pkg/logging"
)

// Migration represents a database migration
type Migration struct {
	Version      int       `json:"version"`
	Name         string    `json:"name"`
	UpSQL        string    `json:"up_sql"`
	DownSQL      string    `json:"down_sql"`
	AppliedAt    time.Time `json:"applied_at"`
	ChecksumUp   string    `json:"checksum_up"`
	ChecksumDown string    `json:"checksum_down"`
}

// MigrationFile represents a migration file
type MigrationFile struct {
	Version  int
	Name     string
	FilePath string
	IsUp     bool
}

// Migrator handles database migrations
type Migrator struct {
	db        *DB
	tableName string
	logger    *logging.Logger
}

// NewMigrator creates a new migrator instance
func NewMigrator(db *DB) *Migrator {
	return &Migrator{
		db:        db,
		tableName: "schema_migrations",
		logger:    logging.GetDefault(),
	}
}

// NewMigratorWithTable creates a new migrator instance with custom table name
func NewMigratorWithTable(db *DB, tableName string) *Migrator {
	return &Migrator{
		db:        db,
		tableName: tableName,
		logger:    logging.GetDefault(),
	}
}

// NewMigratorWithLogger creates a new migrator instance with custom logger
func NewMigratorWithLogger(db *DB, logger *logging.Logger) *Migrator {
	return &Migrator{
		db:        db,
		tableName: "schema_migrations",
		logger:    logger,
	}
}

// Initialize creates the migrations table if it doesn't exist
func (m *Migrator) Initialize(ctx context.Context) error {
	m.logger.Info(ctx, "Initializing migrations table")

	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			checksum_up VARCHAR(64) NOT NULL,
			checksum_down VARCHAR(64),
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`, m.tableName)

	_, err := m.db.Exec(ctx, query)
	if err != nil {
		m.logger.Error(ctx, "Failed to initialize migrations table", err)
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to initialize migrations table")
	}

	m.logger.WithField("table", m.tableName).Info(ctx, "Migrations table initialized successfully")
	return nil
}

// GetAppliedMigrations returns all applied migrations
func (m *Migrator) GetAppliedMigrations(ctx context.Context) ([]Migration, error) {
	query := fmt.Sprintf(`
		SELECT version, name, checksum_up, checksum_down, applied_at 
		FROM %s 
		ORDER BY version ASC
	`, m.tableName)

	rows, err := m.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeQueryFailed, "Failed to get applied migrations")
	}
	defer rows.Close()

	var migrations []Migration
	for rows.Next() {
		var migration Migration
		var checksumDown sql.NullString

		err := rows.Scan(
			&migration.Version,
			&migration.Name,
			&migration.ChecksumUp,
			&checksumDown,
			&migration.AppliedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeQueryFailed, "Failed to scan migration row")
		}

		if checksumDown.Valid {
			migration.ChecksumDown = checksumDown.String
		}

		migrations = append(migrations, migration)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeQueryFailed, "Error iterating migration rows")
	}

	return migrations, nil
}

// GetCurrentVersion returns the current migration version
func (m *Migrator) GetCurrentVersion(ctx context.Context) (int, error) {
	query := fmt.Sprintf(`
		SELECT COALESCE(MAX(version), 0) 
		FROM %s
	`, m.tableName)

	var version int
	err := m.db.QueryRow(ctx, query).Scan(&version)
	if err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeQueryFailed, "Failed to get current migration version")
	}

	return version, nil
}

// IsMigrationApplied checks if a migration version is applied
func (m *Migrator) IsMigrationApplied(ctx context.Context, version int) (bool, error) {
	query := fmt.Sprintf(`
		SELECT EXISTS(SELECT 1 FROM %s WHERE version = $1)
	`, m.tableName)

	var exists bool
	err := m.db.QueryRow(ctx, query, version).Scan(&exists)
	if err != nil {
		return false, errors.Wrap(err, errors.ErrCodeQueryFailed, "Failed to check migration status")
	}

	return exists, nil
}

// ApplyMigration applies a single migration
func (m *Migrator) ApplyMigration(ctx context.Context, migration *Migration) error {
	logger := m.logger.WithFields(map[string]interface{}{
		"migration_version": migration.Version,
		"migration_name":    migration.Name,
	})

	logger.Info(ctx, "Applying migration")

	err := m.db.WithTransaction(ctx, func(tx *sql.Tx) error {
		// Execute the migration SQL
		_, err := tx.ExecContext(ctx, migration.UpSQL)
		if err != nil {
			return errors.Wrapf(err, errors.ErrCodeDatabaseError, "Failed to execute migration %d", migration.Version)
		}

		// Record the migration
		query := fmt.Sprintf(`
			INSERT INTO %s (version, name, checksum_up, checksum_down) 
			VALUES ($1, $2, $3, $4)
		`, m.tableName)

		_, err = tx.ExecContext(ctx, query,
			migration.Version,
			migration.Name,
			migration.ChecksumUp,
			migration.ChecksumDown,
		)
		if err != nil {
			return errors.Wrapf(err, errors.ErrCodeDatabaseError, "Failed to record migration %d", migration.Version)
		}

		return nil
	})

	if err != nil {
		logger.Error(ctx, "Failed to apply migration", err)
		return err
	}

	logger.Info(ctx, "Migration applied successfully")
	return nil
}

// RollbackMigration rolls back a single migration
func (m *Migrator) RollbackMigration(ctx context.Context, migration *Migration) error {
	logger := m.logger.WithFields(map[string]interface{}{
		"migration_version": migration.Version,
		"migration_name":    migration.Name,
	})

	if migration.DownSQL == "" {
		logger.Warn(ctx, "Migration has no down migration, skipping rollback")
		return errors.Newf(errors.ErrCodeValidation, "Migration %d has no down migration", migration.Version)
	}

	logger.Info(ctx, "Rolling back migration")

	err := m.db.WithTransaction(ctx, func(tx *sql.Tx) error {
		// Execute the rollback SQL
		_, err := tx.ExecContext(ctx, migration.DownSQL)
		if err != nil {
			return errors.Wrapf(err, errors.ErrCodeDatabaseError, "Failed to rollback migration %d", migration.Version)
		}

		// Remove the migration record
		query := fmt.Sprintf(`
			DELETE FROM %s WHERE version = $1
		`, m.tableName)

		_, err = tx.ExecContext(ctx, query, migration.Version)
		if err != nil {
			return errors.Wrapf(err, errors.ErrCodeDatabaseError, "Failed to remove migration record %d", migration.Version)
		}

		return nil
	})

	if err != nil {
		logger.Error(ctx, "Failed to rollback migration", err)
		return err
	}

	logger.Info(ctx, "Migration rolled back successfully")
	return nil
}

// MigrateUp applies all pending migrations
func (m *Migrator) MigrateUp(ctx context.Context, migrations []Migration) error {
	m.logger.Info(ctx, "Starting migration up process")

	if err := m.Initialize(ctx); err != nil {
		return err
	}

	currentVersion, err := m.GetCurrentVersion(ctx)
	if err != nil {
		return err
	}

	m.logger.WithField("current_version", currentVersion).Info(ctx, "Current database version")

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	applied := 0
	for _, migration := range migrations {
		if migration.Version <= currentVersion {
			continue // Skip already applied migrations
		}

		if err := m.ApplyMigration(ctx, &migration); err != nil {
			m.logger.WithField("failed_at_version", migration.Version).Error(ctx, "Migration up process failed", err)
			return errors.Wrapf(err, errors.ErrCodeDatabaseError, "Failed to apply migration %d", migration.Version)
		}

		applied++
	}

	if applied == 0 {
		m.logger.Info(ctx, "No pending migrations to apply")
	} else {
		m.logger.WithField("applied_count", applied).Info(ctx, "Migration up process completed successfully")
	}

	return nil
}

// MigrateDown rolls back migrations to a target version
func (m *Migrator) MigrateDown(ctx context.Context, targetVersion int, migrations []Migration) error {
	m.logger.WithField("target_version", targetVersion).Info(ctx, "Starting migration down process")

	appliedMigrations, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}

	// Sort migrations by version descending for rollback
	sort.Slice(appliedMigrations, func(i, j int) bool {
		return appliedMigrations[i].Version > appliedMigrations[j].Version
	})

	// Create a map for quick lookup of migration SQL
	migrationMap := make(map[int]Migration)
	for _, migration := range migrations {
		migrationMap[migration.Version] = migration
	}

	rolledBack := 0
	for _, appliedMigration := range appliedMigrations {
		if appliedMigration.Version <= targetVersion {
			break // Stop when we reach the target version
		}

		// Find the migration with down SQL
		migration, exists := migrationMap[appliedMigration.Version]
		if !exists {
			m.logger.WithField("missing_version", appliedMigration.Version).Error(ctx, "Migration file not found for rollback", nil)
			return errors.Newf(errors.ErrCodeValidation, "Migration %d not found in migration files", appliedMigration.Version)
		}

		migration.DownSQL = migrationMap[appliedMigration.Version].DownSQL

		if err := m.RollbackMigration(ctx, &migration); err != nil {
			m.logger.WithField("failed_at_version", migration.Version).Error(ctx, "Migration down process failed", err)
			return errors.Wrapf(err, errors.ErrCodeDatabaseError, "Failed to rollback migration %d", migration.Version)
		}

		rolledBack++
	}

	if rolledBack == 0 {
		m.logger.Info(ctx, "No migrations to rollback")
	} else {
		m.logger.WithField("rolled_back_count", rolledBack).Info(ctx, "Migration down process completed successfully")
	}

	return nil
}

// Status returns the current migration status
func (m *Migrator) Status(ctx context.Context, migrations []Migration) ([]MigrationStatus, error) {
	if err := m.Initialize(ctx); err != nil {
		return nil, err
	}

	appliedMigrations, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}

	// Create a map of applied migrations
	appliedMap := make(map[int]Migration)
	for _, migration := range appliedMigrations {
		appliedMap[migration.Version] = migration
	}

	// Sort available migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	var status []MigrationStatus
	for _, migration := range migrations {
		applied, exists := appliedMap[migration.Version]
		migrationStatus := MigrationStatus{
			Version: migration.Version,
			Name:    migration.Name,
			Applied: exists,
		}

		if exists {
			migrationStatus.AppliedAt = applied.AppliedAt
		}

		status = append(status, migrationStatus)
	}

	return status, nil
}

// MigrationStatus represents the status of a migration
type MigrationStatus struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	Applied   bool      `json:"applied"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
}

// File-based migration helpers

// LoadMigrationsFromFS loads migrations from an embedded file system
func LoadMigrationsFromFS(fsys fs.FS, migrationDir string) ([]Migration, error) {
	files, err := fs.ReadDir(fsys, migrationDir)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to read migration directory")
	}

	migrationFiles := make(map[int]*MigrationFile)

	// Parse migration files
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		migrationFile, err := parseMigrationFileName(file.Name())
		if err != nil {
			continue // Skip non-migration files
		}

		migrationFile.FilePath = filepath.Join(migrationDir, file.Name())

		if existing, exists := migrationFiles[migrationFile.Version]; exists {
			if migrationFile.IsUp {
				existing.FilePath = migrationFile.FilePath
			}
		} else {
			migrationFiles[migrationFile.Version] = migrationFile
		}
	}

	// Load migration content
	var migrations []Migration
	for version, migrationFile := range migrationFiles {
		upContent, err := fs.ReadFile(fsys, migrationFile.FilePath)
		if err != nil {
			return nil, errors.Wrapf(err, errors.ErrCodeDatabaseError, "Failed to read migration file %s", migrationFile.FilePath)
		}

		migration := Migration{
			Version:    version,
			Name:       migrationFile.Name,
			UpSQL:      string(upContent),
			ChecksumUp: calculateChecksum(string(upContent)),
		}

		// Look for corresponding down migration
		downFile := strings.Replace(migrationFile.FilePath, ".up.sql", ".down.sql", 1)
		if downContent, err := fs.ReadFile(fsys, downFile); err == nil {
			migration.DownSQL = string(downContent)
			migration.ChecksumDown = calculateChecksum(string(downContent))
		}

		migrations = append(migrations, migration)
	}

	return migrations, nil
}

// parseMigrationFileName parses a migration file name
func parseMigrationFileName(filename string) (*MigrationFile, error) {
	if !strings.HasSuffix(filename, ".sql") {
		return nil, errors.New(errors.ErrCodeValidation, "File is not a SQL file")
	}

	// Expected format: {version}_{name}.up.sql or {version}_{name}.down.sql
	parts := strings.Split(filename, "_")
	if len(parts) < 2 {
		return nil, errors.New(errors.ErrCodeValidation, "Invalid migration file name format")
	}

	versionStr := parts[0]
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeValidation, "Invalid version number in migration file")
	}

	nameWithSuffix := strings.Join(parts[1:], "_")

	var isUp bool
	var name string

	if strings.HasSuffix(nameWithSuffix, ".up.sql") {
		isUp = true
		name = strings.TrimSuffix(nameWithSuffix, ".up.sql")
	} else if strings.HasSuffix(nameWithSuffix, ".down.sql") {
		isUp = false
		name = strings.TrimSuffix(nameWithSuffix, ".down.sql")
	} else {
		return nil, errors.New(errors.ErrCodeValidation, "Migration file must end with .up.sql or .down.sql")
	}

	return &MigrationFile{
		Version: version,
		Name:    name,
		IsUp:    isUp,
	}, nil
}

// calculateChecksum calculates a simple checksum for migration content
func calculateChecksum(content string) string {
	// Simple hash for demonstration - in production, use crypto/sha256
	hash := 0
	for _, char := range content {
		hash = hash*31 + int(char)
	}
	return fmt.Sprintf("%x", hash)
}
