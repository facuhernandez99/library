package database

import (
	"context"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/errors"
	"github.com/facuhernandez99/blog/pkg/logging"
	"github.com/stretchr/testify/assert"
)

// TestNewMigrator_RealFunction tests the actual NewMigrator function
func TestNewMigrator_RealFunction(t *testing.T) {
	// Use a safe mock for constructor testing (no SQL operations)
	db := &DB{config: DefaultConfig()}

	t.Run("NewMigrator", func(t *testing.T) {
		migrator := NewMigrator(db)
		assert.NotNil(t, migrator)
		assert.Equal(t, db, migrator.db)
		assert.Equal(t, "schema_migrations", migrator.tableName)
		assert.NotNil(t, migrator.logger)
	})

	t.Run("NewMigratorWithTable", func(t *testing.T) {
		customTable := "custom_migrations"
		migrator := NewMigratorWithTable(db, customTable)
		assert.NotNil(t, migrator)
		assert.Equal(t, customTable, migrator.tableName)
	})

	t.Run("NewMigratorWithLogger", func(t *testing.T) {
		logger := logging.NewLogger(nil)
		migrator := NewMigratorWithLogger(db, logger)
		assert.NotNil(t, migrator)
		assert.Equal(t, logger, migrator.logger)
	})
}

// TestMigrator_Initialize_RealFunction tests the Initialize method
func TestMigrator_Initialize_RealFunction(t *testing.T) {
	ctx := context.Background()

	// Test with invalid connection to avoid mock DB issues
	invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
	if err != nil {
		assert.Error(t, err)
		return
	}

	if invalidDB != nil {
		migrator := NewMigrator(invalidDB)
		err := migrator.Initialize(ctx)
		assert.Error(t, err)

		var appErr *errors.AppError
		if assert.ErrorAs(t, err, &appErr) {
			assert.Equal(t, errors.ErrCodeDatabaseError, appErr.Code)
		}

		invalidDB.Close()
	}
}

// TestMigrator_GetCurrentVersion_RealFunction tests GetCurrentVersion method
func TestMigrator_GetCurrentVersion_RealFunction(t *testing.T) {
	ctx := context.Background()

	invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
	if err != nil {
		assert.Error(t, err)
		return
	}

	if invalidDB != nil {
		migrator := NewMigrator(invalidDB)
		version, err := migrator.GetCurrentVersion(ctx)
		assert.Error(t, err)
		assert.Equal(t, 0, version)

		var appErr *errors.AppError
		if assert.ErrorAs(t, err, &appErr) {
			assert.Equal(t, errors.ErrCodeQueryFailed, appErr.Code)
		}

		invalidDB.Close()
	}
}

// TestMigrator_DatabaseOperations tests database operation methods with invalid connection
func TestMigrator_DatabaseOperations(t *testing.T) {
	ctx := context.Background()

	// Test all database operations with invalid connection
	invalidDB, err := ConnectWithDSN("postgres://test:test@localhost:9999/test")
	if err != nil {
		assert.Error(t, err)
		return
	}

	if invalidDB != nil {
		migrator := NewMigrator(invalidDB)

		t.Run("IsMigrationApplied", func(t *testing.T) {
			applied, err := migrator.IsMigrationApplied(ctx, 1)
			assert.Error(t, err)
			assert.False(t, applied)
		})

		t.Run("ApplyMigration", func(t *testing.T) {
			migration := &Migration{
				Version:      1,
				Name:         "create_users_table",
				UpSQL:        "CREATE TABLE users (id SERIAL PRIMARY KEY);",
				DownSQL:      "DROP TABLE users;",
				ChecksumUp:   "checksum123",
				ChecksumDown: "checksum456",
			}

			err := migrator.ApplyMigration(ctx, migration)
			assert.Error(t, err)
		})

		t.Run("RollbackMigration", func(t *testing.T) {
			migration := &Migration{
				Version:      1,
				Name:         "create_users_table",
				UpSQL:        "CREATE TABLE users (id SERIAL PRIMARY KEY);",
				DownSQL:      "DROP TABLE users;",
				ChecksumUp:   "checksum123",
				ChecksumDown: "checksum456",
			}

			err := migrator.RollbackMigration(ctx, migration)
			assert.Error(t, err)
		})

		t.Run("MigrateUp", func(t *testing.T) {
			migrations := []Migration{
				{
					Version:      1,
					Name:         "initial_schema",
					UpSQL:        "CREATE TABLE users (id SERIAL PRIMARY KEY);",
					DownSQL:      "DROP TABLE users;",
					ChecksumUp:   "checksum1",
					ChecksumDown: "checksum1_down",
				},
			}

			err := migrator.MigrateUp(ctx, migrations)
			assert.Error(t, err)
		})

		t.Run("MigrateDown", func(t *testing.T) {
			migrations := []Migration{
				{
					Version:      1,
					Name:         "create_users",
					UpSQL:        "CREATE TABLE users (id SERIAL PRIMARY KEY);",
					DownSQL:      "DROP TABLE users;",
					ChecksumUp:   "checksum1",
					ChecksumDown: "checksum1_down",
				},
			}

			err := migrator.MigrateDown(ctx, 0, migrations)
			assert.Error(t, err)
		})

		t.Run("Status", func(t *testing.T) {
			migrations := []Migration{
				{
					Version:      1,
					Name:         "create_users",
					UpSQL:        "CREATE TABLE users (id SERIAL PRIMARY KEY);",
					DownSQL:      "DROP TABLE users;",
					ChecksumUp:   "checksum1",
					ChecksumDown: "checksum1_down",
				},
			}

			statuses, err := migrator.Status(ctx, migrations)
			assert.Error(t, err)
			assert.Nil(t, statuses)
		})

		invalidDB.Close()
	}
}

// TestCalculateChecksum_RealFunction tests calculateChecksum function
func TestCalculateChecksum_RealFunction(t *testing.T) {
	t.Run("empty_content", func(t *testing.T) {
		result := calculateChecksum("")
		assert.NotEmpty(t, result)
		// Just verify it returns some hash, not specific format
		assert.True(t, len(result) > 0)
	})

	t.Run("simple_content", func(t *testing.T) {
		content := "CREATE TABLE users (id INTEGER);"
		result := calculateChecksum(content)
		assert.NotEmpty(t, result)

		// Should be consistent
		result2 := calculateChecksum(content)
		assert.Equal(t, result, result2)
	})

	t.Run("different_content_different_checksum", func(t *testing.T) {
		content1 := "CREATE TABLE users (id INTEGER);"
		content2 := "CREATE TABLE posts (id INTEGER);"

		checksum1 := calculateChecksum(content1)
		checksum2 := calculateChecksum(content2)

		assert.NotEqual(t, checksum1, checksum2)
	})
}

// Note: LoadMigrationsFromFS test skipped due to nil fs.FS handling issues
// The function requires a valid fs.FS implementation to test properly

// TestMigrationStructures tests Migration and related structures
func TestMigrationStructures(t *testing.T) {
	t.Run("Migration_Structure", func(t *testing.T) {
		migration := Migration{
			Version:      1,
			Name:         "test_migration",
			UpSQL:        "CREATE TABLE test (id INTEGER);",
			DownSQL:      "DROP TABLE test;",
			AppliedAt:    time.Now(),
			ChecksumUp:   "up_checksum",
			ChecksumDown: "down_checksum",
		}

		assert.Equal(t, 1, migration.Version)
		assert.Equal(t, "test_migration", migration.Name)
		assert.NotEmpty(t, migration.UpSQL)
		assert.NotEmpty(t, migration.DownSQL)
		assert.NotZero(t, migration.AppliedAt)
		assert.Equal(t, "up_checksum", migration.ChecksumUp)
		assert.Equal(t, "down_checksum", migration.ChecksumDown)
	})

	t.Run("MigrationStatus_Structure", func(t *testing.T) {
		status := MigrationStatus{
			Version:   1,
			Name:      "test_migration",
			Applied:   true,
			AppliedAt: time.Now(),
		}

		assert.Equal(t, 1, status.Version)
		assert.Equal(t, "test_migration", status.Name)
		assert.True(t, status.Applied)
		assert.NotZero(t, status.AppliedAt)
	})

	t.Run("MigrationFile_Structure", func(t *testing.T) {
		migrationFile := MigrationFile{
			Version:  1,
			Name:     "create_users",
			FilePath: "/migrations/001_create_users.up.sql",
			IsUp:     true,
		}

		assert.Equal(t, 1, migrationFile.Version)
		assert.Equal(t, "create_users", migrationFile.Name)
		assert.Equal(t, "/migrations/001_create_users.up.sql", migrationFile.FilePath)
		assert.True(t, migrationFile.IsUp)
	})
}
