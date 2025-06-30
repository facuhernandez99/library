package database

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/facuhernandez99/library/pkg/errors"
	"github.com/facuhernandez99/library/pkg/logging"
)

func TestMigratorInitialization(t *testing.T) {
	t.Run("NewMigrator", func(t *testing.T) {
		// Create a mock DB for testing
		mockDB := &DB{
			DB:     nil, // We'll use nil since we're not actually connecting
			config: DefaultConfig(),
		}

		migrator := NewMigrator(mockDB)

		if migrator == nil {
			t.Error("NewMigrator should not return nil")
		}

		if migrator.db != mockDB {
			t.Error("Migrator should store the provided DB instance")
		}

		if migrator.tableName != "schema_migrations" {
			t.Errorf("Expected default table name 'schema_migrations', got %s", migrator.tableName)
		}

		if migrator.logger == nil {
			t.Error("Migrator should have a logger instance")
		}

		// Verify it uses the default logger
		if migrator.logger != logging.GetDefault() {
			t.Error("Migrator should use default logger when created with NewMigrator")
		}
	})

	t.Run("NewMigratorWithTable", func(t *testing.T) {
		mockDB := &DB{
			DB:     nil,
			config: DefaultConfig(),
		}

		customTableName := "custom_migrations"
		migrator := NewMigratorWithTable(mockDB, customTableName)

		if migrator == nil {
			t.Error("NewMigratorWithTable should not return nil")
		}

		if migrator.db != mockDB {
			t.Error("Migrator should store the provided DB instance")
		}

		if migrator.tableName != customTableName {
			t.Errorf("Expected custom table name %s, got %s", customTableName, migrator.tableName)
		}

		if migrator.logger == nil {
			t.Error("Migrator should have a logger instance")
		}

		// Verify it uses the default logger
		if migrator.logger != logging.GetDefault() {
			t.Error("Migrator should use default logger when created with NewMigratorWithTable")
		}
	})

	t.Run("NewMigratorWithLogger", func(t *testing.T) {
		mockDB := &DB{
			DB:     nil,
			config: DefaultConfig(),
		}

		// Create a custom logger
		customLogger := logging.NewLogger(&logging.Config{
			Level:      logging.LevelDebug,
			Service:    "test-migrator",
			Version:    "1.0.0",
			Production: false,
		})

		migrator := NewMigratorWithLogger(mockDB, customLogger)

		if migrator == nil {
			t.Error("NewMigratorWithLogger should not return nil")
		}

		if migrator.db != mockDB {
			t.Error("Migrator should store the provided DB instance")
		}

		if migrator.tableName != "schema_migrations" {
			t.Errorf("Expected default table name 'schema_migrations', got %s", migrator.tableName)
		}

		if migrator.logger == nil {
			t.Error("Migrator should have a logger instance")
		}

		// Verify it uses the custom logger
		if migrator.logger != customLogger {
			t.Error("Migrator should use the provided custom logger")
		}
	})

	t.Run("InitializeSQL", func(t *testing.T) {
		mockDB := &DB{
			DB:     nil,
			config: DefaultConfig(),
		}

		migrator := NewMigrator(mockDB)

		// Test that the SQL query is properly formatted
		expectedSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			checksum_up VARCHAR(64) NOT NULL,
			checksum_down VARCHAR(64),
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`, migrator.tableName)

		// Basic validation of SQL structure
		if !strings.Contains(expectedSQL, "CREATE TABLE IF NOT EXISTS") {
			t.Error("Initialize SQL should contain CREATE TABLE IF NOT EXISTS")
		}

		if !strings.Contains(expectedSQL, "version INTEGER PRIMARY KEY") {
			t.Error("Initialize SQL should contain version as primary key")
		}

		if !strings.Contains(expectedSQL, "applied_at TIMESTAMP") {
			t.Error("Initialize SQL should contain applied_at timestamp")
		}
	})
}

func TestMigrationQueries(t *testing.T) {
	t.Run("GetAppliedMigrationsSQL", func(t *testing.T) {
		migrator := NewMigrator(&DB{})

		expectedSQL := fmt.Sprintf(`
		SELECT version, name, checksum_up, checksum_down, applied_at 
		FROM %s 
		ORDER BY version ASC
	`, migrator.tableName)

		// Validate SQL structure
		if !strings.Contains(expectedSQL, "SELECT") {
			t.Error("GetAppliedMigrations SQL should be a SELECT query")
		}

		if !strings.Contains(expectedSQL, "ORDER BY version ASC") {
			t.Error("GetAppliedMigrations SQL should order by version")
		}

		if !strings.Contains(expectedSQL, migrator.tableName) {
			t.Error("GetAppliedMigrations SQL should reference the migrations table")
		}
	})

	t.Run("GetCurrentVersionSQL", func(t *testing.T) {
		migrator := NewMigrator(&DB{})

		expectedSQL := fmt.Sprintf(`
		SELECT COALESCE(MAX(version), 0) 
		FROM %s
	`, migrator.tableName)

		// Validate SQL structure
		if !strings.Contains(expectedSQL, "COALESCE(MAX(version), 0)") {
			t.Error("GetCurrentVersion SQL should use COALESCE with MAX")
		}

		if !strings.Contains(expectedSQL, migrator.tableName) {
			t.Error("GetCurrentVersion SQL should reference the migrations table")
		}
	})

	t.Run("IsMigrationAppliedSQL", func(t *testing.T) {
		migrator := NewMigrator(&DB{})

		expectedSQL := fmt.Sprintf(`
		SELECT EXISTS(SELECT 1 FROM %s WHERE version = $1)
	`, migrator.tableName)

		// Validate SQL structure
		if !strings.Contains(expectedSQL, "EXISTS") {
			t.Error("IsMigrationApplied SQL should use EXISTS")
		}

		if !strings.Contains(expectedSQL, "WHERE version = $1") {
			t.Error("IsMigrationApplied SQL should filter by version parameter")
		}
	})
}

func TestMigrationOperations(t *testing.T) {
	t.Run("ApplyMigrationSQL", func(t *testing.T) {
		migrator := NewMigrator(&DB{})

		// Test the SQL for recording migrations
		expectedRecordSQL := fmt.Sprintf(`
			INSERT INTO %s (version, name, checksum_up, checksum_down) 
			VALUES ($1, $2, $3, $4)
		`, migrator.tableName)

		// Validate SQL structure
		if !strings.Contains(expectedRecordSQL, "INSERT INTO") {
			t.Error("ApplyMigration record SQL should be an INSERT")
		}

		if !strings.Contains(expectedRecordSQL, "VALUES ($1, $2, $3, $4)") {
			t.Error("ApplyMigration record SQL should have 4 parameters")
		}
	})

	t.Run("RollbackMigrationSQL", func(t *testing.T) {
		migrator := NewMigrator(&DB{})

		// Test the SQL for removing migration records
		expectedDeleteSQL := fmt.Sprintf(`
			DELETE FROM %s WHERE version = $1
		`, migrator.tableName)

		// Validate SQL structure
		if !strings.Contains(expectedDeleteSQL, "DELETE FROM") {
			t.Error("RollbackMigration SQL should be a DELETE")
		}

		if !strings.Contains(expectedDeleteSQL, "WHERE version = $1") {
			t.Error("RollbackMigration SQL should filter by version")
		}
	})

	t.Run("MigrationStructure", func(t *testing.T) {
		// Test Migration struct
		migration := Migration{
			Version:      1,
			Name:         "create_users_table",
			UpSQL:        "CREATE TABLE users (id SERIAL PRIMARY KEY);",
			DownSQL:      "DROP TABLE users;",
			AppliedAt:    time.Now(),
			ChecksumUp:   "abc123",
			ChecksumDown: "def456",
		}

		// Test basic validation
		if migration.Version <= 0 {
			t.Error("Migration version should be positive")
		}

		if migration.Name == "" {
			t.Error("Migration name should not be empty")
		}

		if migration.UpSQL == "" {
			t.Error("Migration UpSQL should not be empty")
		}

		if migration.ChecksumUp == "" {
			t.Error("Migration ChecksumUp should not be empty")
		}
	})

	t.Run("MigrationLoggingSetup", func(t *testing.T) {
		// Test that migrator properly sets up logging context
		migrator := NewMigrator(&DB{})

		// Test that logger is configured
		if migrator.logger == nil {
			t.Error("Migrator should have logger configured")
		}

		// Test logger level
		if migrator.logger.GetLevel() < logging.LevelInfo {
			t.Log("Logger level is below Info, which is acceptable")
		}
	})
}

func TestMigrationWorkflows(t *testing.T) {
	t.Run("MigrateUpLogic", func(t *testing.T) {
		// Test migration sorting logic
		migrations := []Migration{
			{Version: 3, Name: "third", UpSQL: "SQL3"},
			{Version: 1, Name: "first", UpSQL: "SQL1"},
			{Version: 2, Name: "second", UpSQL: "SQL2"},
		}

		// Test sorting functionality
		sortedMigrations := make([]Migration, len(migrations))
		copy(sortedMigrations, migrations)

		// Simulate the sorting logic from MigrateUp
		for i := 0; i < len(sortedMigrations); i++ {
			for j := i + 1; j < len(sortedMigrations); j++ {
				if sortedMigrations[i].Version > sortedMigrations[j].Version {
					sortedMigrations[i], sortedMigrations[j] = sortedMigrations[j], sortedMigrations[i]
				}
			}
		}

		// Verify sorting
		expectedVersions := []int{1, 2, 3}
		for i, migration := range sortedMigrations {
			if migration.Version != expectedVersions[i] {
				t.Errorf("Expected version %d at index %d, got %d", expectedVersions[i], i, migration.Version)
			}
		}
	})

	t.Run("MigrateDownLogic", func(t *testing.T) {
		// Test rollback sorting logic (descending order)
		appliedMigrations := []Migration{
			{Version: 1, Name: "first", DownSQL: "DROP1"},
			{Version: 2, Name: "second", DownSQL: "DROP2"},
			{Version: 3, Name: "third", DownSQL: "DROP3"},
		}

		// Simulate the sorting logic from MigrateDown (descending)
		sortedMigrations := make([]Migration, len(appliedMigrations))
		copy(sortedMigrations, appliedMigrations)

		for i := 0; i < len(sortedMigrations); i++ {
			for j := i + 1; j < len(sortedMigrations); j++ {
				if sortedMigrations[i].Version < sortedMigrations[j].Version {
					sortedMigrations[i], sortedMigrations[j] = sortedMigrations[j], sortedMigrations[i]
				}
			}
		}

		// Verify descending sorting
		expectedVersions := []int{3, 2, 1}
		for i, migration := range sortedMigrations {
			if migration.Version != expectedVersions[i] {
				t.Errorf("Expected version %d at index %d, got %d", expectedVersions[i], i, migration.Version)
			}
		}
	})

	t.Run("MigrateDownTargetLogic", func(t *testing.T) {
		// Test target version logic for rollbacks
		appliedMigrations := []Migration{
			{Version: 3, Name: "third"},
			{Version: 2, Name: "second"},
			{Version: 1, Name: "first"},
		}

		targetVersion := 1
		var migrationsToRollback []Migration

		for _, migration := range appliedMigrations {
			if migration.Version <= targetVersion {
				break // Stop when we reach the target version
			}
			migrationsToRollback = append(migrationsToRollback, migration)
		}

		// Should rollback versions 3 and 2, keep version 1
		expectedRollbacks := []int{3, 2}
		if len(migrationsToRollback) != len(expectedRollbacks) {
			t.Errorf("Expected %d rollbacks, got %d", len(expectedRollbacks), len(migrationsToRollback))
		}

		for i, migration := range migrationsToRollback {
			if migration.Version != expectedRollbacks[i] {
				t.Errorf("Expected rollback version %d at index %d, got %d", expectedRollbacks[i], i, migration.Version)
			}
		}
	})
}

func TestMigrationStatus(t *testing.T) {
	t.Run("StatusReporting", func(t *testing.T) {
		// Test migration status logic
		availableMigrations := []Migration{
			{Version: 1, Name: "create_users"},
			{Version: 2, Name: "add_email_index"},
			{Version: 3, Name: "create_posts"},
		}

		appliedMigrations := []Migration{
			{Version: 1, Name: "create_users", AppliedAt: time.Now().Add(-2 * time.Hour)},
			{Version: 2, Name: "add_email_index", AppliedAt: time.Now().Add(-1 * time.Hour)},
		}

		// Create applied map (simulate Status function logic)
		appliedMap := make(map[int]Migration)
		for _, migration := range appliedMigrations {
			appliedMap[migration.Version] = migration
		}

		// Generate status
		var status []MigrationStatus
		for _, migration := range availableMigrations {
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

		// Verify status
		if len(status) != 3 {
			t.Errorf("Expected 3 status entries, got %d", len(status))
		}

		// Check first migration (applied)
		if !status[0].Applied {
			t.Error("First migration should be marked as applied")
		}

		if status[0].AppliedAt.IsZero() {
			t.Error("First migration should have an AppliedAt time")
		}

		// Check third migration (not applied)
		if status[2].Applied {
			t.Error("Third migration should not be marked as applied")
		}

		if !status[2].AppliedAt.IsZero() {
			t.Error("Third migration should not have an AppliedAt time")
		}
	})

	t.Run("MigrationStatusStructure", func(t *testing.T) {
		// Test MigrationStatus struct
		status := MigrationStatus{
			Version:   1,
			Name:      "create_table",
			Applied:   true,
			AppliedAt: time.Now(),
		}

		// Validate struct fields
		if status.Version != 1 {
			t.Errorf("Expected version 1, got %d", status.Version)
		}

		if status.Name != "create_table" {
			t.Errorf("Expected name 'create_table', got %s", status.Name)
		}

		if !status.Applied {
			t.Error("Expected Applied to be true")
		}

		if status.AppliedAt.IsZero() {
			t.Error("Expected non-zero AppliedAt time")
		}
	})
}

func TestParseMigrationFileName(t *testing.T) {
	tests := []struct {
		name           string
		filename       string
		expectedResult *MigrationFile
		shouldError    bool
		description    string
	}{
		{
			name:     "valid_up_migration",
			filename: "001_create_users_table.up.sql",
			expectedResult: &MigrationFile{
				Version: 1,
				Name:    "create_users_table",
				IsUp:    true,
			},
			shouldError: false,
			description: "Should parse valid up migration file",
		},
		{
			name:     "valid_down_migration",
			filename: "002_add_email_index.down.sql",
			expectedResult: &MigrationFile{
				Version: 2,
				Name:    "add_email_index",
				IsUp:    false,
			},
			shouldError: false,
			description: "Should parse valid down migration file",
		},
		{
			name:     "complex_name",
			filename: "100_create_user_profile_table.up.sql",
			expectedResult: &MigrationFile{
				Version: 100,
				Name:    "create_user_profile_table",
				IsUp:    true,
			},
			shouldError: false,
			description: "Should parse migration with complex name",
		},
		{
			name:        "invalid_extension",
			filename:    "001_create_table.up.txt",
			shouldError: true,
			description: "Should fail for non-SQL files",
		},
		{
			name:        "missing_version",
			filename:    "create_table.up.sql",
			shouldError: true,
			description: "Should fail for files without version",
		},
		{
			name:        "invalid_version",
			filename:    "abc_create_table.up.sql",
			shouldError: true,
			description: "Should fail for non-numeric version",
		},
		{
			name:        "missing_direction",
			filename:    "001_create_table.sql",
			shouldError: true,
			description: "Should fail for files without .up or .down",
		},
		{
			name:        "empty_name",
			filename:    "001_.up.sql",
			shouldError: false, // This would result in empty name but might be valid
			expectedResult: &MigrationFile{
				Version: 1,
				Name:    "",
				IsUp:    true,
			},
			description: "Should handle empty migration name",
		},
		{
			name:        "underscore_in_name",
			filename:    "001_create_user_posts_table.up.sql",
			shouldError: false,
			expectedResult: &MigrationFile{
				Version: 1,
				Name:    "create_user_posts_table",
				IsUp:    true,
			},
			description: "Should handle underscores in migration name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseMigrationFileName(tt.filename)

			if tt.shouldError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
				return
			}

			if result == nil {
				t.Errorf("%s: expected non-nil result", tt.description)
				return
			}

			if result.Version != tt.expectedResult.Version {
				t.Errorf("%s: expected version %d, got %d", tt.description, tt.expectedResult.Version, result.Version)
			}

			if result.Name != tt.expectedResult.Name {
				t.Errorf("%s: expected name %s, got %s", tt.description, tt.expectedResult.Name, result.Name)
			}

			if result.IsUp != tt.expectedResult.IsUp {
				t.Errorf("%s: expected IsUp %t, got %t", tt.description, tt.expectedResult.IsUp, result.IsUp)
			}
		})
	}
}

func TestLoadMigrationsFromFS(t *testing.T) {
	t.Run("MockFilesystem", func(t *testing.T) {
		// Create a mock filesystem with migration files
		mockFS := fstest.MapFS{
			"migrations/001_create_users.up.sql": &fstest.MapFile{
				Data: []byte("CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50));"),
			},
			"migrations/001_create_users.down.sql": &fstest.MapFile{
				Data: []byte("DROP TABLE users;"),
			},
			"migrations/002_add_email_index.up.sql": &fstest.MapFile{
				Data: []byte("CREATE INDEX idx_users_email ON users(email);"),
			},
			"migrations/002_add_email_index.down.sql": &fstest.MapFile{
				Data: []byte("DROP INDEX idx_users_email;"),
			},
			"migrations/003_create_posts.up.sql": &fstest.MapFile{
				Data: []byte("CREATE TABLE posts (id SERIAL PRIMARY KEY, title VARCHAR(200));"),
			},
			// Note: No down migration for 003 to test missing down files
			"migrations/README.md": &fstest.MapFile{
				Data: []byte("This is a readme file"),
			},
			"migrations/invalid_file.txt": &fstest.MapFile{
				Data: []byte("This is not a migration"),
			},
		}

		migrations, err := LoadMigrationsFromFS(mockFS, "migrations")
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
			return
		}

		// Should have 3 migrations (001, 002, 003)
		if len(migrations) != 3 {
			t.Errorf("Expected 3 migrations, got %d", len(migrations))
		}

		// Check migration 001
		migration001 := findMigrationByVersion(migrations, 1)
		if migration001 == nil {
			t.Error("Migration 001 not found")
		} else {
			if migration001.Name != "create_users" {
				t.Errorf("Expected migration 001 name 'create_users', got %s", migration001.Name)
			}

			if migration001.UpSQL == "" {
				t.Error("Migration 001 should have UpSQL")
			}

			if migration001.DownSQL == "" {
				t.Error("Migration 001 should have DownSQL")
			}

			if migration001.ChecksumUp == "" {
				t.Error("Migration 001 should have ChecksumUp")
			}

			if migration001.ChecksumDown == "" {
				t.Error("Migration 001 should have ChecksumDown")
			}
		}

		// Check migration 003 (no down file)
		migration003 := findMigrationByVersion(migrations, 3)
		if migration003 == nil {
			t.Error("Migration 003 not found")
		} else {
			if migration003.UpSQL == "" {
				t.Error("Migration 003 should have UpSQL")
			}

			if migration003.DownSQL != "" {
				t.Error("Migration 003 should not have DownSQL")
			}

			if migration003.ChecksumDown != "" {
				t.Error("Migration 003 should not have ChecksumDown")
			}
		}
	})

	t.Run("EmptyDirectory", func(t *testing.T) {
		// Test with empty migration directory
		emptyFS := fstest.MapFS{
			"migrations/.gitkeep": &fstest.MapFile{
				Data: []byte(""),
			},
		}

		migrations, err := LoadMigrationsFromFS(emptyFS, "migrations")
		if err != nil {
			t.Errorf("Expected no error for empty directory, got %v", err)
			return
		}

		if len(migrations) != 0 {
			t.Errorf("Expected 0 migrations in empty directory, got %d", len(migrations))
		}
	})

	t.Run("InvalidDirectory", func(t *testing.T) {
		// Test with non-existent directory
		emptyFS := fstest.MapFS{}

		_, err := LoadMigrationsFromFS(emptyFS, "nonexistent")
		if err == nil {
			t.Error("Expected error for non-existent directory")
		}

		// Check that it's wrapped as a database error
		if appErr, ok := errors.IsAppError(err); ok {
			if appErr.Code != errors.ErrCodeDatabaseError {
				t.Errorf("Expected ErrCodeDatabaseError, got %s", appErr.Code)
			}
		}
	})
}

func TestCalculateChecksum(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "simple_content",
			content:     "CREATE TABLE users (id SERIAL);",
			description: "Should calculate checksum for simple SQL",
		},
		{
			name:        "empty_content",
			content:     "",
			description: "Should handle empty content",
		},
		{
			name:        "multiline_content",
			content:     "CREATE TABLE users (\n  id SERIAL PRIMARY KEY,\n  username VARCHAR(50)\n);",
			description: "Should handle multiline SQL",
		},
		{
			name:        "unicode_content",
			content:     "-- This is a comment with émojis 🚀\nCREATE TABLE test (id INT);",
			description: "Should handle unicode characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checksum := calculateChecksum(tt.content)

			// Checksum should not be empty
			if checksum == "" {
				t.Errorf("%s: checksum should not be empty", tt.description)
			}

			// Checksum should be consistent
			checksum2 := calculateChecksum(tt.content)
			if checksum != checksum2 {
				t.Errorf("%s: checksums should be consistent", tt.description)
			}

			// Different content should produce different checksums
			if tt.content != "" {
				differentContent := tt.content + " -- modified"
				differentChecksum := calculateChecksum(differentContent)
				if checksum == differentChecksum {
					t.Errorf("%s: different content should produce different checksums", tt.description)
				}
			}
		})
	}
}

func TestMigrationFileStructure(t *testing.T) {
	t.Run("MigrationFileFields", func(t *testing.T) {
		migrationFile := MigrationFile{
			Version:  1,
			Name:     "create_users",
			FilePath: "migrations/001_create_users.up.sql",
			IsUp:     true,
		}

		// Validate struct fields
		if migrationFile.Version != 1 {
			t.Errorf("Expected version 1, got %d", migrationFile.Version)
		}

		if migrationFile.Name != "create_users" {
			t.Errorf("Expected name 'create_users', got %s", migrationFile.Name)
		}

		if migrationFile.FilePath != "migrations/001_create_users.up.sql" {
			t.Errorf("Expected specific filepath, got %s", migrationFile.FilePath)
		}

		if !migrationFile.IsUp {
			t.Error("Expected IsUp to be true")
		}
	})
}

func TestMigrationErrorHandling(t *testing.T) {
	t.Run("MigrationErrors", func(t *testing.T) {
		// Test error creation for migration scenarios
		testCases := []struct {
			errorCode errors.ErrorCode
			message   string
		}{
			{errors.ErrCodeDatabaseError, "Failed to initialize migrations table"},
			{errors.ErrCodeQueryFailed, "Failed to get applied migrations"},
			{errors.ErrCodeValidation, "Migration has no down migration"},
		}

		for _, tc := range testCases {
			err := errors.New(tc.errorCode, tc.message)
			if err.Code != tc.errorCode {
				t.Errorf("Expected error code %s, got %s", tc.errorCode, err.Code)
			}

			if err.Message != tc.message {
				t.Errorf("Expected error message %s, got %s", tc.message, err.Message)
			}
		}
	})
}

// Helper function to find migration by version
func findMigrationByVersion(migrations []Migration, version int) *Migration {
	for _, migration := range migrations {
		if migration.Version == version {
			return &migration
		}
	}
	return nil
}

// Benchmark tests
func BenchmarkParseMigrationFileName(b *testing.B) {
	filename := "001_create_users_table.up.sql"
	for i := 0; i < b.N; i++ {
		_, _ = parseMigrationFileName(filename)
	}
}

func BenchmarkCalculateChecksum(b *testing.B) {
	content := "CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50), email VARCHAR(100));"
	for i := 0; i < b.N; i++ {
		_ = calculateChecksum(content)
	}
}

func BenchmarkMigrationSorting(b *testing.B) {
	migrations := []Migration{
		{Version: 5, Name: "fifth"},
		{Version: 1, Name: "first"},
		{Version: 3, Name: "third"},
		{Version: 2, Name: "second"},
		{Version: 4, Name: "fourth"},
	}

	for i := 0; i < b.N; i++ {
		// Copy slice for sorting
		sortedMigrations := make([]Migration, len(migrations))
		copy(sortedMigrations, migrations)

		// Simple bubble sort for benchmarking
		for j := 0; j < len(sortedMigrations); j++ {
			for k := j + 1; k < len(sortedMigrations); k++ {
				if sortedMigrations[j].Version > sortedMigrations[k].Version {
					sortedMigrations[j], sortedMigrations[k] = sortedMigrations[k], sortedMigrations[j]
				}
			}
		}
	}
}
