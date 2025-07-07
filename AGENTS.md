# Agent Guidelines for Library Project

## Build/Test Commands
- **All tests**: `./scripts/run_all_tests.sh`
- **Unit tests only**: `go test ./pkg/...` or `./scripts/run_all_tests.sh --unit-only`
- **Single test file**: `go test -v path/to/test_file.go`
- **Integration tests**: `./scripts/run_all_tests.sh --integration-only`
- **Database tests**: `./scripts/run_all_tests.sh --database-only`
- **Skip database tests**: `SKIP_DATABASE_TESTS=true ./scripts/run_all_tests.sh`

## Code Style Guidelines
- **Package structure**: Follow `pkg/` organization with clear separation of concerns
- **Imports**: Group standard library, third-party, then local imports with blank lines
- **Naming**: Use camelCase for variables/functions, PascalCase for exported types
- **Error handling**: Use structured errors from `pkg/errors` with proper error codes
- **Types**: Define request/response structs in `pkg/models` with JSON/validation tags
- **Constants**: Group related constants with descriptive names (e.g., `ErrCodeValidation`)
- **Comments**: Document exported functions/types; use `//` for single-line comments
- **Testing**: Use testify for assertions; separate unit and integration tests
- **JSON tags**: Always include JSON tags for structs; use `"-"` for sensitive fields
- **Validation**: Use Gin binding tags for request validation (e.g., `binding:"required"`)
- **Context**: Pass context.Context as first parameter for database/HTTP operations
- **Middleware**: Chain middleware in logical order (logging, auth, CORS, etc.)