#!/bin/bash

# Script to run the authentication, logging, and config integration test
# This demonstrates the complete integration between all three packages

set -e

echo "🚀 Running Authentication, Logging, and Config Integration Test"
echo "=============================================================="

# Set up test environment variables
export JWT_SECRET="test_jwt_secret_key_that_is_long_enough_for_validation_requirements"
export DATABASE_URL="postgres://test:test@localhost:5432/test_db"
export LOG_LEVEL="debug"
export ENVIRONMENT="development"
export REDIS_URL="redis://localhost:6379/1"

echo "✅ Environment variables set for testing"

# Run the integration test
echo "📋 Running integration test..."

# Option 1: Run as a Go test
echo "Running as Go test..."
cd "$(dirname "$0")/.."
go test -v integration/auth_logging_config_integration_test.go

# Option 2: Run as standalone executable (commented out)
# echo "Running as standalone executable..."
# go run integration/auth_logging_config_integration_test.go

echo ""
echo "🎉 Integration test completed successfully!"
echo ""
echo "This test verified:"
echo "  ✅ Configuration package loads settings correctly"
echo "  ✅ Authentication package uses config settings"
echo "  ✅ Logging package captures authentication events"
echo "  ✅ HTTP middleware integrates all packages seamlessly"
echo "  ✅ Error handling works across package boundaries"
echo "  ✅ Token storage integrates with auth and logging" 