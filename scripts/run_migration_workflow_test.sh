#!/bin/bash

# Database Migration Workflow Integration Test Script
# This script runs the comprehensive database migration workflow integration test

set -e

echo "🚀 Database Migration Workflow Integration Test Runner"
echo "======================================================"

# Check if PostgreSQL is running
echo "📋 Checking PostgreSQL availability..."
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL client (psql) not found. Please install PostgreSQL."
    exit 1
fi

# Test database connection
if ! timeout 5 bash -c "echo 'SELECT 1;' | psql postgres://postgres:postgres@localhost:5432/postgres" &> /dev/null; then
    echo "❌ Cannot connect to PostgreSQL database."
    echo "   Please ensure PostgreSQL is running with:"
    echo "   - Host: localhost"
    echo "   - Port: 5432"
    echo "   - User: postgres"
    echo "   - Password: postgres"
    echo "   - Database: postgres"
    exit 1
fi

echo "✅ PostgreSQL is available and accessible"

# Set up environment for the test
echo "🔧 Setting up test environment..."
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres"
export JWT_SECRET="test_migration_jwt_secret_key_for_comprehensive_workflow_testing"
export LOG_LEVEL="debug"
export ENVIRONMENT="development"
export REDIS_URL="redis://localhost:6379/2"

echo "✅ Environment variables configured"

# Change to project root
cd "$(dirname "$0")/.."

echo "📁 Working directory: $(pwd)"

# Run the migration workflow integration test
echo "🧪 Running Database Migration Workflow Integration Test..."
echo "========================================================"

if go test -v integration/database_migration_workflow_integration_test.go; then
    echo ""
    echo "✅ Database Migration Workflow Integration Test PASSED!"
    echo ""
    echo "🎉 Test Summary:"
    echo "   ✅ Configuration management with environment variables"
    echo "   ✅ Structured logging integration with migration operations"
    echo "   ✅ Database connection using configuration"
    echo "   ✅ Migration system initialization with custom logger"
    echo "   ✅ Migration application workflow (MigrateUp)"
    echo "   ✅ Migration status reporting and validation"
    echo "   ✅ Migration rollback workflow (MigrateDown)"
    echo "   ✅ Comprehensive logging throughout all operations"
    echo ""
    echo "🔍 This test demonstrates:"
    echo "   • Integration of pkg/config, pkg/logging, and pkg/database packages"
    echo "   • Real-world migration scenarios with proper error handling"
    echo "   • Structured logging with contextual information"
    echo "   • Configuration-driven database operations"
    echo ""
    exit 0
else
    echo ""
    echo "❌ Database Migration Workflow Integration Test FAILED!"
    echo ""
    echo "🔍 Troubleshooting tips:"
    echo "   1. Ensure PostgreSQL is running and accessible"
    echo "   2. Check database connection parameters"
    echo "   3. Verify all required environment variables are set"
    echo "   4. Check for any database permission issues"
    echo "   5. Review the test output for specific error messages"
    echo ""
    exit 1
fi 