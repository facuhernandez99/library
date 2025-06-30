#!/bin/bash

# Database Configuration and Logging Integration Test Runner
# This script runs integration tests that require PostgreSQL

set -e

echo "🗄️  Database Configuration and Logging Integration Test Runner"
echo "============================================================="

# Function to setup database
setup_database() {
    echo "🔧 Setting up database for testing..."
    
    # Run the database setup script
    if ! bash "$(dirname "$0")/setup_database_for_tests.sh"; then
        echo "❌ Database setup failed"
        exit 1
    fi
    
    echo "✅ Database setup completed"
}

# Function to check PostgreSQL availability
check_postgres() {
    echo "🔍 Checking PostgreSQL availability..."
    
    # Try to connect to PostgreSQL
    if docker exec postgres-test pg_isready -h localhost -p 5432 > /dev/null 2>&1; then
        echo "✅ PostgreSQL is running and accessible"
        return 0
    else
        echo "❌ PostgreSQL is not accessible"
        return 1
    fi
}

# Function to run the integration test
run_test() {
    echo "🧪 Running database configuration and logging integration test..."
    echo ""
    
    # Change to project root directory
    cd "$(dirname "$0")/.."
    
    # Set test environment variables (should already be set by setup script)
    export SKIP_DB_TESTS="false"
    
    # Run the test with verbose output
    if go test -v integration/database_config_logging_integration_test.go; then
        echo ""
        echo "🎉 Database integration test completed successfully!"
        return 0
    else
        echo ""
        echo "❌ Database integration test failed!"
        return 1
    fi
}

# Function to cleanup
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    echo "   Database container will remain running for other tests"
    echo "   To stop database: bash scripts/setup_database_for_tests.sh --cleanup"
}

# Main execution
main() {
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Setup database
    setup_database
    
    # Check PostgreSQL
    if ! check_postgres; then
        echo "❌ PostgreSQL check failed"
        exit 1
    fi
    
    # Run test
    run_test
    
    echo ""
    echo "✅ Database integration test runner completed successfully!"
}

# Show help
show_help() {
    echo "Database Configuration and Logging Integration Test Runner"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo ""
    echo "Requirements:"
    echo "  - Docker installed and running"
    echo "  - Go 1.21+ installed"
    echo ""
    echo "This test will:"
    echo "  ✓ Set up PostgreSQL in Docker container"
    echo "  ✓ Test database connection and configuration"
    echo "  ✓ Test logging integration with database operations"
    echo "  ✓ Test error handling in database operations"
    echo "  ✓ Test structured logging for database events"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo "❌ Unknown option: $1"
        echo "Use -h or --help for usage information"
        exit 1
        ;;
esac 