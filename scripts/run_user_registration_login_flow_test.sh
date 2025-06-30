#!/bin/bash

# User Registration/Login Flow Integration Test Runner
# This script runs the complete user registration and login flow integration test

set -e  # Exit on any error

echo "👤 User Registration/Login Flow Integration Test Runner"
echo "======================================================="

# Check if PostgreSQL is running
check_postgres() {
    echo "🔍 Checking PostgreSQL availability..."
    
    # Try to connect to PostgreSQL
    if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        echo "❌ PostgreSQL is not running on localhost:5432"
        echo ""
        echo "To start PostgreSQL:"
        echo "  - Using Docker: docker run --name postgres-test -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres"
        echo "  - Using system service: sudo service postgresql start"
        echo "  - Using Homebrew (macOS): brew services start postgresql"
        echo ""
        exit 1
    fi
    
    echo "✅ PostgreSQL is available"
}

# Set test environment variables
setup_environment() {
    echo "🔧 Setting up test environment..."
    
    export DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres"
    export JWT_SECRET="test_jwt_secret_key_that_is_long_enough_for_validation_requirements"
    export LOG_LEVEL="debug"
    export ENVIRONMENT="development"
    export SKIP_DB_TESTS="false"
    
    echo "✅ Environment variables configured"
}

# Run the integration test
run_test() {
    echo "🧪 Running user registration/login flow integration test..."
    echo ""
    
    # Change to project root directory
    cd "$(dirname "$0")/.."
    
    # Run the test with verbose output
    if go test -v integration/user_registration_login_flow_integration_test.go; then
        echo ""
        echo "🎉 User registration/login flow integration test completed successfully!"
        return 0
    else
        echo ""
        echo "❌ User registration/login flow integration test failed!"
        return 1
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    # Any cleanup if needed
}

# Main execution
main() {
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Run all steps
    check_postgres
    setup_environment
    run_test
    
    echo ""
    echo "✅ User registration/login flow test runner completed successfully!"
}

# Show help
show_help() {
    echo "User Registration/Login Flow Integration Test Runner"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --skip-checks  Skip PostgreSQL availability check"
    echo ""
    echo "Requirements:"
    echo "  - PostgreSQL running on localhost:5432"
    echo "  - Go 1.21+ installed"
    echo "  - Project dependencies available"
    echo ""
    echo "This test will:"
    echo "  ✓ Load configuration from environment variables"
    echo "  ✓ Set up structured logging with buffer capture"
    echo "  ✓ Create isolated test database with users table"
    echo "  ✓ Test complete user registration flow with validation"
    echo "  ✓ Test user login flow with JWT token generation"
    echo "  ✓ Test password hashing and verification using pkg/auth"
    echo "  ✓ Test protected endpoint access with authentication"
    echo "  ✓ Test refresh token functionality"
    echo "  ✓ Test comprehensive input validation and error handling"
    echo "  ✓ Test database operations using pkg/database"
    echo "  ✓ Verify all shared packages working together"
    echo "  ✓ Verify structured logging throughout the process"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --skip-checks)
        echo "🔍 Skipping PostgreSQL availability check..."
        setup_environment
        run_test
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