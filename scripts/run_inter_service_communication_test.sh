#!/bin/bash

# Inter-Service Communication Integration Test Runner
# This script runs the inter-service communication integration test

set -e  # Exit on any error

echo "🌐 Inter-Service Communication Integration Test Runner"
echo "======================================================"

# Set test environment variables
setup_environment() {
    echo "🔧 Setting up test environment..."
    
    export JWT_SECRET="test_jwt_secret_key_that_is_long_enough_for_validation_requirements"
    export DATABASE_URL="postgres://test:test@localhost:5432/test_db"
    export LOG_LEVEL="debug"
    export ENVIRONMENT="development"
    
    echo "✅ Environment variables configured"
}

# Run the integration test
run_test() {
    echo "🧪 Running inter-service communication integration test..."
    echo ""
    
    # Change to project root directory
    cd "$(dirname "$0")/.."
    
    # Run the test with verbose output
    if go test -v integration/inter_service_communication_integration_test.go; then
        echo ""
        echo "🎉 Inter-service communication integration test completed successfully!"
        return 0
    else
        echo ""
        echo "❌ Inter-service communication integration test failed!"
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
    setup_environment
    run_test
    
    echo ""
    echo "✅ Inter-service communication test runner completed successfully!"
}

# Show help
show_help() {
    echo "Inter-Service Communication Integration Test Runner"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo ""
    echo "Requirements:"
    echo "  - Go 1.21+ installed"
    echo "  - Project dependencies available"
    echo ""
    echo "This test will:"
    echo "  ✓ Create mock microservices (user, post, notification)"
    echo "  ✓ Test service-to-service authentication with JWT tokens"
    echo "  ✓ Test request correlation and ID propagation"
    echo "  ✓ Test cross-service communication chains"
    echo "  ✓ Test error handling across service boundaries"
    echo "  ✓ Test health check communication"
    echo "  ✓ Test retry logic for failed requests"
    echo "  ✓ Test rate limiting between services"
    echo "  ✓ Test service discovery simulation"
    echo "  ✓ Verify comprehensive structured logging"
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