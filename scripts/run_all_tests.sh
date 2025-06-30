#!/bin/bash

# Master Test Runner Script
# Runs all tests in the project: unit tests, integration tests, and database tests

set -e

echo "🧪 Blog Project - Master Test Runner"
echo "===================================="

# Configuration
LOGS_DIR="logs"
FAILED_TESTS=()
PASSED_TESTS=()
SKIPPED_TESTS=()

# Create logs directory
mkdir -p "$LOGS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log test results
log_test_result() {
    local test_name="$1"
    local status="$2"
    local duration="$3"
    
    case $status in
        "PASSED")
            PASSED_TESTS+=("$test_name ($duration)")
            echo -e "${GREEN}✅ $test_name - PASSED${NC} ($duration)"
            ;;
        "FAILED")
            FAILED_TESTS+=("$test_name ($duration)")
            echo -e "${RED}❌ $test_name - FAILED${NC} ($duration)"
            ;;
        "SKIPPED")
            SKIPPED_TESTS+=("$test_name")
            echo -e "${YELLOW}⏭️  $test_name - SKIPPED${NC}"
            ;;
    esac
}

# Function to run unit tests
run_unit_tests() {
    echo -e "\n${BLUE}📋 Phase 1: Unit Tests${NC}"
    echo "========================"
    
    local start_time=$(date +%s)
    
    if go test ./pkg/... -v > "$LOGS_DIR/unit_tests.log" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_test_result "Unit Tests" "PASSED" "${duration}s"
        echo "   📝 Detailed log: $LOGS_DIR/unit_tests.log"
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_test_result "Unit Tests" "FAILED" "${duration}s"
        echo "   📝 Error log: $LOGS_DIR/unit_tests.log"
        echo "   🔍 Last few lines of log:"
        tail -10 "$LOGS_DIR/unit_tests.log"
        return 1
    fi
}

# Function to run standalone integration tests
run_standalone_integration_tests() {
    echo -e "\n${BLUE}📋 Phase 2: Standalone Integration Tests${NC}"
    echo "=========================================="
    
    local tests=(
        "Auth, Logging & Config Integration:integration/auth_logging_config_integration_test.go"
        "HTTP Middleware Stack Integration:integration/http_middleware_stack_integration_test.go"
        "Request Lifecycle Integration:integration/request_lifecycle_integration_test.go"
        "Inter-Service Communication:integration/inter_service_communication_integration_test.go"
        "Error Boundary Comprehensive:integration/error_boundary_comprehensive_test.go"
    )
    
    for test_info in "${tests[@]}"; do
        local test_name=$(echo "$test_info" | cut -d: -f1)
        local test_file=$(echo "$test_info" | cut -d: -f2)
        
        echo -e "\n🧪 Running: $test_name"
        local start_time=$(date +%s)
        
        local log_file="$LOGS_DIR/${test_name// /_}.log"
        if go test -v "$test_file" > "$log_file" 2>&1; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            log_test_result "$test_name" "PASSED" "${duration}s"
        else
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            log_test_result "$test_name" "FAILED" "${duration}s"
            echo "   📝 Error log: $log_file"
            echo "   🔍 Last few lines of log:"
            tail -5 "$log_file"
        fi
    done
}

# Function to setup and run database tests
run_database_tests() {
    echo -e "\n${BLUE}📋 Phase 3: Database Integration Tests${NC}"
    echo "======================================="
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_test_result "Database Tests" "SKIPPED"
        echo "   ⚠️  Docker not available - database tests skipped"
        return 0
    fi
    
    # Setup database
    echo "🔧 Setting up test database..."
    if ! bash scripts/setup_database_for_tests.sh > "$LOGS_DIR/database_setup.log" 2>&1; then
        log_test_result "Database Tests" "FAILED" "setup"
        echo "   📝 Setup error log: $LOGS_DIR/database_setup.log"
        echo "   🔍 Last few lines of setup log:"
        tail -5 "$LOGS_DIR/database_setup.log"
        return 1
    fi
    
    echo "✅ Database setup completed"
    
    # Database test scripts
    local db_tests=(
        "Database Config & Logging:scripts/run_database_integration_test.sh"
        "Migration Workflow:scripts/run_migration_workflow_test.sh"
        "User Registration & Login:scripts/run_user_registration_login_flow_test.sh"
    )
    
    for test_info in "${db_tests[@]}"; do
        local test_name=$(echo "$test_info" | cut -d: -f1)
        local test_script=$(echo "$test_info" | cut -d: -f2)
        
        echo -e "\n🧪 Running: $test_name"
        local start_time=$(date +%s)
        
        local log_file="$LOGS_DIR/${test_name// /_}.log"
        if bash "$test_script" > "$log_file" 2>&1; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            log_test_result "$test_name" "PASSED" "${duration}s"
        else
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            log_test_result "$test_name" "FAILED" "${duration}s"
            echo "   📝 Error log: $log_file"
            echo "   🔍 Last few lines of log:"
            tail -5 "$log_file"
        fi
    done
}

# Function to generate test report
generate_report() {
    echo -e "\n${BLUE}📊 Test Summary Report${NC}"
    echo "======================"
    
    local total_tests=$((${#PASSED_TESTS[@]} + ${#FAILED_TESTS[@]} + ${#SKIPPED_TESTS[@]}))
    
    echo -e "\n📈 Overall Statistics:"
    echo "   Total Tests: $total_tests"
    echo -e "   ${GREEN}Passed: ${#PASSED_TESTS[@]}${NC}"
    echo -e "   ${RED}Failed: ${#FAILED_TESTS[@]}${NC}"
    echo -e "   ${YELLOW}Skipped: ${#SKIPPED_TESTS[@]}${NC}"
    
    if [ ${#PASSED_TESTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ Passed Tests:${NC}"
        for test in "${PASSED_TESTS[@]}"; do
            echo "   ✓ $test"
        done
    fi
    
    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo -e "\n${RED}❌ Failed Tests:${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            echo "   ✗ $test"
        done
    fi
    
    if [ ${#SKIPPED_TESTS[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}⏭️  Skipped Tests:${NC}"
        for test in "${SKIPPED_TESTS[@]}"; do
            echo "   - $test"
        done
    fi
    
    # Calculate success rate
    if [ $total_tests -gt 0 ]; then
        local success_rate=$(( (${#PASSED_TESTS[@]} * 100) / total_tests ))
        echo -e "\n📊 Success Rate: ${success_rate}%"
        
        if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
            echo -e "\n${GREEN}🎉 All tests passed successfully!${NC}"
            return 0
        else
            echo -e "\n${RED}❌ Some tests failed. Check the logs above for details.${NC}"
            return 1
        fi
    fi
}

# Function to cleanup
cleanup() {
    echo -e "\n🧹 Cleanup"
    echo "=========="
    
    # List generated log files
    echo "📝 Generated log files in $LOGS_DIR/:"
    if [ -d "$LOGS_DIR" ]; then
        for log_file in "$LOGS_DIR"/*.log; do
            if [ -f "$log_file" ]; then
                echo "   - $(basename "$log_file")"
            fi
        done
    fi
    
    # Cleanup options
    echo ""
    echo "🔧 Cleanup options:"
    echo "   Remove logs: rm -rf $LOGS_DIR/*.log"
    echo "   Remove logs dir: rm -rf $LOGS_DIR"
    echo "   Stop database: bash scripts/setup_database_for_tests.sh --cleanup"
}

# Main execution function
main() {
    local start_time=$(date +%s)
    
    echo "🚀 Starting comprehensive test suite..."
    echo "   Timestamp: $(date)"
    echo "   Working Directory: $(pwd)"
    echo ""
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    local overall_success=true
    
    # Phase 1: Unit Tests
    if ! run_unit_tests; then
        overall_success=false
    fi
    
    # Phase 2: Standalone Integration Tests
    run_standalone_integration_tests
    
    # Phase 3: Database Tests (only if requested)
    if [ "${SKIP_DATABASE_TESTS:-false}" != "true" ]; then
        run_database_tests
    else
        log_test_result "Database Tests" "SKIPPED"
        echo "   ⚠️  Database tests skipped (SKIP_DATABASE_TESTS=true)"
    fi
    
    # Generate final report
    if ! generate_report; then
        overall_success=false
    fi
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    echo -e "\n⏱️  Total Duration: ${total_duration}s"
    
    if [ "$overall_success" = true ]; then
        echo -e "\n${GREEN}🎯 Test suite completed successfully!${NC}"
        exit 0
    else
        echo -e "\n${RED}❌ Test suite completed with failures!${NC}"
        exit 1
    fi
}

# Show help
show_help() {
    echo "Blog Project Master Test Runner"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  --unit-only         Run only unit tests"
    echo "  --integration-only  Run only integration tests"
    echo "  --database-only     Run only database tests"
    echo "  --skip-database     Skip database tests"
    echo ""
    echo "Environment Variables:"
    echo "  SKIP_DATABASE_TESTS=true    Skip database tests"
    echo ""
    echo "This script will:"
    echo "  ✓ Run all unit tests (pkg/...)"
    echo "  ✓ Run standalone integration tests"
    echo "  ✓ Set up PostgreSQL for database tests"
    echo "  ✓ Run database integration tests"
    echo "  ✓ Generate comprehensive test report"
    echo "  ✓ Create detailed logs for debugging"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --unit-only)
        echo "🧪 Running unit tests only..."
        run_unit_tests
        generate_report
        ;;
    --integration-only)
        echo "🧪 Running integration tests only..."
        run_standalone_integration_tests
        generate_report
        ;;
    --database-only)
        echo "🧪 Running database tests only..."
        run_database_tests
        generate_report
        ;;
    --skip-database)
        echo "🧪 Running all tests except database tests..."
        export SKIP_DATABASE_TESTS=true
        main
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