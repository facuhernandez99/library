#!/bin/bash

# Database Setup Script for Integration Tests
# This script sets up PostgreSQL for running database-dependent tests

set -e

echo "🗄️  Database Setup for Integration Tests"
echo "========================================"

# Configuration
DB_NAME="postgres"
DB_USER="postgres"
DB_PASSWORD="postgres"
DB_PORT="5432"
CONTAINER_NAME="postgres-test"

# Function to check if PostgreSQL is running
check_postgres_running() {
    if docker ps | grep -q $CONTAINER_NAME; then
        echo "✅ PostgreSQL container is already running"
        return 0
    else
        return 1
    fi
}

# Function to check if PostgreSQL is accessible
check_postgres_accessible() {
    if docker exec $CONTAINER_NAME pg_isready -h localhost -p $DB_PORT > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to start PostgreSQL
start_postgres() {
    echo "🚀 Using existing PostgreSQL container..."
    
    # Check if container exists and is running
    if ! docker ps | grep -q $CONTAINER_NAME; then
        echo "🚀 Starting PostgreSQL container..."
        
        # Remove existing container if it exists but stopped
        docker rm -f $CONTAINER_NAME 2>/dev/null || true
        
        # Start new PostgreSQL container
        docker run --name $CONTAINER_NAME \
            -e POSTGRES_DB=$DB_NAME \
            -e POSTGRES_USER=$DB_USER \
            -e POSTGRES_PASSWORD=$DB_PASSWORD \
            -p $DB_PORT:5432 \
            -d postgres:14
    fi
    
    echo "⏳ Waiting for PostgreSQL to be ready..."
    
    # Wait for PostgreSQL to be ready
    for i in {1..30}; do
        if check_postgres_accessible; then
            echo "✅ PostgreSQL is ready!"
            return 0
        fi
        echo "   Waiting... (attempt $i/30)"
        sleep 2
    done
    
    echo "❌ PostgreSQL failed to start properly"
    return 1
}

# Function to create test database and user
setup_database() {
    echo "🔧 Setting up test database..."
    
    # Create additional test database if needed
    docker exec $CONTAINER_NAME psql -U $DB_USER -d $DB_NAME -c "CREATE DATABASE library_integration_test;" 2>/dev/null || true
    
    echo "✅ Database setup completed"
}

# Function to set environment variables
set_env_vars() {
    echo "🌍 Setting environment variables..."
    
    export DATABASE_URL="postgres://$DB_USER:$DB_PASSWORD@localhost:$DB_PORT/$DB_NAME?sslmode=disable"
    export TEST_DATABASE_URL="postgres://$DB_USER:$DB_PASSWORD@localhost:$DB_PORT/library_integration_test?sslmode=disable"
    export POSTGRES_HOST="localhost"
    export POSTGRES_PORT="$DB_PORT"
    export POSTGRES_USER="$DB_USER"
    export POSTGRES_PASSWORD="$DB_PASSWORD"
    export POSTGRES_DB="$DB_NAME"
    
    # Additional test environment variables
    export JWT_SECRET="test_jwt_secret_key_that_is_long_enough_for_validation_requirements"
    export LOG_LEVEL="debug"
    export ENVIRONMENT="test"
    export REDIS_URL="redis://localhost:6379/1"
    export SKIP_DB_TESTS="false"
    
    echo "✅ Environment variables set"
    echo "   DATABASE_URL: $DATABASE_URL"
    echo "   TEST_DATABASE_URL: $TEST_DATABASE_URL"
}

# Function to verify database connection
verify_connection() {
    echo "🔍 Verifying database connection..."
    
    if docker exec $CONTAINER_NAME psql -U $DB_USER -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1; then
        echo "✅ Database connection verified"
        return 0
    else
        echo "❌ Database connection failed"
        return 1
    fi
}

# Function to show connection info
show_info() {
    echo ""
    echo "📋 Database Information:"
    echo "   Host: localhost"
    echo "   Port: $DB_PORT"
    echo "   Database: $DB_NAME"
    echo "   User: $DB_USER"
    echo "   Password: $DB_PASSWORD"
    echo ""
    echo "🔗 Connection Commands:"
    echo "   psql: docker exec -it $CONTAINER_NAME psql -U $DB_USER -d $DB_NAME"
    echo "   Stop: docker stop $CONTAINER_NAME"
    echo "   Remove: docker rm $CONTAINER_NAME"
    echo ""
}

# Function to cleanup
cleanup() {
    echo ""
    echo "🧹 To cleanup later, run:"
    echo "   docker stop $CONTAINER_NAME"
    echo "   docker rm $CONTAINER_NAME"
}

# Main execution
main() {
    echo "🔍 Checking Docker availability..."
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed or not in PATH"
        echo "   Please install Docker to run database tests"
        exit 1
    fi
    
    echo "✅ Docker is available"
    
    # Check if PostgreSQL is already running
    if check_postgres_running && check_postgres_accessible; then
        echo "🔄 PostgreSQL is already running and accessible"
    else
        # Start PostgreSQL
        if ! start_postgres; then
            echo "❌ Failed to start PostgreSQL"
            exit 1
        fi
    fi
    
    # Setup database
    setup_database
    
    # Set environment variables
    set_env_vars
    
    # Verify connection
    if ! verify_connection; then
        echo "❌ Database verification failed"
        exit 1
    fi
    
    # Show information
    show_info
    
    echo "🎉 Database setup completed successfully!"
    echo ""
    echo "You can now run database-dependent tests:"
    echo "   bash scripts/run_database_integration_test.sh"
    echo "   bash scripts/run_user_registration_login_flow_test.sh"
    echo "   bash scripts/run_migration_workflow_test.sh"
}

# Show help
show_help() {
    echo "Database Setup Script for Integration Tests"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --cleanup      Stop and remove the database container"
    echo "  --status       Check database status"
    echo ""
    echo "This script will:"
    echo "  ✓ Start PostgreSQL in a Docker container"
    echo "  ✓ Create test databases"
    echo "  ✓ Set up environment variables"
    echo "  ✓ Verify database connectivity"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --cleanup)
        echo "🧹 Cleaning up database container..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
        echo "✅ Cleanup completed"
        exit 0
        ;;
    --status)
        echo "🔍 Checking database status..."
        if check_postgres_running; then
            if check_postgres_accessible; then
                echo "✅ PostgreSQL is running and accessible"
                docker exec $CONTAINER_NAME psql -U $DB_USER -d $DB_NAME -c "SELECT version();"
            else
                echo "⚠️  PostgreSQL container is running but not accessible"
            fi
        else
            echo "❌ PostgreSQL container is not running"
        fi
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