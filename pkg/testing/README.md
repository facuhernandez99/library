# Testing Infrastructure

This package provides comprehensive testing utilities for the blog microservice, including HTTP test helpers, database utilities, mock implementations, and integration test frameworks.

## Overview

The testing infrastructure consists of four main components:

1. **HTTP Test Helpers** (`http_helpers.go`) - Utilities for API testing
2. **Database Test Utilities** (`database_helpers.go`) - Database setup/teardown and fixtures
3. **Mock Implementations** (`mocks.go`) - Mock objects for external dependencies
4. **Integration Test Framework** (`integration_framework.go`) - Complete integration testing framework

## Quick Start

### HTTP API Testing

```go
func TestUserAPI(t *testing.T) {
    helper := testing.NewHTTPTestHelper(t)
    
    // Setup routes
    helper.Router.POST("/users", userHandler)
    
    // Test creating a user
    user := map[string]interface{}{
        "username": "testuser",
        "password": "password123",
    }
    
    resp := helper.POST("/users", user)
    resp.AssertStatusCode(t, http.StatusCreated)
    resp.AssertSuccess(t)
    resp.AssertHasData(t)
}
```

### Database Testing

```go
func TestUserRepository(t *testing.T) {
    dbHelper, cleanup := testing.SetupTestDatabase(t)
    defer cleanup()
    
    // Create test users
    user := dbHelper.Seed().User()
    assert.NotZero(t, user.ID)
    
    // Verify database state
    dbHelper.AssertRowCount("users", 1)
}
```

### Integration Testing

```go
func TestUserWorkflow(t *testing.T) {
    testing.RunIntegrationTest(t, "user_signup_workflow", func(ctx *testing.IntegrationTestContext) {
        // Setup
        ctx.HTTPHelper.Router.POST("/signup", signupHandler)
        
        // Execute
        resp := ctx.HTTPHelper.POST("/signup", userRequest)
        resp.AssertStatusCode(ctx.T(), http.StatusCreated)
        
        // Verify database state
        if ctx.DBHelper != nil {
            ctx.DBHelper.AssertRowCount("users", 1)
        }
    })
}
```

## HTTP Test Helpers

### Creating HTTP Test Helper

```go
helper := testing.NewHTTPTestHelper(t)
```

### Making HTTP Requests

```go
// GET request
resp := helper.GET("/api/users")

// POST request with JSON body
resp := helper.POST("/api/users", userCreateRequest)

// PUT request
resp := helper.PUT("/api/users/123", userUpdateRequest)

// DELETE request
resp := helper.DELETE("/api/users/123")

// PATCH request
resp := helper.PATCH("/api/users/123", partialUpdate)

// With query parameters
resp := helper.GET("/api/users", map[string]string{
    "page":  "1",
    "limit": "10",
})
```

### Authentication

```go
// Create authenticated helper
authHelper := helper.WithAuth("your-jwt-token")

// Make authenticated requests
resp := authHelper.GET("/api/profile")
resp := authHelper.POST("/api/posts", newPost)
```

### Response Validation

```go
// Status code validation
resp.AssertStatusCode(t, http.StatusOK)

// Success response validation
resp.AssertSuccess(t)

// Error response validation
resp.AssertError(t, "Expected error message")

// Data presence validation
resp.AssertHasData(t)

// Specific field validation
resp.AssertDataField(t, "username", "expected_username")

// Pagination validation
resp.AssertPagination(t, 1, 20, 100) // page, limit, total

// Header validation
resp.AssertHeaderPresent(t, "Content-Type")
resp.AssertHeaderValue(t, "Content-Type", "application/json")
```

### Response Data Access

```go
// Get data as interface{}
data := resp.GetData()

// Get data as map
dataMap := resp.GetDataAsMap()

// Get data as array
dataArray := resp.GetDataAsArray()

// Get error message
errorMsg := resp.GetError()

// Bind response to struct
var user models.UserResponse
err := resp.BindResponseTo(&user)

// Bind data field to struct
var userData models.User
err := resp.BindDataTo(&userData)
```

## Database Test Utilities

### Setup and Teardown

```go
// Manual setup/teardown
dbHelper := testing.NewDatabaseTestHelper(t)
dbHelper.Setup()
defer dbHelper.Teardown()

// Automatic setup/teardown
dbHelper, cleanup := testing.SetupTestDatabase(t)
defer cleanup()
```

### Database Operations

```go
// Execute SQL
result := dbHelper.Exec("INSERT INTO users (username) VALUES ($1)", "testuser")

// Query multiple rows
rows := dbHelper.Query("SELECT * FROM users WHERE active = true")

// Query single row
row := dbHelper.QueryRow("SELECT id FROM users WHERE username = $1", "testuser")

// Truncate tables
dbHelper.Truncate("users", "posts")
dbHelper.TruncateAll()
```

### Test Data Creation

```go
// Create single user
user := dbHelper.Seed().User()

// Create user with custom data
user := dbHelper.Seed().User(map[string]interface{}{
    "username": "customuser",
    "password_hash": "custom-hash",
})

// Create multiple users
users := dbHelper.Seed().Users(5)
```

### Database Assertions

```go
// Assert row count
dbHelper.AssertRowCount("users", 3)

// Assert table exists
dbHelper.AssertTableExists("users")

// Assert column exists
dbHelper.AssertColumnExists("users", "username")
```

### Transaction Testing

```go
// Test within transaction (auto-rollback)
dbHelper.WithTransaction(func(txHelper *testing.TransactionTestHelper) {
    txHelper.Exec("INSERT INTO users (username) VALUES ($1)", "testuser")
    // Transaction will be rolled back automatically
})

// Manual transaction control
txHelper := dbHelper.BeginTransaction()
txHelper.Exec("INSERT INTO users (username) VALUES ($1)", "testuser")
txHelper.Commit() // or txHelper.Rollback()
```

## Mock Implementations

### Token Storage Mock

```go
mockStorage := testing.CreateMockTokenStorage()

// Customize behavior
mockStorage.On("IsBlacklisted", "token123").Return(true, nil)

// Use in tests
isBlacklisted, err := mockStorage.IsBlacklisted("token123")
assert.True(t, isBlacklisted)

// Verify expectations
mockStorage.AssertExpectations(t)
```

### User Repository Mock

```go
mockRepo := testing.CreateMockUserRepository()

// Setup expectations
user := testing.NewUserBuilder().WithUsername("testuser").Build()
mockRepo.On("GetByID", int64(1)).Return(user, nil)

// Use in tests
retrievedUser, err := mockRepo.GetByID(1)
assert.Equal(t, "testuser", retrievedUser.Username)
```

### Test Data Builders

```go
// Build test user
user := testing.NewUserBuilder().
    WithUsername("testuser").
    WithPasswordHash("hash").
    WithID(123).
    Build()

// Error scenarios
errorBuilder := testing.NewErrorBuilder().
    WithDatabaseError()

if errorBuilder.ShouldFail() {
    return errorBuilder.Error()
}
```

## Integration Test Framework

### Test Suite Approach

```go
type MyIntegrationTestSuite struct {
    testing.IntegrationTestSuite
}

func (suite *MyIntegrationTestSuite) TestUserWorkflow() {
    // HTTP helper is available as suite.HTTPHelper
    // Database helper is available as suite.DBHelper (if enabled)
    
    suite.HTTPHelper.Router.GET("/test", testHandler)
    resp := suite.HTTPHelper.GET("/test")
    resp.AssertSuccess(suite.T())
}

func TestMyIntegrationSuite(t *testing.T) {
    suite.Run(t, new(MyIntegrationTestSuite))
}
```

### Test Runner Approach

```go
func TestUserSignup(t *testing.T) {
    config := &testing.IntegrationTestConfig{
        DatabaseEnabled:   true,
        VerboseLogging:    true,
        TestTimeout:       30 * time.Second,
    }
    
    runner := testing.NewIntegrationTestRunner(t, config)
    runner.Run("signup_workflow", func(ctx *testing.IntegrationTestContext) {
        // Test implementation
        ctx.Log("Starting user signup test")
        
        // Setup HTTP routes
        ctx.HTTPHelper.Router.POST("/signup", signupHandler)
        
        // Test signup
        resp := ctx.HTTPHelper.POST("/signup", signupRequest)
        resp.AssertStatusCode(ctx.T(), http.StatusCreated)
        
        // Verify database
        ctx.RequireDB().AssertRowCount("users", 1)
    })
}
```

### Scenario-Based Testing

```go
testing.RunIntegrationTest(t, "user_lifecycle", func(ctx *testing.IntegrationTestContext) {
    scenario := testing.TestScenario{
        Name: "User Signup and Login",
        Setup: func(ctx *testing.IntegrationTestContext) error {
            // Setup routes and test data
            return nil
        },
        Execute: func(ctx *testing.IntegrationTestContext) error {
            // Execute the test scenario
            return nil
        },
        Verify: func(ctx *testing.IntegrationTestContext) error {
            // Verify the results
            return nil
        },
        Cleanup: func(ctx *testing.IntegrationTestContext) error {
            // Clean up test data
            return nil
        },
    }
    
    ctx.RunScenario(scenario)
})
```

### Utility Functions

```go
// Wait for conditions
ctx.WaitForCondition(func() bool {
    return someCondition()
}, 5*time.Second, "waiting for condition")

// Retry operations
err := ctx.Retry(func() error {
    return flakyOperation()
}, 3, 100*time.Millisecond)

// Conditional database operations
ctx.SkipIfNoDatabase() // Skip test if DB not available
dbHelper := ctx.RequireDB() // Require DB or fail test
```

## Configuration

### Environment Variables

- `SKIP_DB_TESTS=true` - Skip database tests
- `SKIP_INTEGRATION_TESTS=true` - Skip integration tests
- `TEST_DB_HOST` - Test database host
- `TEST_DB_PORT` - Test database port
- `TEST_DB_USERNAME` - Test database username
- `TEST_DB_PASSWORD` - Test database password
- `TEST_DB_DATABASE` - Test database name

### Test Database Configuration

The test infrastructure automatically creates isolated test databases with unique names. The database configuration can be customized via environment variables:

```bash
export TEST_DB_HOST="localhost"
export TEST_DB_PORT="5432"
export TEST_DB_USERNAME="test_user"
export TEST_DB_PASSWORD="test_password"
export TEST_DB_DATABASE="blog_test"
```

## Best Practices

### 1. Test Isolation

- Each test should be independent and not rely on other tests
- Use database transactions or truncation between tests
- Reset HTTP routes between tests

### 2. Test Data Management

- Use the seed utilities to create consistent test data
- Use builders for complex test objects
- Clean up test data after tests complete

### 3. Mocking

- Mock external dependencies (APIs, services)
- Use the provided mock factories for common scenarios
- Verify mock expectations in tests

### 4. Integration Tests

- Test complete workflows, not just individual functions
- Include both success and failure scenarios
- Test error handling and edge cases

### 5. Performance

- Use parallel execution for independent tests
- Minimize database operations in unit tests
- Use appropriate timeouts for integration tests

## Examples

### Complete API Test

```go
func TestUserAPIComplete(t *testing.T) {
    helper := testing.NewHTTPTestHelper(t)
    
    // Setup routes
    helper.Router.POST("/users", createUserHandler)
    helper.Router.GET("/users/:id", getUserHandler)
    helper.Router.PUT("/users/:id", updateUserHandler)
    helper.Router.DELETE("/users/:id", deleteUserHandler)
    
    // Test create user
    createReq := models.UserCreateRequest{
        Username: "testuser",
        Password: "password123",
    }
    
    resp := helper.POST("/users", createReq)
    resp.AssertStatusCode(t, http.StatusCreated)
    resp.AssertSuccess(t)
    resp.AssertHasData(t)
    
    // Extract user ID
    userData := resp.GetDataAsMap()
    userID := int(userData["id"].(float64))
    
    // Test get user
    resp = helper.GET(fmt.Sprintf("/users/%d", userID))
    resp.AssertStatusCode(t, http.StatusOK)
    resp.AssertDataField(t, "username", "testuser")
    
    // Test update user
    updateReq := map[string]interface{}{
        "username": "updateduser",
    }
    
    resp = helper.PUT(fmt.Sprintf("/users/%d", userID), updateReq)
    resp.AssertStatusCode(t, http.StatusOK)
    resp.AssertDataField(t, "username", "updateduser")
    
    // Test delete user
    resp = helper.DELETE(fmt.Sprintf("/users/%d", userID))
    resp.AssertStatusCode(t, http.StatusNoContent)
    
    // Verify user is deleted
    resp = helper.GET(fmt.Sprintf("/users/%d", userID))
    resp.AssertStatusCode(t, http.StatusNotFound)
}
```

### Complete Integration Test

```go
func TestCompleteUserWorkflow(t *testing.T) {
    testing.RunIntegrationTest(t, "complete_user_workflow", func(ctx *testing.IntegrationTestContext) {
        // Setup
        setupRoutes(ctx.HTTPHelper.Router)
        
        // Test user registration
        signupReq := models.UserCreateRequest{
            Username: "testuser",
            Password: "password123",
        }
        
        resp := ctx.HTTPHelper.POST("/auth/signup", signupReq)
        resp.AssertStatusCode(ctx.T(), http.StatusCreated)
        
        // Verify user in database
        dbHelper := ctx.RequireDB()
        dbHelper.AssertRowCount("users", 1)
        
        // Test user login
        loginReq := models.UserLoginRequest{
            Username: "testuser",
            Password: "password123",
        }
        
        resp = ctx.HTTPHelper.POST("/auth/login", loginReq)
        resp.AssertStatusCode(ctx.T(), http.StatusOK)
        resp.AssertHasData(ctx.T())
        
        // Extract token
        data := resp.GetDataAsMap()
        token := data["token"].(string)
        
        // Test authenticated request
        authHelper := ctx.HTTPHelper.WithAuth(token)
        resp = authHelper.GET("/profile")
        resp.AssertStatusCode(ctx.T(), http.StatusOK)
        resp.AssertDataField(ctx.T(), "username", "testuser")
    })
}
```

This testing infrastructure provides everything needed to write comprehensive, maintainable tests for your Go microservice. The utilities are designed to be composable and easy to use, allowing you to focus on testing business logic rather than test setup and infrastructure. 