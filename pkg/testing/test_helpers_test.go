package testing

import (
	"net/http"
	"testing"
	"time"

	"github.com/facuhernandez99/library/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// TestHTTPTestHelper tests the HTTP test helper functionality
func TestHTTPTestHelper(t *testing.T) {
	helper := NewHTTPTestHelper(t)

	// Setup a simple route for testing
	helper.Router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    "test response",
		})
	})

	helper.Router.POST("/echo", func(c *gin.Context) {
		var body map[string]interface{}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    body,
		})
	})

	t.Run("GET request", func(t *testing.T) {
		resp := helper.GET("/test")

		resp.AssertStatusCode(t, http.StatusOK)
		resp.AssertSuccess(t)
		assert.Equal(t, "test response", resp.Body["data"])
	})

	t.Run("POST request with JSON body", func(t *testing.T) {
		requestBody := map[string]interface{}{
			"message": "hello",
			"number":  42,
		}

		resp := helper.POST("/echo", requestBody)

		resp.AssertStatusCode(t, http.StatusOK)
		resp.AssertSuccess(t)
		resp.AssertHasData(t)

		data := resp.GetDataAsMap()
		assert.Equal(t, "hello", data["message"])
		assert.Equal(t, float64(42), data["number"]) // JSON numbers are float64
	})

	t.Run("Query parameters", func(t *testing.T) {
		helper.Router.GET("/query", func(c *gin.Context) {
			page := c.Query("page")
			limit := c.Query("limit")

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data": gin.H{
					"page":  page,
					"limit": limit,
				},
			})
		})

		resp := helper.GET("/query", map[string]string{
			"page":  "1",
			"limit": "10",
		})

		resp.AssertStatusCode(t, http.StatusOK)
		data := resp.GetDataAsMap()
		assert.Equal(t, "1", data["page"])
		assert.Equal(t, "10", data["limit"])
	})

	t.Run("Authorization", func(t *testing.T) {
		helper.Router.GET("/protected", func(c *gin.Context) {
			auth := c.GetHeader("Authorization")
			if auth == "" {
				c.JSON(http.StatusUnauthorized, gin.H{
					"success": false,
					"error":   "unauthorized",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data":    "protected content",
			})
		})

		// Test without auth
		resp := helper.GET("/protected")
		resp.AssertStatusCode(t, http.StatusUnauthorized)
		resp.AssertError(t, "unauthorized")

		// Test with auth
		authHelper := helper.WithAuth("test-token")
		resp = authHelper.GET("/protected")
		resp.AssertStatusCode(t, http.StatusOK)
		resp.AssertSuccess(t)
	})
}

// TestMockImplementations tests the mock implementations
func TestMockImplementations(t *testing.T) {
	t.Run("MockTokenStorage", func(t *testing.T) {
		// Create mock without default expectations for this test
		mockStorage := &MockTokenStorage{}

		// Set up specific expectations
		mockStorage.On("IsBlacklisted", "test-token").Return(false, nil)
		mockStorage.On("IsBlacklisted", "blacklisted-token").Return(true, nil)

		// Test normal token
		blacklisted, err := mockStorage.IsBlacklisted("test-token")
		assert.NoError(t, err)
		assert.False(t, blacklisted)

		// Test blacklisted token
		blacklisted, err = mockStorage.IsBlacklisted("blacklisted-token")
		assert.NoError(t, err)
		assert.True(t, blacklisted)

		mockStorage.AssertExpectations(t)
	})

	t.Run("MockUserRepository", func(t *testing.T) {
		// Create mock without default expectations for this test
		mockRepo := &MockUserRepository{}

		// Create test user
		user := NewUserBuilder().WithUsername("testuser").Build()

		// Set up specific expectations
		mockRepo.On("Create", user).Return(nil)
		mockRepo.On("GetByID", 1).Return(user, nil)

		// Test creating a user
		err := mockRepo.Create(user)
		assert.NoError(t, err)

		// Test getting a user
		retrievedUser, err := mockRepo.GetByID(1)
		assert.NoError(t, err)
		assert.Equal(t, user.Username, retrievedUser.Username)

		mockRepo.AssertExpectations(t)
	})
}

// TestUserBuilder tests the user builder functionality
func TestUserBuilder(t *testing.T) {
	t.Run("Default user", func(t *testing.T) {
		user := NewUserBuilder().Build()

		assert.Equal(t, "testuser", user.Username)
		assert.NotEmpty(t, user.PasswordHash)
	})

	t.Run("Custom user", func(t *testing.T) {
		user := NewUserBuilder().
			WithUsername("customuser").
			WithPasswordHash("custom-hash").
			WithID(123).
			Build()

		assert.Equal(t, "customuser", user.Username)
		assert.Equal(t, "custom-hash", user.PasswordHash)
		assert.Equal(t, int64(123), user.ID)
	})
}

// IntegrationTestSuiteExample demonstrates how to use the integration test suite
type IntegrationTestSuiteExample struct {
	IntegrationTestSuite
}

func (suite *IntegrationTestSuiteExample) TestHTTPIntegration() {
	// Setup a route
	suite.HTTPHelper.Router.GET("/integration", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    "integration test",
		})
	})

	// Test the route
	resp := suite.HTTPHelper.GET("/integration")
	resp.AssertStatusCode(suite.T(), http.StatusOK)
	resp.AssertSuccess(suite.T())
}

func (suite *IntegrationTestSuiteExample) TestDatabaseIntegration() {
	if suite.DBHelper == nil {
		suite.T().Skip("Database tests disabled")
		return
	}

	// Test database operations
	suite.DBHelper.AssertTableExists("users")

	// Create a test user
	user := suite.DBHelper.Seed().User()
	assert.NotZero(suite.T(), user.ID)
	assert.NotEmpty(suite.T(), user.Username)

	// Verify user count
	suite.DBHelper.AssertRowCount("users", 1)
}

// Run the integration test suite
func TestIntegrationTestSuite(t *testing.T) {
	// Skip if integration tests are disabled
	SkipIntegrationTest(t, "Integration test suite")

	suite.Run(t, new(IntegrationTestSuiteExample))
}

// TestIntegrationTestRunner demonstrates the integration test runner
func TestIntegrationTestRunner(t *testing.T) {
	config := &IntegrationTestConfig{
		DatabaseEnabled:   false, // Disable database for this example
		TestTimeout:       5 * time.Second,
		VerboseLogging:    true,
		ParallelExecution: false,
	}

	runner := NewIntegrationTestRunner(t, config)

	runner.Run("example_test", func(ctx *IntegrationTestContext) {
		// Setup HTTP route
		ctx.HTTPHelper.Router.GET("/runner-test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "runner test successful",
			})
		})

		// Test the route
		resp := ctx.HTTPHelper.GET("/runner-test")
		resp.AssertStatusCode(ctx.t, http.StatusOK)
		resp.AssertSuccess(ctx.t)

		// Test logging
		ctx.Log("This is a verbose log message")

		// Test condition waiting (simple example)
		counter := 0
		ctx.WaitForCondition(func() bool {
			counter++
			return counter >= 3
		}, 1*time.Second, "counter reaches 3")

		assert.Equal(t, 3, counter)
	})
}

// TestScenarioExecution demonstrates scenario-based testing
func TestScenarioExecution(t *testing.T) {
	RunIntegrationTest(t, "scenario_example", func(ctx *IntegrationTestContext) {
		setupCompleted := false
		executionCompleted := false
		verificationCompleted := false
		cleanupCompleted := false

		scenario := TestScenario{
			Name: "Example Scenario",
			Setup: func(ctx *IntegrationTestContext) error {
				setupCompleted = true
				ctx.Log("Setup phase completed")
				return nil
			},
			Execute: func(ctx *IntegrationTestContext) error {
				executionCompleted = true
				ctx.Log("Execution phase completed")
				return nil
			},
			Verify: func(ctx *IntegrationTestContext) error {
				verificationCompleted = true
				ctx.Log("Verification phase completed")
				assert.True(ctx.t, setupCompleted, "Setup should be completed")
				assert.True(ctx.t, executionCompleted, "Execution should be completed")
				return nil
			},
			Cleanup: func(ctx *IntegrationTestContext) error {
				cleanupCompleted = true
				ctx.Log("Cleanup phase completed")
				return nil
			},
		}

		ctx.RunScenario(scenario)

		// Verify all phases were executed
		assert.True(t, setupCompleted, "Setup should be completed")
		assert.True(t, executionCompleted, "Execution should be completed")
		assert.True(t, verificationCompleted, "Verification should be completed")
		assert.True(t, cleanupCompleted, "Cleanup should be completed")
	})
}

// TestRetryMechanism tests the retry functionality
func TestRetryMechanism(t *testing.T) {
	RunIntegrationTestWithConfig(t, "retry_test", &IntegrationTestConfig{
		DatabaseEnabled: false,
		VerboseLogging:  true,
	}, func(ctx *IntegrationTestContext) {
		attemptCount := 0

		// Test successful retry
		err := ctx.Retry(func() error {
			attemptCount++
			if attemptCount < 3 {
				return assert.AnError
			}
			return nil
		}, 5, 10*time.Millisecond)

		assert.NoError(t, err)
		assert.Equal(t, 3, attemptCount)

		// Test failed retry
		attemptCount = 0
		err = ctx.Retry(func() error {
			attemptCount++
			return assert.AnError
		}, 2, 1*time.Millisecond)

		assert.Error(t, err)
		assert.Equal(t, 3, attemptCount) // 2 retries + 1 initial attempt
	})
}

// BenchmarkHTTPTestHelper benchmarks the HTTP test helper
func BenchmarkHTTPTestHelper(b *testing.B) {
	helper := NewHTTPTestHelper(&testing.T{}) // Use empty testing.T for benchmark

	helper.Router.GET("/benchmark", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp := helper.GET("/benchmark")
		if resp.Code != http.StatusOK {
			b.Fatalf("Expected status 200, got %d", resp.Code)
		}
	}
}

// Example of how to use the testing utilities in a real test
func ExampleHTTPTestHelper() {
	// This would typically be in a real test function
	t := &testing.T{} // In real code, this would be passed to the test function

	// Create HTTP test helper
	helper := NewHTTPTestHelper(t)

	// Setup route
	helper.Router.POST("/users", func(c *gin.Context) {
		var req models.UserCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid request",
			})
			return
		}

		// Create user response
		user := models.UserResponse{
			ID:       1,
			Username: req.Username,
		}

		c.JSON(http.StatusCreated, gin.H{
			"success": true,
			"data":    user,
		})
	})

	// Test creating a user
	userRequest := models.UserCreateRequest{
		Username: "testuser",
		Password: "testpassword123",
	}

	resp := helper.POST("/users", userRequest)
	resp.AssertStatusCode(t, http.StatusCreated)
	resp.AssertSuccess(t)
	resp.AssertHasData(t)

	// Verify user data
	var userResp models.UserResponse
	err := resp.BindDataTo(&userResp)
	if err == nil {
		// User created successfully
		_ = userResp.Username // Use the username
	}
}
