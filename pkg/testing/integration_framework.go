package testing

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite provides a base test suite for integration tests
type IntegrationTestSuite struct {
	suite.Suite
	HTTPHelper *HTTPTestHelper
	DBHelper   *DatabaseTestHelper
	ctx        context.Context
	cancel     context.CancelFunc
	cleanups   []func()
}

// SetupSuite runs once before all tests in the suite
func (s *IntegrationTestSuite) SetupSuite() {
	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Initialize HTTP helper
	s.HTTPHelper = NewHTTPTestHelper(s.T())

	// Initialize database helper if database tests are enabled
	if s.isDatabaseTestEnabled() {
		s.DBHelper = NewDatabaseTestHelper(s.T())
		s.DBHelper.Setup()
		s.addCleanup(s.DBHelper.Teardown)
	}
}

// TearDownSuite runs once after all tests in the suite
func (s *IntegrationTestSuite) TearDownSuite() {
	// Run all cleanup functions in reverse order
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		s.cleanups[i]()
	}

	if s.cancel != nil {
		s.cancel()
	}
}

// SetupTest runs before each test
func (s *IntegrationTestSuite) SetupTest() {
	// Reset Gin routes for each test
	s.HTTPHelper.Router = gin.New()
	gin.SetMode(gin.TestMode)

	// Clean database tables if database is available
	if s.DBHelper != nil {
		s.DBHelper.TruncateAll()
	}
}

// TearDownTest runs after each test
func (s *IntegrationTestSuite) TearDownTest() {
	// Add any per-test cleanup here
}

// addCleanup adds a cleanup function to be called during teardown
func (s *IntegrationTestSuite) addCleanup(cleanup func()) {
	s.cleanups = append(s.cleanups, cleanup)
}

// isDatabaseTestEnabled checks if database tests should be run
func (s *IntegrationTestSuite) isDatabaseTestEnabled() bool {
	return os.Getenv("SKIP_DB_TESTS") != "true"
}

// Integration Test Configuration

// IntegrationTestConfig holds configuration for integration tests
type IntegrationTestConfig struct {
	DatabaseEnabled   bool
	HTTPPort          int
	TestTimeout       time.Duration
	CleanupOnFailure  bool
	VerboseLogging    bool
	ParallelExecution bool
}

// DefaultIntegrationTestConfig returns default configuration for integration tests
func DefaultIntegrationTestConfig() *IntegrationTestConfig {
	return &IntegrationTestConfig{
		DatabaseEnabled:   true,
		HTTPPort:          8080,
		TestTimeout:       30 * time.Second,
		CleanupOnFailure:  true,
		VerboseLogging:    false,
		ParallelExecution: false,
	}
}

// IntegrationTestRunner provides utilities for running integration tests
type IntegrationTestRunner struct {
	config *IntegrationTestConfig
	t      *testing.T
}

// NewIntegrationTestRunner creates a new integration test runner
func NewIntegrationTestRunner(t *testing.T, config *IntegrationTestConfig) *IntegrationTestRunner {
	if config == nil {
		config = DefaultIntegrationTestConfig()
	}

	return &IntegrationTestRunner{
		config: config,
		t:      t,
	}
}

// Run executes an integration test with the provided setup and teardown
func (r *IntegrationTestRunner) Run(name string, testFunc func(*IntegrationTestContext)) {
	r.t.Run(name, func(t *testing.T) {
		if r.config.ParallelExecution {
			t.Parallel()
		}

		// Create test context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), r.config.TestTimeout)
		defer cancel()

		// Setup integration test context
		testCtx := &IntegrationTestContext{
			Context:    ctx,
			HTTPHelper: NewHTTPTestHelper(t),
			t:          t,
			config:     r.config,
		}

		// Setup database if enabled
		if r.config.DatabaseEnabled {
			testCtx.DBHelper = NewDatabaseTestHelper(t)
			testCtx.DBHelper.Setup()
			defer func() {
				if r.config.CleanupOnFailure || !t.Failed() {
					testCtx.DBHelper.Teardown()
				}
			}()
		}

		// Run the test
		testFunc(testCtx)
	})
}

// IntegrationTestContext provides context for integration tests
type IntegrationTestContext struct {
	Context    context.Context
	HTTPHelper *HTTPTestHelper
	DBHelper   *DatabaseTestHelper
	t          *testing.T
	config     *IntegrationTestConfig
}

// GetHTTPHelper returns the HTTP test helper
func (ctx *IntegrationTestContext) GetHTTPHelper() *HTTPTestHelper {
	return ctx.HTTPHelper
}

// GetDBHelper returns the database test helper
func (ctx *IntegrationTestContext) GetDBHelper() *DatabaseTestHelper {
	require.NotNil(ctx.t, ctx.DBHelper, "Database testing is not enabled")
	return ctx.DBHelper
}

// RequireDB ensures database is available for testing
func (ctx *IntegrationTestContext) RequireDB() *DatabaseTestHelper {
	require.NotNil(ctx.t, ctx.DBHelper, "Database testing is required but not enabled")
	return ctx.DBHelper
}

// SkipIfNoDatabase skips the test if database is not available
func (ctx *IntegrationTestContext) SkipIfNoDatabase() {
	if ctx.DBHelper == nil {
		ctx.t.Skip("Skipping test: database not available")
	}
}

// SetVerboseLogging enables or disables verbose logging
func (ctx *IntegrationTestContext) SetVerboseLogging(enabled bool) {
	ctx.config.VerboseLogging = enabled
}

// Log logs a message if verbose logging is enabled
func (ctx *IntegrationTestContext) Log(format string, args ...interface{}) {
	if ctx.config.VerboseLogging {
		ctx.t.Logf(format, args...)
	}
}

// Test Orchestration Utilities

// TestScenario represents a test scenario with setup, execution, and verification
type TestScenario struct {
	Name        string
	Setup       func(*IntegrationTestContext) error
	Execute     func(*IntegrationTestContext) error
	Verify      func(*IntegrationTestContext) error
	Cleanup     func(*IntegrationTestContext) error
	SkipCleanup bool
}

// RunScenario executes a test scenario
func (ctx *IntegrationTestContext) RunScenario(scenario TestScenario) {
	ctx.t.Run(scenario.Name, func(t *testing.T) {
		// Setup phase
		if scenario.Setup != nil {
			ctx.Log("Running setup for scenario: %s", scenario.Name)
			err := scenario.Setup(ctx)
			require.NoError(t, err, "Setup failed for scenario: %s", scenario.Name)
		}

		// Cleanup phase (defer to ensure it runs even if test fails)
		if scenario.Cleanup != nil && !scenario.SkipCleanup {
			defer func() {
				ctx.Log("Running cleanup for scenario: %s", scenario.Name)
				if err := scenario.Cleanup(ctx); err != nil {
					t.Logf("Cleanup failed for scenario %s: %v", scenario.Name, err)
				}
			}()
		}

		// Execute phase
		if scenario.Execute != nil {
			ctx.Log("Executing scenario: %s", scenario.Name)
			err := scenario.Execute(ctx)
			require.NoError(t, err, "Execution failed for scenario: %s", scenario.Name)
		}

		// Verify phase
		if scenario.Verify != nil {
			ctx.Log("Verifying scenario: %s", scenario.Name)
			err := scenario.Verify(ctx)
			require.NoError(t, err, "Verification failed for scenario: %s", scenario.Name)
		}
	})
}

// Utility Functions for Integration Tests

// WaitForCondition waits for a condition to be true with timeout
func (ctx *IntegrationTestContext) WaitForCondition(condition func() bool, timeout time.Duration, message string) {
	ctx.WaitForConditionWithInterval(condition, timeout, 100*time.Millisecond, message)
}

// WaitForConditionWithInterval waits for a condition with custom interval
func (ctx *IntegrationTestContext) WaitForConditionWithInterval(condition func() bool, timeout, interval time.Duration, message string) {
	ctx.Log("Waiting for condition: %s (timeout: %v)", message, timeout)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timeoutCh := time.After(timeout)

	for {
		select {
		case <-timeoutCh:
			ctx.t.Fatalf("Timeout waiting for condition: %s", message)
		case <-ticker.C:
			if condition() {
				ctx.Log("Condition met: %s", message)
				return
			}
		case <-ctx.Context.Done():
			ctx.t.Fatalf("Context cancelled while waiting for condition: %s", message)
		}
	}
}

// Sleep pauses execution for the specified duration (useful for debugging)
func (ctx *IntegrationTestContext) Sleep(duration time.Duration) {
	ctx.Log("Sleeping for %v", duration)
	time.Sleep(duration)
}

// Retry executes a function with retry logic
func (ctx *IntegrationTestContext) Retry(operation func() error, maxRetries int, delay time.Duration) error {
	var lastErr error

	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			ctx.Log("Retrying operation (attempt %d/%d)", i+1, maxRetries+1)
			time.Sleep(delay)
		}

		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err
	}

	return fmt.Errorf("operation failed after %d retries: %w", maxRetries+1, lastErr)
}

// Environment Management

// TestEnvironment manages test environment setup and teardown
type TestEnvironment struct {
	Name        string
	DatabaseURL string
	Redis       *RedisTestConfig
	Services    map[string]*ServiceConfig
	cleanups    []func() error
}

// ServiceConfig represents configuration for external services
type ServiceConfig struct {
	Name      string
	Port      int
	HealthURL string
	StartCmd  string
	StopCmd   string
	Timeout   time.Duration
}

// RedisTestConfig represents Redis configuration for testing
type RedisTestConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(name string) *TestEnvironment {
	return &TestEnvironment{
		Name:     name,
		Services: make(map[string]*ServiceConfig),
		cleanups: make([]func() error, 0),
	}
}

// AddService adds a service to the test environment
func (env *TestEnvironment) AddService(config *ServiceConfig) {
	env.Services[config.Name] = config
}

// Setup sets up the test environment
func (env *TestEnvironment) Setup() error {
	// Setup services (implementation would depend on specific needs)
	// This is a placeholder for more complex environment setup
	return nil
}

// Teardown tears down the test environment
func (env *TestEnvironment) Teardown() error {
	// Run cleanup functions in reverse order
	for i := len(env.cleanups) - 1; i >= 0; i-- {
		if err := env.cleanups[i](); err != nil {
			// Log error but continue with other cleanups
			fmt.Printf("Cleanup error: %v\n", err)
		}
	}
	return nil
}

// AddCleanup adds a cleanup function
func (env *TestEnvironment) AddCleanup(cleanup func() error) {
	env.cleanups = append(env.cleanups, cleanup)
}

// Helper functions for running integration tests

// RunIntegrationTest is a convenience function for running integration tests
func RunIntegrationTest(t *testing.T, name string, testFunc func(*IntegrationTestContext)) {
	runner := NewIntegrationTestRunner(t, nil)
	runner.Run(name, testFunc)
}

// RunIntegrationTestWithConfig runs integration tests with custom configuration
func RunIntegrationTestWithConfig(t *testing.T, name string, config *IntegrationTestConfig, testFunc func(*IntegrationTestContext)) {
	runner := NewIntegrationTestRunner(t, config)
	runner.Run(name, testFunc)
}

// SkipIntegrationTest skips integration tests if integration testing is disabled
func SkipIntegrationTest(t *testing.T, reason string) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skipf("Skipping integration test: %s", reason)
	}
}
