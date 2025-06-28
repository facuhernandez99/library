package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/gin-gonic/gin"
)

func init() {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)
}

func TestAuthMiddleware(t *testing.T) {
	secret := "test_secret_key"

	// Create a test user for generating tokens
	testUser := &models.User{
		ID:       123,
		Username: "testuser",
	}

	// Generate a valid token
	validTokenResponse, err := GenerateJWT(testUser, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		shouldAbort    bool
		expectedError  string
		description    string
	}{
		{
			name:           "valid_token",
			authHeader:     "Bearer " + validTokenResponse.Token,
			expectedStatus: http.StatusOK,
			shouldAbort:    false,
			description:    "Should allow request with valid token",
		},
		{
			name:           "missing_authorization_header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			shouldAbort:    true,
			expectedError:  "Authorization token required",
			description:    "Should reject request without authorization header",
		},
		{
			name:           "invalid_token_format",
			authHeader:     "InvalidFormat",
			expectedStatus: http.StatusUnauthorized,
			shouldAbort:    true,
			expectedError:  "Authorization token required",
			description:    "Should reject request with invalid token format",
		},
		{
			name:           "bearer_without_token",
			authHeader:     "Bearer",
			expectedStatus: http.StatusUnauthorized,
			shouldAbort:    true,
			expectedError:  "Authorization token required",
			description:    "Should reject Bearer header without token",
		},
		{
			name:           "bearer_with_empty_token",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			shouldAbort:    true,
			expectedError:  "Invalid token",
			description:    "Should reject Bearer header with empty token",
		},
		{
			name:           "malformed_token",
			authHeader:     "Bearer invalid.token.format",
			expectedStatus: http.StatusBadRequest,
			shouldAbort:    true,
			expectedError:  "Malformed token",
			description:    "Should reject malformed token",
		},
		{
			name:           "wrong_secret",
			authHeader:     "Bearer " + validTokenResponse.Token,
			expectedStatus: http.StatusUnauthorized,
			shouldAbort:    true,
			expectedError:  "Invalid token",
			description:    "Should reject token with wrong secret",
		},
		{
			name:           "case_insensitive_bearer",
			authHeader:     "bearer " + validTokenResponse.Token,
			expectedStatus: http.StatusOK,
			shouldAbort:    false,
			description:    "Should accept lowercase 'bearer'",
		},
		{
			name:           "mixed_case_bearer",
			authHeader:     "BeArEr " + validTokenResponse.Token,
			expectedStatus: http.StatusOK,
			shouldAbort:    false,
			description:    "Should accept mixed case 'bearer'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new Gin router for each test
			router := gin.New()

			// Use different secret for "wrong_secret" test
			testSecret := secret
			if tt.name == "wrong_secret" {
				testSecret = "wrong_secret"
			}

			// Add the middleware
			router.Use(AuthMiddleware(testSecret))

			// Add test endpoint
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			req, _ := http.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Perform request
			router.ServeHTTP(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, w.Code)
			}

			// Check response body for errors
			if tt.shouldAbort {
				var response models.APIResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("%s: failed to unmarshal error response: %v", tt.description, err)
					return
				}

				if response.Success {
					t.Errorf("%s: expected error response, got success", tt.description)
				}

				if tt.expectedError != "" && response.Error != tt.expectedError {
					t.Errorf("%s: expected error '%s', got '%s'", tt.description, tt.expectedError, response.Error)
				}
			} else {
				// For successful requests, check that the endpoint was reached
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("%s: failed to unmarshal success response: %v", tt.description, err)
					return
				}

				if response["message"] != "success" {
					t.Errorf("%s: expected success message, got %v", tt.description, response["message"])
				}
			}
		})
	}
}

func TestOptionalAuthMiddleware(t *testing.T) {
	secret := "test_secret_key"

	// Create a test user for generating tokens
	testUser := &models.User{
		ID:       456,
		Username: "optionaluser",
	}

	// Generate a valid token
	validTokenResponse, err := GenerateJWT(testUser, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	tests := []struct {
		name                string
		authHeader          string
		expectedUserID      int64
		expectedUsername    string
		expectAuthenticated bool
		description         string
	}{
		{
			name:                "valid_token",
			authHeader:          "Bearer " + validTokenResponse.Token,
			expectedUserID:      456,
			expectedUsername:    "optionaluser",
			expectAuthenticated: true,
			description:         "Should extract user info from valid token",
		},
		{
			name:                "missing_authorization_header",
			authHeader:          "",
			expectedUserID:      0,
			expectedUsername:    "",
			expectAuthenticated: false,
			description:         "Should continue without authentication when no header",
		},
		{
			name:                "invalid_token_format",
			authHeader:          "InvalidFormat",
			expectedUserID:      0,
			expectedUsername:    "",
			expectAuthenticated: false,
			description:         "Should continue without authentication for invalid format",
		},
		{
			name:                "malformed_token",
			authHeader:          "Bearer invalid.token.format",
			expectedUserID:      0,
			expectedUsername:    "",
			expectAuthenticated: false,
			description:         "Should continue without authentication for malformed token",
		},
		{
			name:                "expired_token",
			authHeader:          "Bearer " + validTokenResponse.Token,
			expectedUserID:      0,
			expectedUsername:    "",
			expectAuthenticated: false,
			description:         "Should continue without authentication for expired token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new Gin router for each test
			router := gin.New()

			// Use wrong secret for "expired_token" test to simulate invalid token
			testSecret := secret
			if tt.name == "expired_token" {
				testSecret = "wrong_secret"
			}

			// Add the middleware
			router.Use(OptionalAuthMiddleware(testSecret))

			// Add test endpoint that checks authentication status
			router.GET("/test", func(c *gin.Context) {
				userID, hasUserID := GetUserID(c)
				username, hasUsername := GetUsername(c)
				isAuth := IsAuthenticated(c)

				c.JSON(http.StatusOK, gin.H{
					"authenticated": isAuth,
					"userID":        userID,
					"username":      username,
					"hasUserID":     hasUserID,
					"hasUsername":   hasUsername,
				})
			})

			// Create request
			req, _ := http.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Perform request
			router.ServeHTTP(w, req)

			// Check status code
			if w.Code != http.StatusOK {
				t.Errorf("%s: expected status 200, got %d", tt.description, w.Code)
			}

			// Parse response
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			if err != nil {
				t.Errorf("%s: failed to unmarshal response: %v", tt.description, err)
				return
			}

			// Check authentication status
			authenticated, ok := response["authenticated"].(bool)
			if !ok {
				t.Errorf("%s: failed to get authentication status", tt.description)
				return
			}

			if authenticated != tt.expectAuthenticated {
				t.Errorf("%s: expected authenticated=%v, got %v", tt.description, tt.expectAuthenticated, authenticated)
			}

			// Check user info for authenticated requests
			if tt.expectAuthenticated {
				if userID, ok := response["userID"].(float64); ok {
					if int64(userID) != tt.expectedUserID {
						t.Errorf("%s: expected userID %d, got %d", tt.description, tt.expectedUserID, int64(userID))
					}
				} else {
					t.Errorf("%s: failed to get userID from response", tt.description)
				}

				if username, ok := response["username"].(string); ok {
					if username != tt.expectedUsername {
						t.Errorf("%s: expected username %s, got %s", tt.description, tt.expectedUsername, username)
					}
				} else {
					t.Errorf("%s: failed to get username from response", tt.description)
				}
			}
		})
	}
}

func TestRequireUserID(t *testing.T) {
	secret := "test_secret_key"
	paramName := "userID"

	// Create test users
	testUser1 := &models.User{ID: 123, Username: "user1"}
	testUser2 := &models.User{ID: 456, Username: "user2"}

	// Generate tokens
	token1, err := GenerateJWT(testUser1, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate token for user1: %v", err)
	}

	token2, err := GenerateJWT(testUser2, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate token for user2: %v", err)
	}

	tests := []struct {
		name           string
		authHeader     string
		userIDParam    string
		expectedStatus int
		expectedError  string
		shouldAbort    bool
		description    string
	}{
		{
			name:           "matching_user_id",
			authHeader:     "Bearer " + token1.Token,
			userIDParam:    "123",
			expectedStatus: http.StatusOK,
			shouldAbort:    false,
			description:    "Should allow access when authenticated user matches requested user",
		},
		{
			name:           "non_matching_user_id",
			authHeader:     "Bearer " + token1.Token,
			userIDParam:    "456",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Access denied: cannot access other user's resources",
			shouldAbort:    true,
			description:    "Should deny access when authenticated user doesn't match requested user",
		},
		{
			name:           "no_authentication",
			authHeader:     "",
			userIDParam:    "123",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Authorization token required",
			shouldAbort:    true,
			description:    "Should require authentication",
		},
		{
			name:           "missing_user_id_param",
			authHeader:     "Bearer " + token1.Token,
			userIDParam:    "",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "User ID parameter required",
			shouldAbort:    true,
			description:    "Should require user ID parameter",
		},
		{
			name:           "invalid_user_id_format",
			authHeader:     "Bearer " + token1.Token,
			userIDParam:    "invalid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid user ID format",
			shouldAbort:    true,
			description:    "Should reject invalid user ID format",
		},
		{
			name:           "negative_user_id",
			authHeader:     "Bearer " + token1.Token,
			userIDParam:    "-1",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Access denied: cannot access other user's resources",
			shouldAbort:    true,
			description:    "Should handle negative user ID",
		},
		{
			name:           "zero_user_id",
			authHeader:     "Bearer " + token1.Token,
			userIDParam:    "0",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Access denied: cannot access other user's resources",
			shouldAbort:    true,
			description:    "Should handle zero user ID",
		},
		{
			name:           "different_user_valid_token",
			authHeader:     "Bearer " + token2.Token,
			userIDParam:    "123",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Access denied: cannot access other user's resources",
			shouldAbort:    true,
			description:    "Should deny access when using valid token for different user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new Gin router for each test
			router := gin.New()

			// Add auth middleware first (RequireUserID depends on it)
			router.Use(AuthMiddleware(secret))

			// Add RequireUserID middleware
			router.Use(RequireUserID(paramName))

			// Add test endpoint - use a route that includes the userID parameter
			router.GET("/users/:userID/profile", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request path
			requestPath := "/users/" + tt.userIDParam + "/profile"
			if tt.userIDParam == "" {
				requestPath = "/users//profile" // Handle empty parameter case
			}

			req, _ := http.NewRequest("GET", requestPath, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Perform request
			router.ServeHTTP(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, w.Code)
			}

			// Check response body
			if tt.shouldAbort {
				var response models.APIResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("%s: failed to unmarshal error response: %v", tt.description, err)
					return
				}

				if response.Success {
					t.Errorf("%s: expected error response, got success", tt.description)
				}

				if tt.expectedError != "" && response.Error != tt.expectedError {
					t.Errorf("%s: expected error '%s', got '%s'", tt.description, tt.expectedError, response.Error)
				}
			} else {
				// For successful requests, check that the endpoint was reached
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("%s: failed to unmarshal success response: %v", tt.description, err)
					return
				}

				if response["message"] != "success" {
					t.Errorf("%s: expected success message, got %v", tt.description, response["message"])
				}
			}
		})
	}
}

func TestContextHelpers(t *testing.T) {
	secret := "test_secret_key"

	// Create a test user
	testUser := &models.User{
		ID:       789,
		Username: "contextuser",
	}

	// Generate a valid token
	validTokenResponse, err := GenerateJWT(testUser, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	t.Run("context_helpers_with_authentication", func(t *testing.T) {
		// Create router with auth middleware
		router := gin.New()
		router.Use(AuthMiddleware(secret))

		router.GET("/test", func(c *gin.Context) {
			// Test GetUserID
			userID, hasUserID := GetUserID(c)

			// Test GetUsername
			username, hasUsername := GetUsername(c)

			// Test GetClaims
			claims, hasClaims := GetClaims(c)

			// Test IsAuthenticated
			isAuth := IsAuthenticated(c)

			response := gin.H{
				"userID":        userID,
				"hasUserID":     hasUserID,
				"username":      username,
				"hasUsername":   hasUsername,
				"hasClaims":     hasClaims,
				"authenticated": isAuth,
			}

			if hasClaims {
				response["claimsUserID"] = claims.UserID
				response["claimsUsername"] = claims.Username
			}

			c.JSON(http.StatusOK, response)
		})

		// Create request with valid token
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+validTokenResponse.Token)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check status
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Parse response
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		// Check GetUserID
		if hasUserID, ok := response["hasUserID"].(bool); !ok || !hasUserID {
			t.Error("GetUserID should return true for authenticated request")
		}

		if userID, ok := response["userID"].(float64); !ok || int64(userID) != testUser.ID {
			t.Errorf("Expected userID %d, got %v", testUser.ID, userID)
		}

		// Check GetUsername
		if hasUsername, ok := response["hasUsername"].(bool); !ok || !hasUsername {
			t.Error("GetUsername should return true for authenticated request")
		}

		if username, ok := response["username"].(string); !ok || username != testUser.Username {
			t.Errorf("Expected username %s, got %v", testUser.Username, username)
		}

		// Check GetClaims
		if hasClaims, ok := response["hasClaims"].(bool); !ok || !hasClaims {
			t.Error("GetClaims should return true for authenticated request")
		}

		if claimsUserID, ok := response["claimsUserID"].(float64); ok {
			if int64(claimsUserID) != testUser.ID {
				t.Errorf("Expected claims userID %d, got %d", testUser.ID, int64(claimsUserID))
			}
		} else {
			t.Error("Claims userID should be available")
		}

		// Check IsAuthenticated
		if authenticated, ok := response["authenticated"].(bool); !ok || !authenticated {
			t.Error("IsAuthenticated should return true for authenticated request")
		}
	})

	t.Run("context_helpers_without_authentication", func(t *testing.T) {
		// Create router without auth middleware
		router := gin.New()

		router.GET("/test", func(c *gin.Context) {
			// Test all helper functions without authentication
			userID, hasUserID := GetUserID(c)
			username, hasUsername := GetUsername(c)
			claims, hasClaims := GetClaims(c)
			isAuth := IsAuthenticated(c)

			c.JSON(http.StatusOK, gin.H{
				"userID":        userID,
				"hasUserID":     hasUserID,
				"username":      username,
				"hasUsername":   hasUsername,
				"hasClaims":     hasClaims,
				"authenticated": isAuth,
				"claimsNil":     claims == nil,
			})
		})

		// Create request without authentication
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check status
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Parse response
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		// Check all helpers return false/empty for unauthenticated request
		if hasUserID, ok := response["hasUserID"].(bool); !ok || hasUserID {
			t.Error("GetUserID should return false for unauthenticated request")
		}

		if userID, ok := response["userID"].(float64); !ok || int64(userID) != 0 {
			t.Errorf("Expected userID 0, got %v", userID)
		}

		if hasUsername, ok := response["hasUsername"].(bool); !ok || hasUsername {
			t.Error("GetUsername should return false for unauthenticated request")
		}

		if username, ok := response["username"].(string); !ok || username != "" {
			t.Errorf("Expected empty username, got %v", username)
		}

		if hasClaims, ok := response["hasClaims"].(bool); !ok || hasClaims {
			t.Error("GetClaims should return false for unauthenticated request")
		}

		if claimsNil, ok := response["claimsNil"].(bool); !ok || !claimsNil {
			t.Error("Claims should be nil for unauthenticated request")
		}

		if authenticated, ok := response["authenticated"].(bool); !ok || authenticated {
			t.Error("IsAuthenticated should return false for unauthenticated request")
		}
	})
}

func TestCORSMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
		shouldContinue bool
		description    string
	}{
		{
			name:           "options_request",
			method:         "OPTIONS",
			expectedStatus: http.StatusNoContent,
			shouldContinue: false,
			description:    "Should handle OPTIONS request and abort with 204",
		},
		{
			name:           "get_request",
			method:         "GET",
			expectedStatus: http.StatusOK,
			shouldContinue: true,
			description:    "Should add CORS headers and continue for GET request",
		},
		{
			name:           "post_request",
			method:         "POST",
			expectedStatus: http.StatusOK,
			shouldContinue: true,
			description:    "Should add CORS headers and continue for POST request",
		},
		{
			name:           "put_request",
			method:         "PUT",
			expectedStatus: http.StatusOK,
			shouldContinue: true,
			description:    "Should add CORS headers and continue for PUT request",
		},
		{
			name:           "delete_request",
			method:         "DELETE",
			expectedStatus: http.StatusOK,
			shouldContinue: true,
			description:    "Should add CORS headers and continue for DELETE request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create router with CORS middleware
			router := gin.New()
			router.Use(CORSMiddleware())

			// Add test endpoints for all methods
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "GET success"})
			})
			router.POST("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "POST success"})
			})
			router.PUT("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "PUT success"})
			})
			router.DELETE("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "DELETE success"})
			})
			router.OPTIONS("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "OPTIONS success"})
			})

			// Create request
			req, _ := http.NewRequest(tt.method, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, w.Code)
			}

			// Check CORS headers
			expectedHeaders := map[string]string{
				"Access-Control-Allow-Origin":      "*",
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Allow-Headers":     "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With",
				"Access-Control-Allow-Methods":     "POST, OPTIONS, GET, PUT, DELETE",
			}

			for header, expectedValue := range expectedHeaders {
				actualValue := w.Header().Get(header)
				if actualValue != expectedValue {
					t.Errorf("%s: expected header %s=%s, got %s", tt.description, header, expectedValue, actualValue)
				}
			}

			// Check response body for non-OPTIONS requests
			if tt.shouldContinue {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("%s: failed to unmarshal response: %v", tt.description, err)
					return
				}

				expectedMessage := fmt.Sprintf("%s success", tt.method)
				if message, ok := response["message"].(string); !ok || message != expectedMessage {
					t.Errorf("%s: expected message '%s', got %v", tt.description, expectedMessage, response["message"])
				}
			} else {
				// For OPTIONS request, response body should be empty
				if w.Body.Len() > 0 {
					t.Errorf("%s: expected empty response body for OPTIONS, got %s", tt.description, w.Body.String())
				}
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectError   bool
		expectedToken string
		description   string
	}{
		{
			name:          "valid_bearer_token",
			authHeader:    "Bearer abc123",
			expectError:   false,
			expectedToken: "abc123",
			description:   "Should extract token from valid Bearer header",
		},
		{
			name:          "lowercase_bearer",
			authHeader:    "bearer xyz789",
			expectError:   false,
			expectedToken: "xyz789",
			description:   "Should extract token from lowercase bearer header",
		},
		{
			name:          "mixed_case_bearer",
			authHeader:    "BeArEr mixed123",
			expectError:   false,
			expectedToken: "mixed123",
			description:   "Should extract token from mixed case bearer header",
		},
		{
			name:        "empty_header",
			authHeader:  "",
			expectError: true,
			description: "Should return error for empty header",
		},
		{
			name:        "missing_bearer",
			authHeader:  "abc123",
			expectError: true,
			description: "Should return error for header without Bearer prefix",
		},
		{
			name:        "bearer_without_token",
			authHeader:  "Bearer",
			expectError: true,
			description: "Should return error for Bearer without token",
		},
		{
			name:          "bearer_with_empty_token",
			authHeader:    "Bearer ",
			expectError:   false,
			expectedToken: "",
			description:   "Should extract empty token from 'Bearer '",
		},
		{
			name:        "wrong_auth_type",
			authHeader:  "Basic abc123",
			expectError: true,
			description: "Should return error for non-Bearer auth type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple Gin context for testing
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Create a fake request with the auth header
			c.Request, _ = http.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				c.Request.Header.Set("Authorization", tt.authHeader)
			}

			// Call extractToken
			token, err := extractToken(c)

			// Check error expectation
			if tt.expectError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tt.description, err)
					return
				}

				if token != tt.expectedToken {
					t.Errorf("%s: expected token '%s', got '%s'", tt.description, tt.expectedToken, token)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkAuthMiddleware(b *testing.B) {
	secret := "bench_secret"
	user := &models.User{ID: 123, Username: "benchuser"}

	tokenResponse, err := GenerateJWT(user, secret, 24)
	if err != nil {
		b.Fatalf("Failed to generate token: %v", err)
	}

	router := gin.New()
	router.Use(AuthMiddleware(secret))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.Token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkCORSMiddleware(b *testing.B) {
	router := gin.New()
	router.Use(CORSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
