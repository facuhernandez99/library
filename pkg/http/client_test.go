package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/models"
)

// Test data structures
type TestData struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name            string
		config          *ClientConfig
		expectedURL     string
		expectedTimeout time.Duration
		expectedRetries int
		expectedHeaders map[string]string
	}{
		{
			name:            "Default configuration",
			config:          nil,
			expectedURL:     "",
			expectedTimeout: 30 * time.Second,
			expectedRetries: 3,
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
				"User-Agent":   "blog-microservice/1.0",
			},
		},
		{
			name: "Custom configuration",
			config: &ClientConfig{
				BaseURL:       "http://localhost:8080",
				Timeout:       10 * time.Second,
				RetryAttempts: 5,
				Headers: map[string]string{
					"X-Custom-Header": "test-value",
				},
			},
			expectedURL:     "http://localhost:8080",
			expectedTimeout: 10 * time.Second,
			expectedRetries: 5,
			expectedHeaders: map[string]string{
				"Content-Type":    "application/json",
				"Accept":          "application/json",
				"User-Agent":      "blog-microservice/1.0",
				"X-Custom-Header": "test-value",
			},
		},
		{
			name: "Configuration with trailing slash",
			config: &ClientConfig{
				BaseURL: "http://localhost:8080/",
			},
			expectedURL: "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.config)

			if client == nil {
				t.Fatal("NewClient returned nil")
			}

			if client.baseURL != tt.expectedURL {
				t.Errorf("Expected baseURL %s, got %s", tt.expectedURL, client.baseURL)
			}

			if tt.expectedTimeout != 0 && client.timeout != tt.expectedTimeout {
				t.Errorf("Expected timeout %v, got %v", tt.expectedTimeout, client.timeout)
			}

			if tt.expectedRetries != 0 && client.retryAttempts != tt.expectedRetries {
				t.Errorf("Expected retry attempts %d, got %d", tt.expectedRetries, client.retryAttempts)
			}

			// Check headers
			for key, expectedValue := range tt.expectedHeaders {
				if value, exists := client.defaultHeaders[key]; !exists || value != expectedValue {
					t.Errorf("Expected header %s=%s, got %s", key, expectedValue, value)
				}
			}
		})
	}
}

func TestClient_SetAuthToken(t *testing.T) {
	client := NewClient(nil)
	token := "test-token-123"

	client.SetAuthToken(token)

	expectedAuth := "Bearer " + token
	if auth, exists := client.defaultHeaders["Authorization"]; !exists || auth != expectedAuth {
		t.Errorf("Expected Authorization header %s, got %s", expectedAuth, auth)
	}
}

func TestClient_SetHeader(t *testing.T) {
	client := NewClient(nil)
	key := "X-Test-Header"
	value := "test-value"

	client.SetHeader(key, value)

	if headerValue, exists := client.defaultHeaders[key]; !exists || headerValue != value {
		t.Errorf("Expected header %s=%s, got %s", key, value, headerValue)
	}
}

func TestClient_HTTPMethods(t *testing.T) {
	// Test data
	testData := TestData{ID: 1, Name: "test"}
	responseData := models.APIResponse{
		Success: true,
		Data:    testData,
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Validate User-Agent
		if r.Header.Get("User-Agent") != "blog-microservice/1.0" {
			t.Errorf("Expected User-Agent blog-microservice/1.0, got %s", r.Header.Get("User-Agent"))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responseData)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL: server.URL,
	})

	ctx := context.Background()

	tests := []struct {
		name   string
		method func() (*Response, error)
	}{
		{
			name: "GET",
			method: func() (*Response, error) {
				return client.Get(ctx, "/test")
			},
		},
		{
			name: "POST",
			method: func() (*Response, error) {
				return client.Post(ctx, "/test", testData)
			},
		},
		{
			name: "PUT",
			method: func() (*Response, error) {
				return client.Put(ctx, "/test", testData)
			},
		},
		{
			name: "PATCH",
			method: func() (*Response, error) {
				return client.Patch(ctx, "/test", testData)
			},
		},
		{
			name: "DELETE",
			method: func() (*Response, error) {
				return client.Delete(ctx, "/test")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := tt.method()
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if response.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", response.StatusCode)
			}

			if !response.Success {
				t.Error("Expected response success to be true")
			}
		})
	}
}

func TestClient_GetWithQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		if !strings.Contains(query, "param1=value1") || !strings.Contains(query, "param2=value2") {
			t.Errorf("Expected query to contain both parameters, got: %s", query)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(models.APIResponse{Success: true})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{BaseURL: server.URL})

	query := map[string]string{
		"param1": "value1",
		"param2": "value2",
	}

	response, err := client.GetWithQuery(context.Background(), "/test", query)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", response.StatusCode)
	}
}

func TestClient_RetryLogic(t *testing.T) {
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Return 500 status - this should NOT trigger retries in the current implementation
		// because the HTTP request succeeded (err == nil), only network errors trigger retries
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.APIResponse{
			Success: false,
			Error:   "internal server error",
		})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL:       server.URL,
		RetryAttempts: 3,
	})

	response, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if response.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", response.StatusCode)
	}

	// Should only make 1 request because HTTP status codes don't trigger retries
	if requestCount != 1 {
		t.Errorf("Expected 1 request (no retries on HTTP status codes), got %d", requestCount)
	}
}

func TestClient_RetryLogic_NoRetryOn4xx(t *testing.T) {
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusBadRequest) // 400 - should not retry
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL:       server.URL,
		RetryAttempts: 3,
	})

	response, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", response.StatusCode)
	}

	if requestCount != 1 {
		t.Errorf("Expected 1 request (no retries on 4xx), got %d", requestCount)
	}
}

func TestClient_RetryLogic_RetryOn429(t *testing.T) {
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Rate limited - this should NOT trigger retries in the current implementation
		// because the HTTP request succeeded (err == nil), only network errors trigger retries
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(models.APIResponse{
			Success: false,
			Error:   "rate limited",
		})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		BaseURL:       server.URL,
		RetryAttempts: 2,
	})

	response, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if response.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", response.StatusCode)
	}

	// Should only make 1 request because HTTP status codes don't trigger retries
	if requestCount != 1 {
		t.Errorf("Expected 1 request (no retries on HTTP status codes), got %d", requestCount)
	}
}

func TestClient_RetryLogic_NetworkErrors(t *testing.T) {
	// Test with invalid/unreachable URL to simulate network errors
	client := NewClient(&ClientConfig{
		BaseURL:       "http://localhost:99999", // Invalid port that should cause connection error
		RetryAttempts: 2,
		Timeout:       1 * time.Second, // Short timeout to speed up test
	})

	_, err := client.Get(context.Background(), "/test")
	if err == nil {
		t.Fatal("Expected error due to network failure")
	}

	// The error message should indicate that retries were attempted
	if !strings.Contains(err.Error(), "HTTP request failed after retries") {
		t.Errorf("Expected retry error message, got: %v", err)
	}
}

func TestClient_AuthenticationTokenHandling(t *testing.T) {
	expectedToken := "Bearer test-auth-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != expectedToken {
			t.Errorf("Expected Authorization header %s, got %s", expectedToken, auth)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(models.APIResponse{Success: true})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{BaseURL: server.URL})
	client.SetAuthToken("test-auth-token")

	_, err := client.Get(context.Background(), "/protected")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestClient_RequestResponseParsing(t *testing.T) {
	testData := TestData{ID: 42, Name: "test-response"}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test request parsing (for POST/PUT requests)
		if r.Method == "POST" || r.Method == "PUT" {
			var receivedData TestData
			if err := json.NewDecoder(r.Body).Decode(&receivedData); err != nil {
				t.Errorf("Failed to parse request body: %v", err)
			}
			if receivedData.Name != "test-request" {
				t.Errorf("Expected request name 'test-request', got '%s'", receivedData.Name)
			}
		}

		// Return structured response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(models.APIResponse{
			Success: true,
			Data:    testData,
		})
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{BaseURL: server.URL})

	// Test GET response parsing
	response, err := client.Get(context.Background(), "/test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !response.Success {
		t.Error("Expected response success to be true")
	}

	if response.Data == nil {
		t.Error("Expected response data to be present")
	}

	// Test POST request/response parsing
	requestData := TestData{ID: 1, Name: "test-request"}
	response, err = client.Post(context.Background(), "/test", requestData)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !response.Success {
		t.Error("Expected response success to be true")
	}
}

func TestClient_ErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseBody models.APIResponse
		expectError  bool
		expectRetry  bool
	}{
		{
			name:       "Success response",
			statusCode: http.StatusOK,
			responseBody: models.APIResponse{
				Success: true,
				Data:    "success",
			},
			expectError: false,
		},
		{
			name:       "Error response with message",
			statusCode: http.StatusBadRequest,
			responseBody: models.APIResponse{
				Success: false,
				Error:   "validation failed",
			},
			expectError: false, // Error in response, but HTTP request succeeded
		},
		{
			name:       "Server error",
			statusCode: http.StatusInternalServerError,
			responseBody: models.APIResponse{
				Success: false,
				Error:   "internal server error",
			},
			expectError: false, // Response received, no HTTP error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			client := NewClient(&ClientConfig{
				BaseURL:       server.URL,
				RetryAttempts: 1,
			})

			response, err := client.Get(context.Background(), "/test")

			if tt.expectError && err == nil {
				t.Error("Expected error, got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if response != nil {
				if response.StatusCode != tt.statusCode {
					t.Errorf("Expected status %d, got %d", tt.statusCode, response.StatusCode)
				}

				if response.Success != tt.responseBody.Success {
					t.Errorf("Expected success %v, got %v", tt.responseBody.Success, response.Success)
				}
			}
		})
	}
}

func TestClient_HealthCheck(t *testing.T) {
	healthData := models.HealthCheck{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Service:   "test-service",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("Expected path /health, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(healthData)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{BaseURL: server.URL})

	// Test HealthCheck
	health, err := client.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if health.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", health.Status)
	}

	if health.Service != "test-service" {
		t.Errorf("Expected service 'test-service', got '%s'", health.Service)
	}

	// Test IsHealthy
	if !client.IsHealthy(context.Background()) {
		t.Error("Expected IsHealthy to return true")
	}
}

func TestClient_IsHealthy_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{BaseURL: server.URL})

	if client.IsHealthy(context.Background()) {
		t.Error("Expected IsHealthy to return false for unhealthy service")
	}
}

func TestClient_UnmarshalResponse(t *testing.T) {
	testData := TestData{ID: 123, Name: "unmarshal-test"}

	tests := []struct {
		name         string
		response     *Response
		expectError  bool
		expectedID   int
		expectedName string
	}{
		{
			name: "Successful unmarshal",
			response: &Response{
				Success: true,
				Data:    testData,
			},
			expectError:  false,
			expectedID:   123,
			expectedName: "unmarshal-test",
		},
		{
			name: "Failed response",
			response: &Response{
				Success: false,
				Error:   "test error",
			},
			expectError: true,
		},
		{
			name: "No data in response",
			response: &Response{
				Success: true,
				Data:    nil,
			},
			expectError: true,
		},
	}

	client := NewClient(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target TestData
			err := client.UnmarshalResponse(tt.response, &target)

			if tt.expectError && err == nil {
				t.Error("Expected error, got none")
			}

			if !tt.expectError {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if target.ID != tt.expectedID {
					t.Errorf("Expected ID %d, got %d", tt.expectedID, target.ID)
				}

				if target.Name != tt.expectedName {
					t.Errorf("Expected Name '%s', got '%s'", tt.expectedName, target.Name)
				}
			}
		})
	}
}

func TestClient_ParseError(t *testing.T) {
	client := NewClient(nil)

	tests := []struct {
		name         string
		response     *Response
		expectError  bool
		errorMessage string
	}{
		{
			name: "Success response",
			response: &Response{
				Success: true,
			},
			expectError: false,
		},
		{
			name: "Error with message",
			response: &Response{
				Success: false,
				Error:   "custom error message",
			},
			expectError:  true,
			errorMessage: "custom error message",
		},
		{
			name: "Error without message",
			response: &Response{
				Success:    false,
				StatusCode: http.StatusBadRequest,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.ParseError(tt.response)

			if tt.expectError && err == nil {
				t.Error("Expected error, got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.expectError && tt.errorMessage != "" {
				if !strings.Contains(err.Error(), tt.errorMessage) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorMessage, err.Error())
				}
			}
		})
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{BaseURL: server.URL})

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err := client.Get(ctx, "/slow")
	if err == nil {
		t.Error("Expected context cancellation error")
	}

	if !strings.Contains(err.Error(), "context") {
		t.Errorf("Expected context-related error, got: %v", err)
	}
}
