package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/facuhernandez99/library/pkg/auth"
	"github.com/facuhernandez99/library/pkg/errors"
	"github.com/facuhernandez99/library/pkg/logging"
	"github.com/facuhernandez99/library/pkg/models"
)

// Client represents an HTTP client for inter-service communication
type Client struct {
	httpClient     *http.Client
	baseURL        string
	defaultHeaders map[string]string
	timeout        time.Duration
	retryAttempts  int
	logger         *logging.Logger
	authConfig     *AuthConfig
}

// AuthConfig holds authentication configuration for service-to-service communication
type AuthConfig struct {
	JWTSecret    string            `json:"jwt_secret"`
	ServiceToken string            `json:"service_token"`
	TokenStorage auth.TokenStorage `json:"-"`
	AutoRefresh  bool              `json:"auto_refresh"`
	RefreshToken string            `json:"refresh_token,omitempty"`
}

// ClientConfig holds HTTP client configuration
type ClientConfig struct {
	BaseURL       string            `json:"base_url"`
	Timeout       time.Duration     `json:"timeout"`
	RetryAttempts int               `json:"retry_attempts"`
	Headers       map[string]string `json:"headers"`
	Logger        *logging.Logger   `json:"-"`
	AuthConfig    *AuthConfig       `json:"auth_config,omitempty"`
}

// DefaultClientConfig returns default HTTP client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
		Headers:       make(map[string]string),
		Logger:        logging.GetDefault(),
	}
}

// NewClient creates a new HTTP client for inter-service communication
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}

	// Merge with defaults for missing fields
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.Logger == nil {
		config.Logger = logging.GetDefault()
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	defaultHeaders := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
		"User-Agent":   "library-microservice/1.0",
	}

	// Merge custom headers
	for key, value := range config.Headers {
		defaultHeaders[key] = value
	}

	client := &Client{
		httpClient:     httpClient,
		baseURL:        strings.TrimSuffix(config.BaseURL, "/"),
		defaultHeaders: defaultHeaders,
		timeout:        config.Timeout,
		retryAttempts:  config.RetryAttempts,
		logger:         config.Logger,
		authConfig:     config.AuthConfig,
	}

	// Set up authentication if configured
	if config.AuthConfig != nil {
		client.setupAuthentication()
	}

	return client
}

// setupAuthentication configures authentication for the client
func (c *Client) setupAuthentication() {
	if c.authConfig.ServiceToken != "" {
		c.SetAuthToken(c.authConfig.ServiceToken)
	}
}

// SetAuthToken sets the authorization token for requests
func (c *Client) SetAuthToken(token string) {
	c.defaultHeaders["Authorization"] = fmt.Sprintf("Bearer %s", token)
}

// SetServiceAuthentication configures service-to-service authentication
func (c *Client) SetServiceAuthentication(config *AuthConfig) {
	c.authConfig = config
	c.setupAuthentication()
}

// RefreshAuthToken attempts to refresh the authentication token if configured
func (c *Client) RefreshAuthToken(ctx context.Context) error {
	if c.authConfig == nil || !c.authConfig.AutoRefresh {
		return errors.New(errors.ErrCodeUnauthorized, "Authentication not configured for refresh")
	}

	if c.authConfig.RefreshToken == "" || c.authConfig.JWTSecret == "" {
		return errors.New(errors.ErrCodeUnauthorized, "Refresh token or JWT secret not configured")
	}

	// Use the auth package to refresh the token
	tokenResponse, err := auth.RefreshAccessToken(
		c.authConfig.RefreshToken,
		c.authConfig.JWTSecret,
		72, // 72 hours expiration
	)
	if err != nil {
		c.logger.WithField("error", err.Error()).Error(ctx, "Failed to refresh auth token", err)
		return errors.Wrap(err, errors.ErrCodeUnauthorized, "Failed to refresh authentication token")
	}

	// Update the service token
	c.authConfig.ServiceToken = tokenResponse.Token
	c.SetAuthToken(tokenResponse.Token)

	c.logger.WithField("expires_at", tokenResponse.ExpiresAt).Info(ctx, "Successfully refreshed service authentication token")
	return nil
}

// ValidateAuthToken validates the current authentication token
func (c *Client) ValidateAuthToken(ctx context.Context) error {
	if c.authConfig == nil || c.authConfig.ServiceToken == "" || c.authConfig.JWTSecret == "" {
		return errors.New(errors.ErrCodeUnauthorized, "Authentication not configured")
	}

	// Validate the token using the auth package
	_, err := auth.ValidateJWT(c.authConfig.ServiceToken, c.authConfig.JWTSecret)
	if err != nil {
		c.logger.WithField("error", err.Error()).Warn(ctx, "Service authentication token validation failed")

		// Try to refresh if configured
		if c.authConfig.AutoRefresh {
			refreshErr := c.RefreshAuthToken(ctx)
			if refreshErr != nil {
				return errors.Wrap(refreshErr, errors.ErrCodeUnauthorized, "Token validation failed and refresh failed")
			}
			return nil // Token refreshed successfully
		}

		return errors.Wrap(err, errors.ErrCodeUnauthorized, "Service authentication token is invalid")
	}

	return nil
}

// SetHeader sets a default header for all requests
func (c *Client) SetHeader(key, value string) {
	c.defaultHeaders[key] = value
}

// Request represents an HTTP request
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Body    interface{}       `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Query   map[string]string `json:"query,omitempty"`
}

// Response represents an HTTP response
type Response struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       []byte              `json:"body"`
	Success    bool                `json:"success"`
	Data       interface{}         `json:"data,omitempty"`
	Error      string              `json:"error,omitempty"`
}

// Do executes an HTTP request with retry logic and authentication handling
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	// Validate authentication if configured
	if c.authConfig != nil {
		if err := c.ValidateAuthToken(ctx); err != nil {
			return nil, err
		}
	}

	var lastErr error

	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		if attempt > 0 {
			// Wait before retry (exponential backoff)
			waitTime := time.Duration(attempt) * time.Second

			c.logger.WithFields(map[string]interface{}{
				"attempt":   attempt,
				"wait_time": waitTime,
				"method":    req.Method,
				"path":      req.Path,
			}).Info(ctx, "Retrying HTTP request")

			select {
			case <-ctx.Done():
				return nil, errors.Wrap(ctx.Err(), errors.ErrCodeInternal, "Request cancelled during retry")
			case <-time.After(waitTime):
			}
		}

		response, err := c.doRequest(ctx, req)
		if err == nil {
			// Check for authentication errors and handle token refresh
			if response.StatusCode == 401 && c.authConfig != nil && c.authConfig.AutoRefresh {
				c.logger.WithField("attempt", attempt).Warn(ctx, "Authentication failed, attempting token refresh")

				if refreshErr := c.RefreshAuthToken(ctx); refreshErr == nil {
					// Successfully refreshed token, clear the response and continue to retry
					response = nil
					continue
				} else {
					// Failed to refresh token, treat as auth error
					lastErr = refreshErr
					break
				}
			}

			// For successful responses (non-error status codes)
			if response.StatusCode < 400 {
				// Log successful request
				c.logger.WithFields(map[string]interface{}{
					"method":      req.Method,
					"path":        req.Path,
					"status_code": response.StatusCode,
					"attempt":     attempt + 1,
				}).Debug(ctx, "HTTP request completed successfully")

				return response, nil
			}

			// For HTTP error status codes, return immediately without retry
			// Only network errors should trigger retries
			return response, nil
		} else {
			// Network/connection error - retry these
			lastErr = err
		}
	}

	errorMessage := "unknown error"
	if lastErr != nil {
		errorMessage = lastErr.Error()
	}
	c.logger.WithFields(map[string]interface{}{
		"method":   req.Method,
		"path":     req.Path,
		"attempts": c.retryAttempts + 1,
		"error":    errorMessage,
	}).Error(ctx, "HTTP request failed after all retries", lastErr)

	if lastErr != nil {
		return nil, errors.Wrap(lastErr, errors.ErrCodeInternal, "HTTP request failed after retries")
	}
	return nil, errors.New(errors.ErrCodeInternal, "HTTP request failed after retries")
}

// doRequest executes a single HTTP request with enhanced logging
func (c *Client) doRequest(ctx context.Context, req *Request) (*Response, error) {
	// Build URL
	url := c.baseURL + req.Path
	if len(req.Query) > 0 {
		url += "?" + c.buildQueryString(req.Query)
	}

	// Log request start
	startTime := time.Now()
	c.logger.WithFields(map[string]interface{}{
		"method":   req.Method,
		"url":      url,
		"has_body": req.Body != nil,
	}).Debug(ctx, "Starting HTTP request")

	// Prepare body
	var bodyReader io.Reader
	if req.Body != nil {
		bodyBytes, err := json.Marshal(req.Body)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeValidation, "Failed to marshal request body")
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, url, bodyReader)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to create HTTP request")
	}

	// Set headers
	for key, value := range c.defaultHeaders {
		httpReq.Header.Set(key, value)
	}
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Execute request
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		duration := time.Since(startTime)
		c.logger.WithFields(map[string]interface{}{
			"method":      req.Method,
			"url":         url,
			"duration_ms": float64(duration.Nanoseconds()) / 1e6,
			"error":       err.Error(),
		}).Error(ctx, "HTTP request execution failed", err)

		return nil, errors.Wrap(err, errors.ErrCodeInternal, "HTTP request execution failed")
	}
	defer httpResp.Body.Close()

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to read response body")
	}

	duration := time.Since(startTime)
	response := &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    httpResp.Header,
		Body:       body,
	}

	// Log response
	c.logger.WithFields(map[string]interface{}{
		"method":        req.Method,
		"url":           url,
		"status_code":   httpResp.StatusCode,
		"duration_ms":   float64(duration.Nanoseconds()) / 1e6,
		"response_size": len(body),
	}).Debug(ctx, "HTTP request completed")

	// Try to parse response as APIResponse
	var apiResponse models.APIResponse
	if err := json.Unmarshal(body, &apiResponse); err == nil {
		response.Success = apiResponse.Success
		response.Data = apiResponse.Data
		response.Error = apiResponse.Error
	}

	return response, nil
}

// buildQueryString builds a query string from parameters
func (c *Client) buildQueryString(params map[string]string) string {
	var parts []string
	for key, value := range params {
		parts = append(parts, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(parts, "&")
}

// Convenience methods for common HTTP operations

// Get performs a GET request
func (c *Client) Get(ctx context.Context, path string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "GET",
		Path:   path,
	})
}

// GetWithQuery performs a GET request with query parameters
func (c *Client) GetWithQuery(ctx context.Context, path string, query map[string]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "GET",
		Path:   path,
		Query:  query,
	})
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "POST",
		Path:   path,
		Body:   body,
	})
}

// Put performs a PUT request
func (c *Client) Put(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "PUT",
		Path:   path,
		Body:   body,
	})
}

// Patch performs a PATCH request
func (c *Client) Patch(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "PATCH",
		Path:   path,
		Body:   body,
	})
}

// Delete performs a DELETE request
func (c *Client) Delete(ctx context.Context, path string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "DELETE",
		Path:   path,
	})
}

// Service-specific helper methods

// HealthCheck performs a health check request
func (c *Client) HealthCheck(ctx context.Context) (*models.HealthCheck, error) {
	response, err := c.Get(ctx, "/health")
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.Newf(errors.ErrCodeInternal, "Health check failed with status %d", response.StatusCode)
	}

	var healthCheck models.HealthCheck
	if err := json.Unmarshal(response.Body, &healthCheck); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to parse health check response")
	}

	return &healthCheck, nil
}

// IsHealthy checks if the service is healthy
func (c *Client) IsHealthy(ctx context.Context) bool {
	healthCheck, err := c.HealthCheck(ctx)
	return err == nil && healthCheck != nil && healthCheck.Status == "healthy"
}

// ParseError extracts error information from response
func (c *Client) ParseError(response *Response) error {
	if response.Success {
		return nil
	}

	if response.Error != "" {
		return errors.New(errors.ErrCodeInternal, response.Error)
	}

	return errors.Newf(errors.ErrCodeInternal, "HTTP request failed with status %d", response.StatusCode)
}

// UnmarshalResponse unmarshals response data into target struct
func (c *Client) UnmarshalResponse(response *Response, target interface{}) error {
	if !response.Success {
		return c.ParseError(response)
	}

	if response.Data == nil {
		return errors.New(errors.ErrCodeValidation, "No data in response")
	}

	dataBytes, err := json.Marshal(response.Data)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to marshal response data")
	}

	if err := json.Unmarshal(dataBytes, target); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternal, "Failed to unmarshal response data")
	}

	return nil
}
