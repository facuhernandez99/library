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

	"github.com/facuhernandez99/blog/pkg/errors"
	"github.com/facuhernandez99/blog/pkg/models"
)

// Client represents an HTTP client for inter-service communication
type Client struct {
	httpClient     *http.Client
	baseURL        string
	defaultHeaders map[string]string
	timeout        time.Duration
	retryAttempts  int
}

// ClientConfig holds HTTP client configuration
type ClientConfig struct {
	BaseURL       string            `json:"base_url"`
	Timeout       time.Duration     `json:"timeout"`
	RetryAttempts int               `json:"retry_attempts"`
	Headers       map[string]string `json:"headers"`
}

// DefaultClientConfig returns default HTTP client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
		Headers:       make(map[string]string),
	}
}

// NewClient creates a new HTTP client for inter-service communication
func NewClient(config *ClientConfig) *Client {
	if config == nil {
		config = DefaultClientConfig()
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	defaultHeaders := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
		"User-Agent":   "blog-microservice/1.0",
	}

	// Merge custom headers
	for key, value := range config.Headers {
		defaultHeaders[key] = value
	}

	return &Client{
		httpClient:     httpClient,
		baseURL:        strings.TrimSuffix(config.BaseURL, "/"),
		defaultHeaders: defaultHeaders,
		timeout:        config.Timeout,
		retryAttempts:  config.RetryAttempts,
	}
}

// SetAuthToken sets the authorization token for requests
func (c *Client) SetAuthToken(token string) {
	c.defaultHeaders["Authorization"] = fmt.Sprintf("Bearer %s", token)
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

// Do executes an HTTP request with retry logic
func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	var lastErr error

	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		if attempt > 0 {
			// Wait before retry (exponential backoff)
			waitTime := time.Duration(attempt) * time.Second
			select {
			case <-ctx.Done():
				return nil, errors.Wrap(ctx.Err(), errors.ErrCodeInternal, "Request cancelled during retry")
			case <-time.After(waitTime):
			}
		}

		response, err := c.doRequest(ctx, req)
		if err == nil {
			return response, nil
		}

		lastErr = err

		// Don't retry on client errors (4xx) except 429 (Rate Limited)
		if response != nil && response.StatusCode >= 400 && response.StatusCode < 500 && response.StatusCode != 429 {
			break
		}
	}

	return nil, errors.Wrap(lastErr, errors.ErrCodeInternal, "HTTP request failed after retries")
}

// doRequest executes a single HTTP request
func (c *Client) doRequest(ctx context.Context, req *Request) (*Response, error) {
	// Build URL
	url := c.baseURL + req.Path
	if len(req.Query) > 0 {
		url += "?" + c.buildQueryString(req.Query)
	}

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
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "HTTP request execution failed")
	}
	defer httpResp.Body.Close()

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to read response body")
	}

	response := &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    httpResp.Header,
		Body:       body,
	}

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
