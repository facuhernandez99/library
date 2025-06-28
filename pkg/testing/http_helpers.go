package testing

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HTTPTestHelper provides utilities for HTTP API testing
type HTTPTestHelper struct {
	Router *gin.Engine
	t      *testing.T
}

// NewHTTPTestHelper creates a new HTTP test helper
func NewHTTPTestHelper(t *testing.T) *HTTPTestHelper {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	return &HTTPTestHelper{
		Router: router,
		t:      t,
	}
}

// TestRequest represents an HTTP test request
type TestRequest struct {
	Method      string
	Path        string
	Body        interface{}
	Headers     map[string]string
	QueryParams map[string]string
	AuthToken   string
}

// TestResponse represents an HTTP test response
type TestResponse struct {
	*httptest.ResponseRecorder
	Body map[string]interface{}
}

// MakeRequest performs an HTTP request and returns the response
func (h *HTTPTestHelper) MakeRequest(req TestRequest) *TestResponse {
	var bodyReader io.Reader

	// Handle request body
	if req.Body != nil {
		switch body := req.Body.(type) {
		case string:
			bodyReader = strings.NewReader(body)
		case []byte:
			bodyReader = bytes.NewReader(body)
		default:
			bodyBytes, err := json.Marshal(body)
			require.NoError(h.t, err, "Failed to marshal request body")
			bodyReader = bytes.NewReader(bodyBytes)
		}
	}

	// Create HTTP request
	httpReq, err := http.NewRequest(req.Method, req.Path, bodyReader)
	require.NoError(h.t, err, "Failed to create HTTP request")

	// Add query parameters
	if len(req.QueryParams) > 0 {
		q := url.Values{}
		for key, value := range req.QueryParams {
			q.Add(key, value)
		}
		httpReq.URL.RawQuery = q.Encode()
	}

	// Add headers
	if len(req.Headers) > 0 {
		for key, value := range req.Headers {
			httpReq.Header.Set(key, value)
		}
	}

	// Add authorization header
	if req.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.AuthToken)
	}

	// Set content type if not provided and body exists
	if req.Body != nil && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	h.Router.ServeHTTP(w, httpReq)

	// Parse response body
	var responseBody map[string]interface{}
	if w.Body.Len() > 0 {
		err := json.Unmarshal(w.Body.Bytes(), &responseBody)
		if err != nil {
			// If JSON parsing fails, store raw body as string
			responseBody = map[string]interface{}{
				"raw": w.Body.String(),
			}
		}
	}

	return &TestResponse{
		ResponseRecorder: w,
		Body:             responseBody,
	}
}

// GET performs a GET request
func (h *HTTPTestHelper) GET(path string, params ...map[string]string) *TestResponse {
	req := TestRequest{
		Method: "GET",
		Path:   path,
	}

	if len(params) > 0 {
		req.QueryParams = params[0]
	}

	return h.MakeRequest(req)
}

// POST performs a POST request with JSON body
func (h *HTTPTestHelper) POST(path string, body interface{}) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method: "POST",
		Path:   path,
		Body:   body,
	})
}

// PUT performs a PUT request with JSON body
func (h *HTTPTestHelper) PUT(path string, body interface{}) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method: "PUT",
		Path:   path,
		Body:   body,
	})
}

// DELETE performs a DELETE request
func (h *HTTPTestHelper) DELETE(path string) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method: "DELETE",
		Path:   path,
	})
}

// PATCH performs a PATCH request with JSON body
func (h *HTTPTestHelper) PATCH(path string, body interface{}) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method: "PATCH",
		Path:   path,
		Body:   body,
	})
}

// WithAuth sets authorization token for subsequent requests
func (h *HTTPTestHelper) WithAuth(token string) *AuthorizedHTTPTestHelper {
	return &AuthorizedHTTPTestHelper{
		HTTPTestHelper: h,
		token:          token,
	}
}

// AuthorizedHTTPTestHelper provides HTTP test utilities with authentication
type AuthorizedHTTPTestHelper struct {
	*HTTPTestHelper
	token string
}

// GET performs an authenticated GET request
func (h *AuthorizedHTTPTestHelper) GET(path string, params ...map[string]string) *TestResponse {
	req := TestRequest{
		Method:    "GET",
		Path:      path,
		AuthToken: h.token,
	}

	if len(params) > 0 {
		req.QueryParams = params[0]
	}

	return h.MakeRequest(req)
}

// POST performs an authenticated POST request
func (h *AuthorizedHTTPTestHelper) POST(path string, body interface{}) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method:    "POST",
		Path:      path,
		Body:      body,
		AuthToken: h.token,
	})
}

// PUT performs an authenticated PUT request
func (h *AuthorizedHTTPTestHelper) PUT(path string, body interface{}) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method:    "PUT",
		Path:      path,
		Body:      body,
		AuthToken: h.token,
	})
}

// DELETE performs an authenticated DELETE request
func (h *AuthorizedHTTPTestHelper) DELETE(path string) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method:    "DELETE",
		Path:      path,
		AuthToken: h.token,
	})
}

// PATCH performs an authenticated PATCH request
func (h *AuthorizedHTTPTestHelper) PATCH(path string, body interface{}) *TestResponse {
	return h.MakeRequest(TestRequest{
		Method:    "PATCH",
		Path:      path,
		Body:      body,
		AuthToken: h.token,
	})
}

// Response Validation Methods

// AssertStatusCode validates the HTTP status code
func (r *TestResponse) AssertStatusCode(t *testing.T, expectedCode int) {
	assert.Equal(t, expectedCode, r.Code, "Unexpected status code")
}

// AssertSuccess validates that the response indicates success
func (r *TestResponse) AssertSuccess(t *testing.T) {
	assert.Equal(t, true, r.Body["success"], "Expected success=true")
	assert.Empty(t, r.Body["error"], "Expected no error message")
}

// AssertError validates that the response indicates an error
func (r *TestResponse) AssertError(t *testing.T, expectedMessage string) {
	assert.Equal(t, false, r.Body["success"], "Expected success=false")
	if expectedMessage != "" {
		assert.Equal(t, expectedMessage, r.Body["error"], "Unexpected error message")
	} else {
		assert.NotEmpty(t, r.Body["error"], "Expected error message")
	}
}

// AssertHasData validates that the response contains data
func (r *TestResponse) AssertHasData(t *testing.T) {
	assert.NotNil(t, r.Body["data"], "Expected data to be present")
}

// AssertDataField validates a specific field in the response data
func (r *TestResponse) AssertDataField(t *testing.T, field string, expectedValue interface{}) {
	data, ok := r.Body["data"].(map[string]interface{})
	require.True(t, ok, "Response data should be an object")
	assert.Equal(t, expectedValue, data[field], "Unexpected value for field %s", field)
}

// AssertPagination validates pagination metadata
func (r *TestResponse) AssertPagination(t *testing.T, expectedPage, expectedLimit, expectedTotal int) {
	pagination, ok := r.Body["pagination"].(map[string]interface{})
	require.True(t, ok, "Response should contain pagination")

	assert.Equal(t, float64(expectedPage), pagination["page"], "Unexpected page")
	assert.Equal(t, float64(expectedLimit), pagination["limit"], "Unexpected limit")
	assert.Equal(t, float64(expectedTotal), pagination["total"], "Unexpected total")
}

// AssertHeaderPresent validates that a header is present
func (r *TestResponse) AssertHeaderPresent(t *testing.T, headerName string) {
	assert.NotEmpty(t, r.Header().Get(headerName), "Expected header %s to be present", headerName)
}

// AssertHeaderValue validates a specific header value
func (r *TestResponse) AssertHeaderValue(t *testing.T, headerName, expectedValue string) {
	assert.Equal(t, expectedValue, r.Header().Get(headerName), "Unexpected header value for %s", headerName)
}

// AssertContentType validates the response content type
func (r *TestResponse) AssertContentType(t *testing.T, expectedType string) {
	assert.Equal(t, expectedType, r.Header().Get("Content-Type"), "Unexpected content type")
}

// GetData returns the data field from the response
func (r *TestResponse) GetData() interface{} {
	return r.Body["data"]
}

// GetDataAsMap returns the data field as a map
func (r *TestResponse) GetDataAsMap() map[string]interface{} {
	if data, ok := r.Body["data"].(map[string]interface{}); ok {
		return data
	}
	return nil
}

// GetDataAsArray returns the data field as an array
func (r *TestResponse) GetDataAsArray() []interface{} {
	if data, ok := r.Body["data"].([]interface{}); ok {
		return data
	}
	return nil
}

// GetError returns the error message from the response
func (r *TestResponse) GetError() string {
	if err, ok := r.Body["error"].(string); ok {
		return err
	}
	return ""
}

// BindResponseTo unmarshals response data into the provided struct
func (r *TestResponse) BindResponseTo(v interface{}) error {
	return json.Unmarshal(r.ResponseRecorder.Body.Bytes(), v)
}

// BindDataTo unmarshals response data field into the provided struct
func (r *TestResponse) BindDataTo(v interface{}) error {
	if r.Body["data"] == nil {
		return nil
	}

	dataBytes, err := json.Marshal(r.Body["data"])
	if err != nil {
		return err
	}

	return json.Unmarshal(dataBytes, v)
}

// CreateTestContext creates a Gin test context for testing handlers directly
func CreateTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return c, w
}

// CreateTestContextWithRequest creates a Gin test context with an HTTP request
func CreateTestContextWithRequest(method, path string, body io.Reader) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")

	c, _ := gin.CreateTestContext(w)
	c.Request = req

	return c, w
}

// CreateJSONTestContext creates a test context with JSON request body
func CreateJSONTestContext(method, path string, body interface{}) (*gin.Context, *httptest.ResponseRecorder) {
	jsonBody, _ := json.Marshal(body)
	return CreateTestContextWithRequest(method, path, bytes.NewReader(jsonBody))
}
