package testing

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/facuhernandez99/library/pkg/models"
	"github.com/stretchr/testify/mock"
)

// MockTokenStorage is a mock implementation of auth.TokenStorage
type MockTokenStorage struct {
	mock.Mock
}

func (m *MockTokenStorage) BlacklistToken(tokenID string, expiresAt time.Time) error {
	args := m.Called(tokenID, expiresAt)
	return args.Error(0)
}

func (m *MockTokenStorage) IsBlacklisted(tokenID string) (bool, error) {
	args := m.Called(tokenID)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenStorage) CleanupExpired() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockTokenStorage) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockUserRepository is a mock implementation of a user repository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(id int) (*models.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(username string) (*models.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*models.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *models.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id int) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) List(offset, limit int) ([]*models.User, error) {
	args := m.Called(offset, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserRepository) Count() (int, error) {
	args := m.Called()
	return args.Int(0), args.Error(1)
}

// MockDatabase is a mock implementation of database operations
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) Exec(query string, args ...interface{}) (sql.Result, error) {
	mockArgs := append([]interface{}{query}, args...)
	callArgs := m.Called(mockArgs...)
	return callArgs.Get(0).(sql.Result), callArgs.Error(1)
}

func (m *MockDatabase) Query(query string, args ...interface{}) (*sql.Rows, error) {
	mockArgs := append([]interface{}{query}, args...)
	callArgs := m.Called(mockArgs...)
	if callArgs.Get(0) == nil {
		return nil, callArgs.Error(1)
	}
	return callArgs.Get(0).(*sql.Rows), callArgs.Error(1)
}

func (m *MockDatabase) QueryRow(query string, args ...interface{}) *sql.Row {
	mockArgs := append([]interface{}{query}, args...)
	callArgs := m.Called(mockArgs...)
	return callArgs.Get(0).(*sql.Row)
}

func (m *MockDatabase) Begin() (*sql.Tx, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sql.Tx), args.Error(1)
}

func (m *MockDatabase) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockDatabase) Ping() error {
	args := m.Called()
	return args.Error(0)
}

// MockResult is a mock implementation of sql.Result
type MockResult struct {
	mock.Mock
}

func (m *MockResult) LastInsertId() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockResult) RowsAffected() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

// MockHTTPClient is a mock implementation of an HTTP client
type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Get(url string) (*MockHTTPResponse, error) {
	args := m.Called(url)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MockHTTPResponse), args.Error(1)
}

func (m *MockHTTPClient) Post(url string, body interface{}) (*MockHTTPResponse, error) {
	args := m.Called(url, body)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MockHTTPResponse), args.Error(1)
}

func (m *MockHTTPClient) Put(url string, body interface{}) (*MockHTTPResponse, error) {
	args := m.Called(url, body)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MockHTTPResponse), args.Error(1)
}

func (m *MockHTTPClient) Delete(url string) (*MockHTTPResponse, error) {
	args := m.Called(url)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*MockHTTPResponse), args.Error(1)
}

// MockHTTPResponse represents a mock HTTP response
type MockHTTPResponse struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string
}

// MockEmailService is a mock implementation of an email service
type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) SendEmail(to, subject, body string) error {
	args := m.Called(to, subject, body)
	return args.Error(0)
}

func (m *MockEmailService) SendHTMLEmail(to, subject, htmlBody string) error {
	args := m.Called(to, subject, htmlBody)
	return args.Error(0)
}

func (m *MockEmailService) SendTemplateEmail(to, subject, template string, data interface{}) error {
	args := m.Called(to, subject, template, data)
	return args.Error(0)
}

// MockCacheService is a mock implementation of a cache service
type MockCacheService struct {
	mock.Mock
}

func (m *MockCacheService) Get(key string) (interface{}, error) {
	args := m.Called(key)
	return args.Get(0), args.Error(1)
}

func (m *MockCacheService) Set(key string, value interface{}, expiration time.Duration) error {
	args := m.Called(key, value, expiration)
	return args.Error(0)
}

func (m *MockCacheService) Delete(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockCacheService) Exists(key string) (bool, error) {
	args := m.Called(key)
	return args.Bool(0), args.Error(1)
}

func (m *MockCacheService) Clear() error {
	args := m.Called()
	return args.Error(0)
}

// MockFileStorage is a mock implementation of a file storage service
type MockFileStorage struct {
	mock.Mock
}

func (m *MockFileStorage) Upload(filename string, data []byte) (string, error) {
	args := m.Called(filename, data)
	return args.String(0), args.Error(1)
}

func (m *MockFileStorage) Download(filename string) ([]byte, error) {
	args := m.Called(filename)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockFileStorage) Delete(filename string) error {
	args := m.Called(filename)
	return args.Error(0)
}

func (m *MockFileStorage) Exists(filename string) (bool, error) {
	args := m.Called(filename)
	return args.Bool(0), args.Error(1)
}

func (m *MockFileStorage) GetURL(filename string) (string, error) {
	args := m.Called(filename)
	return args.String(0), args.Error(1)
}

// MockLogger is a mock implementation of a logger
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, args ...interface{}) {
	callArgs := append([]interface{}{msg}, args...)
	m.Called(callArgs...)
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	callArgs := append([]interface{}{msg}, args...)
	m.Called(callArgs...)
}

func (m *MockLogger) Warn(msg string, args ...interface{}) {
	callArgs := append([]interface{}{msg}, args...)
	m.Called(callArgs...)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	callArgs := append([]interface{}{msg}, args...)
	m.Called(callArgs...)
}

func (m *MockLogger) Fatal(msg string, args ...interface{}) {
	callArgs := append([]interface{}{msg}, args...)
	m.Called(callArgs...)
}

// MockContext is a mock implementation of context operations
type MockContext struct {
	mock.Mock
	context.Context
}

func (m *MockContext) Deadline() (deadline time.Time, ok bool) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Bool(1)
}

func (m *MockContext) Done() <-chan struct{} {
	args := m.Called()
	return args.Get(0).(<-chan struct{})
}

func (m *MockContext) Err() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockContext) Value(key interface{}) interface{} {
	args := m.Called(key)
	return args.Get(0)
}

// Test Data Builders

// UserBuilder helps build test users with fluent interface
type UserBuilder struct {
	user *models.User
}

// NewUserBuilder creates a new user builder
func NewUserBuilder() *UserBuilder {
	return &UserBuilder{
		user: &models.User{
			Username:     "testuser",
			PasswordHash: "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", // "password"
		},
	}
}

func (b *UserBuilder) WithUsername(username string) *UserBuilder {
	b.user.Username = username
	return b
}

func (b *UserBuilder) WithPasswordHash(passwordHash string) *UserBuilder {
	b.user.PasswordHash = passwordHash
	return b
}

func (b *UserBuilder) WithID(id int64) *UserBuilder {
	b.user.ID = id
	return b
}

func (b *UserBuilder) Build() *models.User {
	return b.user
}

// Error Builders for testing error scenarios

// ErrorBuilder helps create consistent error responses for testing
type ErrorBuilder struct {
	shouldFail bool
	err        error
}

// NewErrorBuilder creates a new error builder
func NewErrorBuilder() *ErrorBuilder {
	return &ErrorBuilder{
		shouldFail: false,
		err:        nil,
	}
}

func (b *ErrorBuilder) WithError(err error) *ErrorBuilder {
	b.shouldFail = true
	b.err = err
	return b
}

func (b *ErrorBuilder) WithDatabaseError() *ErrorBuilder {
	b.shouldFail = true
	b.err = errors.New("database connection failed")
	return b
}

func (b *ErrorBuilder) WithValidationError() *ErrorBuilder {
	b.shouldFail = true
	b.err = errors.New("validation failed")
	return b
}

func (b *ErrorBuilder) WithNotFoundError() *ErrorBuilder {
	b.shouldFail = true
	b.err = errors.New("resource not found")
	return b
}

func (b *ErrorBuilder) ShouldFail() bool {
	return b.shouldFail
}

func (b *ErrorBuilder) Error() error {
	return b.err
}

// Mock Factories

// CreateMockTokenStorage creates a configured mock token storage
func CreateMockTokenStorage() *MockTokenStorage {
	mockStorage := &MockTokenStorage{}

	// Default behaviors
	mockStorage.On("BlacklistToken", mock.Anything, mock.Anything).Return(nil)
	mockStorage.On("IsBlacklisted", mock.Anything).Return(false, nil)
	mockStorage.On("CleanupExpired").Return(nil)
	mockStorage.On("Close").Return(nil)

	return mockStorage
}

// CreateMockUserRepository creates a configured mock user repository
func CreateMockUserRepository() *MockUserRepository {
	mockRepo := &MockUserRepository{}

	// Default behaviors for common cases
	mockRepo.On("Create", mock.Anything).Return(nil)
	mockRepo.On("Update", mock.Anything).Return(nil)
	mockRepo.On("Delete", mock.Anything).Return(nil)
	mockRepo.On("Count").Return(0, nil)

	return mockRepo
}

// CreateMockDatabase creates a configured mock database
func CreateMockDatabase() *MockDatabase {
	mockDB := &MockDatabase{}

	// Default behaviors
	mockDB.On("Ping").Return(nil)
	mockDB.On("Close").Return(nil)

	return mockDB
}
