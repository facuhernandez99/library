package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/facuhernandez99/library/pkg/errors"
)

// LogLevel represents the severity level of a log entry
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	RequestID string                 `json:"request_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Stack     string                 `json:"stack,omitempty"`
	Service   string                 `json:"service,omitempty"`
	Version   string                 `json:"version,omitempty"`
}

// Logger represents the main logger configuration
type Logger struct {
	level      LogLevel
	output     io.Writer
	service    string
	version    string
	production bool
	mutex      sync.RWMutex
	sanitizer  *ErrorSanitizer
}

// Config holds logger configuration
type Config struct {
	Level      LogLevel
	Output     io.Writer
	Service    string
	Version    string
	Production bool
}

// DefaultConfig returns a default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      LevelInfo,
		Output:     os.Stdout,
		Service:    "library-service",
		Version:    "1.0.0",
		Production: false,
	}
}

// NewLogger creates a new logger instance
func NewLogger(config *Config) *Logger {
	if config == nil {
		config = DefaultConfig()
	}

	return &Logger{
		level:      config.Level,
		output:     config.Output,
		service:    config.Service,
		version:    config.Version,
		production: config.Production,
		sanitizer:  NewErrorSanitizer(config.Production),
	}
}

// Global logger instance
var defaultLogger *Logger
var once sync.Once

// GetDefault returns the default logger instance
func GetDefault() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger(DefaultConfig())
	})
	return defaultLogger
}

// SetDefault sets the default logger instance
func SetDefault(logger *Logger) {
	defaultLogger = logger
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.level = level
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() LogLevel {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.level
}

// shouldLog checks if a message should be logged based on level
func (l *Logger) shouldLog(level LogLevel) bool {
	return level >= l.GetLevel()
}

// log writes a log entry with the specified level and message
func (l *Logger) log(ctx context.Context, level LogLevel, message string, fields map[string]interface{}, err error) {
	if !l.shouldLog(level) {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level.String(),
		Message:   message,
		Service:   l.service,
		Version:   l.version,
		Fields:    fields,
	}

	// Extract context values
	if requestID := GetRequestIDFromContext(ctx); requestID != "" {
		entry.RequestID = requestID
	}
	if userID := GetUserIDFromContext(ctx); userID != "" {
		entry.UserID = userID
	}

	// Handle error
	if err != nil {
		sanitizedErr := l.sanitizer.Sanitize(err)
		entry.Error = sanitizedErr.Error()

		// Add stack trace for errors in non-production or if it's an internal error
		if level >= LevelError && (!l.production || l.isInternalError(err)) {
			entry.Stack = l.getStackTrace()
		}
	}

	// Marshal to JSON
	data, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		// Fallback to simple format if JSON marshaling fails
		fallback := fmt.Sprintf(`{"timestamp":"%s","level":"%s","message":"JSON marshal error: %v","service":"%s"}`,
			entry.Timestamp.Format(time.RFC3339), entry.Level, marshalErr, l.service)
		data = []byte(fallback)
	}

	// Write to output
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.output.Write(data)
	l.output.Write([]byte("\n"))
}

// isInternalError checks if an error is an internal application error
func (l *Logger) isInternalError(err error) bool {
	if appErr, ok := errors.IsAppError(err); ok {
		return appErr.Code == errors.ErrCodeInternal ||
			appErr.Code == errors.ErrCodeDatabaseError ||
			appErr.Code == errors.ErrCodeConnectionFailed ||
			appErr.Code == errors.ErrCodeQueryFailed
	}
	return true // Unknown errors are considered internal
}

// getStackTrace returns the current stack trace
func (l *Logger) getStackTrace() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// WithFields returns a new logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *ContextLogger {
	return &ContextLogger{
		logger: l,
		fields: fields,
	}
}

// WithField returns a new logger with an additional field
func (l *Logger) WithField(key string, value interface{}) *ContextLogger {
	return l.WithFields(map[string]interface{}{key: value})
}

// Debug logs a debug message
func (l *Logger) Debug(ctx context.Context, message string) {
	l.log(ctx, LevelDebug, message, nil, nil)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LevelDebug, fmt.Sprintf(format, args...), nil, nil)
}

// Info logs an info message
func (l *Logger) Info(ctx context.Context, message string) {
	l.log(ctx, LevelInfo, message, nil, nil)
}

// Infof logs a formatted info message
func (l *Logger) Infof(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LevelInfo, fmt.Sprintf(format, args...), nil, nil)
}

// Warn logs a warning message
func (l *Logger) Warn(ctx context.Context, message string) {
	l.log(ctx, LevelWarn, message, nil, nil)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(ctx context.Context, format string, args ...interface{}) {
	l.log(ctx, LevelWarn, fmt.Sprintf(format, args...), nil, nil)
}

// Error logs an error message
func (l *Logger) Error(ctx context.Context, message string, err error) {
	l.log(ctx, LevelError, message, nil, err)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(ctx context.Context, err error, format string, args ...interface{}) {
	l.log(ctx, LevelError, fmt.Sprintf(format, args...), nil, err)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(ctx context.Context, message string, err error) {
	l.log(ctx, LevelFatal, message, nil, err)
	os.Exit(1)
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(ctx context.Context, err error, format string, args ...interface{}) {
	l.log(ctx, LevelFatal, fmt.Sprintf(format, args...), nil, err)
	os.Exit(1)
}

// ContextLogger wraps the main logger with additional context fields
type ContextLogger struct {
	logger *Logger
	fields map[string]interface{}
}

// WithField adds an additional field to the context logger
func (cl *ContextLogger) WithField(key string, value interface{}) *ContextLogger {
	newFields := make(map[string]interface{})
	for k, v := range cl.fields {
		newFields[k] = v
	}
	newFields[key] = value
	return &ContextLogger{
		logger: cl.logger,
		fields: newFields,
	}
}

// WithFields adds additional fields to the context logger
func (cl *ContextLogger) WithFields(fields map[string]interface{}) *ContextLogger {
	newFields := make(map[string]interface{})
	for k, v := range cl.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}
	return &ContextLogger{
		logger: cl.logger,
		fields: newFields,
	}
}

// Debug logs a debug message with context fields
func (cl *ContextLogger) Debug(ctx context.Context, message string) {
	cl.logger.log(ctx, LevelDebug, message, cl.fields, nil)
}

// Debugf logs a formatted debug message with context fields
func (cl *ContextLogger) Debugf(ctx context.Context, format string, args ...interface{}) {
	cl.logger.log(ctx, LevelDebug, fmt.Sprintf(format, args...), cl.fields, nil)
}

// Info logs an info message with context fields
func (cl *ContextLogger) Info(ctx context.Context, message string) {
	cl.logger.log(ctx, LevelInfo, message, cl.fields, nil)
}

// Infof logs a formatted info message with context fields
func (cl *ContextLogger) Infof(ctx context.Context, format string, args ...interface{}) {
	cl.logger.log(ctx, LevelInfo, fmt.Sprintf(format, args...), cl.fields, nil)
}

// Warn logs a warning message with context fields
func (cl *ContextLogger) Warn(ctx context.Context, message string) {
	cl.logger.log(ctx, LevelWarn, message, cl.fields, nil)
}

// Warnf logs a formatted warning message with context fields
func (cl *ContextLogger) Warnf(ctx context.Context, format string, args ...interface{}) {
	cl.logger.log(ctx, LevelWarn, fmt.Sprintf(format, args...), cl.fields, nil)
}

// Error logs an error message with context fields
func (cl *ContextLogger) Error(ctx context.Context, message string, err error) {
	cl.logger.log(ctx, LevelError, message, cl.fields, err)
}

// Errorf logs a formatted error message with context fields
func (cl *ContextLogger) Errorf(ctx context.Context, err error, format string, args ...interface{}) {
	cl.logger.log(ctx, LevelError, fmt.Sprintf(format, args...), cl.fields, err)
}

// Fatal logs a fatal message with context fields and exits
func (cl *ContextLogger) Fatal(ctx context.Context, message string, err error) {
	cl.logger.log(ctx, LevelFatal, message, cl.fields, err)
	os.Exit(1)
}

// Fatalf logs a formatted fatal message with context fields and exits
func (cl *ContextLogger) Fatalf(ctx context.Context, err error, format string, args ...interface{}) {
	cl.logger.log(ctx, LevelFatal, fmt.Sprintf(format, args...), cl.fields, err)
	os.Exit(1)
}

// Package-level convenience functions using the default logger

// Debug logs a debug message using the default logger
func Debug(ctx context.Context, message string) {
	GetDefault().Debug(ctx, message)
}

// Debugf logs a formatted debug message using the default logger
func Debugf(ctx context.Context, format string, args ...interface{}) {
	GetDefault().Debugf(ctx, format, args...)
}

// Info logs an info message using the default logger
func Info(ctx context.Context, message string) {
	GetDefault().Info(ctx, message)
}

// Infof logs a formatted info message using the default logger
func Infof(ctx context.Context, format string, args ...interface{}) {
	GetDefault().Infof(ctx, format, args...)
}

// Warn logs a warning message using the default logger
func Warn(ctx context.Context, message string) {
	GetDefault().Warn(ctx, message)
}

// Warnf logs a formatted warning message using the default logger
func Warnf(ctx context.Context, format string, args ...interface{}) {
	GetDefault().Warnf(ctx, format, args...)
}

// Error logs an error message using the default logger
func Error(ctx context.Context, message string, err error) {
	GetDefault().Error(ctx, message, err)
}

// Errorf logs a formatted error message using the default logger
func Errorf(ctx context.Context, err error, format string, args ...interface{}) {
	GetDefault().Errorf(ctx, err, format, args...)
}

// Fatal logs a fatal message using the default logger and exits
func Fatal(ctx context.Context, message string, err error) {
	GetDefault().Fatal(ctx, message, err)
}

// Fatalf logs a formatted fatal message using the default logger and exits
func Fatalf(ctx context.Context, err error, format string, args ...interface{}) {
	GetDefault().Fatalf(ctx, err, format, args...)
}

// WithField returns a context logger with an additional field using the default logger
func WithField(key string, value interface{}) *ContextLogger {
	return GetDefault().WithField(key, value)
}

// WithFields returns a context logger with additional fields using the default logger
func WithFields(fields map[string]interface{}) *ContextLogger {
	return GetDefault().WithFields(fields)
}
