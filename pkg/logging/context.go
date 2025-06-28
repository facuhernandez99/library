package logging

import (
	"context"
)

// Context keys for logging context values
type contextKey string

const (
	requestIDKey contextKey = "request_id"
	userIDKey    contextKey = "user_id"
)

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestIDFromContext extracts the request ID from context
func GetRequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if value := ctx.Value(requestIDKey); value != nil {
		if requestID, ok := value.(string); ok {
			return requestID
		}
	}
	return ""
}

// WithUserID adds a user ID to the context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// GetUserIDFromContext extracts the user ID from context
func GetUserIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if value := ctx.Value(userIDKey); value != nil {
		if userID, ok := value.(string); ok {
			return userID
		}
	}
	return ""
}

// WithRequestAndUserID adds both request ID and user ID to the context
func WithRequestAndUserID(ctx context.Context, requestID, userID string) context.Context {
	ctx = WithRequestID(ctx, requestID)
	ctx = WithUserID(ctx, userID)
	return ctx
}
