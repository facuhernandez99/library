package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisTokenStorage implements TokenStorage using Redis
type RedisTokenStorage struct {
	client redis.Cmdable
	prefix string
	ctx    context.Context
}

// NewRedisTokenStorage creates a new Redis token storage
func NewRedisTokenStorage(client redis.Cmdable) *RedisTokenStorage {
	return &RedisTokenStorage{
		client: client,
		prefix: "blacklist:",
		ctx:    context.Background(),
	}
}

// NewRedisTokenStorageFromURL creates a Redis token storage from URL
func NewRedisTokenStorageFromURL(redisURL string) (*RedisTokenStorage, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return NewRedisTokenStorage(client), nil
}

// BlacklistToken adds a token to the blacklist with expiration
func (r *RedisTokenStorage) BlacklistToken(tokenID string, expiresAt time.Time) error {
	key := r.prefix + tokenID

	// Calculate TTL from expiration time
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	// Set with expiration
	err := r.client.Set(r.ctx, key, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	return nil
}

// IsBlacklisted checks if a token is blacklisted
func (r *RedisTokenStorage) IsBlacklisted(tokenID string) (bool, error) {
	key := r.prefix + tokenID

	exists, err := r.client.Exists(r.ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}

	return exists > 0, nil
}

// CleanupExpired removes expired tokens from storage
func (r *RedisTokenStorage) CleanupExpired() error {
	// Redis automatically handles expiration, so this is a no-op
	// But we can optionally implement cleanup of specific patterns if needed
	return nil
}

// Close closes the Redis connection
func (r *RedisTokenStorage) Close() error {
	if client, ok := r.client.(*redis.Client); ok {
		return client.Close()
	}
	// For redis.Cmdable interface (like cluster), there's no Close method
	return nil
}

// GetStats returns storage statistics
func (r *RedisTokenStorage) GetStats() (map[string]interface{}, error) {
	// Count blacklisted tokens by scanning keys
	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()

	pattern := r.prefix + "*"
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	return map[string]interface{}{
		"blacklisted_tokens": len(keys),
		"storage_type":       "redis",
	}, nil
}

// SetPrefix sets the key prefix for blacklisted tokens
func (r *RedisTokenStorage) SetPrefix(prefix string) {
	r.prefix = prefix
}

// GetPrefix returns the current key prefix
func (r *RedisTokenStorage) GetPrefix() string {
	return r.prefix
}

// SetContext sets the context for Redis operations
func (r *RedisTokenStorage) SetContext(ctx context.Context) {
	r.ctx = ctx
}
