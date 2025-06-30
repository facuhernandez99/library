package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/facuhernandez99/blog/pkg/config"
	"github.com/facuhernandez99/blog/pkg/logging"
	"github.com/redis/go-redis/v9"
)

// RedisTokenStorage implements TokenStorage using Redis
type RedisTokenStorage struct {
	client redis.Cmdable
	prefix string
	ctx    context.Context
	logger *logging.Logger
}

// NewRedisTokenStorage creates a new Redis token storage
func NewRedisTokenStorage(client redis.Cmdable) *RedisTokenStorage {
	return &RedisTokenStorage{
		client: client,
		prefix: "blacklist:",
		ctx:    context.Background(),
		logger: logging.GetDefault(),
	}
}

// NewRedisTokenStorageFromConfig creates a Redis token storage from configuration
func NewRedisTokenStorageFromConfig(cfg *config.Config) (*RedisTokenStorage, error) {
	logger := logging.GetDefault()
	ctx := context.Background()

	logger.WithFields(map[string]interface{}{
		"redis_url": cfg.RedisURL,
	}).Info(ctx, "Initializing Redis token storage from configuration")

	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"redis_url": cfg.RedisURL,
		}).Error(ctx, "Failed to parse Redis URL from configuration", err)
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection with timeout
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ping(testCtx).Err(); err != nil {
		logger.WithFields(map[string]interface{}{
			"redis_url": cfg.RedisURL,
		}).Error(testCtx, "Failed to connect to Redis using configuration", err)
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info(ctx, "Successfully connected to Redis token storage")

	storage := &RedisTokenStorage{
		client: client,
		prefix: "blacklist:",
		ctx:    ctx,
		logger: logger,
	}

	return storage, nil
}

// NewRedisTokenStorageFromURL creates a Redis token storage from URL
// Deprecated: Use NewRedisTokenStorageFromConfig instead
func NewRedisTokenStorageFromURL(redisURL string) (*RedisTokenStorage, error) {
	logger := logging.GetDefault()
	ctx := context.Background()

	logger.WithFields(map[string]interface{}{
		"redis_url": redisURL,
	}).Info(ctx, "Initializing Redis token storage from URL (deprecated method)")

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"redis_url": redisURL,
		}).Error(ctx, "Failed to parse Redis URL", err)
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ping(testCtx).Err(); err != nil {
		logger.WithFields(map[string]interface{}{
			"redis_url": redisURL,
		}).Error(testCtx, "Failed to connect to Redis", err)
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info(ctx, "Successfully connected to Redis token storage")

	return &RedisTokenStorage{
		client: client,
		prefix: "blacklist:",
		ctx:    ctx,
		logger: logger,
	}, nil
}

// BlacklistToken adds a token to the blacklist with expiration
func (r *RedisTokenStorage) BlacklistToken(tokenID string, expiresAt time.Time) error {
	key := r.prefix + tokenID

	// Calculate TTL from expiration time
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		r.logger.WithFields(map[string]interface{}{
			"token_id":   tokenID,
			"expires_at": expiresAt,
		}).Debug(r.ctx, "Token already expired, skipping blacklist")
		return nil
	}

	// Set with expiration
	err := r.client.Set(r.ctx, key, "1", ttl).Err()
	if err != nil {
		r.logger.WithFields(map[string]interface{}{
			"token_id":    tokenID,
			"key":         key,
			"ttl_seconds": ttl.Seconds(),
		}).Error(r.ctx, "Failed to blacklist token in Redis", err)
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	r.logger.WithFields(map[string]interface{}{
		"token_id":    tokenID,
		"expires_at":  expiresAt,
		"ttl_seconds": ttl.Seconds(),
	}).Info(r.ctx, "Token successfully blacklisted")

	return nil
}

// IsBlacklisted checks if a token is blacklisted
func (r *RedisTokenStorage) IsBlacklisted(tokenID string) (bool, error) {
	key := r.prefix + tokenID

	exists, err := r.client.Exists(r.ctx, key).Result()
	if err != nil {
		r.logger.WithFields(map[string]interface{}{
			"token_id": tokenID,
			"key":      key,
		}).Error(r.ctx, "Failed to check token blacklist status in Redis", err)
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}

	isBlacklisted := exists > 0

	r.logger.WithFields(map[string]interface{}{
		"token_id":       tokenID,
		"is_blacklisted": isBlacklisted,
	}).Debug(r.ctx, "Token blacklist status checked")

	return isBlacklisted, nil
}

// CleanupExpired removes expired tokens from storage
func (r *RedisTokenStorage) CleanupExpired() error {
	// Redis automatically handles expiration, so this is a no-op
	// But we can optionally implement cleanup of specific patterns if needed
	r.logger.Debug(r.ctx, "Redis cleanup called - Redis handles expiration automatically")
	return nil
}

// Close closes the Redis connection
func (r *RedisTokenStorage) Close() error {
	r.logger.Info(r.ctx, "Closing Redis token storage connection")

	if client, ok := r.client.(*redis.Client); ok {
		err := client.Close()
		if err != nil {
			r.logger.Error(r.ctx, "Failed to close Redis connection", err)
			return err
		}
		r.logger.Info(r.ctx, "Redis connection closed successfully")
		return nil
	}

	// For redis.Cmdable interface (like cluster), there's no Close method
	r.logger.Debug(r.ctx, "Redis client does not support close operation (cluster/cmdable interface)")
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
		r.logger.WithFields(map[string]interface{}{
			"pattern": pattern,
		}).Error(ctx, "Failed to get Redis token storage statistics", err)
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	stats := map[string]interface{}{
		"blacklisted_tokens": len(keys),
		"storage_type":       "redis",
		"key_prefix":         r.prefix,
	}

	r.logger.WithFields(stats).Debug(ctx, "Retrieved Redis token storage statistics")

	return stats, nil
}

// SetPrefix sets the key prefix for blacklisted tokens
func (r *RedisTokenStorage) SetPrefix(prefix string) {
	oldPrefix := r.prefix
	r.prefix = prefix

	r.logger.WithFields(map[string]interface{}{
		"old_prefix": oldPrefix,
		"new_prefix": prefix,
	}).Info(r.ctx, "Redis token storage prefix updated")
}

// GetPrefix returns the current key prefix
func (r *RedisTokenStorage) GetPrefix() string {
	return r.prefix
}

// SetContext sets the context for Redis operations
func (r *RedisTokenStorage) SetContext(ctx context.Context) {
	r.ctx = ctx
	r.logger.Debug(ctx, "Redis token storage context updated")
}
