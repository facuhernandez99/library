package auth

import (
	"sync"
	"time"
)

// TokenStorage defines the interface for storing and managing tokens
type TokenStorage interface {
	// BlacklistToken adds a token to the blacklist with expiration
	BlacklistToken(tokenID string, expiresAt time.Time) error

	// IsBlacklisted checks if a token is blacklisted
	IsBlacklisted(tokenID string) (bool, error)

	// CleanupExpired removes expired tokens from storage
	CleanupExpired() error

	// Close closes the storage connection
	Close() error
}

// MemoryTokenStorage implements TokenStorage using in-memory storage
type MemoryTokenStorage struct {
	mu            sync.RWMutex
	blacklist     map[string]time.Time
	cleanupTicker *time.Ticker
	stopCleanup   chan bool
}

// NewMemoryTokenStorage creates a new in-memory token storage
func NewMemoryTokenStorage() *MemoryTokenStorage {
	storage := &MemoryTokenStorage{
		blacklist:   make(map[string]time.Time),
		stopCleanup: make(chan bool),
	}

	// Start cleanup routine every 10 minutes
	storage.cleanupTicker = time.NewTicker(10 * time.Minute)
	go storage.cleanupRoutine()

	return storage
}

// BlacklistToken adds a token to the blacklist
func (m *MemoryTokenStorage) BlacklistToken(tokenID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.blacklist[tokenID] = expiresAt
	return nil
}

// IsBlacklisted checks if a token is blacklisted
func (m *MemoryTokenStorage) IsBlacklisted(tokenID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	expiresAt, exists := m.blacklist[tokenID]
	if !exists {
		return false, nil
	}

	// If token has expired, remove it and return false
	if time.Now().After(expiresAt) {
		delete(m.blacklist, tokenID)
		return false, nil
	}

	return true, nil
}

// CleanupExpired removes expired tokens from storage
func (m *MemoryTokenStorage) CleanupExpired() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for tokenID, expiresAt := range m.blacklist {
		if now.After(expiresAt) {
			delete(m.blacklist, tokenID)
		}
	}

	return nil
}

// Close stops the cleanup routine and closes the storage
func (m *MemoryTokenStorage) Close() error {
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
	}

	select {
	case m.stopCleanup <- true:
	default:
	}

	return nil
}

// cleanupRoutine runs periodic cleanup of expired tokens
func (m *MemoryTokenStorage) cleanupRoutine() {
	for {
		select {
		case <-m.cleanupTicker.C:
			m.CleanupExpired()
		case <-m.stopCleanup:
			return
		}
	}
}

// GetStats returns storage statistics (for debugging/monitoring)
func (m *MemoryTokenStorage) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"blacklisted_tokens": len(m.blacklist),
		"storage_type":       "memory",
	}
}
