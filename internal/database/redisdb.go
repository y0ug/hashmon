package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/y0ug/hashmon/internal/database/models"
	"github.com/y0ug/hashmon/pkg/auth"
)

// RedisDB implements the Database interface using Redis.
type RedisDB struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisDB initializes a new RedisDB instance.
func NewRedisDB(cfg *DatabaseConfig) (*RedisDB, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPass, // no password set
		DB:       cfg.RedisDB,   // use default DB
	})

	// Use context.Background() for initial connection test
	ctx := context.Background()
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}

	return &RedisDB{
		client: rdb,
		ctx:    ctx,
	}, nil
}

// Initialize sets up necessary Redis structures if needed.
func (r *RedisDB) Initialize(ctx context.Context) error {
	// Redis is schema-less; initialization might not be necessary.
	return nil
}

// AddHash adds a new hash record.
func (r *RedisDB) AddHash(ctx context.Context, record models.HashRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal HashRecord: %w", err)
	}

	key := fmt.Sprintf("hash:%s", record.SHA256)
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return err
	}
	if exists == 1 {
		// Hash already exists
		return nil
	}

	return r.client.Set(ctx, key, data, 0).Err()
}

// LoadHashes retrieves all hash records.
func (r *RedisDB) LoadHashes(ctx context.Context) ([]models.HashRecord, error) {
	var records []models.HashRecord

	iter := r.client.Scan(ctx, 0, "hash:*", 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		val, err := r.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var record models.HashRecord
		err = json.Unmarshal([]byte(val), &record)
		if err != nil {
			continue
		}
		records = append(records, record)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

// UpdateHash updates an existing hash record.
func (r *RedisDB) UpdateHash(ctx context.Context, record models.HashRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal HashRecord: %w", err)
	}

	key := fmt.Sprintf("hash:%s", record.SHA256)
	return r.client.Set(ctx, key, data, 0).Err()
}

// DeleteHash removes a hash record and its associated alert data.
func (r *RedisDB) DeleteHash(ctx context.Context, sha256 string) error {
	key := fmt.Sprintf("hash:%s", sha256)
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return err
	}

	// Remove alerted hashes
	pattern := fmt.Sprintf("alerted:%s:*", sha256)
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		alertKey := iter.Val()
		err := r.client.Del(ctx, alertKey).Err()
		if err != nil {
			return err
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}

	return nil
}

// GetHash retrieves a specific hash record.
func (r *RedisDB) GetHash(ctx context.Context, sha256 string) (models.HashRecord, error) {
	var record models.HashRecord

	key := fmt.Sprintf("hash:%s", sha256)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return record, ErrHashNotFound
		}
		return record, err
	}

	err = json.Unmarshal([]byte(val), &record)
	if err != nil {
		return record, err
	}

	return record, nil
}

// MarkAsAlerted marks a hash as alerted for a specific provider.
func (r *RedisDB) MarkAsAlerted(ctx context.Context, sha256, provider string) error {
	key := fmt.Sprintf("alerted:%s:%s", sha256, provider)
	return r.client.Set(ctx, key, "1", 0).Err()
}

// IsAlerted checks if a hash has been alerted for a specific provider.
func (r *RedisDB) IsAlerted(ctx context.Context, sha256, provider string) (bool, error) {
	key := fmt.Sprintf("alerted:%s:%s", sha256, provider)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, err
	}
	return val == "1", nil
}

// Close closes the Redis client connection.
func (r *RedisDB) Close(ctx context.Context) error {
	return r.client.Close()
}

// AddBlacklistedToken adds a token string to the blacklist with its expiration time.
func (r *RedisDB) AddBlacklistedToken(ctx context.Context, tokenString string, exp int64) error {
	// Calculate TTL
	expirationTime := time.Unix(exp, 0)
	ttl := time.Until(expirationTime)
	if ttl <= 0 {
		// Token already expired; no need to blacklist
		return nil
	}

	// Define a unique key for the blacklisted token
	key := fmt.Sprintf("blacklist:%s", tokenString)

	// Store the key with TTL
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsTokenBlacklisted checks if a token is in the blacklist.
func (r *RedisDB) IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	key := fmt.Sprintf("blacklist:%s", tokenString)
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

// StoreRefreshToken saves a refresh token with associated user and expiration.
func (r *RedisDB) StoreRefreshToken(ctx context.Context, token string, userID string, expiresAt time.Time) error {
	// Define a unique key for the refresh token
	key := fmt.Sprintf("refresh_token:%s", token)

	// Create a struct to hold the data
	data := struct {
		UserID    string    `json:"user_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}{
		UserID:    userID,
		ExpiresAt: expiresAt,
	}

	// Serialize the data to JSON
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token data: %w", err)
	}

	// Calculate TTL based on expiration time
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("invalid expiration time for refresh token")
	}

	// Store the refresh token with TTL
	return r.client.Set(ctx, key, encoded, ttl).Err()
}

// ValidateRefreshToken checks if a refresh token is valid and not expired.
// Returns the associated userID if valid.
func (r *RedisDB) ValidateRefreshToken(ctx context.Context, token string) (string, error) {
	// Define the key for the refresh token
	key := fmt.Sprintf("refresh_token:%s", token)

	// Get the token data
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("refresh token not found")
		}
		return "", err
	}

	// Deserialize the data
	var data struct {
		UserID    string    `json:"user_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	err = json.Unmarshal([]byte(val), &data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal refresh token data: %w", err)
	}

	// Check if the token has expired
	if time.Now().After(data.ExpiresAt) {
		// Token expired; revoke it
		r.RevokeRefreshToken(ctx, token)
		return "", fmt.Errorf("refresh token expired")
	}

	return data.UserID, nil
}

// RevokeRefreshToken removes a refresh token from the database.
func (r *RedisDB) RevokeRefreshToken(ctx context.Context, token string) error {
	// Define the key for the refresh token
	key := fmt.Sprintf("refresh_token:%s", token)
	return r.client.Del(ctx, key).Err()
}

// StoreProviderTokens stores the provider's tokens for a user.
func (r *RedisDB) StoreProviderTokens(ctx context.Context, userID, provider string, tokens auth.ProviderTokens) error {
	key := fmt.Sprintf("provider_tokens:%s:%s", provider, userID)
	encoded, err := json.Marshal(tokens)
	if err != nil {
		return fmt.Errorf("failed to marshal ProviderTokens: %w", err)
	}
	// Optionally, set an expiration based on tokens.ExpiresAt
	ttl := time.Until(tokens.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("invalid expiration time for provider tokens")
	}
	return r.client.Set(ctx, key, encoded, ttl).Err()
}

// GetProviderTokens retrieves the provider's tokens for a user.
func (r *RedisDB) GetProviderTokens(ctx context.Context, userID, provider string) (auth.ProviderTokens, error) {
	var tokens auth.ProviderTokens

	key := fmt.Sprintf("provider_tokens:%s:%s", provider, userID)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return tokens, fmt.Errorf("provider tokens not found for userID %s and provider %s", userID, provider)
		}
		return tokens, err
	}

	err = json.Unmarshal([]byte(val), &tokens)
	if err != nil {
		return tokens, fmt.Errorf("failed to unmarshal ProviderTokens: %w", err)
	}

	return tokens, nil
}

// UpdateProviderTokens updates the provider's tokens for a user.
func (r *RedisDB) UpdateProviderTokens(ctx context.Context, userID, provider string, tokens auth.ProviderTokens) error {
	// Overwrite the existing tokens with the new ones
	return r.StoreProviderTokens(ctx, userID, provider, tokens)
}
