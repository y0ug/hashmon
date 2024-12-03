package database

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/y0ug/hashmon/models"
)

// RedisDB implements the Database interface using Redis.
type RedisDB struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisDB initializes a new RedisDB instance.
func NewRedisDB(addr, password string, db int) (*RedisDB, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password, // no password set
		DB:       db,       // use default DB
	})

	// Test connection
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
func (r *RedisDB) Initialize() error {
	// Redis is schema-less; initialization might not be necessary.
	return nil
}

// AddHash adds a new hash record.
func (r *RedisDB) AddHash(record models.HashRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal HashRecord: %w", err)
	}

	key := fmt.Sprintf("hash:%s", record.SHA256)
	exists, err := r.client.Exists(r.ctx, key).Result()
	if err != nil {
		return err
	}
	if exists == 1 {
		// Hash already exists
		return nil
	}

	return r.client.Set(r.ctx, key, data, 0).Err()
}

// LoadHashes retrieves all hash records.
func (r *RedisDB) LoadHashes() ([]models.HashRecord, error) {
	var records []models.HashRecord

	iter := r.client.Scan(r.ctx, 0, "hash:*", 0).Iterator()
	for iter.Next(r.ctx) {
		key := iter.Val()
		val, err := r.client.Get(r.ctx, key).Result()
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
func (r *RedisDB) UpdateHash(record models.HashRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal HashRecord: %w", err)
	}

	key := fmt.Sprintf("hash:%s", record.SHA256)
	return r.client.Set(r.ctx, key, data, 0).Err()
}

// DeleteHash removes a hash record and its associated alert data.
func (r *RedisDB) DeleteHash(sha256 string) error {
	key := fmt.Sprintf("hash:%s", sha256)
	err := r.client.Del(r.ctx, key).Err()
	if err != nil {
		return err
	}

	// Remove alerted hashes
	pattern := fmt.Sprintf("alerted:%s:*", sha256)
	iter := r.client.Scan(r.ctx, 0, pattern, 0).Iterator()
	for iter.Next(r.ctx) {
		alertKey := iter.Val()
		err := r.client.Del(r.ctx, alertKey).Err()
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
func (r *RedisDB) GetHash(sha256 string) (models.HashRecord, error) {
	var record models.HashRecord

	key := fmt.Sprintf("hash:%s", sha256)
	val, err := r.client.Get(r.ctx, key).Result()
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
func (r *RedisDB) MarkAsAlerted(sha256, provider string) error {
	key := fmt.Sprintf("alerted:%s:%s", sha256, provider)
	return r.client.Set(r.ctx, key, "1", 0).Err()
}

// IsAlerted checks if a hash has been alerted for a specific provider.
func (r *RedisDB) IsAlerted(sha256, provider string) (bool, error) {
	key := fmt.Sprintf("alerted:%s:%s", sha256, provider)
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, err
	}
	return val == "1", nil
}

// Close closes the Redis client connection.
func (r *RedisDB) Close() error {
	return r.client.Close()
}
