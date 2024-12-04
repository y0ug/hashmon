package database

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/y0ug/hashmon/models"
	"github.com/y0ug/hashmon/pkg/auth"
	"go.etcd.io/bbolt"
)

// BoltDB implements the Database interface using bbolt.
type BoltDB struct {
	db   *bbolt.DB
	path string
	mu   sync.RWMutex // To ensure thread-safe operations if needed
}

// NewBoltDB initializes a new BoltDB instance.
func NewBoltDB(path string) (*BoltDB, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	boltDB := &BoltDB{
		db:   db,
		path: path,
	}

	err = boltDB.Initialize()
	if err != nil {
		return nil, err
	}

	return boltDB, nil
}

// Initialize sets up the necessary buckets.
func (b *BoltDB) Initialize() error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("Hashes"))
		if err != nil {
			return fmt.Errorf("create Hashes bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("AlertedHashes"))
		if err != nil {
			return fmt.Errorf("create AlertedHashes bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("BlacklistedTokens"))
		if err != nil {
			return fmt.Errorf("create BlacklistedTokens bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("RefreshTokens"))
		if err != nil {
			return fmt.Errorf("create RefreshTokens bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("ProviderRefreshTokens"))
		if err != nil {
			return fmt.Errorf("create ProviderRefreshTokens bucket: %v", err)
		}
		// New bucket for provider tokens
		_, err = tx.CreateBucketIfNotExists([]byte("ProviderTokens"))
		if err != nil {
			return fmt.Errorf("create ProviderTokens bucket: %v", err)
		}
		return nil
	})
}

// AddHash adds a new hash record.
func (b *BoltDB) AddHash(record models.HashRecord) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if hash already exists
	exists := false
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("Hashes"))
		if bucket == nil {
			return fmt.Errorf("Hashes bucket does not exist")
		}
		val := bucket.Get([]byte(record.SHA256))
		if val != nil {
			exists = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	if exists {
		logrus.WithField("sha256", record.SHA256).Info("Hash already exists; skipping addition")
		return nil
	}

	// Initialize LastCheckAt
	record.LastCheckAt = time.Time{} // Zero value

	// Serialize the HashRecord to JSON
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal HashRecord: %w", err)
	}

	// Store in BoltDB
	err = b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("Hashes"))
		if bucket == nil {
			return fmt.Errorf("Hashes bucket does not exist")
		}
		return bucket.Put([]byte(record.SHA256), data)
	})
	if err != nil {
		return fmt.Errorf("failed to add hash to BoltDB: %w", err)
	}

	return nil
}

// LoadHashes retrieves all hash records.
func (b *BoltDB) LoadHashes() ([]models.HashRecord, error) {
	var records []models.HashRecord

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("Hashes"))
		if bucket == nil {
			return fmt.Errorf("Hashes bucket does not exist")
		}
		return bucket.ForEach(func(k, v []byte) error {
			var record models.HashRecord
			err := json.Unmarshal(v, &record)
			if err != nil {
				logrus.WithError(err).Warnf("Failed to unmarshal hash record for SHA256: %s", string(k))
				return nil // Skip invalid records
			}
			records = append(records, record)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return records, nil
}

// UpdateHash updates an existing hash record.
func (b *BoltDB) UpdateHash(record models.HashRecord) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal HashRecord: %w", err)
	}

	err = b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("Hashes"))
		if bucket == nil {
			return fmt.Errorf("Hashes bucket does not exist")
		}
		return bucket.Put([]byte(record.SHA256), data)
	})
	if err != nil {
		return fmt.Errorf("failed to update hash in BoltDB: %w", err)
	}

	return nil
}

// DeleteHash removes a hash record and its associated alert data.
func (b *BoltDB) DeleteHash(sha256 string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Delete from Hashes bucket
	err := b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("Hashes"))
		if bucket == nil {
			return fmt.Errorf("Hashes bucket does not exist")
		}
		return bucket.Delete([]byte(sha256))
	})
	if err != nil {
		return fmt.Errorf("failed to delete hash from BoltDB: %w", err)
	}

	// Remove from alerted hashes
	// This part might need to interact with the Monitor's in-memory state,
	// but assuming that the Database layer is purely for storage,
	// we'll handle only the persisted state here.

	// Delete from AlertedHashes bucket
	err = b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("AlertedHashes"))
		if bucket == nil {
			return fmt.Errorf("AlertedHashes bucket does not exist")
		}
		c := bucket.Cursor()
		prefix := sha256 + "|"
		for k, _ := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
			err := bucket.Delete(k)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to delete alerted hashes from BoltDB: %w", err)
	}

	// Similarly, handle LastCheckTimes if it's stored separately.

	logrus.WithField("sha256", sha256).Info("Hash deleted successfully")
	return nil
}

// GetHash retrieves a specific hash record.
func (b *BoltDB) GetHash(sha256 string) (models.HashRecord, error) {
	var record models.HashRecord

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("Hashes"))
		if bucket == nil {
			return fmt.Errorf("Hashes bucket does not exist")
		}
		val := bucket.Get([]byte(sha256))
		if val == nil {
			return ErrHashNotFound
		}
		return json.Unmarshal(val, &record)
	})
	if err != nil {
		return record, err
	}

	return record, nil
}

// MarkAsAlerted marks a hash as alerted for a specific provider.
func (b *BoltDB) MarkAsAlerted(sha256, provider string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	err := b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("AlertedHashes"))
		if bucket == nil {
			return fmt.Errorf("AlertedHashes bucket does not exist")
		}
		key := fmt.Sprintf("%s|%s", sha256, provider)
		return bucket.Put([]byte(key), []byte("1"))
	})
	if err != nil {
		return err
	}

	return nil
}

// IsAlerted checks if a hash has been alerted for a specific provider.
func (b *BoltDB) IsAlerted(sha256, provider string) (bool, error) {
	var alerted bool

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("AlertedHashes"))
		if bucket == nil {
			return fmt.Errorf("AlertedHashes bucket does not exist")
		}
		key := fmt.Sprintf("%s|%s", sha256, provider)
		val := bucket.Get([]byte(key))
		alerted = val != nil
		return nil
	})
	if err != nil {
		return false, err
	}

	return alerted, nil
}

// Close closes the BoltDB connection.
func (b *BoltDB) Close() error {
	return b.db.Close()
}

// AddBlacklistedToken adds a token string to the blacklist with its expiration time.
func (b *BoltDB) AddBlacklistedToken(tokenString string, exp int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Serialize the expiration time
	data, err := json.Marshal(exp)
	if err != nil {
		return fmt.Errorf("failed to marshal expiration time: %w", err)
	}

	err = b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("BlacklistedTokens"))
		if bucket == nil {
			return fmt.Errorf("BlacklistedTokens bucket does not exist")
		}
		return bucket.Put([]byte(tokenString), data)
	})
	if err != nil {
		return fmt.Errorf("failed to add token to blacklist: %w", err)
	}

	return nil
}

// IsTokenBlacklisted checks if a token is in the blacklist.
// If the token is expired, it removes it from the blacklist.
func (b *BoltDB) IsTokenBlacklisted(tokenString string) (bool, error) {
	var exp int64

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("BlacklistedTokens"))
		if bucket == nil {
			return fmt.Errorf("BlacklistedTokens bucket does not exist")
		}
		val := bucket.Get([]byte(tokenString))
		if val == nil {
			return nil // Not blacklisted
		}
		return json.Unmarshal(val, &exp)
	})
	if err != nil {
		return false, err
	}

	if exp == 0 {
		// Invalid expiration data; treat as not blacklisted
		return false, nil
	}

	// Check if the token has expired
	if time.Now().Unix() > exp {
		// Token has expired; remove it from the blacklist
		err = b.db.Update(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte("BlacklistedTokens"))
			if bucket == nil {
				return fmt.Errorf("BlacklistedTokens bucket does not exist")
			}
			return bucket.Delete([]byte(tokenString))
		})
		if err != nil {
			return false, err
		}
		return false, nil
	}

	return true, nil
}

// StoreRefreshToken saves a refresh token with associated user and expiration
func (b *BoltDB) StoreRefreshToken(token string, userID string, expiresAt time.Time) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("RefreshTokens"))
		if bucket == nil {
			return fmt.Errorf("RefreshTokens bucket not found")
		}
		data := struct {
			UserID    string    `json:"user_id"`
			ExpiresAt time.Time `json:"expires_at"`
		}{
			UserID:    userID,
			ExpiresAt: expiresAt,
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(token), encoded)
	})
}

// ValidateRefreshToken checks if a refresh token is valid and not expired
func (b *BoltDB) ValidateRefreshToken(token string) (string, error) {
	var data struct {
		UserID    string    `json:"user_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("RefreshTokens"))
		if bucket == nil {
			return fmt.Errorf("RefreshTokens bucket not found")
		}
		v := bucket.Get([]byte(token))
		if v == nil {
			return fmt.Errorf("token not found")
		}
		return json.Unmarshal(v, &data)
	})
	if err != nil {
		return "", err
	}
	if time.Now().After(data.ExpiresAt) {
		return "", fmt.Errorf("token expired")
	}
	return data.UserID, nil
}

// RevokeRefreshToken removes a refresh token from the database
func (b *BoltDB) RevokeRefreshToken(token string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("RefreshTokens"))
		if bucket == nil {
			return fmt.Errorf("RefreshTokens bucket not found")
		}
		return bucket.Delete([]byte(token))
	})
}

// StoreProviderTokens stores the provider's tokens for a user.
func (b *BoltDB) StoreProviderTokens(userID string, tokens auth.ProviderTokens) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, err := json.Marshal(tokens)
	if err != nil {
		return fmt.Errorf("failed to marshal ProviderTokens: %w", err)
	}

	err = b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("ProviderTokens"))
		if bucket == nil {
			return fmt.Errorf("ProviderTokens bucket does not exist")
		}
		return bucket.Put([]byte(userID), data)
	})
	if err != nil {
		return fmt.Errorf("failed to store provider tokens: %w", err)
	}

	return nil
}

// GetProviderTokens retrieves the provider's tokens for a user.
func (b *BoltDB) GetProviderTokens(userID string) (auth.ProviderTokens, error) {
	var tokens auth.ProviderTokens

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("ProviderTokens"))
		if bucket == nil {
			return fmt.Errorf("ProviderTokens bucket does not exist")
		}
		val := bucket.Get([]byte(userID))
		if val == nil {
			return fmt.Errorf("provider tokens not found for userID %s", userID)
		}
		return json.Unmarshal(val, &tokens)
	})
	if err != nil {
		return tokens, err
	}

	return tokens, nil
}

// UpdateProviderTokens updates the provider's tokens for a user.
func (b *BoltDB) UpdateProviderTokens(userID string, tokens auth.ProviderTokens) error {
	// Since we're overwriting the tokens, it's the same as storing them
	return b.StoreProviderTokens(userID, tokens)
}
