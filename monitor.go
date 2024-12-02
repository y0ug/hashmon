package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/y0ug/hashmon/apis"          // Replace with your actual module path
	"github.com/y0ug/hashmon/models"        // Replace with your actual module path
	"github.com/y0ug/hashmon/notifications" // Replace with your actual module path

	"github.com/sirupsen/logrus"
	"go.etcd.io/bbolt"
	"golang.org/x/sync/semaphore"
)

// MonitorConfig holds the configuration for the monitoring process.
type MonitorConfig struct {
	PollInterval  time.Duration
	Notifier      *notifications.Notifier
	APIClients    []apis.APIClient
	CheckInterval time.Duration
}

// Monitor handles the monitoring of hashes.
type Monitor struct {
	Config MonitorConfig
	// HashRecords    []models.HashRecord
	alerted map[string]map[string]bool
	mutex   sync.RWMutex
	sem     *semaphore.Weighted
	db      *bbolt.DB
}

// NewMonitor initializes a new Monitor.
func NewMonitor(config MonitorConfig, maxConcurrency int64, dbPath string) *Monitor {
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		logrus.Fatalf("Failed to open BoltDB: %v", err)
	}

	// Initialize buckets
	db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("Hashes"))
		if err != nil {
			return fmt.Errorf("create Hashes bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("AlertedHashes"))
		if err != nil {
			return fmt.Errorf("create AlertedHashes bucket: %v", err)
		}
		return nil
	})

	// Initialize map of alerted hashes from DB
	alerted := make(map[string]map[string]bool)
	db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("AlertedHashes"))
		if bucket == nil {
			return nil
		}
		bucket.ForEach(func(k, v []byte) error {
			// Key format: "hash|provider"
			keyParts := strings.SplitN(string(k), "|", 2)
			if len(keyParts) != 2 {
				return nil // Skip invalid keys
			}
			hash, provider := keyParts[0], keyParts[1]
			if alerted[hash] == nil {
				alerted[hash] = make(map[string]bool)
			}
			alerted[hash][provider] = true
			return nil
		})
		return nil
	})

	return &Monitor{
		Config:  config,
		alerted: alerted,
		mutex:   sync.RWMutex{},
		sem:     semaphore.NewWeighted(maxConcurrency),
		db:      db,
	}
}

// LoadHashes loads all hash records from the Hashes bucket into memory.
func (m *Monitor) LoadHashes() ([]models.HashRecord, error) {
	var records []models.HashRecord

	err := m.db.View(func(tx *bbolt.Tx) error {
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

// AddHash adds a new hash record to the Hashes bucket.
func (m *Monitor) AddHash(record models.HashRecord) error {
	// Check if hash already exists
	var exists bool
	err := m.db.View(func(tx *bbolt.Tx) error {
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
		return fmt.Errorf("failed to check existing hash in BoltDB: %w", err)
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
	err = m.db.Update(func(tx *bbolt.Tx) error {
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

// ImportHashesFromFile imports hashes from a given file path into BoltDB.
func (m *Monitor) ImportHashesFromFile(filePath string) error {
	hashRecords, err := ReadRecords(filePath) // Implement ReadRecords as per previous instructions
	if err != nil {
		return fmt.Errorf("failed to read records from file: %w", err)
	}

	for _, record := range hashRecords {
		err := m.AddHash(record)
		if err != nil {
			logrus.WithError(err).WithField("sha256", record.SHA256).Error("Failed to add hash")
			// Decide whether to continue or halt on error
			continue
		}
	}

	logrus.WithField("record_count", len(hashRecords)).Info("Imported hashes successfully")
	return nil
}

// Start begins the monitoring process.
// It listens to the context for cancellation signals to stop monitoring gracefully.
func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.Config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logrus.Info("Monitoring stopped due to context cancellation")
			return
		default:
			m.checkAllHashes(ctx)
			select {
			case <-ctx.Done():
				logrus.Info("Monitoring stopped due to context cancellation")
				return
			case <-ticker.C:
				// Continue to next iteration
			}
		}
	}
}

// checkAllHashes iterates over all hashes and checks them.
func (m *Monitor) checkAllHashes(ctx context.Context) {
	var wg sync.WaitGroup

	// Retrieve all hashes from BoltDB
	hashRecords, err := m.LoadHashes()
	if err != nil {
		logrus.WithError(err).Error("Failed to load hashes for checking")
		return
	}

	for _, record := range hashRecords {
		// Acquire semaphore to limit concurrency
		if err := m.sem.Acquire(ctx, 1); err != nil {
			logrus.WithError(err).Error("Failed to acquire semaphore")
			continue
		}

		wg.Add(1)
		go func(rec models.HashRecord) {
			defer wg.Done()
			defer m.sem.Release(1)
			m.checkHash(ctx, rec)
		}(record)
	}

	wg.Wait()
}

// checkHash checks a single hash across all APIs.
func (m *Monitor) checkHash(ctx context.Context, record models.HashRecord) {
	// Determine if the hash needs to be checked based on LastCheckAt
	if !record.LastCheckAt.IsZero() && time.Since(record.LastCheckAt) < m.Config.CheckInterval {
		logrus.WithFields(logrus.Fields{
			"sha256":       record.SHA256,
			"last_checked": record.LastCheckAt,
		}).Info("Skipping hash check; checked recently")
		return
	}

	for _, apiClient := range m.Config.APIClients {
		logrus.WithField("sha256", record.SHA256).Info("checkHash")

		provider := apiClient.ProviderName()

		m.mutex.RLock()
		if m.alerted[record.SHA256] != nil && m.alerted[record.SHA256][provider] {
			m.mutex.RUnlock()
			continue // Already alerted for this provider
		}
		m.mutex.RUnlock()

		logger := logrus.WithFields(logrus.Fields{
			"sha256":   record.SHA256,
			"filename": record.FileName,
			"api":      provider,
			"context":  ctx.Err(),
		})

		exists, err := apiClient.CheckHash(ctx, record.SHA256)
		if err != nil {
			logger.WithField("error", err).Error("Error checking hash in API")
			continue
		}

		if exists {
			logger.Info("Hash found in API")

			// Send notification
			message := fmt.Sprintf("Hash **%s** was found in **%s**.\nFilename: %s",
				record.SHA256, provider, record.FileName)
			m.Config.Notifier.Send("Hash Found", message)

			// Mark as alerted
			m.mutex.Lock()
			if m.alerted[record.SHA256] == nil {
				m.alerted[record.SHA256] = make(map[string]bool)
			}
			m.alerted[record.SHA256][provider] = true
			m.mutex.Unlock()

			// Persist to DB
			// Generate the key by concatenating hash and provider
			err = m.db.Update(func(tx *bbolt.Tx) error {
				bucket := tx.Bucket([]byte("AlertedHashes"))
				key := fmt.Sprintf("%s|%s", record.SHA256, provider)
				return bucket.Put([]byte(key), []byte("1"))
			})
			if err != nil {
				logrus.WithError(err).Error("Failed to update BoltDB with alerted hash")
			}
		}

		// Update LastCheckAt regardless of whether the hash exists
		now := time.Now().UTC()
		record.LastCheckAt = now

		// Persist the updated HashRecord back to BoltDB
		err = m.db.Update(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte("Hashes"))
			if bucket == nil {
				return fmt.Errorf("Hashes bucket does not exist")
			}
			data, err := json.Marshal(record)
			if err != nil {
				return fmt.Errorf("failed to marshal updated HashRecord: %w", err)
			}
			return bucket.Put([]byte(record.SHA256), data)
		})
		if err != nil {
			logrus.WithError(err).Error("Failed to update BoltDB with LastCheckAt")
		}
	}
}

// GetAllHashStatuses retrieves the status of all hashes.
func (m *Monitor) GetAllHashStatuses() []models.HashStatus {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var statuses []models.HashStatus
	hashRecords, err := m.LoadHashes()
	if err != nil {
		logrus.WithError(err).Error("Failed to load hashes for status retrieval")
		return statuses
	}

	for _, record := range hashRecords {
		providersStatus := make(map[string]bool)
		alertedBy := []string{}
		if m.alerted[record.SHA256] != nil {
			for provider, alerted := range m.alerted[record.SHA256] {
				providersStatus[provider] = alerted
				if alerted {
					alertedBy = append(alertedBy, provider)
				}
			}
		}
		status := models.HashStatus{
			FileName:    record.FileName,
			BuildId:     record.BuildId,
			LastCheckAt: record.LastCheckAt,
			SHA256:      record.SHA256,
			Providers:   providersStatus,
		}
		if len(alertedBy) > 0 {
			status.AlertedBy = alertedBy
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// GetHashStatus retrieves the status of a specific hash.
func (m *Monitor) GetHashStatus(sha256 string) (models.HashStatus, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var status models.HashStatus
	found := false
	hashRecords, err := m.LoadHashes()
	if err != nil {
		logrus.WithError(err).Error("Failed to load hashes for status retrieval")
		return status, false
	}

	for _, record := range hashRecords {
		if record.SHA256 == sha256 {
			status = models.HashStatus{
				SHA256:      record.SHA256,
				LastCheckAt: record.LastCheckAt,
				Providers:   make(map[string]bool),
			}
			if m.alerted[record.SHA256] != nil {
				for provider, alerted := range m.alerted[record.SHA256] {
					status.Providers[provider] = alerted
					if alerted {
						status.AlertedBy = append(status.AlertedBy, provider)
					}
				}
			}
			found = true
			break
		}
	}
	return status, found
}

// DeleteHash removes a hash record from the Hashes bucket and associated alert data.
func (m *Monitor) DeleteHash(sha256 string) error {
	// Delete from Hashes bucket
	err := m.db.Update(func(tx *bbolt.Tx) error {
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
	m.mutex.Lock()
	delete(m.alerted, sha256)
	m.mutex.Unlock()

	// Delete from AlertedHashes bucket
	err = m.db.Update(func(tx *bbolt.Tx) error {
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

	// Delete from LastCheckTimes bucket
	err = m.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("LastCheckTimes"))
		if bucket == nil {
			return fmt.Errorf("LastCheckTimes bucket does not exist")
		}
		return bucket.Delete([]byte(sha256))
	})
	if err != nil {
		return fmt.Errorf("failed to delete last check time from BoltDB: %w", err)
	}

	logrus.WithField("sha256", sha256).Info("Hash deleted successfully")
	return nil
}
