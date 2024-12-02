package main

import (
	"context"
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
	Config         MonitorConfig
	HashRecords    []models.HashRecord
	alerted        map[string]map[string]bool
	lastCheckTimes map[string]time.Time // New field
	mutex          sync.RWMutex
	sem            *semaphore.Weighted
	db             *bbolt.DB
}

// NewMonitor initializes a new Monitor.
func NewMonitor(config MonitorConfig, records []models.HashRecord, maxConcurrency int64, dbPath string) *Monitor {
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		logrus.Fatalf("Failed to open BoltDB: %v", err)
	}

	// Initialize buckets
	db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("AlertedHashes"))
		if err != nil {
			return fmt.Errorf("create AlertedHashes bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("LastCheckTimes"))
		return err
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

	// Initialize map of last check times from DB
	lastCheckTimes := make(map[string]time.Time)
	db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("LastCheckTimes"))
		if bucket == nil {
			return nil
		}
		bucket.ForEach(func(k, v []byte) error {
			sha256 := string(k)
			timestamp, err := time.Parse(time.RFC3339, string(v))
			logrus.WithFields(logrus.Fields{"sha256": sha256, "timestamp": timestamp}).Info("lastCheckTimes")
			if err != nil {
				logrus.WithError(err).Warnf("Invalid timestamp for hash %s", sha256)
				return nil // Skip invalid timestamps
			}
			lastCheckTimes[sha256] = timestamp
			return nil
		})
		return nil
	})

	return &Monitor{
		Config:         config,
		HashRecords:    records,
		alerted:        alerted,
		lastCheckTimes: lastCheckTimes,
		mutex:          sync.RWMutex{},
		sem:            semaphore.NewWeighted(maxConcurrency),
		db:             db,
	}
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

	for _, record := range m.HashRecords {
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
	m.mutex.RLock()
	lastCheck, exists := m.lastCheckTimes[record.SHA256]
	m.mutex.RUnlock()

	// If the hash was checked recently, skip it
	if exists && time.Since(lastCheck) < m.Config.CheckInterval {
		logrus.WithFields(logrus.Fields{
			"sha256":       record.SHA256,
			"last_checked": lastCheck,
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
			err := m.db.Update(func(tx *bbolt.Tx) error {
				bucket := tx.Bucket([]byte("AlertedHashes"))
				key := fmt.Sprintf("%s|%s", record.SHA256, provider)
				return bucket.Put([]byte(key), []byte("1"))
			})
			if err != nil {
				logrus.WithError(err).Error("Failed to update BoltDB with alerted hash")
			}
		}

		// Update last check time regardless of whether the hash exists
		now := time.Now().UTC()
		m.mutex.Lock()
		m.lastCheckTimes[record.SHA256] = now
		m.mutex.Unlock()

		// Persist last check time to DB
		err = m.db.Update(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte("LastCheckTimes"))
			if bucket == nil {
				return fmt.Errorf("LastCheckTimes bucket does not exist")
			}
			return bucket.Put([]byte(record.SHA256), []byte(now.Format(time.RFC3339)))
		})
		if err != nil {
			logrus.WithError(err).Error("Failed to update BoltDB with last check time")
		}
	}
}

// GetAllHashStatuses retrieves the status of all hashes.
func (m *Monitor) GetAllHashStatuses() []models.HashStatus {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var statuses []models.HashStatus
	for _, record := range m.HashRecords {
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
			LastCheckAt: m.lastCheckTimes[record.SHA256],
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
	for _, record := range m.HashRecords {
		if record.SHA256 == sha256 {
			status = models.HashStatus{
				SHA256:      record.SHA256,
				LastCheckAt: m.lastCheckTimes[record.SHA256],
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
