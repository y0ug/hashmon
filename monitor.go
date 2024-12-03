package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/y0ug/hashmon/apis"
	"github.com/y0ug/hashmon/database"
	"github.com/y0ug/hashmon/models"
	"github.com/y0ug/hashmon/notifications"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

// MonitorConfig holds the configuration for the monitoring process.
type MonitorConfig struct {
	PollInterval  time.Duration
	Notifier      *notifications.Notifier
	APIClients    []apis.APIClient
	CheckInterval time.Duration
	Database      database.Database
}

// Monitor handles the monitoring of hashes.
type Monitor struct {
	Config  MonitorConfig
	alerted map[string]map[string]bool
	mutex   sync.RWMutex
	sem     *semaphore.Weighted
}

// NewMonitor initializes a new Monitor.
func NewMonitor(config MonitorConfig, maxConcurrency int64) *Monitor {
	// Initialize alerted map from the database
	alerted := make(map[string]map[string]bool)
	hashes, err := config.Database.LoadHashes()
	if err != nil {
		logrus.Fatalf("Failed to load hashes from database: %v", err)
	}

	for _, record := range hashes {
		// For each hash, check if it's alerted by any provider
		for _, apiClient := range config.APIClients {
			provider := apiClient.ProviderName()
			alertedStatus, err := config.Database.IsAlerted(record.SHA256, provider)
			if err != nil {
				logrus.WithError(err).Errorf("Failed to check alerted status for hash %s and provider %s", record.SHA256, provider)
				continue
			}
			if alertedStatus {
				if alerted[record.SHA256] == nil {
					alerted[record.SHA256] = make(map[string]bool)
				}
				alerted[record.SHA256][provider] = true
			}
		}
	}

	return &Monitor{
		Config:  config,
		alerted: alerted,
		sem:     semaphore.NewWeighted(maxConcurrency),
	}
}

// AddHash adds a new hash record to the database.
func (m *Monitor) AddHash(record models.HashRecord) error {
	return m.Config.Database.AddHash(record)
}

// ImportHashesFromFile imports hashes from a given file path into the database.
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

// LoadHashes loads all hash records from the database.
func (m *Monitor) LoadHashes() ([]models.HashRecord, error) {
	return m.Config.Database.LoadHashes()
}

// Start begins the monitoring process.
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

	// Retrieve all hashes from the database
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
			err = m.Config.Database.MarkAsAlerted(record.SHA256, provider)
			if err != nil {
				logrus.WithError(err).Error("Failed to update database with alerted hash")
			}
		}

		// Update LastCheckAt regardless of whether the hash exists
		now := time.Now().UTC()
		record.LastCheckAt = now

		// Persist the updated HashRecord back to the database
		err = m.Config.Database.UpdateHash(record)
		if err != nil {
			logrus.WithError(err).Error("Failed to update database with LastCheckAt")
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
		status, err := m.GetHashStatus(record.SHA256)
		if err != nil {
			logrus.WithError(err).Error("Failed to find hash")
			continue
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func (m *Monitor) GetHashStatus(sha256 string) (models.HashStatus, error) {
	hash, err := m.Config.Database.GetHash(sha256)
	if err != nil {
		return models.HashStatus{}, err
	}

	providersStatus := make(map[string]bool)
	alertedBy := []string{}
	for _, apiClient := range m.Config.APIClients {
		provider := apiClient.ProviderName()
		alerted, err := m.Config.Database.IsAlerted(sha256, provider)
		if err != nil {
			logrus.WithError(err).Warnf("Failed to get alerted status for hash %s and provider %s", sha256, provider)
			continue
		}
		providersStatus[provider] = alerted
		if alerted {
			alertedBy = append(alertedBy, provider)
		}
	}

	return models.HashStatus{
		FileName:    hash.FileName,
		BuildId:     hash.BuildId,
		LastCheckAt: hash.LastCheckAt,
		SHA256:      hash.SHA256,
		Providers:   providersStatus,
		AlertedBy:   alertedBy,
	}, nil
}
