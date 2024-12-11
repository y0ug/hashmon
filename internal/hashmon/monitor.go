package hashmon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/y0ug/hashmon/internal/database"
	"github.com/y0ug/hashmon/internal/database/models"
	"github.com/y0ug/hashmon/internal/hashmon/apis"
	"github.com/y0ug/hashmon/internal/notifications"

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
	Config MonitorConfig
	sem    *semaphore.Weighted
}

// NewMonitor initializes a new Monitor.
func NewMonitor(config MonitorConfig, maxConcurrency int64) *Monitor {
	return &Monitor{
		Config: config,
		sem:    semaphore.NewWeighted(maxConcurrency),
	}
}

// AddHash adds a new hash record to the database.
func (m *Monitor) AddHash(ctx context.Context, record models.HashRecord) error {
	return m.Config.Database.AddHash(ctx, record)
}

// ImportHashesFromFile imports hashes from a given file path into the database.
func (m *Monitor) ImportHashesFromFile(ctx context.Context, filePath string) error {
	hashRecords, err := ReadRecords(filePath) // Implement ReadRecords as per previous instructions
	if err != nil {
		return fmt.Errorf("failed to read records from file: %w", err)
	}

	for _, record := range hashRecords {
		err := m.AddHash(ctx, record)
		if err != nil {
			logrus.WithError(err).WithField("sha256", record.SHA256).Error("Failed to add hash")
			// Decide whether to continue or halt on error
			continue
		}
	}

	logrus.WithField("record_count", len(hashRecords)).Info("Imported hashes successfully")
	return nil
}

// LoadHashesPaginated retrieves a specific page of hash statuses along with the total count.
// It accepts an optional filter to retrieve only found or not found hashes.
func (m *Monitor) LoadHashesPaginated(ctx context.Context, page, perPage int, filterFound *bool) ([]models.HashStatus, int, error) {
	hashStatuses, total, err := m.Config.Database.LoadHashesPaginated(ctx, page, perPage, filterFound)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load paginated hashes: %w", err)
	}

	return hashStatuses, total, nil
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
	hashRecords, err := m.Config.Database.LoadHashes(ctx)
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
		go func(rec models.HashStatus) {
			defer wg.Done()
			defer m.sem.Release(1)
			m.checkHash(ctx, rec)
		}(record)
	}

	wg.Wait()
}

// checkHash checks a single hash across all APIs.
func (m *Monitor) checkHash(ctx context.Context, record models.HashStatus) {
	// Determine if the hash needs to be checked based on LastCheckAt
	if !record.LastCheckAt.IsZero() && time.Since(record.LastCheckAt) < m.Config.CheckInterval {
		logrus.WithFields(logrus.Fields{
			"sha256":       record.SHA256,
			"last_checked": record.LastCheckAt,
		}).Debug("Skipping hash check; checked recently")
		return
	}

	for _, apiClient := range m.Config.APIClients {
		logrus.WithField("sha256", record.SHA256).Debug("checkHash")

		provider := apiClient.ProviderName()

		isAlerted, exists := record.Providers[provider]
		if exists && isAlerted && !record.LastCheckAt.IsZero() {
			continue
		}

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

			// Persist to DB
			err = m.Config.Database.MarkAsAlerted(ctx, record.SHA256, provider)
			if err != nil {
				logrus.WithError(err).Error("Failed to update database with alerted hash")
			}
		}

		// Update LastCheckAt regardless of whether the hash exists
		now := time.Now().UTC()
		record.LastCheckAt = now

		// Persist the updated HashRecord back to the database
		err = m.Config.Database.UpdateHash(ctx, record.SHA256, record.ToHashRecord())
		if err != nil {
			logrus.WithError(err).Error("Failed to update database with LastCheckAt")
		}
	}
}

func (m *Monitor) GetHashStatus(ctx context.Context, sha256 string) (models.HashStatus, error) {
	hash, err := m.Config.Database.GetHash(ctx, sha256)
	if err != nil {
		return models.HashStatus{}, err
	}
	return hash, nil
}

// GetStats retrieves the current statistics from the database.
func (m *Monitor) GetStats(ctx context.Context) (models.StatsResponse, error) {
	var stats models.StatsResponse

	// Get Total Hashes
	totalHashes, err := m.Config.Database.GetTotalHashes(ctx)
	if err != nil {
		return stats, fmt.Errorf("failed to get total hashes: %w", err)
	}
	stats.TotalHashes = totalHashes

	// Get Global Last Check Time
	globalLastCheckAt, err := m.Config.Database.GetGlobalLastCheckAt(ctx)
	if err != nil {
		return stats, fmt.Errorf("failed to get global last check time: %w", err)
	}
	stats.GlobalLastCheckAt = globalLastCheckAt

	// Get Total Hashes Found
	totalHashesFound, err := m.Config.Database.GetTotalHashesFound(ctx)
	if err != nil {
		return stats, fmt.Errorf("failed to get total hashes found: %w", err)
	}
	stats.TotalHashesFound = totalHashesFound

	// Get Hashes Found Today
	hashesFoundToday, err := m.Config.Database.GetHashesFoundToday(ctx)
	if err != nil {
		return stats, fmt.Errorf("failed to get hashes found today: %w", err)
	}
	stats.HashesFoundToday = hashesFoundToday

	return stats, nil
}
