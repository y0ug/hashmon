package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/y0ug/hashmon/internal/database/models"
	"github.com/y0ug/hashmon/pkg/auth"
)

type SQLiteDB struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewSQLiteDB initializes a new SQLiteDB instance.
func NewSQLiteDB(dataSourceName string, logger *logrus.Logger) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite3 database: %w", err)
	}

	// Set connection pool parameters
	db.SetMaxOpenConns(1) // SQLite3 doesn't support multiple writers well.

	// Initialize the schema
	sqliteDB := &SQLiteDB{
		db:     db,
		logger: logger,
	}

	if err := sqliteDB.Initialize(context.TODO()); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return sqliteDB, nil
}

func (s *SQLiteDB) Close(context.Context) error {
	return s.db.Close()
}

// initializeSchema creates the necessary tables and indexes.
func (s *SQLiteDB) Initialize(ctx context.Context) error {
	schema := `
    CREATE TABLE IF NOT EXISTS hashes (
        sha256 TEXT PRIMARY KEY,
        file_name TEXT NOT NULL,
        build_id TEXT NOT NULL,
        last_check_at DATETIME NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerted_hashes (
        sha256 TEXT NOT NULL,
        provider TEXT NOT NULL,
        alerted_at DATETIME NOT NULL,
        PRIMARY KEY (sha256, provider),
        FOREIGN KEY (sha256) REFERENCES hashes(sha256) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_alerted_hashes_alerted_at ON alerted_hashes(alerted_at);
    CREATE INDEX IF NOT EXISTS idx_hashes_last_check_at ON hashes(last_check_at);

	-- Blacklisted Tokens
	CREATE TABLE IF NOT EXISTS blacklisted_tokens (
		token TEXT PRIMARY KEY,
		expires_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_blacklisted_tokens_expires_at ON blacklisted_tokens(expires_at);

	-- Refresh Tokens
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		token TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);

	-- Provider Tokens
	CREATE TABLE IF NOT EXISTS provider_tokens (
		user_id TEXT NOT NULL,
		provider TEXT NOT NULL,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		expires_at DATETIME,
		PRIMARY KEY (user_id, provider)
	);

	CREATE INDEX IF NOT EXISTS idx_provider_tokens_user_id ON provider_tokens(user_id);
	
    `
	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}
	return nil
}

// GetHash retrieves a single hash record by its SHA256.
func (s *SQLiteDB) GetHash(ctx context.Context, sha256 string) (models.HashStatus, error) {
	var hashStatus models.HashStatus

	query := `
		SELECT h.sha256, h.file_name, h.build_id, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
		FROM hashes h
		LEFT JOIN alerted_hashes a ON h.sha256 = a.sha256
		WHERE h.sha256 = ?
		GROUP BY h.sha256;
	`

	var lastCheckAtStr string
	var alertedBy sql.NullString

	err := s.db.QueryRowContext(ctx, query, sha256).Scan(
		&hashStatus.SHA256,
		&hashStatus.FileName,
		&hashStatus.BuildId,
		&lastCheckAtStr,
		&alertedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return hashStatus, fmt.Errorf("hash with SHA256 %s not found", sha256)
		}
		s.logger.WithError(err).Errorf("GetHash: failed to retrieve hash %s", sha256)
		return hashStatus, err
	}

	lastCheckAt, err := time.Parse(time.RFC3339, lastCheckAtStr)
	if err != nil {
		s.logger.WithError(err).Warnf("GetHash: invalid time format for hash %s", sha256)
		return hashStatus, fmt.Errorf("invalid time format for hash %s", sha256)
	}

	hashStatus.LastCheckAt = lastCheckAt

	// Parse alerted_by
	hashStatus.Providers = make(map[string]bool)
	hashStatus.AlertedBy = []string{}
	if alertedBy.Valid && alertedBy.String != "" {
		providerList := strings.Split(alertedBy.String, ",")
		for _, provider := range providerList {
			hashStatus.Providers[provider] = true
			hashStatus.AlertedBy = append(hashStatus.AlertedBy, provider)
		}
	}

	return hashStatus, nil
}

func (s *SQLiteDB) LoadHashes(ctx context.Context) ([]models.HashStatus, error) {
	var records []models.HashStatus

	var query string = `
            SELECT h.sha256, h.file_name, h.build_id, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
            FROM hashes h
            LEFT JOIN alerted_hashes a ON h.sha256 = a.sha256
            GROUP BY h.sha256
            ORDER BY h.last_check_at DESC;
        `

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		s.logger.WithError(err).Error("LoadHashesPaginated: failed to execute query")
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var sha256, fileName, buildId string
		var lastCheckAtStr string
		var alertedBy sql.NullString

		err := rows.Scan(&sha256, &fileName, &buildId, &lastCheckAtStr, &alertedBy)
		if err != nil {
			s.logger.WithError(err).Warn("LoadHashesPaginated: failed to scan row")
			continue
		}

		lastCheckAt, err := time.Parse(time.RFC3339, lastCheckAtStr)
		if err != nil {
			s.logger.WithError(err).Warnf("LoadHashesPaginated: invalid time format for hash %s", sha256)
			continue
		}

		providers := make(map[string]bool)
		alertedBySlice := []string{}
		if alertedBy.Valid && alertedBy.String != "" {
			providerList := strings.Split(alertedBy.String, ",")
			for _, provider := range providerList {
				providers[provider] = true
				alertedBySlice = append(alertedBySlice, provider)
			}
		}

		hashStatus := models.HashStatus{
			SHA256:      sha256,
			FileName:    fileName,
			BuildId:     buildId,
			LastCheckAt: lastCheckAt,
			Providers:   providers,
			AlertedBy:   alertedBySlice,
		}

		records = append(records, hashStatus)
	}

	if err := rows.Err(); err != nil {
		s.logger.WithError(err).Error("LoadHashesPaginated: row iteration error")
		return nil, err
	}
	return records, nil
}

// LoadHashesPaginated retrieves a specific page of hash records and the total count.
// Supports filtering based on whether hashes have been found.
func (s *SQLiteDB) LoadHashesPaginated(ctx context.Context, page, perPage int, filterFound *bool) ([]models.HashStatus, int, error) {
	var records []models.HashStatus
	var total int

	offset := (page - 1) * perPage
	limit := perPage

	var query string
	var args []interface{}

	if filterFound != nil {
		if *filterFound {
			// Only hashes that have been found (exist in alerted_hashes)
			query = `
                SELECT h.sha256, h.file_name, h.build_id, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
                FROM hashes h
                JOIN alerted_hashes a ON h.sha256 = a.sha256
                GROUP BY h.sha256
                ORDER BY h.last_check_at DESC
                LIMIT ? OFFSET ?;
            `
			args = append(args, limit, offset)
		} else {
			// Only hashes that have NOT been found (not exist in alerted_hashes)
			query = `
                SELECT h.sha256, h.file_name, h.build_id, h.last_check_at, NULL as alerted_by
                FROM hashes h
                LEFT JOIN alerted_hashes a ON h.sha256 = a.sha256
                WHERE a.sha256 IS NULL
                ORDER BY h.last_check_at DESC
                LIMIT ? OFFSET ?;
            `
			args = append(args, limit, offset)
		}
	} else {
		// No filter; retrieve all hashes
		query = `
            SELECT h.sha256, h.file_name, h.build_id, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
            FROM hashes h
            LEFT JOIN alerted_hashes a ON h.sha256 = a.sha256
            GROUP BY h.sha256
            ORDER BY h.last_check_at DESC
            LIMIT ? OFFSET ?;
        `
		args = append(args, limit, offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.logger.WithError(err).Error("LoadHashesPaginated: failed to execute query")
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var sha256, fileName, buildId string
		var lastCheckAtStr string
		var alertedBy sql.NullString

		err := rows.Scan(&sha256, &fileName, &buildId, &lastCheckAtStr, &alertedBy)
		if err != nil {
			s.logger.WithError(err).Warn("LoadHashesPaginated: failed to scan row")
			continue
		}

		lastCheckAt, err := time.Parse(time.RFC3339, lastCheckAtStr)
		if err != nil {
			s.logger.WithError(err).Warnf("LoadHashesPaginated: invalid time format for hash %s", sha256)
			continue
		}

		providers := make(map[string]bool)
		alertedBySlice := []string{}
		if alertedBy.Valid && alertedBy.String != "" {
			providerList := strings.Split(alertedBy.String, ",")
			for _, provider := range providerList {
				providers[provider] = true
				alertedBySlice = append(alertedBySlice, provider)
			}
		}

		hashStatus := models.HashStatus{
			SHA256:      sha256,
			FileName:    fileName,
			BuildId:     buildId,
			LastCheckAt: lastCheckAt,
			Providers:   providers,
			AlertedBy:   alertedBySlice,
		}

		records = append(records, hashStatus)
	}

	if err := rows.Err(); err != nil {
		s.logger.WithError(err).Error("LoadHashesPaginated: row iteration error")
		return nil, 0, err
	}

	// Get total count based on filter
	countQuery := ""
	if filterFound != nil {
		if *filterFound {
			countQuery = `
                SELECT COUNT(DISTINCT h.sha256)
                FROM hashes h
                JOIN alerted_hashes a ON h.sha256 = a.sha256;
            `
		} else {
			countQuery = `
                SELECT COUNT(*)
                FROM hashes h
                LEFT JOIN alerted_hashes a ON h.sha256 = a.sha256
                WHERE a.sha256 IS NULL;
            `
		}
	} else {
		countQuery = `
            SELECT COUNT(*)
            FROM hashes;
        `
	}

	err = s.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		s.logger.WithError(err).Error("LoadHashesPaginated: failed to get total count")
		return records, 0, err
	}

	return records, total, nil
}

// GetTotalHashes retrieves the total number of hashes based on the filter.
func (s *SQLiteDB) GetTotalHashes(ctx context.Context) (int, error) {
	var total int
	var query string
	var args []interface{}

	query = `
            SELECT COUNT(*)
            FROM hashes;
        `

	err := s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	if err != nil {
		s.logger.WithError(err).Error("GetTotalHashes: failed to execute query")
		return 0, err
	}

	return total, nil
}

// GetGlobalLastCheckAt retrieves the most recent LastCheckAt timestamp based on the filter.
func (s *SQLiteDB) GetGlobalLastCheckAt(ctx context.Context) (time.Time, error) {
	var latestStr string
	var query string
	var args []interface{}

	// Latest check among all hashes
	query = `
            SELECT MAX(last_check_at)
            FROM hashes;
        `

	err := s.db.QueryRowContext(ctx, query, args...).Scan(&latestStr)
	if err != nil {
		s.logger.WithError(err).Error("GetGlobalLastCheckAt: failed to execute query")
		return time.Time{}, err
	}

	if latestStr == "" {
		return time.Time{}, nil // No records found
	}

	latest, err := time.Parse(time.RFC3339, latestStr)
	if err != nil {
		s.logger.WithError(err).Warnf("GetGlobalLastCheckAt: invalid time format: %s", latestStr)
		return time.Time{}, err
	}

	return latest, nil
}

// GetTotalHashesFound retrieves the total number of hashes found based on the filter.
func (s *SQLiteDB) GetTotalHashesFound(ctx context.Context) (int, error) {
	var total int
	query := `
        SELECT COUNT(DISTINCT sha256)
        FROM alerted_hashes;
    `
	err := s.db.QueryRowContext(ctx, query).Scan(&total)
	if err != nil {
		s.logger.WithError(err).Error("GetTotalHashesFound: failed to execute query")
		return 0, err
	}
	return total, nil
}

// GetHashesFoundToday retrieves the number of hashes found within the last 24 hours based on the filter.
func (s *SQLiteDB) GetHashesFoundToday(ctx context.Context) (int, error) {
	cutoffTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	var count int
	var query string
	var args []interface{}

	// Count of found hashes within last 24 hours
	query = `
            SELECT COUNT(*)
            FROM alerted_hashes
            WHERE alerted_at >= ?;
        `
	args = append(args, cutoffTime)

	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		s.logger.WithError(err).Error("GetHashesFoundToday: failed to execute query")
		return 0, err
	}

	return count, nil
}

// AddHash adds a new hash record to the database.
func (s *SQLiteDB) AddHash(ctx context.Context, record models.HashRecord) error {
	query := `
        INSERT INTO hashes (sha256, file_name, build_id, last_check_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(sha256) DO UPDATE SET
            file_name=excluded.file_name,
            build_id=excluded.build_id,
            last_check_at=excluded.last_check_at;
    `
	_, err := s.db.ExecContext(ctx, query, record.SHA256, record.FileName, record.BuildId, record.LastCheckAt.Format(time.RFC3339))
	if err != nil {
		s.logger.WithError(err).Errorf("AddHash: failed to insert/update hash %s", record.SHA256)
		return err
	}
	return nil
}

// DeleteHash removes a hash record and its associated alerts from the database.
func (s *SQLiteDB) DeleteHash(ctx context.Context, sha256 string) error {
	query := `
        DELETE FROM hashes
        WHERE sha256 = ?;
    `
	_, err := s.db.ExecContext(ctx, query, sha256)
	if err != nil {
		s.logger.WithError(err).Errorf("DeleteHash: failed to delete hash %s", sha256)
		return err
	}
	return nil
}

// MarkAsAlerted marks a hash as alerted by a specific provider with the current timestamp.
func (s *SQLiteDB) MarkAsAlerted(ctx context.Context, sha256, provider string) error {
	currentTime := time.Now().Format(time.RFC3339)

	query := `
        INSERT INTO alerted_hashes (sha256, provider, alerted_at)
        VALUES (?, ?, ?)
        ON CONFLICT(sha256, provider) DO UPDATE SET
            alerted_at=excluded.alerted_at;
    `
	_, err := s.db.ExecContext(ctx, query, sha256, provider, currentTime)
	if err != nil {
		s.logger.WithError(err).Errorf("MarkAsAlerted: failed to insert/update alert for hash %s by provider %s", sha256, provider)
		return err
	}
	return nil
}

// -----------------------
// Token Blacklisting
// -----------------------

// AddBlacklistedToken adds a token string to the blacklist with its expiration time.
func (s *SQLiteDB) AddBlacklistedToken(ctx context.Context, tokenString string, exp int64) error {
	query := `
		INSERT INTO blacklisted_tokens (token, expires_at)
		VALUES (?, ?)
		ON CONFLICT(token) DO UPDATE SET
			expires_at=excluded.expires_at;
	`
	_, err := s.db.ExecContext(ctx, query, tokenString, exp)
	if err != nil {
		s.logger.WithError(err).Errorf("AddBlacklistedToken: failed to add token %s", tokenString)
		return err
	}
	return nil
}

// IsTokenBlacklisted checks if a token is in the blacklist.
// If the token is expired, it removes it from the blacklist.
func (s *SQLiteDB) IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error) {
	var expiresAt int64
	query := `
		SELECT expires_at
		FROM blacklisted_tokens
		WHERE token = ?;
	`
	err := s.db.QueryRowContext(ctx, query, tokenString).Scan(&expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // Token not blacklisted
		}
		s.logger.WithError(err).Errorf("IsTokenBlacklisted: failed to query token %s", tokenString)
		return false, err
	}

	currentUnix := time.Now().Unix()
	if expiresAt < currentUnix {
		// Token expired; remove from blacklist
		delQuery := `
			DELETE FROM blacklisted_tokens
			WHERE token = ?;
		`
		_, delErr := s.db.ExecContext(ctx, delQuery, tokenString)
		if delErr != nil {
			s.logger.WithError(delErr).Errorf("IsTokenBlacklisted: failed to delete expired token %s", tokenString)
			return false, delErr
		}
		return false, nil
	}

	return true, nil // Token is blacklisted and not expired
}

// -----------------------
// Refresh Token Management
// -----------------------

// StoreRefreshToken saves a refresh token with associated user and expiration.
func (s *SQLiteDB) StoreRefreshToken(ctx context.Context, token string, userID string, expiresAt time.Time) error {
	query := `
		INSERT INTO refresh_tokens (token, user_id, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT(token) DO UPDATE SET
			user_id=excluded.user_id,
			expires_at=excluded.expires_at;
	`
	_, err := s.db.ExecContext(ctx, query, token, userID, expiresAt.Format(time.RFC3339))
	if err != nil {
		s.logger.WithError(err).Errorf("StoreRefreshToken: failed to store refresh token %s for user %s", token, userID)
		return err
	}
	return nil
}

// ValidateRefreshToken checks if a refresh token is valid and not expired.
// Returns the associated userID if valid.
func (s *SQLiteDB) ValidateRefreshToken(ctx context.Context, token string) (string, error) {
	var userID string
	var expiresAtStr string
	query := `
		SELECT user_id, expires_at
		FROM refresh_tokens
		WHERE token = ?;
	`
	err := s.db.QueryRowContext(ctx, query, token).Scan(&userID, &expiresAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("refresh token not found")
		}
		s.logger.WithError(err).Errorf("ValidateRefreshToken: failed to query token %s", token)
		return "", err
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		s.logger.WithError(err).Warnf("ValidateRefreshToken: invalid expiration time format for token %s", token)
		// Optionally, revoke the token due to invalid format
		return "", fmt.Errorf("invalid expiration time format")
	}

	if time.Now().After(expiresAt) {
		// Token expired; revoke it
		err = s.RevokeRefreshToken(ctx, token)
		if err != nil {
			s.logger.WithError(err).Errorf("ValidateRefreshToken: failed to revoke expired token %s", token)
			return "", fmt.Errorf("token expired and failed to revoke")
		}
		return "", fmt.Errorf("refresh token expired")
	}

	return userID, nil // Token is valid
}

// RevokeRefreshToken removes a refresh token from the database.
func (s *SQLiteDB) RevokeRefreshToken(ctx context.Context, token string) error {
	query := `
		DELETE FROM refresh_tokens
		WHERE token = ?;
	`
	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		s.logger.WithError(err).Errorf("RevokeRefreshToken: failed to revoke token %s", token)
		return err
	}
	return nil
}

// -----------------------
// Provider Token Management
// -----------------------

// StoreProviderTokens saves tokens obtained from a provider for a user.
func (s *SQLiteDB) StoreProviderTokens(ctx context.Context, userID string, provider string, tokens auth.ProviderTokens) error {
	query := `
		INSERT INTO provider_tokens (user_id, provider, access_token, refresh_token, expires_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, provider) DO UPDATE SET
			access_token=excluded.access_token,
			refresh_token=excluded.refresh_token,
			expires_at=excluded.expires_at;
	`
	expiresAtStr := ""
	if !tokens.ExpiresAt.IsZero() {
		expiresAtStr = tokens.ExpiresAt.Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, query, userID, provider, tokens.AccessToken, tokens.RefreshToken, expiresAtStr)
	if err != nil {
		s.logger.WithError(err).Errorf("StoreProviderTokens: failed to store tokens for user %s and provider %s", userID, provider)
		return err
	}
	return nil
}

// GetProviderTokens retrieves tokens obtained from a provider for a user.
func (s *SQLiteDB) GetProviderTokens(ctx context.Context, userID string, provider string) (auth.ProviderTokens, error) {
	var accessToken, refreshToken string
	var expiresAtStr sql.NullString
	query := `
		SELECT access_token, refresh_token, expires_at
		FROM provider_tokens
		WHERE user_id = ? AND provider = ?;
	`
	err := s.db.QueryRowContext(ctx, query, userID, provider).Scan(&accessToken, &refreshToken, &expiresAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return auth.ProviderTokens{}, fmt.Errorf("provider tokens not found for user %s and provider %s", userID, provider)
		}
		s.logger.WithError(err).Errorf("GetProviderTokens: failed to query tokens for user %s and provider %s", userID, provider)
		return auth.ProviderTokens{}, err
	}

	var expiresAt time.Time
	if expiresAtStr.Valid && expiresAtStr.String != "" {
		expiresAt, err = time.Parse(time.RFC3339, expiresAtStr.String)
		if err != nil {
			s.logger.WithError(err).Warnf("GetProviderTokens: invalid expires_at format for user %s and provider %s", userID, provider)
			// Optionally, handle the invalid format
			expiresAt = time.Time{}
		}
	}

	tokens := auth.ProviderTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}

	return tokens, nil
}

// UpdateProviderTokens updates tokens obtained from a provider for a user.
func (s *SQLiteDB) UpdateProviderTokens(ctx context.Context, userID string, provider string, tokens auth.ProviderTokens) error {
	// Reuse StoreProviderTokens as it handles upsert logic
	return s.StoreProviderTokens(ctx, userID, provider, tokens)
}

// UpdateHash updates specific fields of a hash record identified by its SHA256.
func (s *SQLiteDB) UpdateHash(ctx context.Context, sha256 string, updatedFields models.HashRecord) error {
	// Build the SET clause dynamically based on non-zero fields
	setClauses := []string{}
	args := []interface{}{}

	if updatedFields.FileName != "" {
		setClauses = append(setClauses, "file_name = ?")
		args = append(args, updatedFields.FileName)
	}
	if updatedFields.BuildId != "" {
		setClauses = append(setClauses, "build_id = ?")
		args = append(args, updatedFields.BuildId)
	}
	if !updatedFields.LastCheckAt.IsZero() {
		setClauses = append(setClauses, "last_check_at = ?")
		args = append(args, updatedFields.LastCheckAt.Format(time.RFC3339))
	}

	if len(setClauses) == 0 {
		return fmt.Errorf("no fields to update for hash %s", sha256)
	}

	query := fmt.Sprintf(`
		UPDATE hashes
		SET %s
		WHERE sha256 = ?;
	`, strings.Join(setClauses, ", "))

	args = append(args, sha256)

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		s.logger.WithError(err).Errorf("UpdateHash: failed to update hash %s", sha256)
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		s.logger.WithError(err).Warnf("UpdateHash: failed to get rows affected for hash %s", sha256)
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no hash found with SHA256 %s", sha256)
	}

	return nil
}
