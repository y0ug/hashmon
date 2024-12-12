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

// SQLiteDB represents the SQLite implementation of the Database interface.
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

// Initialize creates the necessary tables and indexes.
func (s *SQLiteDB) Initialize(ctx context.Context) error {
	schema := `
    CREATE TABLE IF NOT EXISTS hashes (
        hash TEXT PRIMARY KEY,
        comment TEXT NOT NULL,
        last_check_at DATETIME NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerted_hashes (
        hash TEXT NOT NULL,
        provider TEXT NOT NULL,
        alerted_at DATETIME NOT NULL,
        PRIMARY KEY (hash, provider),
        FOREIGN KEY (hash) REFERENCES hashes(hash) ON DELETE CASCADE
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

// GetHash retrieves a single hash record by its Hash.
func (s *SQLiteDB) GetHash(ctx context.Context, hash string) (models.HashStatus, error) {
	var hashStatus models.HashStatus

	query := `
		SELECT h.hash, h.comment, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
		FROM hashes h
		LEFT JOIN alerted_hashes a ON h.hash = a.hash
		WHERE h.hash = ?
		GROUP BY h.hash;
	`

	var lastCheckAtStr string
	var alertedBy sql.NullString

	err := s.db.QueryRowContext(ctx, query, hash).Scan(
		&hashStatus.Hash,
		&hashStatus.Comment,
		&lastCheckAtStr,
		&alertedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return hashStatus, fmt.Errorf("hash with Hash %s not found", hash)
		}
		s.logger.WithError(err).Errorf("GetHash: failed to retrieve hash %s", hash)
		return hashStatus, err
	}

	lastCheckAt, err := time.Parse(time.RFC3339, lastCheckAtStr)
	if err != nil {
		s.logger.WithError(err).Warnf("GetHash: invalid time format for hash %s", hash)
		return hashStatus, fmt.Errorf("invalid time format for hash %s", hash)
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
            SELECT h.hash, h.comment, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
            FROM hashes h
            LEFT JOIN alerted_hashes a ON h.hash = a.hash
            GROUP BY h.hash
            ORDER BY h.last_check_at DESC;
        `

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		s.logger.WithError(err).Error("LoadHashes: failed to execute query")
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var hash, comment string
		var lastCheckAtStr string
		var alertedBy sql.NullString

		err := rows.Scan(&hash, &comment, &lastCheckAtStr, &alertedBy)
		if err != nil {
			s.logger.WithError(err).Warn("LoadHashes: failed to scan row")
			continue
		}

		lastCheckAt, err := time.Parse(time.RFC3339, lastCheckAtStr)
		if err != nil {
			s.logger.WithError(err).Warnf("LoadHashes: invalid time format for hash %s", hash)
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
			Hash:        hash,
			Comment:     comment,
			LastCheckAt: lastCheckAt,
			Providers:   providers,
			AlertedBy:   alertedBySlice,
		}

		records = append(records, hashStatus)
	}

	if err := rows.Err(); err != nil {
		s.logger.WithError(err).Error("LoadHashes: row iteration error")
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
                SELECT h.hash, h.comment, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
                FROM hashes h
                JOIN alerted_hashes a ON h.hash = a.hash
                GROUP BY h.hash
                ORDER BY h.last_check_at DESC
                LIMIT ? OFFSET ?;
            `
			args = append(args, limit, offset)
		} else {
			// Only hashes that have NOT been found (not exist in alerted_hashes)
			query = `
                SELECT h.hash, h.comment, h.last_check_at, NULL as alerted_by
                FROM hashes h
                LEFT JOIN alerted_hashes a ON h.hash = a.hash
                WHERE a.hash IS NULL
                ORDER BY h.last_check_at DESC
                LIMIT ? OFFSET ?;
            `
			args = append(args, limit, offset)
		}
	} else {
		// No filter; retrieve all hashes
		query = `
            SELECT h.hash, h.comment, h.last_check_at, GROUP_CONCAT(a.provider) as alerted_by
            FROM hashes h
            LEFT JOIN alerted_hashes a ON h.hash = a.hash
            GROUP BY h.hash
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
		var hash, comment string
		var lastCheckAtStr string
		var alertedBy sql.NullString

		err := rows.Scan(&hash, &comment, &lastCheckAtStr, &alertedBy)
		if err != nil {
			s.logger.WithError(err).Warn("LoadHashesPaginated: failed to scan row")
			continue
		}

		lastCheckAt, err := time.Parse(time.RFC3339, lastCheckAtStr)
		if err != nil {
			s.logger.WithError(err).Warnf("LoadHashesPaginated: invalid time format for hash %s", hash)
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
			Hash:        hash,
			Comment:     comment,
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
                SELECT COUNT(DISTINCT h.hash)
                FROM hashes h
                JOIN alerted_hashes a ON h.hash = a.hash;
            `
		} else {
			countQuery = `
                SELECT COUNT(*)
                FROM hashes h
                LEFT JOIN alerted_hashes a ON h.hash = a.hash
                WHERE a.hash IS NULL;
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

// GetTotalHashes retrieves the total number of hashes.
func (s *SQLiteDB) GetTotalHashes(ctx context.Context) (int, error) {
	var total int
	var query string

	query = `
            SELECT COUNT(*)
            FROM hashes;
        `

	err := s.db.QueryRowContext(ctx, query).Scan(&total)
	if err != nil {
		s.logger.WithError(err).Error("GetTotalHashes: failed to execute query")
		return 0, err
	}

	return total, nil
}

// GetGlobalLastCheckAt retrieves the most recent LastCheckAt timestamp.
func (s *SQLiteDB) GetGlobalLastCheckAt(ctx context.Context) (time.Time, error) {
	var latestStr string
	var query string

	// Latest check among all hashes
	query = `
            SELECT MAX(last_check_at)
            FROM hashes;
        `

	err := s.db.QueryRowContext(ctx, query).Scan(&latestStr)
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

// GetTotalHashesFound retrieves the total number of hashes found.
func (s *SQLiteDB) GetTotalHashesFound(ctx context.Context) (int, error) {
	var total int
	query := `
        SELECT COUNT(DISTINCT hash)
        FROM alerted_hashes;
    `
	err := s.db.QueryRowContext(ctx, query).Scan(&total)
	if err != nil {
		s.logger.WithError(err).Error("GetTotalHashesFound: failed to execute query")
		return 0, err
	}
	return total, nil
}

// GetHashesFoundToday retrieves the number of hashes found within the last 24 hours.
func (s *SQLiteDB) GetHashesFoundToday(ctx context.Context) (int, error) {
	cutoffTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	var count int
	query := `
            SELECT COUNT(*)
            FROM alerted_hashes
            WHERE alerted_at >= ?;
        `
	err := s.db.QueryRowContext(ctx, query, cutoffTime).Scan(&count)
	if err != nil {
		s.logger.WithError(err).Error("GetHashesFoundToday: failed to execute query")
		return 0, err
	}

	return count, nil
}

// AddHash adds a new hash record to the database after validation.
func (s *SQLiteDB) AddHash(ctx context.Context, record models.HashRecord) error {
	// Validate the hash
	if err := record.ValidateHash(); err != nil {
		s.logger.WithError(err).Warnf("AddHash: invalid hash format for %s", record.Hash)
		return err
	}

	query := `
        INSERT INTO hashes (hash, comment, last_check_at)
        VALUES (?, ?, ?)
        ON CONFLICT(hash) DO UPDATE SET
            comment=excluded.comment,
            last_check_at=excluded.last_check_at;
    `
	_, err := s.db.ExecContext(ctx, query, record.Hash, record.Comment, record.LastCheckAt.Format(time.RFC3339))
	if err != nil {
		s.logger.WithError(err).Errorf("AddHash: failed to insert/update hash %s", record.Hash)
		return err
	}
	return nil
}

// DeleteHash removes a hash record and its associated alerts from the database.
func (s *SQLiteDB) DeleteHash(ctx context.Context, hash string) error {
	query := `
        DELETE FROM hashes
        WHERE hash = ?;
    `
	_, err := s.db.ExecContext(ctx, query, hash)
	if err != nil {
		s.logger.WithError(err).Errorf("DeleteHash: failed to delete hash %s", hash)
		return err
	}
	return nil
}

// MarkAsAlerted marks a hash as alerted by a specific provider with the current timestamp.
func (s *SQLiteDB) MarkAsAlerted(ctx context.Context, hash, provider string) error {
	currentTime := time.Now().Format(time.RFC3339)

	query := `
        INSERT INTO alerted_hashes (hash, provider, alerted_at)
        VALUES (?, ?, ?)
        ON CONFLICT(hash, provider) DO UPDATE SET
            alerted_at=excluded.alerted_at;
    `
	_, err := s.db.ExecContext(ctx, query, hash, provider, currentTime)
	if err != nil {
		s.logger.WithError(err).Errorf("MarkAsAlerted: failed to insert/update alert for hash %s by provider %s", hash, provider)
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

// UpdateHash updates specific fields of a hash record identified by its Hash.
func (s *SQLiteDB) UpdateHash(ctx context.Context, hash string, updatedFields models.HashRecord) error {
	// Validate the hash if it's being updated
	if updatedFields.Hash != "" && updatedFields.Hash != hash {
		if err := updatedFields.ValidateHash(); err != nil {
			s.logger.WithError(err).Warnf("UpdateHash: invalid hash format for %s", updatedFields.Hash)
			return err
		}
	}

	// Build the SET clause dynamically based on non-zero fields
	setClauses := []string{}
	args := []interface{}{}

	if updatedFields.Comment != "" {
		setClauses = append(setClauses, "comment = ?")
		args = append(args, updatedFields.Comment)
	}
	if !updatedFields.LastCheckAt.IsZero() {
		setClauses = append(setClauses, "last_check_at = ?")
		args = append(args, updatedFields.LastCheckAt.Format(time.RFC3339))
	}

	if len(setClauses) == 0 {
		return fmt.Errorf("no fields to update for hash %s", hash)
	}

	query := fmt.Sprintf(`
		UPDATE hashes
		SET %s
		WHERE hash = ?;
	`, strings.Join(setClauses, ", "))

	args = append(args, hash)

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		s.logger.WithError(err).Errorf("UpdateHash: failed to update hash %s", hash)
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		s.logger.WithError(err).Warnf("UpdateHash: failed to get rows affected for hash %s", hash)
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no hash found with Hash %s", hash)
	}

	return nil
}
