package database

import (
	"fmt"
	"os"
	"strconv"
)

// DatabaseConfig holds the database-related configuration.
type DatabaseConfig struct {
	Type      string
	Path      string
	RedisAddr string
	RedisPass string
	RedisDB   int
}

// LoadDatabaseConfig loads database configuration from environment variables.
func LoadDatabaseConfig() (*DatabaseConfig, error) {
	dbType := os.Getenv("DATABASE_TYPE")
	if dbType == "" {
		return nil, fmt.Errorf("DATABASE_TYPE environment variable is required")
	}

	config := &DatabaseConfig{
		Type: dbType,
	}

	switch dbType {
	case "bolt":
		config.Path = os.Getenv("DATABASE_PATH")
		if config.Path == "" {
			return nil, fmt.Errorf("DATABASE_PATH is required for BoltDB")
		}
	case "redis":
		config.RedisAddr = os.Getenv("REDIS_ADDR")
		if config.RedisAddr == "" {
			return nil, fmt.Errorf("REDIS_ADDR is required for RedisDB")
		}
		config.RedisPass = os.Getenv("REDIS_PASSWORD")
		dbStr := os.Getenv("REDIS_DB")
		if dbStr == "" {
			config.RedisDB = 0 // default DB
		} else {
			db, err := strconv.Atoi(dbStr)
			if err != nil {
				return nil, fmt.Errorf("invalid REDIS_DB value: %v", err)
			}
			config.RedisDB = db
		}
	default:
		return nil, fmt.Errorf("unsupported DATABASE_TYPE: %s", dbType)
	}

	return config, nil
}
