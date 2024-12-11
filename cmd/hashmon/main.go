package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"github.com/y0ug/hashmon/internal/database"
	"github.com/y0ug/hashmon/internal/hashmon"
	"github.com/y0ug/hashmon/internal/hashmon/apis"
	"github.com/y0ug/hashmon/internal/notifications"
	"github.com/y0ug/hashmon/internal/webserver"
	"github.com/y0ug/hashmon/pkg/auth"
	"golang.org/x/time/rate"
)

func main() {
	ctx := context.Background()

	// Initialize Logrus
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{}) // Optional: JSON formatting
	logger.SetLevel(logrus.DebugLevel)           // Set default log level to Debug

	// Define a command-line flag for the input file path
	inputFilePathFlag := flag.String("i", "", "Path to the input file")

	// Parse command-line flags
	flag.Parse()

	// Load .env file if present
	err := godotenv.Load()
	if err != nil {
		logrus.Info("No .env file found for hashmon configuration. Proceeding with environment variables.")
	}

	// Load hashmon-specific configuration
	hashmonCfg, err := hashmon.LoadConfig()
	if err != nil {
		logger.Fatalf("Failed to load hashmon configuration: %v", err)
	}

	// Override the input file path if the flag is provided
	if *inputFilePathFlag != "" {
		logger.Debugf("Overriding input file path with command-line flag: %s", *inputFilePathFlag)
		hashmonCfg.InputFilePath = *inputFilePathFlag
	}

	// Validate the input file path
	if hashmonCfg.InputFilePath == "" {
		logger.Fatal("Input file path is required but not provided.")
	}

	// Load database configuration
	dbConfig, err := database.LoadDatabaseConfig()
	if err != nil {
		logger.Fatalf("Failed to load database configuration: %v", err)
	}

	// Initialize Database
	var db database.Database
	switch dbConfig.Type {
	case "sqlite":
		db, err = database.NewSQLiteDB(dbConfig.Path, logger)
		if err != nil {
			logger.Fatalf("Failed to initialize SQlite: %v", err)
		}
		defer db.Close(ctx)
		logger.Info("SQLite initialized successfully")
		// case "bolt":
	// 	db, err = database.NewBoltDB(dbConfig)
	// 	if err != nil {
	// 		logger.Fatalf("Failed to initialize BoltDB: %v", err)
	// 	}
	// 	defer db.Close(ctx)
	// 	logger.Info("BoltDB initialized successfully")
	// case "redis":
	// 	db, err = database.NewRedisDB(dbConfig)
	// 	if err != nil {
	// 		logger.Fatalf("Failed to initialize RedisDB: %v", err)
	// 	}
	// 	defer db.Close(ctx)
	// 	logger.Info("RedisDB initialized successfully")
	default:
		logger.Fatalf("Unsupported database type: %s", dbConfig.Type)
	}

	// Ensure the database implements auth.Database interface
	authDB, ok := db.(auth.Database)
	if !ok {
		logger.Fatal("Database does not implement the required authentication interface")
	}

	// Load notification configuration
	notificationCfg, err := notifications.LoadNotificationConfig()
	if err != nil {
		logger.Fatalf("Failed to load notification configuration: %v", err)
	}

	// Initialize Notifier
	notifier, err := notifications.NewNotifier(notificationCfg)
	if err != nil {
		logger.Fatalf("Failed to initialize notifier: %v", err)
	}
	logger.Info("Notifier initialized successfully")

	// Initialize Auth Config
	authConfig, err := auth.NewConfig()
	if err != nil {
		logger.Fatalf("Failed to initialize auth config: %v", err)
	}

	logger.Infof("Auth type: %v", authConfig.AuthType)
	for _, provider := range authConfig.Providers {
		logger.Infof("Auth provider: %s", provider.Name())
	}
	// Initialize Auth Handler
	authHandler := auth.NewHandler(authConfig, authDB, logger)

	// Initialize API clients
	var apiClients []apis.APIClient

	if hashmonCfg.VirusTotalAPIKey != "" {
		vtClient := apis.NewVirusTotalClient(hashmonCfg.VirusTotalAPIKey)
		apiClients = append(apiClients, vtClient)
		logger.Info("VirusTotal client initialized")
	} else {
		logger.Warn("VirusTotal API key not provided. Skipping VirusTotal monitoring.")
	}

	if hashmonCfg.CuckooAPIKey != "" && hashmonCfg.CuckooBaseURL != "" {
		cuckooClient := apis.NewCuckooClient(hashmonCfg.CuckooBaseURL, hashmonCfg.CuckooAPIKey)
		apiClients = append(apiClients, cuckooClient)
		logger.Info("Cuckoo Sandbox client initialized")
	} else {
		logger.Warn("Cuckoo Sandbox settings incomplete. Skipping Cuckoo monitoring.")
	}

	if len(apiClients) == 0 {
		logger.Fatal("No API clients initialized. Exiting.")
	}

	// Set rate limiters for API clients
	for _, apiClient := range apiClients {
		for _, rl := range hashmonCfg.RateLimits {
			if rl.APIName == apiClient.ProviderName() {
				limiter := &apis.RateLimiter{
					Limiter: rate.NewLimiter(rl.Rate, rl.Burst),
					Burst:   rl.Burst,
					Rate:    rl.Rate,
				}
				logger.Infof("Setting rate limiter for %s: %v",
					apiClient.ProviderName(), limiter)
				apiClient.SetRateLimiter(limiter)
			}
		}
	}

	// Initialize Monitor
	monitorConfig := hashmon.MonitorConfig{
		PollInterval:  hashmonCfg.PollInterval,
		Notifier:      notifier,
		APIClients:    apiClients,
		CheckInterval: hashmonCfg.CheckInterval,
		Database:      db,
	}

	monitor := hashmon.NewMonitor(monitorConfig, 5) // maxConcurrency is 5

	// Check if hashes exist in the database; if not, import from file
	hashCount, err := db.GetTotalHashes(ctx)
	if err != nil {
		logger.Fatalf("Failed to load hashes from database: %v", err)
	}

	if hashCount == 0 {
		logger.Info("Hashes bucket is empty. Importing hashes from file.")
		err := monitor.ImportHashesFromFile(ctx, hashmonCfg.InputFilePath)
		if err != nil {
			logger.Fatalf("Failed to import hashes: %v", err)
		}
	} else {
		logger.WithField("hash_count", hashCount).Info("Loaded existing hashes from database")
	}

	// // Load hashes into memory (if needed)
	// hashRecords, err := monitor.LoadHashes(ctx)
	// if err != nil {
	// 	logger.Fatalf("Failed to load hashes from database: %v", err)
	// }
	// logger.WithField("record_count", len(hashRecords)).Info("Hashes loaded successfully")

	webServerConfig, err := webserver.NewWebserverConfig()
	if err != nil {
		logger.Fatalf("Failed to load webserver configuration: %v", err)
	}

	// Initialize Web Server
	webServer := webserver.NewWebServer(monitor, webServerConfig, authConfig, authHandler, logger)

	// Create a cancellable context
	ctxCancel, cancel := context.WithCancel(ctx)
	defer cancel()

	// Channel to listen for errors from the server
	serverErrors := make(chan error, 1)

	// Start the web server
	server, err := webserver.StartWebServer(ctxCancel, webServer)
	if err != nil {
		logger.Fatalf("Failed to start web server: %v", err)
	}

	// Start monitoring in a separate goroutine
	go func() {
		logger.Info("Starting monitoring process")
		monitor.Start(ctxCancel)
	}()

	// Listen for OS signals to handle graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received or an error occurs
	select {
	case sig := <-sigs:
		logger.Infof("Received signal: %s. Initiating shutdown...", sig)
	case err := <-serverErrors:
		logger.Fatalf("Web server error: %v", err)
	}

	// Initiate shutdown
	cancel() // Cancel the monitor's context

	// Create a context with timeout for the server's shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()

	// Shutdown the web server gracefully
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Fatalf("Failed to gracefully shutdown the server: %v", err)
	}

	logger.Info("Shutdown complete. Exiting.")
}
