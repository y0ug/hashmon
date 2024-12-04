package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/y0ug/hashmon/apis"
	"github.com/y0ug/hashmon/config"
	"github.com/y0ug/hashmon/database" // Database abstraction
	"github.com/y0ug/hashmon/notifications"
	"github.com/y0ug/hashmon/pkg/auth"
	"golang.org/x/time/rate"
)

func main() {
	// Initialize Logrus
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// Define a command-line flag for the input file path
	inputFilePathFlag := flag.String("i", "", "Path to the input file")

	// Parse command-line flags
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Override the input file path if the flag is provided
	if *inputFilePathFlag != "" {
		logrus.Debugf("Overriding input file path with command-line flag: %s", *inputFilePathFlag)
		cfg.InputFilePath = *inputFilePathFlag
	}

	// Validate the input file path
	if cfg.InputFilePath == "" {
		logrus.Fatal("Input file path is required but not provided.")
	}

	// Initialize Database
	var db database.Database
	switch cfg.DatabaseType {
	case "bolt":
		// Assume cfg.DatabasePath is provided in config
		db, err = database.NewBoltDB(cfg.DatabasePath)
		if err != nil {
			logrus.Fatalf("Failed to initialize BoltDB: %v", err)
		}
		defer db.Close()
		logrus.Info("BoltDB initialized successfully")
	case "redis":
		// Initialize RedisDB (assuming Redis configuration is in config)
		// db, err = database.NewRedisDB(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
		// if err != nil {
		// 	logrus.Fatalf("Failed to initialize RedisDB: %v", err)
		// }
		// defer db.Close()
		// logrus.Info("RedisDB initialized successfully")
	default:
		logrus.Fatalf("Unsupported database type: %s", cfg.DatabaseType)
	}

	// Ensure the database implements auth.Database interface
	authDB, ok := db.(auth.Database)
	if !ok {
		logrus.Fatal("Database does not implement the required authentication interface")
	}

	// Initialize Auth Config
	authConfig, err := auth.NewConfig()
	if err != nil {
		logrus.Fatalf("Failed to initialize auth config: %v", err)
	}

	// Initialize Auth Handler
	authHandler := auth.NewHandler(authConfig, authDB)

	// Initialize API clients
	var apiClients []apis.APIClient

	if cfg.VirusTotalAPIKey != "" {
		vtClient := apis.NewVirusTotalClient(cfg.VirusTotalAPIKey)
		apiClients = append(apiClients, vtClient)
		logrus.Info("VirusTotal client initialized")
	} else {
		logrus.Warn("VirusTotal API key not provided. Skipping VirusTotal monitoring.")
	}

	if cfg.CuckooAPIKey != "" && cfg.CuckooBaseURL != "" {
		cuckooClient := apis.NewCuckooClient(cfg.CuckooBaseURL, cfg.CuckooAPIKey)
		apiClients = append(apiClients, cuckooClient)
		logrus.Info("Cuckoo Sandbox client initialized")
	} else {
		logrus.Warn("Cuckoo Sandbox settings incomplete. Skipping Cuckoo monitoring.")
	}

	if len(apiClients) == 0 {
		logrus.Fatal("No API clients initialized. Exiting.")
	}

	// Set rate limiters for API clients
	for _, apiClient := range apiClients {
		for _, rl := range cfg.RateLimits {
			if rl.APIName == apiClient.ProviderName() {
				limiter := &apis.RateLimiter{
					Limiter: rate.NewLimiter(rl.Rate, rl.Burst),
					Burst:   rl.Burst,
					Rate:    rl.Rate,
				}
				logrus.Infof("Setting rate limiter for %s: %v",
					apiClient.ProviderName(), limiter)
				apiClient.SetRateLimiter(limiter)
			}
		}
	}

	// Initialize Notifier
	notifier, err := notifications.NewNotifier(cfg.ShoutrrrURLs)
	if err != nil {
		logrus.Fatalf("Failed to initialize notifier: %v", err)
	}
	logrus.Info("Notifier initialized successfully")

	// Initialize Monitor
	monitorConfig := MonitorConfig{
		PollInterval:  cfg.PollInterval,
		Notifier:      notifier,
		APIClients:    apiClients,
		CheckInterval: cfg.CheckInterval,
		Database:      db,
	}

	monitor := NewMonitor(monitorConfig, 5) // maxConcurrency is 5

	// Check if hashes exist in the database; if not, import from file
	hashCount, err := func() (int, error) {
		hashes, err := db.LoadHashes()
		if err != nil {
			return 0, err
		}
		return len(hashes), nil
	}()
	if err != nil {
		logrus.Fatalf("Failed to load hashes from database: %v", err)
	}

	if hashCount == 0 {
		logrus.Info("Hashes bucket is empty. Importing hashes from file.")
		err := monitor.ImportHashesFromFile(cfg.InputFilePath)
		if err != nil {
			logrus.Fatalf("Failed to import hashes: %v", err)
		}
	} else {
		logrus.WithField("hash_count", hashCount).Info("Loaded existing hashes from database")
	}

	// Load hashes into memory (if needed)
	hashRecords, err := monitor.LoadHashes()
	if err != nil {
		logrus.Fatalf("Failed to load hashes from database: %v", err)
	}
	logrus.WithField("record_count", len(hashRecords)).Info("Hashes loaded successfully")

	// Initialize Web Server
	webServer := NewWebServer(monitor, cfg.WebserverConfig, authConfig, authHandler)

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to listen for errors from the server
	serverErrors := make(chan error, 1)

	// Start the web server
	server, err := StartWebServer(ctx, webServer)
	if err != nil {
		logrus.Fatalf("Failed to start web server: %v", err)
	}

	// Start monitoring in a separate goroutine
	go func() {
		logrus.Info("Starting monitoring process")
		monitor.Start(ctx)
	}()

	// Listen for OS signals to handle graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received or an error occurs
	select {
	case sig := <-sigs:
		logrus.Infof("Received signal: %s. Initiating shutdown...", sig)
	case err := <-serverErrors:
		logrus.Fatalf("Web server error: %v", err)
	}

	// Initiate shutdown
	cancel() // Cancel the monitor's context

	// Create a context with timeout for the server's shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// Shutdown the web server gracefully
	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.Fatalf("Failed to gracefully shutdown the server: %v", err)
	}

	logrus.Info("Shutdown complete. Exiting.")
}
