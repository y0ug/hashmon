package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/y0ug/hashmon/apis"
	"github.com/y0ug/hashmon/config"
	"github.com/y0ug/hashmon/models"
	"github.com/y0ug/hashmon/notifications"

	"github.com/sirupsen/logrus"
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

	// Read file
	ext := strings.ToLower(filepath.Ext(cfg.InputFilePath))
	var hashRecords []models.HashRecord
	switch ext {
	case ".csv":
		hashRecords, err = ReadCSV(cfg.InputFilePath)
		if err != nil {
			logrus.Fatalf("Error reading CSV: %v", err)
		}
	default:
		hashRecords, err = ReadTxtFile(cfg.InputFilePath)
		if err != nil {
			logrus.Fatalf("Error reading file: %v", err)
		}
	}

	logrus.WithField("record_count", len(hashRecords)).Info("file loaded successfully")

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
	}

	monitor := NewMonitor(monitorConfig,
		hashRecords, 5, "alerted_hashes.db")

	// Initialize Web Server
	webServer := NewWebServer(monitor)
	server := &http.Server{
		Addr:    ":8808", // You can make this configurable
		Handler: webServer,
	}

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to listen for errors from the server
	serverErrors := make(chan error, 1)

	// Start the web server in a separate goroutine
	go func() {
		logrus.Infof("Starting web server on %s", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

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
