package webserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/y0ug/hashmon/internal/database/models"
	"github.com/y0ug/hashmon/internal/hashmon"
	"github.com/y0ug/hashmon/pkg/auth"
)

// WebServer holds the data needed for handling HTTP requests.
type WebServer struct {
	Monitor     *hashmon.Monitor
	config      *WebserverConfig
	authConfig  *auth.Config
	authHandler *auth.Handler
	Logger      *logrus.Logger // Added Logger field
}

// StartWebServer starts the HTTP server.
func StartWebServer(ctx context.Context, ws *WebServer) (*http.Server, error) {
	router := ws.InitRouter()

	// Configure CORS options
	corsOptions := cors.Options{
		AllowedOrigins:   ws.config.CorsAllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: true,
		Debug:            false,
	}

	// Create CORS handler
	handler := cors.New(corsOptions).Handler(router)

	// Create the server
	server := &http.Server{
		Addr:    ws.config.ListenTo,
		Handler: handler,
	}

	// Start the server in a separate goroutine
	go func() {
		ws.Logger.Infof("Server starting on %s", ws.config.ListenTo)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ws.Logger.Errorf("ListenAndServe(): %v", err)
		}
	}()

	ws.Logger.Infof("Server started on %s", ws.config.ListenTo)
	return server, nil
}

// NewWebServer initializes a new WebServer.
func NewWebServer(monitor *hashmon.Monitor, config *WebserverConfig, authConfig *auth.Config, authHandler *auth.Handler, logger *logrus.Logger) *WebServer {
	return &WebServer{
		Monitor:     monitor,
		config:      config,
		authConfig:  authConfig,
		authHandler: authHandler,
		Logger:      logger,
	}
}

// InitRouter initializes the HTTP routes.
func (ws *WebServer) InitRouter() *mux.Router {
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	authRouter := r.PathPrefix("/auth").Subrouter()

	// Authentication routes
	if ws.authConfig.AuthType == "oauth2" {

		authRouter.HandleFunc("/providers", ws.authHandler.HandlerProviders).Methods("GET")
		authRouter.HandleFunc("/login/{provider}", ws.authHandler.HandleLogin).Methods("GET")
		authRouter.HandleFunc("/callback/{provider}", ws.authHandler.HandleCallback).Methods("GET")

		authRouter.Handle("/status", ws.authHandler.AuthMiddleware(http.HandlerFunc(ws.authHandler.HandleStatus))).Methods("GET")
		authRouter.Handle("/logout", ws.authHandler.AuthMiddleware(http.HandlerFunc(ws.authHandler.HandleLogout))).Methods("POST")
		authRouter.Handle("/logout", ws.authHandler.AuthMiddleware(http.HandlerFunc(ws.authHandler.HandleLogout))).Methods("GET")
		authRouter.HandleFunc("/refresh", ws.authHandler.HandleRefresh).Methods("POST")
		authRouter.HandleFunc("/refresh", ws.authHandler.HandleRefresh).Methods("GET")

		api.Use(ws.authHandler.AuthMiddleware)
	}

	// API routes
	api.HandleFunc("/stats", ws.handleGetStats).Methods(http.MethodGet)
	api.HandleFunc("/hashes", ws.handleGetHashes).Methods(http.MethodGet)
	api.HandleFunc("/hashes/{hash}", ws.handleGetHashDetail).Methods(http.MethodGet)
	api.HandleFunc("/hashes", ws.handleAddHash).Methods(http.MethodPut)
	api.HandleFunc("/hashes/{hash}", ws.handleDeleteHash).Methods(http.MethodDelete)

	// Static file serving
	r.PathPrefix("/").Handler(
		http.StripPrefix("/", http.FileServer(http.Dir("./build/"))))
	return r
}

// handleGetHashes handles the GET /hashes endpoint.
func (ws *WebServer) handleGetHashes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters for pagination
	query := r.URL.Query()
	page, err := strconv.Atoi(query.Get("page"))
	if err != nil || page < 1 {
		page = 1 // Default to page 1
	}
	perPage, err := strconv.Atoi(query.Get("per_page"))
	if err != nil || perPage < 1 {
		perPage = 50 // Default to 50 items per page
	}

	// Parse 'found' query parameter for filtering
	foundParam := strings.ToLower(query.Get("found"))
	var filterFound *bool
	if foundParam == "true" {
		value := true
		filterFound = &value
	} else if foundParam == "false" {
		value := false
		filterFound = &value
	}

	// Fetch paginated hash statuses
	hashes, total, err := ws.Monitor.LoadHashesPaginated(ctx, page, perPage, filterFound)
	if err != nil {
		ws.Logger.WithError(err).Error("Failed to load paginated hashes")
		auth.WriteErrorResponse(w, "Failed to retrieve hashes", http.StatusInternalServerError)
		return
	}

	// Calculate total pages
	totalPages := (total + perPage - 1) / perPage

	// Construct the response with pagination metadata
	response := models.HashesResponse{
		Hashes:     hashes,
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}

	auth.WriteSuccessResponse(w, "Hashes retrieved successfully", response)
}

// handleGetHashDetail handles the GET /hashes/{hash} endpoint.
func (ws *WebServer) handleGetHashDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	hash := vars["hash"]
	hashStatus, err := ws.Monitor.GetHashStatus(ctx, hash)
	if err != nil {
		ws.Logger.Errorf("Failed to get hash status for %s: %v", hash, err)
		auth.WriteErrorResponse(w, "Hash not found", http.StatusNotFound)
		return
	}

	response := models.HashDetailResponse{
		Hash: hashStatus,
	}

	auth.WriteSuccessResponse(w, "Hash detail retrieved successfully", response)
}

// handleAddHash handles the PUT /hashes endpoint.
func (ws *WebServer) handleAddHash(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var newHash models.HashRecord

	// Decode the JSON payload
	err := r.ParseForm()
	if err != nil {
		ws.Logger.Errorf("Error parsing form: %v", err)
		auth.WriteErrorResponse(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	err = json.NewDecoder(r.Body).Decode(&newHash)
	if err != nil {
		ws.Logger.Errorf("Invalid JSON payload: %v", err)
		auth.WriteErrorResponse(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Basic validation
	if newHash.Hash == "" {
		ws.Logger.Warn("Hash field is required")
		auth.WriteErrorResponse(w, "Hash field is required", http.StatusBadRequest)
		return
	}

	// Add the new hash to the monitor
	err = ws.Monitor.AddHash(ctx, newHash)
	if err != nil {
		ws.Logger.Errorf("Failed to add hash: %v", err)
		auth.WriteErrorResponse(w, "Failed to add hash", http.StatusInternalServerError)
		return
	}

	// Respond with the created hash
	auth.WriteSuccessResponse(w, "Hash added successfully", newHash)
}

// handleDeleteHash handles the DELETE /hashes/{hash} endpoint.
func (ws *WebServer) handleDeleteHash(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	hash, exists := vars["hash"]
	if !exists || hash == "" {
		ws.Logger.Warn("Hash parameter is required")
		auth.WriteErrorResponse(w, "Hash parameter is required", http.StatusBadRequest)
		return
	}

	// Delete the hash from the monitor
	err := ws.Monitor.Config.Database.DeleteHash(ctx, hash)
	if err != nil {
		ws.Logger.Errorf("Failed to delete hash %s: %v", hash, err)
		auth.WriteErrorResponse(w, "Failed to delete hash", http.StatusInternalServerError)
		return
	}

	// Respond with no content
	auth.WriteSuccessResponse(w, "Hash deleted successfully", nil)
}

// handleGetStats handles the GET /api/stats endpoint.
func (ws *WebServer) handleGetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Fetch statistics from the Monitor
	stats, err := ws.Monitor.GetStats(ctx)
	if err != nil {
		ws.Logger.WithError(err).Error("Failed to retrieve stats")
		auth.WriteErrorResponse(w, "Failed to retrieve statistics", http.StatusInternalServerError)
		return
	}

	// Construct the response
	response := models.StatsResponse{
		TotalHashes:       stats.TotalHashes,
		GlobalLastCheckAt: stats.GlobalLastCheckAt,
		TotalHashesFound:  stats.TotalHashesFound,
		HashesFoundToday:  stats.HashesFoundToday,
	}

	auth.WriteSuccessResponse(w, "Statistics retrieved successfully", response)
}
