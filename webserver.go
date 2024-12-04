package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/y0ug/hashmon/config"
	"github.com/y0ug/hashmon/models"
	"github.com/y0ug/hashmon/pkg/auth"
)

// WebServer holds the data needed for handling HTTP requests.
type WebServer struct {
	Monitor     *Monitor
	config      *config.WebserverConfig
	authConfig  *auth.Config
	authHandler *auth.Handler
}

// StartWebServer starts the HTTP server.
func StartWebServer(ctx context.Context, ws *WebServer) (*http.Server, error) {
	router := ws.InitRouter()

	// Configure CORS options
	corsOptions := cors.Options{
		AllowedOrigins:   ws.config.CorsAllowedOrigins, // Adjust as needed
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
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("ListenAndServe(): %v", err)
		}
	}()

	fmt.Printf("Server started on %s\n", ws.config.ListenTo)
	return server, nil
}

// NewWebServer initializes a new WebServer.
func NewWebServer(monitor *Monitor, config *config.WebserverConfig, authConfig *auth.Config, authHandler *auth.Handler) *WebServer {
	return &WebServer{
		Monitor:     monitor,
		config:      config,
		authConfig:  authConfig,
		authHandler: authHandler,
	}
}

// InitRouter initializes the HTTP routes.
func (ws *WebServer) InitRouter() *mux.Router {
	r := mux.NewRouter()
	api := r.PathPrefix("/api").Subrouter()
	authRouter := r.PathPrefix("/auth").Subrouter()

	// Authentication routes
	if ws.authConfig.AuthType == "oauth2" {
		authRouter.HandleFunc("/login", ws.authHandler.HandleLogin).Methods("GET")
		authRouter.HandleFunc("/callback", ws.authHandler.HandleCallback).Methods("GET")
		authRouter.Handle("/status", ws.authHandler.AuthMiddleware(http.HandlerFunc(ws.authHandler.HandleStatus))).Methods("GET")
		authRouter.Handle("/logout", ws.authHandler.AuthMiddleware(http.HandlerFunc(ws.authHandler.HandleLogout))).Methods("POST")
		authRouter.Handle("/logout", ws.authHandler.AuthMiddleware(http.HandlerFunc(ws.authHandler.HandleLogout))).Methods("GET")
		authRouter.HandleFunc("/refresh", ws.authHandler.HandleRefresh).Methods("POST")
		authRouter.HandleFunc("/refresh", ws.authHandler.HandleRefresh).Methods("GET")

		api.Use(ws.authHandler.AuthMiddleware)
	}

	// API routes
	api.HandleFunc("/hashes", ws.handleGetHashes).Methods(http.MethodGet)
	api.HandleFunc("/hashes/{sha256}", ws.handleGetHashDetail).Methods(http.MethodGet)
	api.HandleFunc("/hashes", ws.handleAddHash).Methods(http.MethodPut)
	api.HandleFunc("/hashes/{sha256}", ws.handleDeleteHash).Methods(http.MethodDelete)

	// Static file serving
	r.PathPrefix("/").Handler(
		http.StripPrefix("/", http.FileServer(http.Dir("./build/"))))
	return r
}

// handleGetHashes handles the GET /hashes endpoint.
func (ws *WebServer) handleGetHashes(w http.ResponseWriter, r *http.Request) {
	hashes := ws.Monitor.GetAllHashStatuses()

	response := models.HashesResponse{
		Hashes: hashes,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGetHashDetail handles the GET /hashes/{sha256} endpoint.
func (ws *WebServer) handleGetHashDetail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sha256 := vars["sha256"]
	hashStatus, err := ws.Monitor.GetHashStatus(sha256)
	if err != nil {
		http.Error(w, "Hash not found", http.StatusNotFound)
		return
	}

	response := models.HashDetailResponse{
		Hash: hashStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAddHash handles the PUT /hashes endpoint.
func (ws *WebServer) handleAddHash(w http.ResponseWriter, r *http.Request) {
	var newHash models.HashRecord

	// Decode the JSON payload
	err := json.NewDecoder(r.Body).Decode(&newHash)
	if err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Basic validation
	if newHash.SHA256 == "" {
		http.Error(w, "SHA256 field is required", http.StatusBadRequest)
		return
	}

	// Add the new hash to the monitor
	err = ws.Monitor.AddHash(newHash)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to add hash: %v", err), http.StatusInternalServerError)
		return
	}

	// Respond with the created hash
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newHash)
}

// handleDeleteHash handles the DELETE /hashes/{sha256} endpoint.
func (ws *WebServer) handleDeleteHash(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sha256, exists := vars["sha256"]
	if !exists || sha256 == "" {
		http.Error(w, "SHA256 parameter is required", http.StatusBadRequest)
		return
	}

	// Delete the hash from the monitor
	err := ws.Monitor.Config.Database.DeleteHash(sha256)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete hash: %v", err), http.StatusInternalServerError)
		return
	}

	// Respond with no content
	w.WriteHeader(http.StatusNoContent)
}
