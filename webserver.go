package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/y0ug/hashmon/models" // Replace with your actual module path
)

// WebServer holds the data needed for handling HTTP requests.
type WebServer struct {
	Monitor *Monitor
}

// NewWebServer initializes a new WebServer.
func NewWebServer(monitor *Monitor) *WebServer {
	return &WebServer{
		Monitor: monitor,
	}
}

func (ws *WebServer) InitRouter() *mux.Router {
	r := mux.NewRouter()
	// Routes
	r.HandleFunc("/hashes", ws.handleGetHashes).Methods(http.MethodGet)
	r.HandleFunc("/hashes/{sha256}", ws.handleGetHashDetail).Methods(http.MethodGet)
	r.HandleFunc("/hashes", ws.handleAddHash).Methods(http.MethodPut)
	r.HandleFunc("/hashes/{sha256}", ws.handleDeleteHash).Methods(http.MethodDelete)
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
	hashStatus, found := ws.Monitor.GetHashStatus(sha256)
	if !found {
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
	err := ws.Monitor.DeleteHash(sha256)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete hash: %v", err), http.StatusInternalServerError)
		return
	}

	// Respond with no content
	w.WriteHeader(http.StatusNoContent)
}
