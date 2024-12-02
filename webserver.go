package main

import (
	"encoding/json"
	"net/http"
	"strings"

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

// ServeHTTP dispatches the request to the handler whose pattern most closely matches the request URL.
func (ws *WebServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Simple router based on URL paths
	if r.Method == http.MethodGet {
		if r.URL.Path == "/hashes" {
			ws.handleGetHashes(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/hashes/") {
			sha256 := strings.TrimPrefix(r.URL.Path, "/hashes/")
			ws.handleGetHashDetail(w, r, sha256)
			return
		}

		// Add more routes here as needed

		// If no route matches
		http.NotFound(w, r)
		return
	}

	// If method not allowed
	w.WriteHeader(http.StatusMethodNotAllowed)
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
func (ws *WebServer) handleGetHashDetail(w http.ResponseWriter, r *http.Request, sha256 string) {
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
