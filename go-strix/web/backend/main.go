package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// CORS middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type ScanRequest struct {
	Targets     []string `json:"targets"`
	Instruction string   `json:"instruction,omitempty"`
	RunName     string   `json:"run_name,omitempty"`
}

type ScanStatus struct {
	Type       string      `json:"type"`
	Data       interface{} `json:"data"`
	Timestamp  time.Time   `json:"timestamp"`
}

type Vulnerability struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	FoundAt     string    `json:"found_at"`
	URL         string    `json:"url"`
	Timestamp   time.Time `json:"timestamp"`
}

type AgentEvent struct {
	AgentID   string `json:"agent_id"`
	EventType string `json:"event_type"`
	Message   string `json:"message"`
	Tool      string `json:"tool,omitempty"`
}

type ScanManager struct {
	mu           sync.RWMutex
	activeScans  map[string]*Scan
}

type Scan struct {
	ID              string
	Status          string
	Targets         []string
	StartTime       time.Time
	Vulnerabilities []Vulnerability
	Events          []AgentEvent
	cmd             *exec.Cmd
	clients         map[*websocket.Conn]bool
	clientsMu       sync.RWMutex
}

var scanManager = &ScanManager{
	activeScans: make(map[string]*Scan),
}

func main() {
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/scans", createScan).Methods("POST")
	api.HandleFunc("/scans", listScans).Methods("GET")
	api.HandleFunc("/scans/{id}", getScan).Methods("GET")
	api.HandleFunc("/scans/{id}", stopScan).Methods("DELETE")
	api.HandleFunc("/scans/{id}/ws", scanWebSocket)

	// Health check
	api.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}).Methods("GET")

	// Use our custom CORS middleware
	handler := corsMiddleware(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Endpoint Web API on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func createScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "at least one target is required", http.StatusBadRequest)
		return
	}

	scanID := req.RunName
	if scanID == "" {
		scanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	}

	scan := &Scan{
		ID:              scanID,
		Status:          "starting",
		Targets:         req.Targets,
		StartTime:       time.Now(),
		Vulnerabilities: []Vulnerability{},
		Events:          []AgentEvent{},
		clients:         make(map[*websocket.Conn]bool),
	}

	scanManager.mu.Lock()
	scanManager.activeScans[scanID] = scan
	scanManager.mu.Unlock()

	// Start scan in background
	go runEndpointScan(scan, req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      scanID,
		"status":  "starting",
		"targets": req.Targets,
	})
}

func runEndpointScan(scan *Scan, req ScanRequest) {
	// Build endpoint command
	args := []string{"--no-sandbox"}

	for _, target := range req.Targets {
		args = append(args, "-t", target)
	}

	if req.Instruction != "" {
		args = append(args, "-i", req.Instruction)
	}

	cmd := exec.Command("/Users/tim/strix/go-strix/endpoint", args...)

	// Set environment for Ollama
	cmd.Env = append(os.Environ(),
		"ENDPOINT_LLM=ollama_chat/qwen2.5:7b",
		"LLM_API_BASE=http://localhost:11434",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		scan.Status = "error"
		broadcast(scan, ScanStatus{Type: "error", Data: err.Error(), Timestamp: time.Now()})
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		scan.Status = "error"
		broadcast(scan, ScanStatus{Type: "error", Data: err.Error(), Timestamp: time.Now()})
		return
	}

	scan.cmd = cmd
	scan.Status = "running"
	broadcast(scan, ScanStatus{Type: "status", Data: "running", Timestamp: time.Now()})

	if err := cmd.Start(); err != nil {
		scan.Status = "error"
		broadcast(scan, ScanStatus{Type: "error", Data: err.Error(), Timestamp: time.Now()})
		return
	}

	// Stream output
	go streamOutput(scan, stdout, "stdout")
	go streamOutput(scan, stderr, "stderr")

	// Wait for completion
	err = cmd.Wait()
	if err != nil {
		scan.Status = "error"
		broadcast(scan, ScanStatus{Type: "error", Data: err.Error(), Timestamp: time.Now()})
	} else {
		scan.Status = "completed"
		broadcast(scan, ScanStatus{Type: "status", Data: "completed", Timestamp: time.Now()})
	}
}

func streamOutput(scan *Scan, reader io.Reader, streamType string) {
	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		event := AgentEvent{
			EventType: streamType,
			Message:   line,
		}

		scan.Events = append(scan.Events, event)

		// Parse for vulnerabilities (simplified - enhance based on actual output format)
		if containsVulnerability(line) {
			vuln := parseVulnerability(line)
			if vuln != nil {
				scan.Vulnerabilities = append(scan.Vulnerabilities, *vuln)
				broadcast(scan, ScanStatus{
					Type:      "vulnerability",
					Data:      vuln,
					Timestamp: time.Now(),
				})
			}
		}

		broadcast(scan, ScanStatus{
			Type:      "output",
			Data:      map[string]string{"stream": streamType, "line": line},
			Timestamp: time.Now(),
		})
	}
}

func containsVulnerability(line string) bool {
	return strings.Contains(line, "[VULNERABILITY]")
}

func parseVulnerability(line string) *Vulnerability {
	// Parse [VULNERABILITY]{"title":"...","severity":"...","description":"...","url":"..."}[/VULNERABILITY]
	startTag := "[VULNERABILITY]"
	endTag := "[/VULNERABILITY]"

	startIdx := strings.Index(line, startTag)
	endIdx := strings.Index(line, endTag)

	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return nil
	}

	jsonStr := line[startIdx+len(startTag) : endIdx]

	var vuln struct {
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		URL         string `json:"url"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &vuln); err != nil {
		log.Printf("Failed to parse vulnerability JSON: %v", err)
		return nil
	}

	return &Vulnerability{
		ID:          fmt.Sprintf("vuln-%d", time.Now().UnixNano()),
		Title:       vuln.Title,
		Severity:    vuln.Severity,
		Description: vuln.Description,
		FoundAt:     vuln.URL,
		URL:         vuln.URL,
		Timestamp:   time.Now(),
	}
}

func broadcast(scan *Scan, status ScanStatus) {
	scan.clientsMu.Lock()
	defer scan.clientsMu.Unlock()

	msg, _ := json.Marshal(status)
	for client := range scan.clients {
		client.WriteMessage(websocket.TextMessage, msg)
	}
}

func listScans(w http.ResponseWriter, r *http.Request) {
	scanManager.mu.RLock()
	defer scanManager.mu.RUnlock()

	scans := make([]map[string]interface{}, 0)
	for _, scan := range scanManager.activeScans {
		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"status":          scan.Status,
			"targets":         scan.Targets,
			"start_time":      scan.StartTime,
			"vulnerabilities": len(scan.Vulnerabilities),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func getScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	scanManager.mu.RLock()
	scan, exists := scanManager.activeScans[scanID]
	scanManager.mu.RUnlock()

	if !exists {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":              scan.ID,
		"status":          scan.Status,
		"targets":         scan.Targets,
		"start_time":      scan.StartTime,
		"vulnerabilities": scan.Vulnerabilities,
		"events":          scan.Events,
	})
}

func stopScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	scanManager.mu.Lock()
	scan, exists := scanManager.activeScans[scanID]
	scanManager.mu.Unlock()

	if !exists {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.cmd != nil && scan.cmd.Process != nil {
		scan.cmd.Process.Kill()
	}

	scan.Status = "stopped"
	broadcast(scan, ScanStatus{Type: "status", Data: "stopped", Timestamp: time.Now()})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func scanWebSocket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	scanManager.mu.RLock()
	scan, exists := scanManager.activeScans[scanID]
	scanManager.mu.RUnlock()

	if !exists {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()

	// Register client
	scan.clientsMu.Lock()
	scan.clients[conn] = true
	scan.clientsMu.Unlock()

	defer func() {
		scan.clientsMu.Lock()
		delete(scan.clients, conn)
		scan.clientsMu.Unlock()
	}()

	// Send current state
	initialState := ScanStatus{
		Type: "init",
		Data: map[string]interface{}{
			"id":              scan.ID,
			"status":          scan.Status,
			"targets":         scan.Targets,
			"vulnerabilities": scan.Vulnerabilities,
			"events":          scan.Events,
		},
		Timestamp: time.Now(),
	}
	msg, _ := json.Marshal(initialState)
	conn.WriteMessage(websocket.TextMessage, msg)

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
