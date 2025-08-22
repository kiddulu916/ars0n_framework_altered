package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// URL Workflow Session Types
type URLWorkflowSession struct {
	ID                 string         `json:"id"`
	SessionID          string         `json:"session_id"`
	ScopeTargetID      string         `json:"scope_target_id"`
	SelectedURLs       []string       `json:"selected_urls"`
	Status             string         `json:"status"`
	CurrentPhase       string         `json:"current_phase"`
	PhaseProgress      map[string]any `json:"phase_progress"`
	ResultsSummary     map[string]any `json:"results_summary"`
	ErrorMessage       sql.NullString `json:"error_message,omitempty"`
	StartedAt          time.Time      `json:"started_at"`
	CompletedAt        sql.NullTime   `json:"completed_at,omitempty"`
	TotalFindings      int            `json:"total_findings"`
	TotalEvidenceItems int            `json:"total_evidence_items"`
	AutoScanSessionID  sql.NullString `json:"auto_scan_session_id,omitempty"`
}

type URLWorkflowStatusResponse struct {
	SessionID          string                 `json:"session_id"`
	Status             string                 `json:"status"`
	CurrentPhase       string                 `json:"current_phase"`
	PhaseProgress      map[string]interface{} `json:"phase_progress"`
	ResultsSummary     map[string]interface{} `json:"results_summary"`
	TotalFindings      int                    `json:"total_findings"`
	TotalEvidenceItems int                    `json:"total_evidence_items"`
	StartedAt          time.Time              `json:"started_at"`
	CompletedAt        *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage       string                 `json:"error_message,omitempty"`
}

// ROI Algorithm - Get top scoring URLs for URL workflow
func GetROIScoredURLs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	scopeTargetID := vars["scopeTargetId"]

	if scopeTargetID == "" {
		http.Error(w, "Missing scope target ID", http.StatusBadRequest)
		return
	}

	maxURLsParam := r.URL.Query().Get("max_urls")
	maxURLs := 10 // Default to top 10
	if maxURLsParam != "" {
		if parsed, err := strconv.Atoi(maxURLsParam); err == nil && parsed > 0 {
			maxURLs = parsed
		}
	}

	// Check if Company and Wildcard workflows are completed
	prerequisiteComplete, err := checkPrerequisiteWorkflows(scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to check prerequisite workflows: %v", err)
		http.Error(w, "Failed to validate prerequisites", http.StatusInternalServerError)
		return
	}

	if !prerequisiteComplete {
		http.Error(w, "Company and Wildcard workflows must be completed before URL workflow", http.StatusPreconditionFailed)
		return
	}

	// Get ROI-scored URLs from consolidated attack surface assets
	roiURLs, err := getTopROIURLs(scopeTargetID, maxURLs)
	if err != nil {
		log.Printf("[ERROR] Failed to get ROI URLs: %v", err)
		http.Error(w, "Failed to retrieve ROI-scored URLs", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"scope_target_id": scopeTargetID,
		"max_urls":        maxURLs,
		"urls":            roiURLs,
		"count":           len(roiURLs),
		"message":         fmt.Sprintf("Retrieved %d ROI-scored URLs", len(roiURLs)),
	}

	json.NewEncoder(w).Encode(response)
}

// Initiate URL Workflow
func InitiateURLWorkflow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	scopeTargetID := vars["scopeTargetId"]

	if scopeTargetID == "" {
		http.Error(w, "Missing scope target ID", http.StatusBadRequest)
		return
	}

	// Parse request body for custom URL selection
	var request struct {
		SelectedURLs []string `json:"selected_urls,omitempty"`
		MaxURLs      int      `json:"max_urls,omitempty"`
	}

	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&request)
	}

	// Validate prerequisites
	prerequisiteComplete, err := checkPrerequisiteWorkflows(scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to check prerequisite workflows: %v", err)
		http.Error(w, "Failed to validate prerequisites", http.StatusInternalServerError)
		return
	}

	if !prerequisiteComplete {
		http.Error(w, "Company and Wildcard workflows must be completed first", http.StatusPreconditionFailed)
		return
	}

	// Get URLs for testing
	var selectedURLs []string
	if len(request.SelectedURLs) > 0 {
		selectedURLs = request.SelectedURLs
	} else {
		maxURLs := request.MaxURLs
		if maxURLs == 0 {
			maxURLs = 10
		}

		roiURLs, err := getTopROIURLs(scopeTargetID, maxURLs)
		if err != nil {
			log.Printf("[ERROR] Failed to get ROI URLs: %v", err)
			http.Error(w, "Failed to retrieve URLs for testing", http.StatusInternalServerError)
			return
		}
		selectedURLs = roiURLs
	}

	if len(selectedURLs) == 0 {
		http.Error(w, "No URLs available for testing. Ensure Company and Wildcard workflows have discovered live web servers.", http.StatusBadRequest)
		return
	}

	// Create URL workflow session
	sessionID := uuid.New().String()
	session, err := createURLWorkflowSession(scopeTargetID, sessionID, selectedURLs)
	if err != nil {
		log.Printf("[ERROR] Failed to create URL workflow session: %v", err)
		http.Error(w, "Failed to create workflow session", http.StatusInternalServerError)
		return
	}

	// Start workflow execution asynchronously
	go executeURLWorkflowPipeline(session)

	response := map[string]interface{}{
		"session_id":     sessionID,
		"status":         "initiated",
		"selected_urls":  selectedURLs,
		"estimated_time": fmt.Sprintf("%d minutes", len(selectedURLs)*5), // Estimate 5 minutes per URL
		"message":        fmt.Sprintf("URL workflow initiated for %d URLs", len(selectedURLs)),
	}

	json.NewEncoder(w).Encode(response)
}

// Get URL Workflow Status
func GetURLWorkflowStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	session, err := getURLWorkflowSession(sessionID)
	if err != nil {
		log.Printf("[ERROR] Failed to get URL workflow session: %v", err)
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(session)
}

// Helper functions

func checkPrerequisiteWorkflows(scopeTargetID string) (bool, error) {
	// Check if there are completed auto-scan sessions for Company/Wildcard workflows
	query := `
		SELECT COUNT(*) 
		FROM auto_scan_sessions 
		WHERE scope_target_id = $1 
		  AND status = 'completed'
		  AND (config_snapshot->>'amass' = 'true' OR config_snapshot->>'subfinder' = 'true')
	`

	var count int
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check prerequisite workflows: %w", err)
	}

	// Also check if we have discovered assets
	assetQuery := `
		SELECT COUNT(*) 
		FROM consolidated_attack_surface_assets 
		WHERE scope_target_id = $1 
		  AND asset_type = 'live_web_server'
	`

	var assetCount int
	err = dbPool.QueryRow(context.Background(), assetQuery, scopeTargetID).Scan(&assetCount)
	if err != nil {
		return false, fmt.Errorf("failed to check asset availability: %w", err)
	}

	return count > 0 && assetCount > 0, nil
}

func getTopROIURLs(scopeTargetID string, maxURLs int) ([]string, error) {
	// Query target_urls with highest ROI scores
	query := `
		SELECT url, roi_score 
		FROM target_urls 
		WHERE scope_target_id = $1 
		  AND roi_score IS NOT NULL
		  AND status_code BETWEEN 200 AND 299
		  AND url_workflow_eligible = true
		ORDER BY roi_score DESC 
		LIMIT $2
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID, maxURLs)
	if err != nil {
		return nil, fmt.Errorf("failed to query ROI URLs: %w", err)
	}
	defer rows.Close()

	var urls []string
	for rows.Next() {
		var url string
		var roiScore int

		if err := rows.Scan(&url, &roiScore); err != nil {
			log.Printf("[WARN] Failed to scan ROI URL row: %v", err)
			continue
		}

		urls = append(urls, url)
	}

	// If no ROI-scored URLs, fall back to any live web servers
	if len(urls) == 0 {
		fallbackQuery := `
			SELECT url 
			FROM target_urls 
			WHERE scope_target_id = $1 
			  AND status_code BETWEEN 200 AND 299
			ORDER BY created_at DESC 
			LIMIT $2
		`

		rows, err := dbPool.Query(context.Background(), fallbackQuery, scopeTargetID, maxURLs)
		if err != nil {
			return nil, fmt.Errorf("failed to query fallback URLs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var url string
			if err := rows.Scan(&url); err != nil {
				log.Printf("[WARN] Failed to scan fallback URL row: %v", err)
				continue
			}
			urls = append(urls, url)
		}
	}

	return urls, nil
}

func createURLWorkflowSession(scopeTargetID, sessionID string, selectedURLs []string) (*URLWorkflowSession, error) {
	selectedURLsJSON, _ := json.Marshal(selectedURLs)

	query := `
		INSERT INTO url_workflow_sessions (
			session_id, scope_target_id, selected_urls, status, current_phase,
			phase_progress, results_summary, started_at
		) VALUES ($1, $2, $3, 'pending', 'attack_surface_mapping', '{}', '{}', NOW())
		RETURNING id, session_id, scope_target_id, selected_urls, status, current_phase, started_at
	`

	session := &URLWorkflowSession{}
	var selectedURLsStr string

	err := dbPool.QueryRow(context.Background(), query, sessionID, scopeTargetID, selectedURLsJSON).Scan(
		&session.ID, &session.SessionID, &session.ScopeTargetID,
		&selectedURLsStr, &session.Status, &session.CurrentPhase, &session.StartedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create URL workflow session: %w", err)
	}

	// Parse selected URLs
	json.Unmarshal([]byte(selectedURLsStr), &session.SelectedURLs)

	log.Printf("[INFO] Created URL workflow session %s for %d URLs", sessionID, len(selectedURLs))
	return session, nil
}

func getURLWorkflowSession(sessionID string) (*URLWorkflowStatusResponse, error) {
	query := `
		SELECT session_id, status, current_phase, phase_progress, results_summary,
		       total_findings, total_evidence_items, started_at, completed_at, error_message
		FROM url_workflow_sessions 
		WHERE session_id = $1
	`

	var response URLWorkflowStatusResponse
	var phaseProgressStr, resultsSummaryStr string

	err := dbPool.QueryRow(context.Background(), query, sessionID).Scan(
		&response.SessionID, &response.Status, &response.CurrentPhase,
		&phaseProgressStr, &resultsSummaryStr, &response.TotalFindings,
		&response.TotalEvidenceItems, &response.StartedAt, &response.CompletedAt,
		&response.ErrorMessage,
	)

	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Parse JSON fields
	json.Unmarshal([]byte(phaseProgressStr), &response.PhaseProgress)
	json.Unmarshal([]byte(resultsSummaryStr), &response.ResultsSummary)

	return &response, nil
}

func executeURLWorkflowPipeline(session *URLWorkflowSession) {
	log.Printf("[INFO] Starting URL workflow pipeline for session %s", session.SessionID)

	// Update status to running
	updateSessionStatus(session.SessionID, "attack_surface_mapping", "attack_surface_mapping", nil)

	// Phase 1: Attack Surface Mapping
	if err := executeAttackSurfaceMapping(session); err != nil {
		log.Printf("[ERROR] Attack surface mapping failed: %v", err)
		updateSessionStatus(session.SessionID, "failed", "attack_surface_mapping", err)
		return
	}

	// Phase 2: DAST Scanning
	updateSessionStatus(session.SessionID, "dast_scanning", "dast_scanning", nil)
	if err := executeDASTScanning(session); err != nil {
		log.Printf("[ERROR] DAST scanning failed: %v", err)
		updateSessionStatus(session.SessionID, "failed", "dast_scanning", err)
		return
	}

	// Phase 3: Targeted Vulnerability Testing
	updateSessionStatus(session.SessionID, "targeted_testing", "targeted_testing", nil)
	if err := executeTargetedTesting(session); err != nil {
		log.Printf("[ERROR] Targeted testing failed: %v", err)
		updateSessionStatus(session.SessionID, "failed", "targeted_testing", err)
		return
	}

	// Phase 4: Evidence Collection and Reporting
	updateSessionStatus(session.SessionID, "evidence_collection", "evidence_collection", nil)
	if err := executeEvidenceCollection(session); err != nil {
		log.Printf("[ERROR] Evidence collection failed: %v", err)
		updateSessionStatus(session.SessionID, "failed", "evidence_collection", err)
		return
	}

	// Complete the workflow
	updateSessionStatus(session.SessionID, "completed", "completed", nil)
	log.Printf("[INFO] URL workflow pipeline completed for session %s", session.SessionID)
}

func updateSessionStatus(sessionID, status, phase string, err error) {
	var errorMsg string
	if err != nil {
		errorMsg = err.Error()
	}

	query := `
		UPDATE url_workflow_sessions 
		SET status = $1, current_phase = $2, error_message = $3,
		    completed_at = CASE WHEN $1 IN ('completed', 'failed') THEN NOW() ELSE NULL END
		WHERE session_id = $4
	`

	_, updateErr := dbPool.Exec(context.Background(), query, status, phase, errorMsg, sessionID)
	if updateErr != nil {
		log.Printf("[ERROR] Failed to update session status: %v", updateErr)
	}
}

// Phase implementations (stubs for now - will be implemented in separate files)

func executeAttackSurfaceMapping(session *URLWorkflowSession) error {
	log.Printf("[INFO] Executing attack surface mapping for session %s", session.SessionID)
	// Implementation will be in url_workflow/attack_surface.go
	time.Sleep(2 * time.Second) // Simulate processing
	return nil
}

func executeDASTScanning(session *URLWorkflowSession) error {
	log.Printf("[INFO] Executing DAST scanning for session %s", session.SessionID)
	// Implementation will be in url_workflow/dast_engine.go
	time.Sleep(3 * time.Second) // Simulate processing
	return nil
}

func executeTargetedTesting(session *URLWorkflowSession) error {
	log.Printf("[INFO] Executing targeted testing for session %s", session.SessionID)
	// Implementation will be in url_workflow/vuln_testing.go
	time.Sleep(2 * time.Second) // Simulate processing
	return nil
}

func executeEvidenceCollection(session *URLWorkflowSession) error {
	log.Printf("[INFO] Executing evidence collection for session %s", session.SessionID)
	// Implementation will be in url_workflow/evidence_collector.go
	time.Sleep(1 * time.Second) // Simulate processing
	return nil
}
