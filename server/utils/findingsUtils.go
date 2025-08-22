package utils

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Core Findings Pipeline Types
type Finding struct {
	ID                             string          `json:"id"`
	KeyHash                        string          `json:"key_hash"`
	Title                          string          `json:"title"`
	Description                    sql.NullString  `json:"description,omitempty"`
	Category                       string          `json:"category"`
	Severity                       string          `json:"severity"`
	Confidence                     string          `json:"confidence"`
	Signal                         string          `json:"signal"`
	Status                         string          `json:"status"`
	URL                            string          `json:"url"`
	Method                         string          `json:"method"`
	Parameters                     map[string]any  `json:"parameters"`
	VulnerabilityClass             sql.NullString  `json:"vulnerability_class,omitempty"`
	AffectedComponent              sql.NullString  `json:"affected_component,omitempty"`
	ImpactDescription              sql.NullString  `json:"impact_description,omitempty"`
	RemediationNotes               sql.NullString  `json:"remediation_notes,omitempty"`
	References                     []string        `json:"references"`
	CVSSScore                      sql.NullFloat64 `json:"cvss_score,omitempty"`
	CVSSVector                     sql.NullString  `json:"cvss_vector,omitempty"`
	CWEID                          sql.NullString  `json:"cwe_id,omitempty"`
	OWASPCategory                  sql.NullString  `json:"owasp_category,omitempty"`
	ManualVerificationRequired     bool            `json:"manual_verification_required"`
	AutomatedReproductionAvailable bool            `json:"automated_reproduction_available"`
	URLWorkflowSessionID           sql.NullString  `json:"url_workflow_session_id,omitempty"`
	ScopeTargetID                  string          `json:"scope_target_id"`
	DiscoveredAt                   time.Time       `json:"discovered_at"`
	LastUpdated                    time.Time       `json:"last_updated"`
	LastVerified                   sql.NullTime    `json:"last_verified,omitempty"`
	VerifiedBy                     sql.NullString  `json:"verified_by,omitempty"`
	Tags                           []string        `json:"tags"`
	Metadata                       map[string]any  `json:"metadata"`
}

type CreateFindingRequest struct {
	Title                string         `json:"title"`
	Description          string         `json:"description,omitempty"`
	Category             string         `json:"category"`
	Severity             string         `json:"severity"`
	Confidence           string         `json:"confidence,omitempty"`
	Signal               string         `json:"signal"`
	URL                  string         `json:"url"`
	Method               string         `json:"method,omitempty"`
	Parameters           map[string]any `json:"parameters,omitempty"`
	VulnerabilityClass   string         `json:"vulnerability_class,omitempty"`
	URLWorkflowSessionID string         `json:"url_workflow_session_id,omitempty"`
	ScopeTargetID        string         `json:"scope_target_id"`
	Tags                 []string       `json:"tags,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

type UpdateFindingStatusRequest struct {
	Status     string `json:"status"`
	VerifiedBy string `json:"verified_by,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

type FindingsListResponse struct {
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
	Limit    int       `json:"limit"`
	Offset   int       `json:"offset"`
	HasMore  bool      `json:"has_more"`
}

// Generate unique key hash for finding deduplication
func GenerateFindingKeyHash(category, url, method, params, identity, tenant string) string {
	// Create deterministic hash for deduplication
	// SHA256(vuln_class|url_template|method|params|identity|tenant)

	// Normalize URL template (remove specific parameter values)
	urlTemplate := normalizeURLTemplate(url)

	// Create composite key
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		category, urlTemplate, method, params, identity, tenant)

	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", hash)
}

func normalizeURLTemplate(url string) string {
	// Basic URL template normalization
	// Replace numeric IDs with placeholders for better deduplication
	normalizedURL := url

	// Replace numeric path segments (e.g., /user/123 -> /user/{id})
	parts := strings.Split(url, "/")
	for i, part := range parts {
		if len(part) > 0 && isNumeric(part) {
			parts[i] = "{id}"
		}
	}
	normalizedURL = strings.Join(parts, "/")

	// Remove query parameter values but keep structure
	if strings.Contains(normalizedURL, "?") {
		urlParts := strings.Split(normalizedURL, "?")
		if len(urlParts) == 2 {
			baseURL := urlParts[0]
			queryPart := urlParts[1]

			// Normalize query parameters
			params := strings.Split(queryPart, "&")
			for i, param := range params {
				if strings.Contains(param, "=") {
					paramParts := strings.Split(param, "=")
					params[i] = paramParts[0] + "={value}"
				}
			}
			normalizedURL = baseURL + "?" + strings.Join(params, "&")
		}
	}

	return normalizedURL
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// Create or Update Finding
func CreateOrUpdateFinding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var request CreateFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if request.Title == "" || request.Category == "" || request.Severity == "" ||
		request.Signal == "" || request.URL == "" || request.ScopeTargetID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Generate key hash for deduplication
	paramsJSON, _ := json.Marshal(request.Parameters)
	keyHash := GenerateFindingKeyHash(
		request.Category,
		request.URL,
		request.Method,
		string(paramsJSON),
		"default", // TODO: Extract from context
		"default", // TODO: Extract from context
	)

	// Check if finding already exists
	existingID, err := findExistingFinding(keyHash)
	if err != nil {
		log.Printf("[ERROR] Failed to check existing finding: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	var findingID string
	if existingID != "" {
		// Update existing finding
		findingID = existingID
		err = updateExistingFinding(findingID, request)
		if err != nil {
			log.Printf("[ERROR] Failed to update finding: %v", err)
			http.Error(w, "Failed to update finding", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] Updated existing finding %s with key hash %s", findingID, keyHash)
	} else {
		// Create new finding
		findingID, err = createNewFinding(keyHash, request)
		if err != nil {
			log.Printf("[ERROR] Failed to create finding: %v", err)
			http.Error(w, "Failed to create finding", http.StatusInternalServerError)
			return
		}
		log.Printf("[INFO] Created new finding %s with key hash %s", findingID, keyHash)
	}

	response := map[string]interface{}{
		"finding_id": findingID,
		"key_hash":   keyHash,
		"status":     "success",
		"action":     map[string]bool{"created": existingID == "", "updated": existingID != ""},
	}

	json.NewEncoder(w).Encode(response)
}

// Get Finding by ID
func GetFinding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	findingID := vars["id"]

	if findingID == "" {
		http.Error(w, "Missing finding ID", http.StatusBadRequest)
		return
	}

	finding, err := getFindingByID(findingID)
	if err != nil {
		log.Printf("[ERROR] Failed to get finding: %v", err)
		http.Error(w, "Finding not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(finding)
}

// List Findings
func ListFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	query := r.URL.Query()
	scopeTargetID := query.Get("scope_target_id")
	sessionID := query.Get("url_workflow_session_id")
	category := query.Get("category")
	severities := query["severity"]
	statuses := query["status"]

	limitStr := query.Get("limit")
	limit := 50 // Default limit
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	offsetStr := query.Get("offset")
	offset := 0
	if offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	findings, total, err := listFindings(scopeTargetID, sessionID, category, severities, statuses, limit, offset)
	if err != nil {
		log.Printf("[ERROR] Failed to list findings: %v", err)
		http.Error(w, "Failed to retrieve findings", http.StatusInternalServerError)
		return
	}

	response := FindingsListResponse{
		Findings: findings,
		Total:    total,
		Limit:    limit,
		Offset:   offset,
		HasMore:  offset+len(findings) < total,
	}

	json.NewEncoder(w).Encode(response)
}

// Update Finding Status
func UpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	findingID := vars["id"]

	if findingID == "" {
		http.Error(w, "Missing finding ID", http.StatusBadRequest)
		return
	}

	var request UpdateFindingStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.Status == "" {
		http.Error(w, "Status is required", http.StatusBadRequest)
		return
	}

	err := updateFindingStatus(findingID, request.Status, request.VerifiedBy, request.Notes)
	if err != nil {
		log.Printf("[ERROR] Failed to update finding status: %v", err)
		http.Error(w, "Failed to update finding status", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"finding_id": findingID,
		"status":     request.Status,
		"updated_at": time.Now(),
		"message":    "Finding status updated successfully",
	}

	json.NewEncoder(w).Encode(response)
}

// Export Findings
func ExportFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	query := r.URL.Query()
	scopeTargetID := query.Get("scope_target_id")
	sessionID := query.Get("url_workflow_session_id")
	format := query.Get("format")

	if format == "" {
		format = "json"
	}

	findings, _, err := listFindings(scopeTargetID, sessionID, "", nil, nil, 1000, 0)
	if err != nil {
		log.Printf("[ERROR] Failed to export findings: %v", err)
		http.Error(w, "Failed to export findings", http.StatusInternalServerError)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=findings.json")

		export := map[string]interface{}{
			"export_timestamp":        time.Now(),
			"scope_target_id":         scopeTargetID,
			"url_workflow_session_id": sessionID,
			"findings_count":          len(findings),
			"findings":                findings,
		}

		json.NewEncoder(w).Encode(export)

	default:
		http.Error(w, "Unsupported export format", http.StatusBadRequest)
	}
}

// Helper functions

func findExistingFinding(keyHash string) (string, error) {
	query := `SELECT id FROM findings WHERE key_hash = $1`

	var findingID string
	err := dbPool.QueryRow(context.Background(), query, keyHash).Scan(&findingID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return "", nil // Not found, but not an error
		}
		return "", err
	}

	return findingID, nil
}

func createNewFinding(keyHash string, request CreateFindingRequest) (string, error) {
	findingID := uuid.New().String()

	// Set defaults
	if request.Method == "" {
		request.Method = "GET"
	}
	if request.Confidence == "" {
		request.Confidence = "medium"
	}

	// Serialize complex fields
	parametersJSON, _ := json.Marshal(request.Parameters)
	tagsJSON, _ := json.Marshal(request.Tags)
	metadataJSON, _ := json.Marshal(request.Metadata)

	query := `
		INSERT INTO findings (
			id, key_hash, title, description, category, severity, confidence,
			signal, url, method, parameters, vulnerability_class,
			url_workflow_session_id, scope_target_id, tags, metadata,
			discovered_at, last_updated
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW()
		)
	`

	_, err := dbPool.Exec(context.Background(), query,
		findingID, keyHash, request.Title, request.Description, request.Category,
		request.Severity, request.Confidence, request.Signal, request.URL, request.Method,
		parametersJSON, request.VulnerabilityClass, request.URLWorkflowSessionID,
		request.ScopeTargetID, tagsJSON, metadataJSON,
	)

	if err != nil {
		return "", fmt.Errorf("failed to insert finding: %w", err)
	}

	return findingID, nil
}

func updateExistingFinding(findingID string, request CreateFindingRequest) error {
	// Update finding with new information
	query := `
		UPDATE findings 
		SET title = $1, description = $2, severity = $3, signal = $4,
		    last_updated = NOW()
		WHERE id = $5
	`

	_, err := dbPool.Exec(context.Background(), query,
		request.Title, request.Description, request.Severity, request.Signal, findingID,
	)

	return err
}

func getFindingByID(findingID string) (*Finding, error) {
	query := `
		SELECT id, key_hash, title, description, category, severity, confidence,
		       signal, status, url, method, parameters, vulnerability_class,
		       url_workflow_session_id, scope_target_id, discovered_at, last_updated,
		       tags, metadata
		FROM findings 
		WHERE id = $1
	`

	finding := &Finding{}
	var parametersStr, tagsStr, metadataStr string

	err := dbPool.QueryRow(context.Background(), query, findingID).Scan(
		&finding.ID, &finding.KeyHash, &finding.Title, &finding.Description,
		&finding.Category, &finding.Severity, &finding.Confidence, &finding.Signal,
		&finding.Status, &finding.URL, &finding.Method, &parametersStr,
		&finding.VulnerabilityClass, &finding.URLWorkflowSessionID,
		&finding.ScopeTargetID, &finding.DiscoveredAt, &finding.LastUpdated,
		&tagsStr, &metadataStr,
	)

	if err != nil {
		return nil, err
	}

	// Parse JSON fields
	json.Unmarshal([]byte(parametersStr), &finding.Parameters)
	json.Unmarshal([]byte(tagsStr), &finding.Tags)
	json.Unmarshal([]byte(metadataStr), &finding.Metadata)

	return finding, nil
}

func listFindings(scopeTargetID, sessionID, category string, severities, statuses []string, limit, offset int) ([]Finding, int, error) {
	// Build dynamic query
	whereClauses := []string{}
	args := []interface{}{}
	argIndex := 1

	if scopeTargetID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("scope_target_id = $%d", argIndex))
		args = append(args, scopeTargetID)
		argIndex++
	}

	if sessionID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("url_workflow_session_id = $%d", argIndex))
		args = append(args, sessionID)
		argIndex++
	}

	if category != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, category)
		argIndex++
	}

	if len(severities) > 0 {
		placeholders := []string{}
		for _, severity := range severities {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
			args = append(args, severity)
			argIndex++
		}
		whereClauses = append(whereClauses, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(statuses) > 0 {
		placeholders := []string{}
		for _, status := range statuses {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIndex))
			args = append(args, status)
			argIndex++
		}
		whereClauses = append(whereClauses, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}

	whereClause := ""
	if len(whereClauses) > 0 {
		whereClause = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM findings %s", whereClause)
	var total int
	err := dbPool.QueryRow(context.Background(), countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get findings
	findingsQuery := fmt.Sprintf(`
		SELECT id, key_hash, title, description, category, severity, confidence,
		       signal, status, url, method, vulnerability_class,
		       url_workflow_session_id, scope_target_id, discovered_at, last_updated
		FROM findings %s
		ORDER BY discovered_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := dbPool.Query(context.Background(), findingsQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		finding := Finding{}
		err := rows.Scan(
			&finding.ID, &finding.KeyHash, &finding.Title, &finding.Description,
			&finding.Category, &finding.Severity, &finding.Confidence, &finding.Signal,
			&finding.Status, &finding.URL, &finding.Method, &finding.VulnerabilityClass,
			&finding.URLWorkflowSessionID, &finding.ScopeTargetID,
			&finding.DiscoveredAt, &finding.LastUpdated,
		)
		if err != nil {
			log.Printf("[WARN] Failed to scan finding row: %v", err)
			continue
		}

		findings = append(findings, finding)
	}

	return findings, total, nil
}

func updateFindingStatus(findingID, status, verifiedBy, notes string) error {
	query := `
		UPDATE findings 
		SET status = $1, verified_by = $2, last_updated = NOW(),
		    last_verified = CASE WHEN $1 = 'confirmed' THEN NOW() ELSE last_verified END
		WHERE id = $3
	`

	_, err := dbPool.Exec(context.Background(), query, status, verifiedBy, findingID)
	return err
}
