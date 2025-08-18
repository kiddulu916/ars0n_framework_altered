# Go Findings API Enhancement - Complete Implementation

## Overview

This document provides the complete implementation for enhancing the existing Go API with comprehensive findings management endpoints. This builds directly on the Evidence & Findings Pipeline foundation and integrates seamlessly with the existing Gorilla Mux router and CORS patterns.

## API Endpoint Implementation

### 1. Main Router Enhancement

```go
// server/main.go - Enhanced router with findings endpoints
package main

import (
    "log"
    "net/http"
    "os"
    
    "github.com/gorilla/mux"
    "github.com/rs/cors"
)

func main() {
    // Initialize database pool (existing)
    dbPool := initializeDatabase()
    defer dbPool.Close()
    
    // Initialize findings system
    utils.InitFindingsDB(dbPool)
    
    // Create router
    router := mux.NewRouter()
    
    // Setup existing routes
    setupExistingRoutes(router)
    
    // Setup new findings routes
    setupFindingsRoutes(router)
    
    // Setup evidence routes
    setupEvidenceRoutes(router)
    
    // Setup multi-identity testing routes
    setupMultiIdentityRoutes(router)
    
    // Setup OOB routes
    setupOOBRoutes(router)
    
    // Setup CORS (existing pattern)
    c := cors.New(cors.Options{
        AllowedOrigins: []string{"*"},
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders: []string{"*"},
    })
    
    handler := c.Handler(router)
    
    port := os.Getenv("PORT")
    if port == "" {
        port = "8443"
    }
    
    log.Printf("Server starting on port %s", port)
    log.Fatal(http.ListenAndServe(":"+port, handler))
}

// Setup findings management routes
func setupFindingsRoutes(router *mux.Router) {
    // Core findings endpoints
    router.HandleFunc("/api/findings", utils.CreateOrUpdateFinding).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/findings", utils.ListFindings).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/{id}", utils.GetFinding).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/{id}", utils.UpdateFinding).Methods("PUT", "OPTIONS")
    router.HandleFunc("/api/findings/{id}", utils.DeleteFinding).Methods("DELETE", "OPTIONS")
    
    // Finding status management
    router.HandleFunc("/api/findings/{id}/status", utils.UpdateFindingStatus).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/findings/{id}/triage", utils.TriageFinding).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/findings/{id}/confirm", utils.ConfirmFinding).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/findings/{id}/close", utils.CloseFinding).Methods("POST", "OPTIONS")
    
    // Finding relationships
    router.HandleFunc("/api/findings/{id}/related", utils.GetRelatedFindings).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/{id}/duplicates", utils.GetDuplicateFindings).Methods("GET", "OPTIONS")
    
    // Bulk operations
    router.HandleFunc("/api/findings/bulk/status", utils.BulkUpdateFindingStatus).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/findings/bulk/delete", utils.BulkDeleteFindings).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/findings/bulk/export", utils.BulkExportFindings).Methods("POST", "OPTIONS")
    
    // Export and reporting
    router.HandleFunc("/api/findings/export", utils.ExportFindings).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/report/{format}", utils.GenerateFindingsReport).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/stats", utils.GetFindingsStatistics).Methods("GET", "OPTIONS")
    
    // Search and filtering
    router.HandleFunc("/api/findings/search", utils.SearchFindings).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/filter", utils.FilterFindings).Methods("POST", "OPTIONS")
    
    // Kill chain endpoints
    router.HandleFunc("/api/findings/kill-chains", utils.GetKillChains).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/kill-chains/{id}", utils.GetKillChain).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/findings/kill-chains/{id}/validate", utils.ValidateKillChain).Methods("POST", "OPTIONS")
}

// Setup evidence management routes
func setupEvidenceRoutes(router *mux.Router) {
    router.HandleFunc("/api/evidence/finding/{findingId}", utils.GetFindingEvidence).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/evidence/upload", utils.UploadEvidence).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/evidence/download/{evidenceId}", utils.DownloadEvidence).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/evidence/{evidenceId}/metadata", utils.GetEvidenceMetadata).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/evidence/search", utils.SearchEvidence).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/evidence/bulk/download", utils.BulkDownloadEvidence).Methods("POST", "OPTIONS")
}

// Setup multi-identity testing routes
func setupMultiIdentityRoutes(router *mux.Router) {
    router.HandleFunc("/api/multi-identity/test", utils.RunMultiIdentityTest).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/multi-identity/tests/{id}", utils.GetMultiIdentityTest).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/multi-identity/identities", utils.GetIdentityContexts).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/multi-identity/identities", utils.CreateIdentityContext).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/multi-identity/violations", utils.GetAccessViolations).Methods("GET", "OPTIONS")
}

// Setup OOB interaction routes
func setupOOBRoutes(router *mux.Router) {
    router.HandleFunc("/api/oob/test", utils.CreateOOBTest).Methods("POST", "OPTIONS")
    router.HandleFunc("/api/oob/test/{token}/check", utils.CheckOOBInteraction).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/oob/interactions", utils.GetOOBInteractions).Methods("GET", "OPTIONS")
    router.HandleFunc("/api/oob/interactions/{id}", utils.GetOOBInteraction).Methods("GET", "OPTIONS")
}
```

### 2. Enhanced Findings Utilities

```go
// server/utils/findingsApiUtils.go
package utils

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "strings"
    "time"
    
    "github.com/gorilla/mux"
    "github.com/jackc/pgx/v5/pgxpool"
)

// Enhanced finding update with full validation
func UpdateFinding(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    findingID := vars["id"]
    
    if findingID == "" {
        http.Error(w, "Finding ID required", http.StatusBadRequest)
        return
    }
    
    var updateRequest struct {
        Title       string                 `json:"title,omitempty"`
        Category    string                 `json:"category,omitempty"`
        Severity    string                 `json:"severity,omitempty"`
        Status      string                 `json:"status,omitempty"`
        Signal      map[string]interface{} `json:"signal,omitempty"`
        Metadata    map[string]interface{} `json:"metadata,omitempty"`
        Notes       string                 `json:"notes,omitempty"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Validate finding exists
    finding, err := getFindingByID(findingID)
    if err != nil {
        if err.Error() == "finding not found" {
            http.Error(w, "Finding not found", http.StatusNotFound)
        } else {
            http.Error(w, "Database error", http.StatusInternalServerError)
        }
        return
    }
    
    // Build update query dynamically
    updates := []string{}
    args := []interface{}{}
    argCount := 0
    
    if updateRequest.Title != "" {
        argCount++
        updates = append(updates, fmt.Sprintf("title = $%d", argCount))
        args = append(args, updateRequest.Title)
    }
    
    if updateRequest.Category != "" {
        argCount++
        updates = append(updates, fmt.Sprintf("category = $%d", argCount))
        args = append(args, updateRequest.Category)
    }
    
    if updateRequest.Severity != "" && isValidSeverity(updateRequest.Severity) {
        argCount++
        updates = append(updates, fmt.Sprintf("severity = $%d", argCount))
        args = append(args, updateRequest.Severity)
    }
    
    if updateRequest.Status != "" && isValidStatus(updateRequest.Status) {
        argCount++
        updates = append(updates, fmt.Sprintf("status = $%d", argCount))
        args = append(args, updateRequest.Status)
    }
    
    if updateRequest.Signal != nil {
        argCount++
        signalJSON, _ := json.Marshal(updateRequest.Signal)
        updates = append(updates, fmt.Sprintf("signal = $%d", argCount))
        args = append(args, signalJSON)
    }
    
    if updateRequest.Metadata != nil {
        argCount++
        metadataJSON, _ := json.Marshal(updateRequest.Metadata)
        updates = append(updates, fmt.Sprintf("metadata = $%d", argCount))
        args = append(args, metadataJSON)
    }
    
    // Always update timestamp
    argCount++
    updates = append(updates, fmt.Sprintf("updated_at = $%d", argCount))
    args = append(args, time.Now())
    
    if len(updates) == 1 { // Only timestamp update
        http.Error(w, "No valid fields to update", http.StatusBadRequest)
        return
    }
    
    // Execute update
    argCount++
    query := fmt.Sprintf("UPDATE findings SET %s WHERE id = $%d", strings.Join(updates, ", "), argCount)
    args = append(args, findingID)
    
    _, err = dbPool.Exec(context.Background(), query, args...)
    if err != nil {
        log.Printf("Failed to update finding: %v", err)
        http.Error(w, "Update failed", http.StatusInternalServerError)
        return
    }
    
    // Return updated finding
    updatedFinding, err := getFindingByID(findingID)
    if err != nil {
        http.Error(w, "Failed to retrieve updated finding", http.StatusInternalServerError)
        return
    }
    
    json.NewEncoder(w).Encode(updatedFinding)
}

// Triage finding with detailed analysis
func TriageFinding(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    findingID := vars["id"]
    
    var triageRequest struct {
        Analyst     string `json:"analyst"`
        Priority    string `json:"priority"`     // 'low', 'medium', 'high', 'critical'
        Notes       string `json:"notes"`
        Assignee    string `json:"assignee,omitempty"`
        DueDate     string `json:"due_date,omitempty"`
        Tags        []string `json:"tags,omitempty"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&triageRequest); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Validate finding exists
    finding, err := getFindingByID(findingID)
    if err != nil {
        if err.Error() == "finding not found" {
            http.Error(w, "Finding not found", http.StatusNotFound)
        } else {
            http.Error(w, "Database error", http.StatusInternalServerError)
        }
        return
    }
    
    // Create triage record
    triageID := uuid.New().String()
    now := time.Now()
    
    triageData := map[string]interface{}{
        "analyst":     triageRequest.Analyst,
        "priority":    triageRequest.Priority,
        "notes":       triageRequest.Notes,
        "assignee":    triageRequest.Assignee,
        "tags":        triageRequest.Tags,
        "triaged_at":  now,
        "triage_id":   triageID,
    }
    
    // Parse due date if provided
    if triageRequest.DueDate != "" {
        if dueDate, err := time.Parse("2006-01-02", triageRequest.DueDate); err == nil {
            triageData["due_date"] = dueDate
        }
    }
    
    triageJSON, _ := json.Marshal(triageData)
    
    // Update finding status and add triage data
    query := `
        UPDATE findings 
        SET status = 'triaged', 
            metadata = COALESCE(metadata, '{}') || $1,
            updated_at = $2
        WHERE id = $3
    `
    
    _, err = dbPool.Exec(context.Background(), query, triageJSON, now, findingID)
    if err != nil {
        log.Printf("Failed to triage finding: %v", err)
        http.Error(w, "Triage failed", http.StatusInternalServerError)
        return
    }
    
    // Create triage history record
    historyQuery := `
        INSERT INTO finding_history (id, finding_id, action, actor, details, created_at)
        VALUES ($1, $2, 'triaged', $3, $4, $5)
    `
    
    _, err = dbPool.Exec(context.Background(), historyQuery, 
        uuid.New().String(), findingID, triageRequest.Analyst, triageJSON, now)
    if err != nil {
        log.Printf("Failed to create triage history: %v", err)
        // Continue anyway - triage was successful
    }
    
    response := map[string]interface{}{
        "finding_id":  findingID,
        "status":      "triaged",
        "triage_id":   triageID,
        "triaged_by":  triageRequest.Analyst,
        "triaged_at":  now,
    }
    
    json.NewEncoder(w).Encode(response)
}

// Confirm finding with validation details
func ConfirmFinding(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    findingID := vars["id"]
    
    var confirmRequest struct {
        Validator       string   `json:"validator"`
        ConfirmationType string  `json:"confirmation_type"` // 'manual', 'automated', 'reproduction'
        ReproSteps      []string `json:"repro_steps,omitempty"`
        Impact          string   `json:"impact"`
        Risk            string   `json:"risk"`           // 'low', 'medium', 'high', 'critical'
        CVSSScore       float64  `json:"cvss_score,omitempty"`
        Notes           string   `json:"notes"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&confirmRequest); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Validate finding exists
    finding, err := getFindingByID(findingID)
    if err != nil {
        if err.Error() == "finding not found" {
            http.Error(w, "Finding not found", http.StatusNotFound)
        } else {
            http.Error(w, "Database error", http.StatusInternalServerError)
        }
        return
    }
    
    now := time.Now()
    confirmationID := uuid.New().String()
    
    confirmationData := map[string]interface{}{
        "validator":         confirmRequest.Validator,
        "confirmation_type": confirmRequest.ConfirmationType,
        "repro_steps":      confirmRequest.ReproSteps,
        "impact":           confirmRequest.Impact,
        "risk":             confirmRequest.Risk,
        "cvss_score":       confirmRequest.CVSSScore,
        "notes":            confirmRequest.Notes,
        "confirmed_at":     now,
        "confirmation_id":  confirmationID,
    }
    
    confirmationJSON, _ := json.Marshal(confirmationData)
    
    // Update finding status
    query := `
        UPDATE findings 
        SET status = 'confirmed',
            metadata = COALESCE(metadata, '{}') || $1,
            updated_at = $2
        WHERE id = $3
    `
    
    _, err = dbPool.Exec(context.Background(), query, confirmationJSON, now, findingID)
    if err != nil {
        log.Printf("Failed to confirm finding: %v", err)
        http.Error(w, "Confirmation failed", http.StatusInternalServerError)
        return
    }
    
    // Create confirmation history
    historyQuery := `
        INSERT INTO finding_history (id, finding_id, action, actor, details, created_at)
        VALUES ($1, $2, 'confirmed', $3, $4, $5)
    `
    
    _, err = dbPool.Exec(context.Background(), historyQuery,
        uuid.New().String(), findingID, confirmRequest.Validator, confirmationJSON, now)
    if err != nil {
        log.Printf("Failed to create confirmation history: %v", err)
    }
    
    response := map[string]interface{}{
        "finding_id":       findingID,
        "status":           "confirmed",
        "confirmation_id":  confirmationID,
        "confirmed_by":     confirmRequest.Validator,
        "confirmed_at":     now,
        "risk_level":       confirmRequest.Risk,
    }
    
    json.NewEncoder(w).Encode(response)
}

// Get related findings based on similarity
func GetRelatedFindings(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    findingID := vars["id"]
    
    // Validate finding exists
    finding, err := getFindingByID(findingID)
    if err != nil {
        if err.Error() == "finding not found" {
            http.Error(w, "Finding not found", http.StatusNotFound)
        } else {
            http.Error(w, "Database error", http.StatusInternalServerError)
        }
        return
    }
    
    // Find related findings based on multiple criteria
    query := `
        SELECT id, title, category, severity, status, created_at,
               CASE 
                   WHEN category = $2 THEN 3
                   WHEN severity = $3 THEN 2  
                   WHEN scope_target_id = $4 THEN 1
                   ELSE 0
               END as relevance_score
        FROM findings 
        WHERE id != $1 
          AND (category = $2 OR severity = $3 OR scope_target_id = $4)
        ORDER BY relevance_score DESC, created_at DESC
        LIMIT 20
    `
    
    rows, err := dbPool.Query(context.Background(), query, 
        findingID, finding.Category, finding.Severity, finding.ScopeTargetID)
    if err != nil {
        log.Printf("Failed to get related findings: %v", err)
        http.Error(w, "Query failed", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    
    var relatedFindings []map[string]interface{}
    for rows.Next() {
        var related map[string]interface{} = make(map[string]interface{})
        var relevanceScore int
        var createdAt time.Time
        
        err := rows.Scan(&related["id"], &related["title"], &related["category"], 
                        &related["severity"], &related["status"], &createdAt, &relevanceScore)
        if err != nil {
            continue
        }
        
        related["created_at"] = createdAt
        related["relevance_score"] = relevanceScore
        relatedFindings = append(relatedFindings, related)
    }
    
    response := map[string]interface{}{
        "finding_id":       findingID,
        "related_findings": relatedFindings,
        "count":           len(relatedFindings),
    }
    
    json.NewEncoder(w).Encode(response)
}

// Advanced search with multiple criteria
func SearchFindings(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    // Parse query parameters
    query := r.URL.Query().Get("q")
    category := r.URL.Query().Get("category")
    severity := r.URL.Query().Get("severity") 
    status := r.URL.Query().Get("status")
    sessionID := r.URL.Query().Get("session_id")
    scopeTargetID := r.URL.Query().Get("scope_target_id")
    
    limitStr := r.URL.Query().Get("limit")
    offsetStr := r.URL.Query().Get("offset")
    
    limit := 50
    offset := 0
    
    if limitStr != "" {
        if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
            limit = l
        }
    }
    
    if offsetStr != "" {
        if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
            offset = o
        }
    }
    
    // Build dynamic search query
    var conditions []string
    var args []interface{}
    argCount := 0
    
    if query != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR category ILIKE $%d)", argCount, argCount))
        args = append(args, "%"+query+"%")
    }
    
    if category != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("category = $%d", argCount))
        args = append(args, category)
    }
    
    if severity != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("severity = $%d", argCount))
        args = append(args, severity)
    }
    
    if status != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("status = $%d", argCount))
        args = append(args, status)
    }
    
    if sessionID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("url_workflow_session_id = $%d", argCount))
        args = append(args, sessionID)
    }
    
    if scopeTargetID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("scope_target_id = $%d", argCount))
        args = append(args, scopeTargetID)
    }
    
    whereClause := ""
    if len(conditions) > 0 {
        whereClause = "WHERE " + strings.Join(conditions, " AND ")
    }
    
    // Count total results
    countQuery := fmt.Sprintf("SELECT COUNT(*) FROM findings %s", whereClause)
    var total int
    err := dbPool.QueryRow(context.Background(), countQuery, args...).Scan(&total)
    if err != nil {
        log.Printf("Failed to count search results: %v", err)
        http.Error(w, "Search failed", http.StatusInternalServerError)
        return
    }
    
    // Get results with pagination
    argCount++
    limitArg := argCount
    argCount++
    offsetArg := argCount
    
    searchQuery := fmt.Sprintf(`
        SELECT id, title, category, severity, status, kill_chain_score, created_at, updated_at
        FROM findings %s 
        ORDER BY 
            CASE WHEN kill_chain_score > 0 THEN kill_chain_score ELSE 0 END DESC,
            CASE severity 
                WHEN 'critical' THEN 4 
                WHEN 'high' THEN 3 
                WHEN 'medium' THEN 2 
                WHEN 'low' THEN 1 
                ELSE 0 
            END DESC,
            created_at DESC
        LIMIT $%d OFFSET $%d
    `, whereClause, limitArg, offsetArg)
    
    args = append(args, limit, offset)
    
    rows, err := dbPool.Query(context.Background(), searchQuery, args...)
    if err != nil {
        log.Printf("Failed to execute search query: %v", err)
        http.Error(w, "Search failed", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    
    var findings []map[string]interface{}
    for rows.Next() {
        var finding map[string]interface{} = make(map[string]interface{})
        var createdAt, updatedAt time.Time
        
        err := rows.Scan(&finding["id"], &finding["title"], &finding["category"],
                        &finding["severity"], &finding["status"], &finding["kill_chain_score"],
                        &createdAt, &updatedAt)
        if err != nil {
            continue
        }
        
        finding["created_at"] = createdAt
        finding["updated_at"] = updatedAt
        findings = append(findings, finding)
    }
    
    response := map[string]interface{}{
        "findings":    findings,
        "total":       total,
        "limit":       limit,
        "offset":      offset,
        "has_more":    offset+limit < total,
        "query_info": map[string]interface{}{
            "text":           query,
            "category":       category,
            "severity":       severity,
            "status":         status,
            "session_id":     sessionID,
            "scope_target_id": scopeTargetID,
        },
    }
    
    json.NewEncoder(w).Encode(response)
}

// Get comprehensive statistics
func GetFindingsStatistics(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    sessionID := r.URL.Query().Get("session_id")
    scopeTargetID := r.URL.Query().Get("scope_target_id")
    
    var conditions []string
    var args []interface{}
    argCount := 0
    
    if sessionID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("url_workflow_session_id = $%d", argCount))
        args = append(args, sessionID)
    }
    
    if scopeTargetID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf("scope_target_id = $%d", argCount))
        args = append(args, scopeTargetID)
    }
    
    whereClause := ""
    if len(conditions) > 0 {
        whereClause = "WHERE " + strings.Join(conditions, " AND ")
    }
    
    // Get comprehensive statistics
    statsQuery := fmt.Sprintf(`
        SELECT 
            COUNT(*) as total_findings,
            COUNT(CASE WHEN status = 'open' THEN 1 END) as open_findings,
            COUNT(CASE WHEN status = 'triaged' THEN 1 END) as triaged_findings,
            COUNT(CASE WHEN status = 'confirmed' THEN 1 END) as confirmed_findings,
            COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed_findings,
            COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_findings,
            COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_findings,
            COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_findings,
            COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_findings,
            COUNT(CASE WHEN severity = 'info' THEN 1 END) as info_findings,
            COUNT(CASE WHEN kill_chain_score > 0 THEN 1 END) as kill_chain_findings,
            AVG(CASE WHEN kill_chain_score > 0 THEN kill_chain_score END) as avg_kill_chain_score,
            MAX(kill_chain_score) as max_kill_chain_score
        FROM findings %s
    `, whereClause)
    
    var stats struct {
        Total            int     `json:"total_findings"`
        Open             int     `json:"open_findings"`
        Triaged          int     `json:"triaged_findings"`
        Confirmed        int     `json:"confirmed_findings"`
        Closed           int     `json:"closed_findings"`
        Critical         int     `json:"critical_findings"`
        High             int     `json:"high_findings"`
        Medium           int     `json:"medium_findings"`
        Low              int     `json:"low_findings"`
        Info             int     `json:"info_findings"`
        KillChain        int     `json:"kill_chain_findings"`
        AvgKillChainScore *float64 `json:"avg_kill_chain_score"`
        MaxKillChainScore int     `json:"max_kill_chain_score"`
    }
    
    err := dbPool.QueryRow(context.Background(), statsQuery, args...).Scan(
        &stats.Total, &stats.Open, &stats.Triaged, &stats.Confirmed, &stats.Closed,
        &stats.Critical, &stats.High, &stats.Medium, &stats.Low, &stats.Info,
        &stats.KillChain, &stats.AvgKillChainScore, &stats.MaxKillChainScore)
    
    if err != nil {
        log.Printf("Failed to get findings statistics: %v", err)
        http.Error(w, "Statistics query failed", http.StatusInternalServerError)
        return
    }
    
    // Get category breakdown
    categoryQuery := fmt.Sprintf(`
        SELECT category, COUNT(*) as count 
        FROM findings %s 
        GROUP BY category 
        ORDER BY count DESC
    `, whereClause)
    
    rows, err := dbPool.Query(context.Background(), categoryQuery, args...)
    if err != nil {
        log.Printf("Failed to get category breakdown: %v", err)
        http.Error(w, "Category query failed", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    
    categoryBreakdown := make(map[string]int)
    for rows.Next() {
        var category string
        var count int
        if err := rows.Scan(&category, &count); err == nil {
            categoryBreakdown[category] = count
        }
    }
    
    response := map[string]interface{}{
        "summary":            stats,
        "category_breakdown": categoryBreakdown,
        "generated_at":       time.Now(),
    }
    
    json.NewEncoder(w).Encode(response)
}

// Helper validation functions
func isValidSeverity(severity string) bool {
    validSeverities := []string{"info", "low", "medium", "high", "critical"}
    for _, v := range validSeverities {
        if v == severity {
            return true
        }
    }
    return false
}

func isValidStatus(status string) bool {
    validStatuses := []string{"open", "triaged", "confirmed", "closed"}
    for _, v := range validStatuses {
        if v == status {
            return true
        }
    }
    return false
}
```

### 3. Database Schema Enhancement

```sql
-- Finding history table for audit trail
CREATE TABLE IF NOT EXISTS finding_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,  -- 'created', 'updated', 'triaged', 'confirmed', 'closed'
    actor VARCHAR(100),           -- User who performed the action
    details JSONB DEFAULT '{}',   -- Action-specific details
    created_at TIMESTAMP DEFAULT NOW(),
    
    INDEX(finding_id),
    INDEX(action),
    INDEX(created_at)
);

-- Finding tags for categorization
CREATE TABLE IF NOT EXISTS finding_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tag VARCHAR(50) NOT NULL,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(finding_id, tag),
    INDEX(finding_id),
    INDEX(tag)
);

-- Finding comments for collaboration
CREATE TABLE IF NOT EXISTS finding_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    author VARCHAR(100) NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    INDEX(finding_id),
    INDEX(created_at)
);
```

This comprehensive Go API enhancement provides complete findings management functionality with advanced search, statistics, collaboration features, and full integration with the existing Ars0n Framework architecture.
