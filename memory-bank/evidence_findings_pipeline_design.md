# Evidence & Findings Pipeline Foundation - Ars0n Framework Integration

## Overview

This document outlines the implementation of Option A: Evidence & Findings Pipeline foundation, adapted for the existing Ars0n Framework architecture. This system provides one centralized place to collect, deduplicate, and replay every probe (DAST, plugins, browser) using the existing Go backend, PostgreSQL database, and containerized architecture.

## Goal

**One place to collect, dedupe, and replay every probe (DAST, plugins, browser) integrated with the existing Ars0n Framework architecture.**

## Architecture Integration

### 1. Database Schema (PostgreSQL) - Integrated with Existing Schema

Building on the existing 50+ table PostgreSQL schema, we add the findings pipeline tables:

```sql
-- Core findings table (central evidence repository)
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(64) NOT NULL UNIQUE,  -- For deduplication
    title TEXT NOT NULL,
    category VARCHAR(50) NOT NULL,         -- 'xss', 'idor', 'ssrf', 'sqli', etc.
    severity VARCHAR(20) NOT NULL,         -- 'info', 'low', 'medium', 'high', 'critical'
    signal JSONB NOT NULL,                 -- Raw detection signal/payload
    status VARCHAR(20) DEFAULT 'open',     -- 'open', 'triaged', 'confirmed', 'closed'
    
    -- Framework integration
    url_workflow_session_id UUID REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    
    -- Kill chain integration
    kill_chain_score INTEGER DEFAULT 0,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Vectors table (attack vector details)
CREATE TABLE IF NOT EXISTS vectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- HTTP request details
    method VARCHAR(10) NOT NULL,           -- GET, POST, PUT, etc.
    url_template TEXT NOT NULL,            -- URL with parameter placeholders
    params_shape JSONB DEFAULT '{}',       -- Parameter structure and types
    headers_shape JSONB DEFAULT '{}',      -- Required headers structure
    content_type VARCHAR(100),             -- Content-Type if applicable
    
    -- Payload details
    payload TEXT,                          -- Actual exploit payload
    injection_point VARCHAR(50),           -- Where payload was injected
    
    -- Response details
    response_indicators JSONB DEFAULT '{}', -- What indicates successful exploitation
    
    created_at TIMESTAMP DEFAULT NOW()
);

-- Evidence blobs table (artifact storage)
CREATE TABLE IF NOT EXISTS evidence_blobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- Blob details
    type VARCHAR(20) NOT NULL,             -- 'har', 'screenshot', 'dom', 'pcap', 'log'
    path TEXT NOT NULL,                    -- File path in blob storage
    filename VARCHAR(255),                 -- Original filename
    sha256 VARCHAR(64) NOT NULL,           -- File integrity hash
    size BIGINT NOT NULL,                  -- File size in bytes
    
    -- Content metadata
    content_type VARCHAR(100),
    encoding VARCHAR(20) DEFAULT 'utf-8',
    
    -- Storage metadata
    storage_backend VARCHAR(20) DEFAULT 'filesystem', -- 'filesystem', 's3', etc.
    compressed BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP DEFAULT NOW()
);

-- Contexts table (testing context and identity)
CREATE TABLE IF NOT EXISTS contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- Identity context
    identity VARCHAR(20) NOT NULL,         -- 'guest', 'user', 'admin'
    tenant VARCHAR(100),                   -- Multi-tenant context if applicable
    session_id VARCHAR(100),               -- Session identifier
    
    -- Authentication details
    auth_method VARCHAR(50),               -- 'none', 'basic', 'bearer', 'cookie'
    auth_details JSONB DEFAULT '{}',       -- Auth-specific metadata
    
    -- Browser context
    user_agent TEXT,
    browser_session JSONB DEFAULT '{}',    -- Browser state/cookies
    
    -- Request context
    referrer TEXT,
    origin TEXT,
    
    created_at TIMESTAMP DEFAULT NOW()
);

-- Reproduction recipes table (repro instructions)
CREATE TABLE IF NOT EXISTS repro_recipes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- Reproduction artifacts
    curl_json JSONB NOT NULL,              -- Curl command in structured format
    playwright_script_path TEXT,           -- Path to Playwright reproduction script
    har_slice_path TEXT,                   -- Path to minimal HAR file
    
    -- Instructions and metadata
    notes TEXT,                            -- Human-readable reproduction steps
    prerequisites TEXT,                    -- Required setup/conditions
    success_indicators TEXT,               -- How to verify successful reproduction
    
    -- Automation metadata
    automated BOOLEAN DEFAULT FALSE,       -- Can be automatically reproduced
    validation_status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'validated', 'failed'
    last_validated_at TIMESTAMP,
    
    -- Redaction and security
    pii_redacted BOOLEAN DEFAULT TRUE,
    redaction_pattern TEXT,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Out-of-band events table (OOB interactions)
CREATE TABLE IF NOT EXISTS oob_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- OOB details
    channel VARCHAR(10) NOT NULL,          -- 'dns', 'http', 'smtp'
    token VARCHAR(100) NOT NULL UNIQUE,    -- Unique interaction token
    timestamp TIMESTAMP NOT NULL,          -- When interaction occurred
    
    -- Interaction metadata
    source_ip INET,                        -- Source IP of interaction
    user_agent TEXT,                       -- User-Agent if HTTP
    request_details JSONB DEFAULT '{}',    -- Full request details
    
    -- Validation
    validated BOOLEAN DEFAULT FALSE,       -- Has been validated as genuine
    validation_method VARCHAR(50),         -- How validation was performed
    
    -- Integration
    external_service VARCHAR(50),          -- 'interactsh', 'custom', etc.
    external_id VARCHAR(100),              -- External service identifier
    
    meta JSONB DEFAULT '{}',               -- Additional metadata
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_findings_key_hash ON findings(key_hash);
CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(url_workflow_session_id);
CREATE INDEX IF NOT EXISTS idx_findings_scope_target_id ON findings(scope_target_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_kill_chain_score ON findings(kill_chain_score);
CREATE INDEX IF NOT EXISTS idx_vectors_finding_id ON vectors(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_blobs_finding_id ON evidence_blobs(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_blobs_type ON evidence_blobs(type);
CREATE INDEX IF NOT EXISTS idx_contexts_finding_id ON contexts(finding_id);
CREATE INDEX IF NOT EXISTS idx_contexts_identity ON contexts(identity);
CREATE INDEX IF NOT EXISTS idx_repro_recipes_finding_id ON repro_recipes(finding_id);
CREATE INDEX IF NOT EXISTS idx_oob_events_finding_id ON oob_events(finding_id);
CREATE INDEX IF NOT EXISTS idx_oob_events_token ON oob_events(token);
CREATE INDEX IF NOT EXISTS idx_oob_events_channel ON oob_events(channel);
```

### 2. Go API Integration (Extends Existing Backend)

Integration with the existing Go backend at `server/main.go` and `server/utils/`:

```go
// server/utils/findingsUtils.go
package utils

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sort"
    "time"
    
    "github.com/google/uuid"
    "github.com/gorilla/mux"
    "github.com/jackc/pgx/v5/pgxpool"
)

// Core finding structures
type Finding struct {
    ID                    string                 `json:"id"`
    KeyHash              string                 `json:"key_hash"`
    Title                string                 `json:"title"`
    Category             string                 `json:"category"`
    Severity             string                 `json:"severity"`
    Signal               map[string]interface{} `json:"signal"`
    Status               string                 `json:"status"`
    URLWorkflowSessionID string                 `json:"url_workflow_session_id"`
    ScopeTargetID        string                 `json:"scope_target_id"`
    KillChainScore       int                    `json:"kill_chain_score"`
    Metadata             map[string]interface{} `json:"metadata"`
    CreatedAt            time.Time              `json:"created_at"`
    UpdatedAt            time.Time              `json:"updated_at"`
    
    // Related objects (populated on demand)
    Vectors      []Vector       `json:"vectors,omitempty"`
    Evidence     []EvidenceBlob `json:"evidence,omitempty"`
    Contexts     []Context      `json:"contexts,omitempty"`
    ReproRecipes []ReproRecipe  `json:"repro_recipes,omitempty"`
    OOBEvents    []OOBEvent     `json:"oob_events,omitempty"`
}

type Vector struct {
    ID                  string                 `json:"id"`
    FindingID           string                 `json:"finding_id"`
    Method              string                 `json:"method"`
    URLTemplate         string                 `json:"url_template"`
    ParamsShape         map[string]interface{} `json:"params_shape"`
    HeadersShape        map[string]interface{} `json:"headers_shape"`
    ContentType         string                 `json:"content_type"`
    Payload             string                 `json:"payload"`
    InjectionPoint      string                 `json:"injection_point"`
    ResponseIndicators  map[string]interface{} `json:"response_indicators"`
    CreatedAt           time.Time              `json:"created_at"`
}

type EvidenceBlob struct {
    ID             string    `json:"id"`
    FindingID      string    `json:"finding_id"`
    Type           string    `json:"type"`
    Path           string    `json:"path"`
    Filename       string    `json:"filename"`
    SHA256         string    `json:"sha256"`
    Size           int64     `json:"size"`
    ContentType    string    `json:"content_type"`
    Encoding       string    `json:"encoding"`
    StorageBackend string    `json:"storage_backend"`
    Compressed     bool      `json:"compressed"`
    CreatedAt      time.Time `json:"created_at"`
}

type Context struct {
    ID             string                 `json:"id"`
    FindingID      string                 `json:"finding_id"`
    Identity       string                 `json:"identity"`
    Tenant         string                 `json:"tenant"`
    SessionID      string                 `json:"session_id"`
    AuthMethod     string                 `json:"auth_method"`
    AuthDetails    map[string]interface{} `json:"auth_details"`
    UserAgent      string                 `json:"user_agent"`
    BrowserSession map[string]interface{} `json:"browser_session"`
    Referrer       string                 `json:"referrer"`
    Origin         string                 `json:"origin"`
    CreatedAt      time.Time              `json:"created_at"`
}

type ReproRecipe struct {
    ID                   string                 `json:"id"`
    FindingID            string                 `json:"finding_id"`
    CurlJSON             map[string]interface{} `json:"curl_json"`
    PlaywrightScriptPath string                 `json:"playwright_script_path"`
    HARSlicePath         string                 `json:"har_slice_path"`
    Notes                string                 `json:"notes"`
    Prerequisites        string                 `json:"prerequisites"`
    SuccessIndicators    string                 `json:"success_indicators"`
    Automated            bool                   `json:"automated"`
    ValidationStatus     string                 `json:"validation_status"`
    LastValidatedAt      *time.Time             `json:"last_validated_at"`
    PIIRedacted          bool                   `json:"pii_redacted"`
    RedactionPattern     string                 `json:"redaction_pattern"`
    CreatedAt            time.Time              `json:"created_at"`
    UpdatedAt            time.Time              `json:"updated_at"`
}

type OOBEvent struct {
    ID                string                 `json:"id"`
    FindingID         string                 `json:"finding_id"`
    Channel           string                 `json:"channel"`
    Token             string                 `json:"token"`
    Timestamp         time.Time              `json:"timestamp"`
    SourceIP          string                 `json:"source_ip"`
    UserAgent         string                 `json:"user_agent"`
    RequestDetails    map[string]interface{} `json:"request_details"`
    Validated         bool                   `json:"validated"`
    ValidationMethod  string                 `json:"validation_method"`
    ExternalService   string                 `json:"external_service"`
    ExternalID        string                 `json:"external_id"`
    Meta              map[string]interface{} `json:"meta"`
    CreatedAt         time.Time              `json:"created_at"`
}

// Request/Response structures
type CreateFindingRequest struct {
    Title                string                 `json:"title"`
    Category             string                 `json:"category"`
    Severity             string                 `json:"severity"`
    Signal               map[string]interface{} `json:"signal"`
    URLWorkflowSessionID string                 `json:"url_workflow_session_id"`
    ScopeTargetID        string                 `json:"scope_target_id"`
    Vector               *Vector                `json:"vector,omitempty"`
    Context              *Context               `json:"context,omitempty"`
    Evidence             []EvidenceBlob         `json:"evidence,omitempty"`
    Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

type UpdateFindingStatusRequest struct {
    Status string `json:"status"`
    Notes  string `json:"notes,omitempty"`
}

type ExportFindingsResponse struct {
    Findings []Finding `json:"findings"`
    Meta     struct {
        Total     int       `json:"total"`
        ExportedAt time.Time `json:"exported_at"`
        Format    string    `json:"format"`
    } `json:"meta"`
}

// Database pool (reuse existing)
var dbPool *pgxpool.Pool

func InitFindingsDB(pool *pgxpool.Pool) {
    dbPool = pool
}

// API Handlers (integrate with existing Gorilla Mux router)

// POST /api/findings (upsert by key_hash, attach evidence)
func CreateOrUpdateFinding(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    var req CreateFindingRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Validate required fields
    if err := validateCreateFindingRequest(req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // Generate key_hash for deduplication
    keyHash := generateKeyHash(req.Category, req.Vector, req.Context)
    
    // Check for existing finding with same key_hash
    existingFinding, err := getFindingByKeyHash(keyHash)
    if err != nil && err.Error() != "finding not found" {
        log.Printf("[ERROR] Failed to check existing finding: %v", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    
    var finding *Finding
    
    if existingFinding != nil {
        // Update existing finding
        finding, err = updateExistingFinding(existingFinding, req)
        if err != nil {
            log.Printf("[ERROR] Failed to update finding: %v", err)
            http.Error(w, "Update failed", http.StatusInternalServerError)
            return
        }
        log.Printf("[INFO] Updated existing finding: %s", finding.ID)
    } else {
        // Create new finding
        finding, err = createNewFinding(req, keyHash)
        if err != nil {
            log.Printf("[ERROR] Failed to create finding: %v", err)
            http.Error(w, "Creation failed", http.StatusInternalServerError)
            return
        }
        log.Printf("[INFO] Created new finding: %s", finding.ID)
    }
    
    // Attach evidence if provided
    if len(req.Evidence) > 0 {
        if err := attachEvidence(finding.ID, req.Evidence); err != nil {
            log.Printf("[ERROR] Failed to attach evidence: %v", err)
        }
    }
    
    // Generate reproduction recipe if automation is possible
    go generateReproRecipeAsync(finding.ID, req)
    
    json.NewEncoder(w).Encode(finding)
}

// GET /api/findings/{id} (includes evidence, repro pack)
func GetFinding(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    findingID := vars["id"]
    
    if findingID == "" {
        http.Error(w, "Finding ID required", http.StatusBadRequest)
        return
    }
    
    finding, err := getFindingByID(findingID)
    if err != nil {
        if err.Error() == "finding not found" {
            http.Error(w, "Finding not found", http.StatusNotFound)
            return
        }
        log.Printf("[ERROR] Failed to get finding: %v", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    
    // Load related objects
    if err := loadFindingRelations(finding); err != nil {
        log.Printf("[ERROR] Failed to load finding relations: %v", err)
    }
    
    json.NewEncoder(w).Encode(finding)
}

// POST /api/findings/{id}/status (open/triaged/confirmed/closed)
func UpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    findingID := vars["id"]
    
    var req UpdateFindingStatusRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Validate status
    validStatuses := []string{"open", "triaged", "confirmed", "closed"}
    if !contains(validStatuses, req.Status) {
        http.Error(w, "Invalid status", http.StatusBadRequest)
        return
    }
    
    query := `UPDATE findings SET status = $1, updated_at = NOW() WHERE id = $2`
    _, err := dbPool.Exec(context.Background(), query, req.Status, findingID)
    if err != nil {
        log.Printf("[ERROR] Failed to update finding status: %v", err)
        http.Error(w, "Update failed", http.StatusInternalServerError)
        return
    }
    
    // Log status change
    log.Printf("[INFO] Finding %s status updated to %s", findingID, req.Status)
    
    response := map[string]string{
        "id":     findingID,
        "status": req.Status,
    }
    json.NewEncoder(w).Encode(response)
}

// GET /api/findings/export?format=json (report-stage feed)
func ExportFindings(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    // Get query parameters
    format := r.URL.Query().Get("format")
    if format == "" {
        format = "json"
    }
    
    sessionID := r.URL.Query().Get("session_id")
    scopeTargetID := r.URL.Query().Get("scope_target_id")
    status := r.URL.Query().Get("status")
    
    findings, err := getFilteredFindings(sessionID, scopeTargetID, status)
    if err != nil {
        log.Printf("[ERROR] Failed to get findings for export: %v", err)
        http.Error(w, "Export failed", http.StatusInternalServerError)
        return
    }
    
    // Load relations for export
    for i := range findings {
        if err := loadFindingRelations(&findings[i]); err != nil {
            log.Printf("[ERROR] Failed to load relations for finding %s: %v", findings[i].ID, err)
        }
    }
    
    response := ExportFindingsResponse{
        Findings: findings,
    }
    response.Meta.Total = len(findings)
    response.Meta.ExportedAt = time.Now()
    response.Meta.Format = format
    
    json.NewEncoder(w).Encode(response)
}

// GET /api/findings (list with filters)
func ListFindings(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    // Get query parameters
    sessionID := r.URL.Query().Get("session_id")
    scopeTargetID := r.URL.Query().Get("scope_target_id")
    status := r.URL.Query().Get("status")
    category := r.URL.Query().Get("category")
    severity := r.URL.Query().Get("severity")
    
    findings, err := getFilteredFindingsAdvanced(sessionID, scopeTargetID, status, category, severity)
    if err != nil {
        log.Printf("[ERROR] Failed to list findings: %v", err)
        http.Error(w, "List failed", http.StatusInternalServerError)
        return
    }
    
    json.NewEncoder(w).Encode(findings)
}

// Core business logic functions

func generateKeyHash(category string, vector *Vector, context *Context) string {
    // Create consistent hash for deduplication
    var hashParts []string
    
    hashParts = append(hashParts, category)
    
    if vector != nil {
        hashParts = append(hashParts, vector.URLTemplate)
        hashParts = append(hashParts, vector.Method)
        
        // Sort parameter keys for consistency
        var paramKeys []string
        for key := range vector.ParamsShape {
            paramKeys = append(paramKeys, key)
        }
        sort.Strings(paramKeys)
        for _, key := range paramKeys {
            hashParts = append(hashParts, key)
        }
    }
    
    if context != nil {
        hashParts = append(hashParts, context.Identity)
        if context.Tenant != "" {
            hashParts = append(hashParts, context.Tenant)
        }
    }
    
    // Generate SHA256 hash
    h := sha256.New()
    for _, part := range hashParts {
        h.Write([]byte(part))
    }
    
    return hex.EncodeToString(h.Sum(nil))
}

func validateCreateFindingRequest(req CreateFindingRequest) error {
    if req.Title == "" {
        return fmt.Errorf("title is required")
    }
    if req.Category == "" {
        return fmt.Errorf("category is required")
    }
    if req.Severity == "" {
        return fmt.Errorf("severity is required")
    }
    if req.ScopeTargetID == "" {
        return fmt.Errorf("scope_target_id is required")
    }
    
    // Validate severity
    validSeverities := []string{"info", "low", "medium", "high", "critical"}
    if !contains(validSeverities, req.Severity) {
        return fmt.Errorf("invalid severity: %s", req.Severity)
    }
    
    return nil
}

func createNewFinding(req CreateFindingRequest, keyHash string) (*Finding, error) {
    finding := &Finding{
        ID:                   uuid.New().String(),
        KeyHash:             keyHash,
        Title:               req.Title,
        Category:            req.Category,
        Severity:            req.Severity,
        Signal:              req.Signal,
        Status:              "open",
        URLWorkflowSessionID: req.URLWorkflowSessionID,
        ScopeTargetID:       req.ScopeTargetID,
        Metadata:            req.Metadata,
        CreatedAt:           time.Now(),
        UpdatedAt:           time.Now(),
    }
    
    if finding.Metadata == nil {
        finding.Metadata = make(map[string]interface{})
    }
    
    // Insert into database
    query := `
        INSERT INTO findings (id, key_hash, title, category, severity, signal, status,
                            url_workflow_session_id, scope_target_id, metadata, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    `
    
    signalJSON, _ := json.Marshal(finding.Signal)
    metadataJSON, _ := json.Marshal(finding.Metadata)
    
    _, err := dbPool.Exec(context.Background(), query,
        finding.ID, finding.KeyHash, finding.Title, finding.Category, finding.Severity,
        signalJSON, finding.Status, finding.URLWorkflowSessionID, finding.ScopeTargetID,
        metadataJSON, finding.CreatedAt, finding.UpdatedAt)
    
    if err != nil {
        return nil, err
    }
    
    // Create vector if provided
    if req.Vector != nil {
        if err := createVector(finding.ID, req.Vector); err != nil {
            log.Printf("[ERROR] Failed to create vector: %v", err)
        }
    }
    
    // Create context if provided
    if req.Context != nil {
        if err := createContext(finding.ID, req.Context); err != nil {
            log.Printf("[ERROR] Failed to create context: %v", err)
        }
    }
    
    return finding, nil
}

// Helper function implementations
func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func getFindingByKeyHash(keyHash string) (*Finding, error) {
    query := `SELECT id, key_hash, title, category, severity, signal, status,
                     url_workflow_session_id, scope_target_id, kill_chain_score, metadata,
                     created_at, updated_at
              FROM findings WHERE key_hash = $1`
    
    var finding Finding
    var signalJSON, metadataJSON []byte
    
    err := dbPool.QueryRow(context.Background(), query, keyHash).Scan(
        &finding.ID, &finding.KeyHash, &finding.Title, &finding.Category, &finding.Severity,
        &signalJSON, &finding.Status, &finding.URLWorkflowSessionID, &finding.ScopeTargetID,
        &finding.KillChainScore, &metadataJSON, &finding.CreatedAt, &finding.UpdatedAt)
    
    if err != nil {
        if err.Error() == "no rows in result set" {
            return nil, fmt.Errorf("finding not found")
        }
        return nil, err
    }
    
    // Parse JSON fields
    json.Unmarshal(signalJSON, &finding.Signal)
    json.Unmarshal(metadataJSON, &finding.Metadata)
    
    return &finding, nil
}

func getFindingByID(id string) (*Finding, error) {
    query := `SELECT id, key_hash, title, category, severity, signal, status,
                     url_workflow_session_id, scope_target_id, kill_chain_score, metadata,
                     created_at, updated_at
              FROM findings WHERE id = $1`
    
    var finding Finding
    var signalJSON, metadataJSON []byte
    
    err := dbPool.QueryRow(context.Background(), query, id).Scan(
        &finding.ID, &finding.KeyHash, &finding.Title, &finding.Category, &finding.Severity,
        &signalJSON, &finding.Status, &finding.URLWorkflowSessionID, &finding.ScopeTargetID,
        &finding.KillChainScore, &metadataJSON, &finding.CreatedAt, &finding.UpdatedAt)
    
    if err != nil {
        if err.Error() == "no rows in result set" {
            return nil, fmt.Errorf("finding not found")
        }
        return nil, err
    }
    
    // Parse JSON fields
    json.Unmarshal(signalJSON, &finding.Signal)
    json.Unmarshal(metadataJSON, &finding.Metadata)
    
    return &finding, nil
}

func updateExistingFinding(existing *Finding, req CreateFindingRequest) (*Finding, error) {
    // Update fields that can change
    existing.Title = req.Title
    existing.Signal = req.Signal
    existing.UpdatedAt = time.Now()
    
    // Merge metadata
    if req.Metadata != nil {
        for key, value := range req.Metadata {
            existing.Metadata[key] = value
        }
    }
    
    query := `UPDATE findings SET title = $1, signal = $2, metadata = $3, updated_at = $4
              WHERE id = $5`
    
    signalJSON, _ := json.Marshal(existing.Signal)
    metadataJSON, _ := json.Marshal(existing.Metadata)
    
    _, err := dbPool.Exec(context.Background(), query,
        existing.Title, signalJSON, metadataJSON, existing.UpdatedAt, existing.ID)
    
    return existing, err
}

func getFilteredFindings(sessionID, scopeTargetID, status string) ([]Finding, error) {
    var conditions []string
    var args []interface{}
    argCount := 0
    
    baseQuery := `SELECT id, key_hash, title, category, severity, signal, status,
                         url_workflow_session_id, scope_target_id, kill_chain_score, metadata,
                         created_at, updated_at
                  FROM findings WHERE 1=1`
    
    if sessionID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND url_workflow_session_id = $%d", argCount))
        args = append(args, sessionID)
    }
    
    if scopeTargetID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND scope_target_id = $%d", argCount))
        args = append(args, scopeTargetID)
    }
    
    if status != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND status = $%d", argCount))
        args = append(args, status)
    }
    
    query := baseQuery
    for _, condition := range conditions {
        query += condition
    }
    query += " ORDER BY created_at DESC"
    
    rows, err := dbPool.Query(context.Background(), query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var findings []Finding
    for rows.Next() {
        var finding Finding
        var signalJSON, metadataJSON []byte
        
        err := rows.Scan(&finding.ID, &finding.KeyHash, &finding.Title, &finding.Category,
                        &finding.Severity, &signalJSON, &finding.Status, &finding.URLWorkflowSessionID,
                        &finding.ScopeTargetID, &finding.KillChainScore, &metadataJSON,
                        &finding.CreatedAt, &finding.UpdatedAt)
        if err != nil {
            continue
        }
        
        json.Unmarshal(signalJSON, &finding.Signal)
        json.Unmarshal(metadataJSON, &finding.Metadata)
        
        findings = append(findings, finding)
    }
    
    return findings, nil
}

func getFilteredFindingsAdvanced(sessionID, scopeTargetID, status, category, severity string) ([]Finding, error) {
    var conditions []string
    var args []interface{}
    argCount := 0
    
    baseQuery := `SELECT id, key_hash, title, category, severity, signal, status,
                         url_workflow_session_id, scope_target_id, kill_chain_score, metadata,
                         created_at, updated_at
                  FROM findings WHERE 1=1`
    
    if sessionID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND url_workflow_session_id = $%d", argCount))
        args = append(args, sessionID)
    }
    
    if scopeTargetID != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND scope_target_id = $%d", argCount))
        args = append(args, scopeTargetID)
    }
    
    if status != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND status = $%d", argCount))
        args = append(args, status)
    }
    
    if category != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND category = $%d", argCount))
        args = append(args, category)
    }
    
    if severity != "" {
        argCount++
        conditions = append(conditions, fmt.Sprintf(" AND severity = $%d", argCount))
        args = append(args, severity)
    }
    
    query := baseQuery
    for _, condition := range conditions {
        query += condition
    }
    query += " ORDER BY kill_chain_score DESC, created_at DESC"
    
    rows, err := dbPool.Query(context.Background(), query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var findings []Finding
    for rows.Next() {
        var finding Finding
        var signalJSON, metadataJSON []byte
        
        err := rows.Scan(&finding.ID, &finding.KeyHash, &finding.Title, &finding.Category,
                        &finding.Severity, &signalJSON, &finding.Status, &finding.URLWorkflowSessionID,
                        &finding.ScopeTargetID, &finding.KillChainScore, &metadataJSON,
                        &finding.CreatedAt, &finding.UpdatedAt)
        if err != nil {
            continue
        }
        
        json.Unmarshal(signalJSON, &finding.Signal)
        json.Unmarshal(metadataJSON, &finding.Metadata)
        
        findings = append(findings, finding)
    }
    
    return findings, nil
}

func loadFindingRelations(finding *Finding) error {
    // Load vectors
    vectors, err := getVectorsByFindingID(finding.ID)
    if err != nil {
        log.Printf("[ERROR] Failed to load vectors: %v", err)
    } else {
        finding.Vectors = vectors
    }
    
    // Load evidence
    evidence, err := getEvidenceByFindingID(finding.ID)
    if err != nil {
        log.Printf("[ERROR] Failed to load evidence: %v", err)
    } else {
        finding.Evidence = evidence
    }
    
    // Load contexts
    contexts, err := getContextsByFindingID(finding.ID)
    if err != nil {
        log.Printf("[ERROR] Failed to load contexts: %v", err)
    } else {
        finding.Contexts = contexts
    }
    
    // Load repro recipes
    recipes, err := getReproRecipesByFindingID(finding.ID)
    if err != nil {
        log.Printf("[ERROR] Failed to load repro recipes: %v", err)
    } else {
        finding.ReproRecipes = recipes
    }
    
    // Load OOB events
    oobEvents, err := getOOBEventsByFindingID(finding.ID)
    if err != nil {
        log.Printf("[ERROR] Failed to load OOB events: %v", err)
    } else {
        finding.OOBEvents = oobEvents
    }
    
    return nil
}

// Additional helper functions would be implemented here...
func createVector(findingID string, vector *Vector) error {
    // Implementation for creating vector
    return nil
}

func createContext(findingID string, context *Context) error {
    // Implementation for creating context
    return nil
}

func attachEvidence(findingID string, evidence []EvidenceBlob) error {
    // Implementation for attaching evidence
    return nil
}

func generateReproRecipeAsync(findingID string, req CreateFindingRequest) {
    // Implementation for async repro recipe generation
}

func getVectorsByFindingID(findingID string) ([]Vector, error) {
    // Implementation for loading vectors
    return []Vector{}, nil
}

func getEvidenceByFindingID(findingID string) ([]EvidenceBlob, error) {
    // Implementation for loading evidence
    return []EvidenceBlob{}, nil
}

func getContextsByFindingID(findingID string) ([]Context, error) {
    // Implementation for loading contexts
    return []Context{}, nil
}

func getReproRecipesByFindingID(findingID string) ([]ReproRecipe, error) {
    // Implementation for loading repro recipes
    return []ReproRecipe{}, nil
}

func getOOBEventsByFindingID(findingID string) ([]OOBEvent, error) {
    // Implementation for loading OOB events
    return []OOBEvent{}, nil
}
```

### 3. Reproduction Pack Builder (Go Implementation)

```go
// server/utils/reproPackBuilder.go
package utils

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "text/template"
    "time"
)

type ReproPackBuilder struct {
    BlobStoragePath string
    Templates       map[string]*template.Template
    PIIPatterns     map[string]*regexp.Regexp
}

type ReproPackInput struct {
    Finding   Finding `json:"finding"`
    Vector    Vector  `json:"vector"`
    Context   Context `json:"context"`
    Evidence  []EvidenceBlob `json:"evidence"`
}

type ReproPackOutput struct {
    CurlJSON             map[string]interface{} `json:"curl_json"`
    PlaywrightScriptPath string                 `json:"playwright_script_path"`
    HARSlicePath         string                 `json:"har_slice_path"`
    Notes                string                 `json:"notes"`
    Prerequisites        string                 `json:"prerequisites"`
    SuccessIndicators    string                 `json:"success_indicators"`
}

func NewReproPackBuilder(blobStoragePath string) *ReproPackBuilder {
    rpb := &ReproPackBuilder{
        BlobStoragePath: blobStoragePath,
        Templates:       make(map[string]*template.Template),
        PIIPatterns:     initializePIIPatterns(),
    }
    
    rpb.initializeTemplates()
    return rpb
}

func initializePIIPatterns() map[string]*regexp.Regexp {
    return map[string]*regexp.Regexp{
        "email":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
        "ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
        "credit_card": regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
        "phone":       regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
        "ip_address":  regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
        "api_key":     regexp.MustCompile(`\b[A-Za-z0-9]{32,}\b`),
    }
}

func (rpb *ReproPackBuilder) GenerateReproPack(input ReproPackInput) (*ReproPackOutput, error) {
    log.Printf("[INFO] Generating reproduction pack for finding %s", input.Finding.ID)
    
    // 1. Generate curl command (JSON format)
    curlJSON, err := rpb.generateCurlCommand(input.Vector, input.Context)
    if err != nil {
        return nil, fmt.Errorf("failed to generate curl command: %w", err)
    }
    
    // 2. Generate Playwright script
    playwrightPath, err := rpb.generatePlaywrightScript(input)
    if err != nil {
        log.Printf("[WARN] Failed to generate Playwright script: %v", err)
        playwrightPath = "" // Optional component
    }
    
    // 3. Extract HAR slice
    harPath, err := rpb.extractHARSlice(input.Evidence, input.Finding.ID)
    if err != nil {
        log.Printf("[WARN] Failed to extract HAR slice: %v", err)
        harPath = "" // Optional component
    }
    
    // 4. Generate human-readable notes
    notes := rpb.generateNotes(input)
    
    // 5. Generate prerequisites
    prerequisites := rpb.generatePrerequisites(input)
    
    // 6. Generate success indicators
    successIndicators := rpb.generateSuccessIndicators(input)
    
    // 7. Apply PII redaction
    curlJSON = rpb.redactPIIFromJSON(curlJSON)
    
    output := &ReproPackOutput{
        CurlJSON:             curlJSON,
        PlaywrightScriptPath: playwrightPath,
        HARSlicePath:         harPath,
        Notes:                notes,
        Prerequisites:        prerequisites,
        SuccessIndicators:    successIndicators,
    }
    
    log.Printf("[INFO] Successfully generated reproduction pack for finding %s", input.Finding.ID)
    return output, nil
}

func (rpb *ReproPackBuilder) generateCurlCommand(vector Vector, context Context) (map[string]interface{}, error) {
    curlCmd := map[string]interface{}{
        "url":    vector.URLTemplate,
        "method": vector.Method,
    }
    
    // Add headers
    if len(vector.HeadersShape) > 0 {
        headers := make(map[string]string)
        for key, value := range vector.HeadersShape {
            headers[key] = fmt.Sprintf("%v", value)
        }
        curlCmd["headers"] = headers
    }
    
    // Add authentication
    if context.AuthMethod != "" && context.AuthMethod != "none" {
        auth := make(map[string]interface{})
        auth["method"] = context.AuthMethod
        
        switch context.AuthMethod {
        case "bearer":
            if token, exists := context.AuthDetails["token"]; exists {
                auth["token"] = rpb.redactPII(fmt.Sprintf("%v", token))
            }
        case "basic":
            if username, exists := context.AuthDetails["username"]; exists {
                auth["username"] = rpb.redactPII(fmt.Sprintf("%v", username))
            }
            auth["password"] = "[REDACTED]"
        case "cookie":
            if cookies, exists := context.BrowserSession["cookies"]; exists {
                auth["cookies"] = rpb.redactPII(fmt.Sprintf("%v", cookies))
            }
        }
        
        curlCmd["auth"] = auth
    }
    
    // Add data payload for POST/PUT requests
    if vector.Method == "POST" || vector.Method == "PUT" {
        if vector.Payload != "" {
            curlCmd["data"] = rpb.redactPII(vector.Payload)
        }
        
        if vector.ContentType != "" {
            if curlCmd["headers"] == nil {
                curlCmd["headers"] = make(map[string]string)
            }
            curlCmd["headers"].(map[string]string)["Content-Type"] = vector.ContentType
        }
    }
    
    // Add parameters
    if len(vector.ParamsShape) > 0 {
        params := make(map[string]interface{})
        for key, value := range vector.ParamsShape {
            params[key] = value
        }
        curlCmd["params"] = params
    }
    
    // Add metadata
    curlCmd["meta"] = map[string]interface{}{
        "vulnerability_type": vector.FindingID, // Will be populated with actual finding data
        "injection_point":    vector.InjectionPoint,
        "generated_at":       time.Now().Format(time.RFC3339),
    }
    
    return curlCmd, nil
}

func (rpb *ReproPackBuilder) generatePlaywrightScript(input ReproPackInput) (string, error) {
    if rpb.Templates["playwright"] == nil {
        return "", fmt.Errorf("playwright template not available")
    }
    
    filename := fmt.Sprintf("repro_%s_%d.js", input.Finding.ID, time.Now().Unix())
    filepath := filepath.Join(rpb.BlobStoragePath, "repro_scripts", filename)
    
    // Ensure directory exists
    if err := os.MkdirAll(filepath.Dir(filepath), 0755); err != nil {
        return "", err
    }
    
    // Prepare template data
    templateData := struct {
        Finding          Finding
        Vector           Vector
        Context          Context
        URL              string
        Method           string
        Payload          string
        SuccessPattern   string
        ErrorPattern     string
        TimeoutMs        int
    }{
        Finding:        input.Finding,
        Vector:         input.Vector,
        Context:        input.Context,
        URL:            input.Vector.URLTemplate,
        Method:         input.Vector.Method,
        Payload:        rpb.redactPII(input.Vector.Payload),
        SuccessPattern: rpb.getSuccessPattern(input.Finding.Category),
        ErrorPattern:   rpb.getErrorPattern(input.Finding.Category),
        TimeoutMs:      30000,
    }
    
    // Generate script
    file, err := os.Create(filepath)
    if err != nil {
        return "", err
    }
    defer file.Close()
    
    if err := rpb.Templates["playwright"].Execute(file, templateData); err != nil {
        return "", err
    }
    
    return filename, nil
}

func (rpb *ReproPackBuilder) extractHARSlice(evidence []EvidenceBlob, findingID string) (string, error) {
    // Find HAR evidence
    var harBlob *EvidenceBlob
    for _, blob := range evidence {
        if blob.Type == "har" {
            harBlob = &blob
            break
        }
    }
    
    if harBlob == nil {
        return "", fmt.Errorf("no HAR evidence found")
    }
    
    // Read original HAR file
    harPath := filepath.Join(rpb.BlobStoragePath, harBlob.Path)
    harData, err := ioutil.ReadFile(harPath)
    if err != nil {
        return "", err
    }
    
    // Parse HAR and extract relevant entries
    var har map[string]interface{}
    if err := json.Unmarshal(harData, &har); err != nil {
        return "", err
    }
    
    // Create minimal HAR slice
    harSlice := rpb.createMinimalHARSlice(har, findingID)
    
    // Apply PII redaction
    harSlice = rpb.redactPIIFromHAR(harSlice)
    
    // Save HAR slice
    sliceFilename := fmt.Sprintf("har_slice_%s_%d.har", findingID, time.Now().Unix())
    slicePath := filepath.Join(rpb.BlobStoragePath, "har_slices", sliceFilename)
    
    if err := os.MkdirAll(filepath.Dir(slicePath), 0755); err != nil {
        return "", err
    }
    
    sliceData, _ := json.MarshalIndent(harSlice, "", "  ")
    if err := ioutil.WriteFile(slicePath, sliceData, 0644); err != nil {
        return "", err
    }
    
    return sliceFilename, nil
}

func (rpb *ReproPackBuilder) createMinimalHARSlice(har map[string]interface{}, findingID string) map[string]interface{} {
    // Extract only relevant entries (this is a simplified implementation)
    slice := map[string]interface{}{
        "log": map[string]interface{}{
            "version": "1.2",
            "creator": map[string]interface{}{
                "name":    "Ars0n Framework",
                "version": "2.0",
            },
            "entries": []interface{}{},
        },
    }
    
    // In a real implementation, this would filter and extract
    // only the relevant HTTP requests/responses for the finding
    
    return slice
}

func (rpb *ReproPackBuilder) generateNotes(input ReproPackInput) string {
    notes := fmt.Sprintf("# Reproduction Instructions for %s\n\n", input.Finding.Title)
    notes += fmt.Sprintf("**Vulnerability Type:** %s\n", input.Finding.Category)
    notes += fmt.Sprintf("**Severity:** %s\n", input.Finding.Severity)
    notes += fmt.Sprintf("**Target URL:** %s\n\n", input.Vector.URLTemplate)
    
    notes += "## Summary\n"
    notes += fmt.Sprintf("This finding represents a %s vulnerability discovered during automated testing. ", input.Finding.Category)
    notes += "The vulnerability allows an attacker to potentially compromise the application's security.\n\n"
    
    notes += "## Reproduction Steps\n"
    notes += "1. Use the provided curl command to reproduce the basic vulnerability signal\n"
    notes += "2. If available, run the Playwright script for browser-based validation\n"
    notes += "3. Review the HAR file slice for detailed request/response information\n"
    notes += "4. Verify the success indicators mentioned below\n\n"
    
    if input.Vector.InjectionPoint != "" {
        notes += fmt.Sprintf("**Injection Point:** %s\n", input.Vector.InjectionPoint)
    }
    
    if input.Vector.Payload != "" {
        notes += fmt.Sprintf("**Payload:** %s\n", rpb.redactPII(input.Vector.Payload))
    }
    
    return notes
}

func (rpb *ReproPackBuilder) generatePrerequisites(input ReproPackInput) string {
    var prerequisites []string
    
    // Authentication prerequisites
    if input.Context.AuthMethod != "" && input.Context.AuthMethod != "none" {
        switch input.Context.AuthMethod {
        case "bearer":
            prerequisites = append(prerequisites, "Valid bearer token for authentication")
        case "basic":
            prerequisites = append(prerequisites, "Valid username and password for basic authentication")
        case "cookie":
            prerequisites = append(prerequisites, "Valid session cookies")
        }
    }
    
    // Identity prerequisites
    switch input.Context.Identity {
    case "admin":
        prerequisites = append(prerequisites, "Administrative privileges required")
    case "user":
        prerequisites = append(prerequisites, "Authenticated user session required")
    case "guest":
        prerequisites = append(prerequisites, "No authentication required (guest access)")
    }
    
    // Category-specific prerequisites
    switch input.Finding.Category {
    case "ssrf":
        prerequisites = append(prerequisites, "Target must be accessible from the vulnerable server")
    case "idor":
        prerequisites = append(prerequisites, "Knowledge of valid object IDs")
    case "file_upload":
        prerequisites = append(prerequisites, "Access to file upload functionality")
    case "xss":
        prerequisites = append(prerequisites, "User interaction may be required for stored XSS")
    }
    
    if len(prerequisites) == 0 {
        return "No specific prerequisites required."
    }
    
    return "- " + strings.Join(prerequisites, "\n- ")
}

func (rpb *ReproPackBuilder) generateSuccessIndicators(input ReproPackInput) string {
    var indicators []string
    
    // Category-specific success indicators
    switch input.Finding.Category {
    case "xss":
        indicators = append(indicators, "JavaScript execution in browser context")
        indicators = append(indicators, "Alert dialog or custom payload execution")
        indicators = append(indicators, "Reflected payload in HTTP response")
    case "ssrf":
        indicators = append(indicators, "Internal network requests visible in logs")
        indicators = append(indicators, "Response from internal/restricted endpoints")
        indicators = append(indicators, "DNS queries to controlled domain")
    case "idor":
        indicators = append(indicators, "Access to unauthorized data or resources")
        indicators = append(indicators, "Successful manipulation of object references")
        indicators = append(indicators, "Data belonging to other users returned")
    case "sqli":
        indicators = append(indicators, "Database error messages")
        indicators = append(indicators, "Time delays in response")
        indicators = append(indicators, "Data extraction successful")
    case "command_injection":
        indicators = append(indicators, "Command execution on target system")
        indicators = append(indicators, "System information disclosure")
        indicators = append(indicators, "File system access")
    default:
        indicators = append(indicators, "Unexpected application behavior")
        indicators = append(indicators, "Error messages indicating vulnerability")
    }
    
    // Response indicators from vector
    if len(input.Vector.ResponseIndicators) > 0 {
        for key, value := range input.Vector.ResponseIndicators {
            indicators = append(indicators, fmt.Sprintf("%s: %v", key, value))
        }
    }
    
    return "- " + strings.Join(indicators, "\n- ")
}

func (rpb *ReproPackBuilder) getSuccessPattern(category string) string {
    patterns := map[string]string{
        "xss":                `alert\(|<script|javascript:`,
        "ssrf":               `HTTP/1\.|curl:|wget:`,
        "idor":               `"id":|"user_id":|unauthorized`,
        "sqli":               `SQL|syntax error|mysql_`,
        "command_injection":  `uid=|gid=|/bin/|cmd.exe`,
        "file_upload":        `uploaded|file saved|upload successful`,
        "auth_bypass":        `admin|dashboard|unauthorized access`,
    }
    
    if pattern, exists := patterns[category]; exists {
        return pattern
    }
    return `error|vulnerability|exploit`
}

func (rpb *ReproPackBuilder) getErrorPattern(category string) string {
    return `error|exception|failed|denied|forbidden`
}

func (rpb *ReproPackBuilder) redactPII(text string) string {
    result := text
    
    for name, pattern := range rpb.PIIPatterns {
        result = pattern.ReplaceAllStringFunc(result, func(match string) string {
            return fmt.Sprintf("[REDACTED_%s]", strings.ToUpper(name))
        })
    }
    
    return result
}

func (rpb *ReproPackBuilder) redactPIIFromJSON(data map[string]interface{}) map[string]interface{} {
    result := make(map[string]interface{})
    
    for key, value := range data {
        switch v := value.(type) {
        case string:
            result[key] = rpb.redactPII(v)
        case map[string]interface{}:
            result[key] = rpb.redactPIIFromJSON(v)
        case map[string]string:
            redactedMap := make(map[string]string)
            for k, val := range v {
                redactedMap[k] = rpb.redactPII(val)
            }
            result[key] = redactedMap
        default:
            result[key] = value
        }
    }
    
    return result
}

func (rpb *ReproPackBuilder) redactPIIFromHAR(har map[string]interface{}) map[string]interface{} {
    // This would implement HAR-specific PII redaction
    // For now, return as-is (simplified implementation)
    return har
}

func (rpb *ReproPackBuilder) initializeTemplates() {
    // Playwright script template
    playwrightTemplate := `
const { chromium } = require('playwright');

async function reproduceVulnerability() {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    try {
        console.log('Reproducing vulnerability: {{.Finding.Title}}');
        console.log('Category: {{.Finding.Category}}');
        console.log('Target URL: {{.URL}}');
        
        // Navigate to target
        await page.goto('{{.URL}}', { waitUntil: 'networkidle' });
        
        {{if eq .Finding.Category "xss"}}
        // XSS reproduction
        const payload = '{{.Payload}}';
        await page.fill('input[type="text"], textarea', payload);
        await page.click('input[type="submit"], button[type="submit"]');
        
        // Wait for potential XSS execution
        await page.waitForTimeout(2000);
        
        // Check for success indicators
        const content = await page.content();
        if (content.includes('{{.SuccessPattern}}')) {
            console.log('SUCCESS: XSS vulnerability confirmed');
            return true;
        }
        {{end}}
        
        {{if eq .Finding.Category "idor"}}
        // IDOR reproduction
        const response = await page.request.{{.Method}}('{{.URL}}', {
            data: '{{.Payload}}'
        });
        
        const responseText = await response.text();
        if (responseText.includes('{{.SuccessPattern}}')) {
            console.log('SUCCESS: IDOR vulnerability confirmed');
            return true;
        }
        {{end}}
        
        {{if eq .Finding.Category "ssrf"}}
        // SSRF reproduction
        await page.fill('input[name*="url"], input[name*="link"]', '{{.Payload}}');
        await page.click('input[type="submit"], button[type="submit"]');
        
        await page.waitForTimeout(3000);
        
        const content = await page.content();
        if (content.includes('{{.SuccessPattern}}')) {
            console.log('SUCCESS: SSRF vulnerability confirmed');
            return true;
        }
        {{end}}
        
        console.log('FAILED: Vulnerability could not be reproduced');
        return false;
        
    } catch (error) {
        console.error('ERROR during reproduction:', error);
        return false;
    } finally {
        await browser.close();
    }
}

// Run the reproduction
reproduceVulnerability().then(success => {
    process.exit(success ? 0 : 1);
});
`
    
    tmpl, err := template.New("playwright").Parse(playwrightTemplate)
    if err != nil {
        log.Printf("[ERROR] Failed to parse Playwright template: %v", err)
    } else {
        rpb.Templates["playwright"] = tmpl
    }
}
```

### 4. Deduplication Logic

```go
// server/utils/deduplicationUtils.go
package utils

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sort"
    "strings"
    "context"
    "log"
)

type DeduplicationEngine struct {
    dbPool *pgxpool.Pool
}

func NewDeduplicationEngine(dbPool *pgxpool.Pool) *DeduplicationEngine {
    return &DeduplicationEngine{
        dbPool: dbPool,
    }
}

// Generate consistent key_hash for deduplication
// key_hash = hash(vuln_class, url_template, method, sorted(param_keys), identity, tenant)
func (de *DeduplicationEngine) GenerateKeyHash(finding CreateFindingRequest) string {
    var hashComponents []string
    
    // 1. Vulnerability class (category)
    hashComponents = append(hashComponents, finding.Category)
    
    // 2. URL template (if vector provided)
    if finding.Vector != nil {
        // Normalize URL template (remove dynamic parts)
        urlTemplate := de.normalizeURLTemplate(finding.Vector.URLTemplate)
        hashComponents = append(hashComponents, urlTemplate)
        
        // 3. HTTP method
        hashComponents = append(hashComponents, finding.Vector.Method)
        
        // 4. Sorted parameter keys
        var paramKeys []string
        for key := range finding.Vector.ParamsShape {
            paramKeys = append(paramKeys, key)
        }
        sort.Strings(paramKeys)
        for _, key := range paramKeys {
            hashComponents = append(hashComponents, key)
        }
    }
    
    // 5. Identity context
    if finding.Context != nil {
        hashComponents = append(hashComponents, finding.Context.Identity)
        
        // 6. Tenant (if multi-tenant)
        if finding.Context.Tenant != "" {
            hashComponents = append(hashComponents, finding.Context.Tenant)
        }
    }
    
    // Generate SHA256 hash
    combined := strings.Join(hashComponents, "|")
    h := sha256.New()
    h.Write([]byte(combined))
    
    keyHash := hex.EncodeToString(h.Sum(nil))
    
    log.Printf("[DEBUG] Generated key_hash for %s: %s (components: %v)", 
        finding.Category, keyHash[:16]+"...", hashComponents)
    
    return keyHash
}

// Normalize URL template to handle dynamic parameters
func (de *DeduplicationEngine) normalizeURLTemplate(url string) string {
    // Replace common dynamic parameters with placeholders
    normalized := url
    
    // Replace UUIDs with placeholder
    uuidPattern := `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
    normalized = regexp.MustCompile(uuidPattern).ReplaceAllString(normalized, "{UUID}")
    
    // Replace numeric IDs with placeholder
    numericIDPattern := `/\d+(?:/|$)`
    normalized = regexp.MustCompile(numericIDPattern).ReplaceAllString(normalized, "/{ID}/")
    
    // Replace common dynamic parameters
    dynamicParams := []string{
        `user_id=\d+`,
        `id=\d+`,
        `session=[a-zA-Z0-9]+`,
        `token=[a-zA-Z0-9]+`,
    }
    
    for _, pattern := range dynamicParams {
        re := regexp.MustCompile(pattern)
        normalized = re.ReplaceAllString(normalized, pattern[:strings.Index(pattern, "=")]+"={VALUE}")
    }
    
    return normalized
}

// Check for existing duplicates and similar findings
func (de *DeduplicationEngine) FindDuplicates(keyHash string) ([]Finding, error) {
    // Exact match by key_hash
    exactMatch, err := de.findExactDuplicate(keyHash)
    if err != nil {
        return nil, err
    }
    
    var duplicates []Finding
    if exactMatch != nil {
        duplicates = append(duplicates, *exactMatch)
    }
    
    // Find similar findings (fuzzy matching)
    similar, err := de.findSimilarFindings(keyHash)
    if err != nil {
        log.Printf("[ERROR] Failed to find similar findings: %v", err)
    } else {
        duplicates = append(duplicates, similar...)
    }
    
    return duplicates, nil
}

func (de *DeduplicationEngine) findExactDuplicate(keyHash string) (*Finding, error) {
    query := `
        SELECT id, key_hash, title, category, severity, signal, status,
               url_workflow_session_id, scope_target_id, kill_chain_score, metadata,
               created_at, updated_at
        FROM findings 
        WHERE key_hash = $1
        LIMIT 1
    `
    
    var finding Finding
    var signalJSON, metadataJSON []byte
    
    err := de.dbPool.QueryRow(context.Background(), query, keyHash).Scan(
        &finding.ID, &finding.KeyHash, &finding.Title, &finding.Category, &finding.Severity,
        &signalJSON, &finding.Status, &finding.URLWorkflowSessionID, &finding.ScopeTargetID,
        &finding.KillChainScore, &metadataJSON, &finding.CreatedAt, &finding.UpdatedAt)
    
    if err != nil {
        if err.Error() == "no rows in result set" {
            return nil, nil // No duplicate found
        }
        return nil, err
    }
    
    // Parse JSON fields
    json.Unmarshal(signalJSON, &finding.Signal)
    json.Unmarshal(metadataJSON, &finding.Metadata)
    
    return &finding, nil
}

func (de *DeduplicationEngine) findSimilarFindings(keyHash string) ([]Finding, error) {
    // Find findings with similar characteristics but different key_hash
    // This implements fuzzy matching based on category, URL patterns, etc.
    
    query := `
        SELECT id, key_hash, title, category, severity, signal, status,
               url_workflow_session_id, scope_target_id, kill_chain_score, metadata,
               created_at, updated_at
        FROM findings 
        WHERE key_hash != $1
          AND category = (SELECT category FROM findings WHERE key_hash = $1 LIMIT 1)
        ORDER BY created_at DESC
        LIMIT 10
    `
    
    rows, err := de.dbPool.Query(context.Background(), query, keyHash)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var similar []Finding
    for rows.Next() {
        var finding Finding
        var signalJSON, metadataJSON []byte
        
        err := rows.Scan(&finding.ID, &finding.KeyHash, &finding.Title, &finding.Category,
                        &finding.Severity, &signalJSON, &finding.Status, &finding.URLWorkflowSessionID,
                        &finding.ScopeTargetID, &finding.KillChainScore, &metadataJSON,
                        &finding.CreatedAt, &finding.UpdatedAt)
        if err != nil {
            continue
        }
        
        json.Unmarshal(signalJSON, &finding.Signal)
        json.Unmarshal(metadataJSON, &finding.Metadata)
        
        similar = append(similar, finding)
    }
    
    return similar, nil
}

// Merge duplicate findings
func (de *DeduplicationEngine) MergeDuplicateFindings(primaryID, duplicateID string) error {
    log.Printf("[INFO] Merging duplicate finding %s into primary %s", duplicateID, primaryID)
    
    tx, err := de.dbPool.Begin(context.Background())
    if err != nil {
        return err
    }
    defer tx.Rollback(context.Background())
    
    // Move all related records to primary finding
    tables := []string{"vectors", "evidence_blobs", "contexts", "repro_recipes", "oob_events"}
    
    for _, table := range tables {
        query := fmt.Sprintf("UPDATE %s SET finding_id = $1 WHERE finding_id = $2", table)
        _, err := tx.Exec(context.Background(), query, primaryID, duplicateID)
        if err != nil {
            log.Printf("[ERROR] Failed to update %s: %v", table, err)
            return err
        }
    }
    
    // Delete duplicate finding
    _, err = tx.Exec(context.Background(), "DELETE FROM findings WHERE id = $1", duplicateID)
    if err != nil {
        return err
    }
    
    return tx.Commit(context.Background())
}

// Calculate similarity score between findings
func (de *DeduplicationEngine) CalculateSimilarityScore(finding1, finding2 Finding) float64 {
    score := 0.0
    
    // Category match (high weight)
    if finding1.Category == finding2.Category {
        score += 0.4
    }
    
    // Severity match
    if finding1.Severity == finding2.Severity {
        score += 0.1
    }
    
    // URL similarity (if vectors available)
    if len(finding1.Vectors) > 0 && len(finding2.Vectors) > 0 {
        urlSimilarity := de.calculateURLSimilarity(finding1.Vectors[0].URLTemplate, finding2.Vectors[0].URLTemplate)
        score += urlSimilarity * 0.3
    }
    
    // Signal similarity
    signalSimilarity := de.calculateSignalSimilarity(finding1.Signal, finding2.Signal)
    score += signalSimilarity * 0.2
    
    return score
}

func (de *DeduplicationEngine) calculateURLSimilarity(url1, url2 string) float64 {
    // Simple URL similarity based on common path components
    path1 := strings.Split(url1, "/")
    path2 := strings.Split(url2, "/")
    
    commonParts := 0
    maxParts := len(path1)
    if len(path2) > maxParts {
        maxParts = len(path2)
    }
    
    minParts := len(path1)
    if len(path2) < minParts {
        minParts = len(path2)
    }
    
    for i := 0; i < minParts; i++ {
        if path1[i] == path2[i] {
            commonParts++
        }
    }
    
    if maxParts == 0 {
        return 0.0
    }
    
    return float64(commonParts) / float64(maxParts)
}

func (de *DeduplicationEngine) calculateSignalSimilarity(signal1, signal2 map[string]interface{}) float64 {
    // Simple signal similarity based on common keys
    commonKeys := 0
    totalKeys := 0
    
    keys1 := make(map[string]bool)
    for key := range signal1 {
        keys1[key] = true
        totalKeys++
    }
    
    for key := range signal2 {
        if !keys1[key] {
            totalKeys++
        } else {
            commonKeys++
        }
    }
    
    if totalKeys == 0 {
        return 0.0
    }
    
    return float64(commonKeys) / float64(totalKeys)
}

// Clean up old duplicate findings
func (de *DeduplicationEngine) CleanupOldDuplicates(olderThanDays int) error {
    query := `
        DELETE FROM findings 
        WHERE status = 'closed' 
          AND created_at < NOW() - INTERVAL '%d days'
          AND EXISTS (
              SELECT 1 FROM findings f2 
              WHERE f2.key_hash = findings.key_hash 
                AND f2.id != findings.id 
                AND f2.status != 'closed'
          )
    `
    
    result, err := de.dbPool.Exec(context.Background(), fmt.Sprintf(query, olderThanDays))
    if err != nil {
        return err
    }
    
    rowsAffected := result.RowsAffected()
    log.Printf("[INFO] Cleaned up %d old duplicate findings", rowsAffected)
    
    return nil
}
```

### 5. Definition of Done Implementation

```go
// server/tests/findings_pipeline_test.go
package tests

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestFindingsPipelineE2E(t *testing.T) {
    // Definition of Done Test:
    // Create 3 synthetic findings via test stub (XSS, IDOR, SSRF) → 
    // API shows them; export returns valid JSON; repro scripts run headless and reproduce the signal.
    
    // Setup test environment
    setupTestDB(t)
    defer cleanupTestDB(t)
    
    // Test synthetic findings
    findings := []CreateFindingRequest{
        createSyntheticXSSFinding(t),
        createSyntheticIDORFinding(t),
        createSyntheticSSRFFinding(t),
    }
    
    var findingIDs []string
    
    // 1. Create findings via API
    for i, finding := range findings {
        t.Run(fmt.Sprintf("CreateFinding_%d_%s", i+1, finding.Category), func(t *testing.T) {
            // Create finding via API
            findingJSON, _ := json.Marshal(finding)
            req := httptest.NewRequest("POST", "/api/findings", strings.NewReader(string(findingJSON)))
            req.Header.Set("Content-Type", "application/json")
            
            w := httptest.NewRecorder()
            CreateOrUpdateFinding(w, req)
            
            // Verify creation
            assert.Equal(t, http.StatusOK, w.Code)
            
            var response Finding
            err := json.NewDecoder(w.Body).Decode(&response)
            require.NoError(t, err)
            
            assert.Equal(t, finding.Category, response.Category)
            assert.Equal(t, finding.Severity, response.Severity)
            assert.Equal(t, "open", response.Status)
            
            findingIDs = append(findingIDs, response.ID)
        })
    }
    
    // 2. Verify API shows all findings
    t.Run("VerifyFindingsVisible", func(t *testing.T) {
        req := httptest.NewRequest("GET", "/api/findings", nil)
        w := httptest.NewRecorder()
        ListFindings(w, req)
        
        assert.Equal(t, http.StatusOK, w.Code)
        
        var foundFindings []Finding
        err := json.NewDecoder(w.Body).Decode(&foundFindings)
        require.NoError(t, err)
        
        assert.GreaterOrEqual(t, len(foundFindings), 3)
        
        // Verify each synthetic finding is present
        categories := make(map[string]bool)
        for _, finding := range foundFindings {
            categories[finding.Category] = true
        }
        
        assert.True(t, categories["xss"])
        assert.True(t, categories["idor"])
        assert.True(t, categories["ssrf"])
    })
    
    // 3. Test export functionality
    t.Run("TestExportValidJSON", func(t *testing.T) {
        req := httptest.NewRequest("GET", "/api/findings/export?format=json", nil)
        w := httptest.NewRecorder()
        ExportFindings(w, req)
        
        assert.Equal(t, http.StatusOK, w.Code)
        
        var exportResponse ExportFindingsResponse
        err := json.NewDecoder(w.Body).Decode(&exportResponse)
        require.NoError(t, err)
        
        assert.GreaterOrEqual(t, exportResponse.Meta.Total, 3)
        assert.Equal(t, "json", exportResponse.Meta.Format)
        assert.WithinDuration(t, time.Now(), exportResponse.Meta.ExportedAt, time.Minute)
        
        // Verify export contains our synthetic findings
        exportedCategories := make(map[string]bool)
        for _, finding := range exportResponse.Findings {
            exportedCategories[finding.Category] = true
        }
        
        assert.True(t, exportedCategories["xss"])
        assert.True(t, exportedCategories["idor"])
        assert.True(t, exportedCategories["ssrf"])
    })
    
    // 4. Test reproduction pack generation and execution
    t.Run("TestReproPacksGeneration", func(t *testing.T) {
        rpb := NewReproPackBuilder("/tmp/test_blobs")
        
        for i, findingID := range findingIDs {
            // Get finding with full details
            finding, err := getFindingByID(findingID)
            require.NoError(t, err)
            
            // Load relations
            err = loadFindingRelations(finding)
            require.NoError(t, err)
            
            // Generate repro pack
            input := ReproPackInput{
                Finding: *finding,
            }
            
            if len(finding.Vectors) > 0 {
                input.Vector = finding.Vectors[0]
            }
            if len(finding.Contexts) > 0 {
                input.Context = finding.Contexts[0]
            }
            
            reproPack, err := rpb.GenerateReproPack(input)
            require.NoError(t, err)
            
            // Verify repro pack structure
            assert.NotEmpty(t, reproPack.CurlJSON)
            assert.NotEmpty(t, reproPack.Notes)
            assert.NotEmpty(t, reproPack.SuccessIndicators)
            
            // Test curl command structure
            assert.Contains(t, reproPack.CurlJSON, "url")
            assert.Contains(t, reproPack.CurlJSON, "method")
            
            t.Logf("Generated repro pack for finding %d (%s)", i+1, finding.Category)
        }
    })
    
    // 5. Test deduplication logic
    t.Run("TestDeduplication", func(t *testing.T) {
        de := NewDeduplicationEngine(dbPool)
        
        // Create duplicate XSS finding
        duplicateXSS := createSyntheticXSSFinding(t)
        keyHash := de.GenerateKeyHash(duplicateXSS)
        
        // Check for duplicates
        duplicates, err := de.FindDuplicates(keyHash)
        require.NoError(t, err)
        
        // Should find at least one duplicate (our original XSS)
        assert.GreaterOrEqual(t, len(duplicates), 1)
        
        // Verify duplicate has same category
        found := false
        for _, dup := range duplicates {
            if dup.Category == "xss" {
                found = true
                break
            }
        }
        assert.True(t, found, "Should find duplicate XSS finding")
    })
    
    // 6. Test status updates
    t.Run("TestStatusUpdates", func(t *testing.T) {
        for i, findingID := range findingIDs {
            // Update status to confirmed
            statusUpdate := UpdateFindingStatusRequest{
                Status: "confirmed",
                Notes:  fmt.Sprintf("Test confirmation for finding %d", i+1),
            }
            
            statusJSON, _ := json.Marshal(statusUpdate)
            req := httptest.NewRequest("POST", fmt.Sprintf("/api/findings/%s/status", findingID), 
                                     strings.NewReader(string(statusJSON)))
            req.Header.Set("Content-Type", "application/json")
            
            w := httptest.NewRecorder()
            UpdateFindingStatus(w, req)
            
            assert.Equal(t, http.StatusOK, w.Code)
            
            // Verify status was updated
            finding, err := getFindingByID(findingID)
            require.NoError(t, err)
            assert.Equal(t, "confirmed", finding.Status)
        }
    })
}

// Helper functions for creating synthetic findings
func createSyntheticXSSFinding(t *testing.T) CreateFindingRequest {
    return CreateFindingRequest{
        Title:                "Reflected XSS in search parameter",
        Category:             "xss",
        Severity:             "high",
        URLWorkflowSessionID: "test-session-1",
        ScopeTargetID:        "test-scope-1",
        Signal: map[string]interface{}{
            "payload":         "<script>alert('xss')</script>",
            "reflection_point": "search parameter",
            "method":          "GET",
        },
        Vector: &Vector{
            Method:      "GET",
            URLTemplate: "https://example.com/search?q={XSS_PAYLOAD}",
            ParamsShape: map[string]interface{}{
                "q": "string",
            },
            InjectionPoint: "query_parameter",
            Payload:       "<script>alert('xss')</script>",
            ResponseIndicators: map[string]interface{}{
                "contains": "<script>alert('xss')</script>",
            },
        },
        Context: &Context{
            Identity:   "guest",
            AuthMethod: "none",
            UserAgent:  "Mozilla/5.0 (Test Agent)",
        },
        Metadata: map[string]interface{}{
            "test_case": "synthetic_xss",
        },
    }
}

func createSyntheticIDORFinding(t *testing.T) CreateFindingRequest {
    return CreateFindingRequest{
        Title:                "IDOR in user profile access",
        Category:             "idor",
        Severity:             "medium",
        URLWorkflowSessionID: "test-session-1",
        ScopeTargetID:        "test-scope-1",
        Signal: map[string]interface{}{
            "unauthorized_access": true,
            "user_id":            "123",
            "accessed_user_id":   "456",
        },
        Vector: &Vector{
            Method:      "GET",
            URLTemplate: "https://example.com/api/users/{USER_ID}/profile",
            ParamsShape: map[string]interface{}{
                "user_id": "integer",
            },
            InjectionPoint: "path_parameter",
            Payload:       "456",
            ResponseIndicators: map[string]interface{}{
                "status_code": 200,
                "contains":    "user_id",
            },
        },
        Context: &Context{
            Identity:   "user",
            AuthMethod: "bearer",
            AuthDetails: map[string]interface{}{
                "user_id": "123",
            },
        },
        Metadata: map[string]interface{}{
            "test_case": "synthetic_idor",
        },
    }
}

func createSyntheticSSRFFinding(t *testing.T) CreateFindingRequest {
    return CreateFindingRequest{
        Title:                "SSRF via URL parameter",
        Category:             "ssrf",
        Severity:             "high",
        URLWorkflowSessionID: "test-session-1",
        ScopeTargetID:        "test-scope-1",
        Signal: map[string]interface{}{
            "internal_request": true,
            "target_url":      "http://169.254.169.254/metadata",
            "response_code":   200,
        },
        Vector: &Vector{
            Method:      "POST",
            URLTemplate: "https://example.com/api/fetch",
            ParamsShape: map[string]interface{}{
                "url": "string",
            },
            HeadersShape: map[string]interface{}{
                "Content-Type": "application/json",
            },
            ContentType:    "application/json",
            InjectionPoint: "post_parameter",
            Payload:       "http://169.254.169.254/metadata",
            ResponseIndicators: map[string]interface{}{
                "contains": "instance-id",
            },
        },
        Context: &Context{
            Identity:   "user",
            AuthMethod: "cookie",
            BrowserSession: map[string]interface{}{
                "session_id": "test-session-123",
            },
        },
        Metadata: map[string]interface{}{
            "test_case": "synthetic_ssrf",
        },
    }
}

func setupTestDB(t *testing.T) {
    // Setup test database connection and schema
    // This would create test tables and initialize the database pool
}

func cleanupTestDB(t *testing.T) {
    // Clean up test database
}
```

## Non-negotiables Implementation

### Rate Limits & Scope Guard
```go
// server/utils/rateLimitUtils.go (integrated with existing architecture)
// Already designed in previous artifacts - integrated with Redis and existing Go patterns

// server/utils/scopeGuardUtils.go (leverages existing scope validation)
// Extends existing scope validation logic in server/utils/scopeTargetUtils.go
```

### Artifacts Storage
```go
// Evidence storage integrated with existing blob storage patterns
// Uses filesystem storage with optional S3 backend
// HAR, screenshot, DOM snapshot storage for each finding
```

This Evidence & Findings Pipeline provides a comprehensive foundation for collecting, deduplicating, and replaying every probe in the Ars0n Framework, fully integrated with the existing Go backend architecture and PostgreSQL database.
