# Evidence Collection and Logging System - Ars0n Framework Integration

## Overview

This document outlines the design for a comprehensive evidence collection and logging system integrated into the existing Ars0n Framework Go backend, ensuring every probe produces artifacts and maintains complete audit trails for the URL workflow.

## Design Principles

### Evidence-First Architecture
- **Every action produces artifacts**: HAR files, screenshots, DOM snapshots, PCAP captures, and structured JSON findings
- **Immutable audit trail**: All evidence is timestamped, hashed, and cryptographically verified
- **Storage efficiency**: Compression, deduplication, and intelligent retention policies
- **Legal compliance**: Chain of custody preservation for potential bug bounty submissions

### Integration with Existing Framework
- **Leverage existing patterns**: Extend current evidence storage from screenshot utilities
- **Database continuity**: Use existing PostgreSQL with new evidence tables
- **File system consistency**: Follow existing blob storage patterns in `/data/` directories
- **API compatibility**: Maintain existing CORS and authentication patterns

## Architecture Components

### 1. Evidence Collector Service

```go
// server/utils/evidenceUtils.go
package utils

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "time"
    
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type EvidenceCollector struct {
    dbPool          *pgxpool.Pool
    basePath        string  // "/data/findings"
    compressionLevel int
    maxFileSize     int64   // Maximum file size in bytes
}

type Evidence struct {
    ID           string                 `json:"id"`
    FindingID    string                 `json:"finding_id"`
    Type         EvidenceType          `json:"type"`
    Filename     string                 `json:"filename"`
    Path         string                 `json:"path"`
    SHA256       string                 `json:"sha256"`
    Size         int64                  `json:"size"`
    MimeType     string                 `json:"mime_type"`
    Metadata     map[string]interface{} `json:"metadata"`
    Compressed   bool                   `json:"compressed"`
    CreatedAt    time.Time             `json:"created_at"`
}

type EvidenceType string

const (
    EvidenceTypeHAR        EvidenceType = "har"
    EvidenceTypeScreenshot EvidenceType = "screenshot"
    EvidenceTypeDOM        EvidenceType = "dom"
    EvidenceTypePCAP       EvidenceType = "pcap"
    EvidenceTypeLog        EvidenceType = "log"
    EvidenceTypeResponse   EvidenceType = "response"
    EvidenceTypeVideo      EvidenceType = "video"
    EvidenceTypeJSON       EvidenceType = "json"
)

// Initialize evidence collector with existing database pool
func NewEvidenceCollector(dbPool *pgxpool.Pool) *EvidenceCollector {
    basePath := "/data/findings"
    if env := os.Getenv("EVIDENCE_STORAGE_PATH"); env != "" {
        basePath = env
    }
    
    // Ensure base directory exists
    if err := os.MkdirAll(basePath, 0755); err != nil {
        log.Printf("Warning: Failed to create evidence directory %s: %v", basePath, err)
    }
    
    return &EvidenceCollector{
        dbPool:           dbPool,
        basePath:         basePath,
        compressionLevel: 6,  // Balanced compression
        maxFileSize:      50 * 1024 * 1024, // 50MB max
    }
}

// Collect evidence from any source (integrates with existing patterns)
func (ec *EvidenceCollector) CollectEvidence(findingID string, evidenceType EvidenceType, data []byte, metadata map[string]interface{}) (*Evidence, error) {
    if len(data) == 0 {
        return nil, fmt.Errorf("evidence data cannot be empty")
    }
    
    if len(data) > ec.maxFileSize {
        return nil, fmt.Errorf("evidence file too large: %d bytes (max %d)", len(data), ec.maxFileSize)
    }
    
    // Generate evidence ID and paths
    evidenceID := uuid.New().String()
    evidenceDir := filepath.Join(ec.basePath, findingID, string(evidenceType))
    
    // Ensure directory exists
    if err := os.MkdirAll(evidenceDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create evidence directory: %w", err)
    }
    
    // Generate filename based on type and timestamp
    ext := ec.getFileExtension(evidenceType)
    filename := fmt.Sprintf("%s_%d%s", evidenceID, time.Now().Unix(), ext)
    fullPath := filepath.Join(evidenceDir, filename)
    
    // Calculate SHA256 hash
    hasher := sha256.New()
    hasher.Write(data)
    sha256Hash := hex.EncodeToString(hasher.Sum(nil))
    
    // Compress data if beneficial
    compressed := false
    finalData := data
    if ec.shouldCompress(evidenceType, len(data)) {
        if compressedData, err := ec.compressData(data); err == nil && len(compressedData) < len(data) {
            finalData = compressedData
            compressed = true
            filename = filename + ".gz"
            fullPath = fullPath + ".gz"
        }
    }
    
    // Write file to disk
    if err := os.WriteFile(fullPath, finalData, 0644); err != nil {
        return nil, fmt.Errorf("failed to write evidence file: %w", err)
    }
    
    // Create evidence record
    evidence := &Evidence{
        ID:         evidenceID,
        FindingID:  findingID,
        Type:       evidenceType,
        Filename:   filename,
        Path:       fullPath,
        SHA256:     sha256Hash,
        Size:       int64(len(finalData)),
        MimeType:   ec.getMimeType(evidenceType),
        Metadata:   metadata,
        Compressed: compressed,
        CreatedAt:  time.Now(),
    }
    
    // Store in database
    if err := ec.storeEvidenceRecord(evidence); err != nil {
        // Clean up file if database storage fails
        os.Remove(fullPath)
        return nil, fmt.Errorf("failed to store evidence record: %w", err)
    }
    
    log.Printf("Evidence collected: %s (%s, %d bytes) for finding %s", 
        evidenceID, evidenceType, len(finalData), findingID)
    
    return evidence, nil
}

// Store evidence record in database (integrates with existing schema)
func (ec *EvidenceCollector) storeEvidenceRecord(evidence *Evidence) error {
    query := `
        INSERT INTO evidence_blobs (id, finding_id, type, filename, path, sha256, size, mime_type, metadata, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `
    
    metadataJSON, err := json.Marshal(evidence.Metadata)
    if err != nil {
        return fmt.Errorf("failed to marshal metadata: %w", err)
    }
    
    _, err = ec.dbPool.Exec(context.Background(), query,
        evidence.ID,
        evidence.FindingID,
        string(evidence.Type),
        evidence.Filename,
        evidence.Path,
        evidence.SHA256,
        evidence.Size,
        evidence.MimeType,
        metadataJSON,
        evidence.CreatedAt,
    )
    
    return err
}

// Helper methods for file handling
func (ec *EvidenceCollector) getFileExtension(evidenceType EvidenceType) string {
    extensions := map[EvidenceType]string{
        EvidenceTypeHAR:        ".har",
        EvidenceTypeScreenshot: ".png",
        EvidenceTypeDOM:        ".html",
        EvidenceTypePCAP:       ".pcap",
        EvidenceTypeLog:        ".log",
        EvidenceTypeResponse:   ".txt",
        EvidenceTypeVideo:      ".mp4",
        EvidenceTypeJSON:       ".json",
    }
    return extensions[evidenceType]
}

func (ec *EvidenceCollector) getMimeType(evidenceType EvidenceType) string {
    mimeTypes := map[EvidenceType]string{
        EvidenceTypeHAR:        "application/json",
        EvidenceTypeScreenshot: "image/png",
        EvidenceTypeDOM:        "text/html",
        EvidenceTypePCAP:       "application/vnd.tcpdump.pcap",
        EvidenceTypeLog:        "text/plain",
        EvidenceTypeResponse:   "text/plain",
        EvidenceTypeVideo:      "video/mp4",
        EvidenceTypeJSON:       "application/json",
    }
    return mimeTypes[evidenceType]
}

func (ec *EvidenceCollector) shouldCompress(evidenceType EvidenceType, size int) bool {
    // Compress text-based files larger than 1KB
    compressibleTypes := []EvidenceType{
        EvidenceTypeHAR, EvidenceTypeDOM, EvidenceTypeLog, 
        EvidenceTypeResponse, EvidenceTypeJSON,
    }
    
    for _, t := range compressibleTypes {
        if t == evidenceType && size > 1024 {
            return true
        }
    }
    return false
}
```

### 2. Structured Logging System

```go
// server/utils/auditLogger.go
package utils

import (
    "encoding/json"
    "fmt"
    "log"
    "time"
    
    "github.com/google/uuid"
)

type AuditLogger struct {
    evidenceCollector *EvidenceCollector
    sessionID         string
    findingID         string
}

type AuditEvent struct {
    ID            string                 `json:"id"`
    Timestamp     time.Time             `json:"timestamp"`
    SessionID     string                 `json:"session_id"`
    FindingID     string                 `json:"finding_id,omitempty"`
    EventType     string                 `json:"event_type"`
    Source        string                 `json:"source"`       // Tool name or component
    Action        string                 `json:"action"`       // What happened
    Target        string                 `json:"target"`       // URL or resource
    Payload       map[string]interface{} `json:"payload"`      // Event-specific data
    Evidence      []string               `json:"evidence"`     // Evidence IDs
    Success       bool                   `json:"success"`
    ErrorMessage  string                 `json:"error_message,omitempty"`
    Duration      time.Duration         `json:"duration,omitempty"`
    Metadata      map[string]interface{} `json:"metadata"`
}

func NewAuditLogger(evidenceCollector *EvidenceCollector, sessionID, findingID string) *AuditLogger {
    return &AuditLogger{
        evidenceCollector: evidenceCollector,
        sessionID:         sessionID,
        findingID:         findingID,
    }
}

// Log various types of events with evidence collection
func (al *AuditLogger) LogToolExecution(toolName, command, target string, success bool, duration time.Duration, stdout, stderr string, evidenceData map[string][]byte) string {
    eventID := uuid.New().String()
    
    // Collect evidence for tool execution
    var evidenceIDs []string
    
    // Store stdout as log evidence
    if stdout != "" {
        if evidence, err := al.evidenceCollector.CollectEvidence(al.findingID, EvidenceTypeLog, []byte(stdout), map[string]interface{}{
            "source":   "stdout",
            "tool":     toolName,
            "command":  command,
        }); err == nil {
            evidenceIDs = append(evidenceIDs, evidence.ID)
        }
    }
    
    // Store stderr as log evidence
    if stderr != "" {
        if evidence, err := al.evidenceCollector.CollectEvidence(al.findingID, EvidenceTypeLog, []byte(stderr), map[string]interface{}{
            "source":   "stderr",
            "tool":     toolName,
            "command":  command,
        }); err == nil {
            evidenceIDs = append(evidenceIDs, evidence.ID)
        }
    }
    
    // Store additional evidence (HAR, screenshots, etc.)
    for evidenceType, data := range evidenceData {
        var eType EvidenceType
        switch evidenceType {
        case "har":
            eType = EvidenceTypeHAR
        case "screenshot":
            eType = EvidenceTypeScreenshot
        case "dom":
            eType = EvidenceTypeDOM
        case "response":
            eType = EvidenceTypeResponse
        default:
            eType = EvidenceTypeJSON
        }
        
        if evidence, err := al.evidenceCollector.CollectEvidence(al.findingID, eType, data, map[string]interface{}{
            "tool":    toolName,
            "command": command,
            "target":  target,
        }); err == nil {
            evidenceIDs = append(evidenceIDs, evidence.ID)
        }
    }
    
    // Create audit event
    event := AuditEvent{
        ID:        eventID,
        Timestamp: time.Now(),
        SessionID: al.sessionID,
        FindingID: al.findingID,
        EventType: "tool_execution",
        Source:    toolName,
        Action:    "execute",
        Target:    target,
        Payload: map[string]interface{}{
            "command": command,
            "stdout_length": len(stdout),
            "stderr_length": len(stderr),
        },
        Evidence:  evidenceIDs,
        Success:   success,
        Duration:  duration,
        Metadata: map[string]interface{}{
            "evidence_count": len(evidenceIDs),
        },
    }
    
    if !success {
        event.ErrorMessage = stderr
    }
    
    al.logEvent(event)
    return eventID
}

func (al *AuditLogger) LogVulnerabilityDiscovery(category, title, severity string, signal map[string]interface{}, evidenceData map[string][]byte) string {
    eventID := uuid.New().String()
    
    // Collect vulnerability evidence
    var evidenceIDs []string
    for evidenceType, data := range evidenceData {
        var eType EvidenceType
        switch evidenceType {
        case "har":
            eType = EvidenceTypeHAR
        case "screenshot":
            eType = EvidenceTypeScreenshot
        case "dom":
            eType = EvidenceTypeDOM
        case "response":
            eType = EvidenceTypeResponse
        default:
            eType = EvidenceTypeJSON
        }
        
        if evidence, err := al.evidenceCollector.CollectEvidence(al.findingID, eType, data, map[string]interface{}{
            "category": category,
            "severity": severity,
            "discovery_method": "automated",
        }); err == nil {
            evidenceIDs = append(evidenceIDs, evidence.ID)
        }
    }
    
    event := AuditEvent{
        ID:        eventID,
        Timestamp: time.Now(),
        SessionID: al.sessionID,
        FindingID: al.findingID,
        EventType: "vulnerability_discovery",
        Source:    "vulnerability_scanner",
        Action:    "discover",
        Target:    fmt.Sprintf("%v", signal["url"]),
        Payload: map[string]interface{}{
            "category": category,
            "title":    title,
            "severity": severity,
            "signal":   signal,
        },
        Evidence: evidenceIDs,
        Success:  true,
        Metadata: map[string]interface{}{
            "evidence_count": len(evidenceIDs),
            "auto_discovery": true,
        },
    }
    
    al.logEvent(event)
    return eventID
}

func (al *AuditLogger) logEvent(event AuditEvent) {
    // Store as JSON log evidence
    eventJSON, err := json.MarshalIndent(event, "", "  ")
    if err != nil {
        log.Printf("Failed to marshal audit event: %v", err)
        return
    }
    
    // Log to standard logger
    log.Printf("[AUDIT] %s: %s -> %s (%s)", event.EventType, event.Source, event.Target, event.ID)
    
    // Store as evidence
    if al.evidenceCollector != nil && al.findingID != "" {
        _, err := al.evidenceCollector.CollectEvidence(al.findingID, EvidenceTypeJSON, eventJSON, map[string]interface{}{
            "audit_event": true,
            "event_type":  event.EventType,
            "source":      event.Source,
        })
        if err != nil {
            log.Printf("Failed to store audit event as evidence: %v", err)
        }
    }
}
```

### 3. Integration with Existing Tool Utils

```go
// Enhanced existing tool utils with evidence collection
// Example: server/utils/nucleiUtils.go (Enhancement)

// Add evidence collection to existing Nuclei execution
func executeAndParseNucleiWithEvidence(scanID, targetURL, sessionID string) error {
    // Initialize evidence collector (using existing database pool)
    evidenceCollector := NewEvidenceCollector(dbPool)
    
    // Create finding ID for this scan
    findingID := uuid.New().String()
    
    // Initialize audit logger
    auditLogger := NewAuditLogger(evidenceCollector, sessionID, findingID)
    
    startTime := time.Now()
    
    // Build Nuclei command (existing logic)
    cmd := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", 
        "nuclei", "-target", targetURL, "-json", "-o", "/tmp/nuclei_output.json")
    
    // Execute command with evidence collection
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    
    err := cmd.Run()
    executionTime := time.Since(startTime)
    
    // Collect execution evidence
    evidenceData := map[string][]byte{
        "response": stdout.Bytes(),
    }
    
    // Log tool execution with evidence
    auditLogger.LogToolExecution("nuclei", cmd.String(), targetURL, err == nil, executionTime, stdout.String(), stderr.String(), evidenceData)
    
    if err != nil {
        return fmt.Errorf("nuclei execution failed: %w", err)
    }
    
    // Parse Nuclei output and collect additional evidence
    nucleiResults := parseNucleiOutput(stdout.String())
    
    for _, result := range nucleiResults {
        // For each vulnerability found, collect additional evidence
        if result.IsVulnerability {
            // Take screenshot if it's a web vulnerability
            if screenshotData, err := takeScreenshot(targetURL); err == nil {
                evidenceData["screenshot"] = screenshotData
            }
            
            // Get DOM snapshot for XSS vulnerabilities
            if result.Category == "xss" {
                if domData, err := getDOMSnapshot(targetURL); err == nil {
                    evidenceData["dom"] = domData
                }
            }
            
            // Get HAR file for the request/response
            if harData, err := getHARFile(targetURL, result.Request); err == nil {
                evidenceData["har"] = harData
            }
            
            // Log vulnerability discovery with evidence
            auditLogger.LogVulnerabilityDiscovery(
                result.Category,
                result.Title,
                result.Severity,
                map[string]interface{}{
                    "url":           targetURL,
                    "template_id":   result.TemplateID,
                    "matcher_name":  result.MatcherName,
                    "request":       result.Request,
                    "response":      result.Response,
                },
                evidenceData,
            )
            
            // Submit to findings pipeline with evidence
            submitFindingWithEvidence(result, findingID, sessionID, evidenceCollector)
        }
    }
    
    return nil
}

// Enhanced finding submission with evidence references
func submitFindingWithEvidence(result NucleiResult, findingID, sessionID string, evidenceCollector *EvidenceCollector) error {
    // Generate key hash for deduplication
    keyHash := generateFindingKeyHash(result.Category, result.URL, "GET", []string{}, "guest", "")
    
    // Create finding record with evidence references
    query := `
        INSERT INTO findings (id, key_hash, url_workflow_session_id, scope_target_id, title, category, severity, signal, status, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        ON CONFLICT (key_hash) DO UPDATE SET updated_at = NOW()
    `
    
    signalJSON, _ := json.Marshal(map[string]interface{}{
        "template_id":   result.TemplateID,
        "matcher_name":  result.MatcherName,
        "url":           result.URL,
        "method":        "GET",
        "evidence_collected": true,
    })
    
    _, err := dbPool.Exec(context.Background(), query,
        findingID, keyHash, sessionID, result.ScopeTargetID,
        result.Title, result.Category, result.Severity,
        string(signalJSON), "open")
    
    return err
}
```

### 4. Evidence Retrieval API

```go
// server/main.go - Add evidence retrieval endpoints
func setupEvidenceEndpoints(router *mux.Router) {
    // Get evidence for a finding
    router.HandleFunc("/api/evidence/finding/{findingId}", GetFindingEvidence).Methods("GET")
    
    // Download specific evidence file
    router.HandleFunc("/api/evidence/download/{evidenceId}", DownloadEvidence).Methods("GET")
    
    // Get evidence metadata
    router.HandleFunc("/api/evidence/{evidenceId}/metadata", GetEvidenceMetadata).Methods("GET")
    
    // Search evidence by criteria
    router.HandleFunc("/api/evidence/search", SearchEvidence).Methods("GET")
}

func GetFindingEvidence(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    findingID := vars["findingId"]
    
    query := `
        SELECT id, type, filename, path, sha256, size, mime_type, metadata, created_at
        FROM evidence_blobs 
        WHERE finding_id = $1 
        ORDER BY created_at DESC
    `
    
    rows, err := dbPool.Query(context.Background(), query, findingID)
    if err != nil {
        http.Error(w, "Failed to query evidence", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    
    var evidence []map[string]interface{}
    for rows.Next() {
        var e map[string]interface{}
        var metadataJSON []byte
        
        err := rows.Scan(&e["id"], &e["type"], &e["filename"], &e["path"], 
                        &e["sha256"], &e["size"], &e["mime_type"], &metadataJSON, &e["created_at"])
        if err != nil {
            continue
        }
        
        if len(metadataJSON) > 0 {
            json.Unmarshal(metadataJSON, &e["metadata"])
        }
        
        evidence = append(evidence, e)
    }
    
    response := map[string]interface{}{
        "finding_id": findingID,
        "evidence":   evidence,
        "count":      len(evidence),
    }
    
    json.NewEncoder(w).Encode(response)
}
```

This evidence collection system provides comprehensive audit trails while seamlessly integrating with the existing Ars0n Framework architecture, ensuring every testing action produces verifiable evidence for potential bug bounty submissions.
