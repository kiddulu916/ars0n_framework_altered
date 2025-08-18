# Out-of-Band (OOB) Interaction Server Integration Design - Ars0n Framework

## Overview

This document outlines the integration of an Out-of-Band (OOB) interaction server into the existing Ars0n Framework containerized architecture. The OOB server enables detection of blind vulnerabilities (SSRF, XXE, Blind XSS, DNS exfiltration) by providing a reliable external interaction endpoint that can be monitored for incoming requests.

## OOB Interaction Philosophy

### Core Concepts
- **Blind Vulnerability Detection**: Identify vulnerabilities that don't produce visible output in responses
- **External Validation**: Use controlled external endpoints to confirm exploitation
- **Multi-Protocol Support**: Handle HTTP, DNS, SMTP, and other protocol interactions
- **Token-Based Tracking**: Unique tokens link interactions back to specific tests
- **Evidence Collection**: Comprehensive logging of all interaction attempts

### Common OOB Use Cases
```
SSRF Testing → HTTP/HTTPS requests to OOB server
DNS Exfiltration → DNS queries to OOB subdomain  
Blind XSS → JavaScript callbacks to OOB endpoint
XXE Attacks → XML external entity requests to OOB server
Time-Based Attacks → Delayed responses via OOB validation
Command Injection → Curl/wget callbacks to OOB server
```

## Architecture Integration

### 1. OOB Server Core Implementation

```go
// server/utils/oobServer.go
package utils

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"
    
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/miekg/dns"
)

type OOBInteractionServer struct {
    dbPool           *pgxpool.Pool
    httpServer       *http.Server
    dnsServer        *dns.Server
    domain           string  // OOB domain (e.g., oob.ars0n.local)
    httpPort         int     // HTTP server port (default: 8080)
    dnsPort          int     // DNS server port (default: 53)
    interactions     map[string]*OOBInteraction
    interactionMutex sync.RWMutex
    evidenceCollector *EvidenceCollector
}

type OOBInteraction struct {
    ID            string                 `json:"id"`
    Token         string                 `json:"token"`
    FindingID     string                 `json:"finding_id"`
    SessionID     string                 `json:"session_id"`
    Protocol      string                 `json:"protocol"`    // 'http', 'dns', 'smtp'
    SourceIP      string                 `json:"source_ip"`
    RequestData   map[string]interface{} `json:"request_data"`
    UserAgent     string                 `json:"user_agent"`
    Timestamp     time.Time             `json:"timestamp"`
    Validated     bool                   `json:"validated"`
    TestContext   map[string]interface{} `json:"test_context"`
}

type OOBTest struct {
    ID          string                 `json:"id"`
    Token       string                 `json:"token"`
    TestType    string                 `json:"test_type"`    // 'ssrf', 'xss', 'xxe', 'dns_exfil'
    TargetURL   string                 `json:"target_url"`
    Payload     string                 `json:"payload"`
    ExpectedProtocol string            `json:"expected_protocol"`
    CreatedAt   time.Time             `json:"created_at"`
    ExpiresAt   time.Time             `json:"expires_at"`
    Metadata    map[string]interface{} `json:"metadata"`
}

func NewOOBInteractionServer(dbPool *pgxpool.Pool, domain string) *OOBInteractionServer {
    return &OOBInteractionServer{
        dbPool:           dbPool,
        domain:           domain,
        httpPort:         8080,
        dnsPort:          53,
        interactions:     make(map[string]*OOBInteraction),
        evidenceCollector: NewEvidenceCollector(dbPool),
    }
}

// Start OOB servers (HTTP and DNS)
func (oob *OOBInteractionServer) Start() error {
    log.Printf("[OOB] Starting OOB interaction server on domain %s", oob.domain)
    
    // Start HTTP server
    go func() {
        if err := oob.startHTTPServer(); err != nil {
            log.Printf("[OOB] HTTP server failed: %v", err)
        }
    }()
    
    // Start DNS server
    go func() {
        if err := oob.startDNSServer(); err != nil {
            log.Printf("[OOB] DNS server failed: %v", err)
        }
    }()
    
    // Start cleanup routine
    go oob.cleanupExpiredTests()
    
    log.Printf("[OOB] OOB interaction server started successfully")
    return nil
}

// Start HTTP server for OOB interactions
func (oob *OOBInteractionServer) startHTTPServer() error {
    mux := http.NewServeMux()
    
    // Catch-all handler for OOB interactions
    mux.HandleFunc("/", oob.handleHTTPInteraction)
    
    // Health check endpoint
    mux.HandleFunc("/health", oob.handleHealthCheck)
    
    // Admin endpoint for interaction status
    mux.HandleFunc("/admin/interactions", oob.handleAdminInteractions)
    
    oob.httpServer = &http.Server{
        Addr:    fmt.Sprintf(":%d", oob.httpPort),
        Handler: mux,
    }
    
    log.Printf("[OOB] HTTP server listening on port %d", oob.httpPort)
    return oob.httpServer.ListenAndServe()
}

// Start DNS server for OOB interactions
func (oob *OOBInteractionServer) startDNSServer() error {
    dns.HandleFunc(".", oob.handleDNSInteraction)
    
    oob.dnsServer = &dns.Server{
        Addr: fmt.Sprintf(":%d", oob.dnsPort),
        Net:  "udp",
    }
    
    log.Printf("[OOB] DNS server listening on port %d", oob.dnsPort)
    return oob.dnsServer.ListenAndServe()
}

// Handle HTTP OOB interactions
func (oob *OOBInteractionServer) handleHTTPInteraction(w http.ResponseWriter, r *http.Request) {
    // Extract token from URL path or query parameters
    token := oob.extractTokenFromRequest(r)
    if token == "" {
        // Generate interaction even without token for general monitoring
        token = "unknown_" + uuid.New().String()[:8]
    }
    
    // Create interaction record
    interaction := &OOBInteraction{
        ID:        uuid.New().String(),
        Token:     token,
        Protocol:  "http",
        SourceIP:  oob.getRealIP(r),
        RequestData: map[string]interface{}{
            "method":      r.Method,
            "url":         r.URL.String(),
            "headers":     oob.formatHeaders(r.Header),
            "query_params": r.URL.Query(),
            "host":        r.Host,
        },
        UserAgent: r.UserAgent(),
        Timestamp: time.Now(),
        Validated: false,
    }
    
    // Read request body if present
    if r.ContentLength > 0 && r.ContentLength < 10240 { // Max 10KB
        body := make([]byte, r.ContentLength)
        r.Body.Read(body)
        interaction.RequestData["body"] = string(body)
    }
    
    // Store interaction
    oob.storeInteraction(interaction)
    
    // Log interaction
    log.Printf("[OOB] HTTP interaction: %s from %s (token: %s)", 
        r.Method, interaction.SourceIP, token)
    
    // Respond with success
    w.Header().Set("Content-Type", "text/plain")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(fmt.Sprintf("OOB interaction recorded: %s", interaction.ID)))
}

// Handle DNS OOB interactions
func (oob *OOBInteractionServer) handleDNSInteraction(w dns.ResponseWriter, r *dns.Msg) {
    // Extract token from DNS query
    if len(r.Question) == 0 {
        return
    }
    
    question := r.Question[0]
    queryName := strings.ToLower(question.Name)
    
    // Extract token from subdomain
    token := oob.extractTokenFromDNSQuery(queryName)
    
    // Create interaction record
    interaction := &OOBInteraction{
        ID:       uuid.New().String(),
        Token:    token,
        Protocol: "dns",
        SourceIP: oob.getClientIP(w),
        RequestData: map[string]interface{}{
            "query_name": queryName,
            "query_type": dns.TypeToString[question.Qtype],
            "query_class": dns.ClassToString[question.Qclass],
        },
        Timestamp: time.Now(),
        Validated: false,
    }
    
    // Store interaction
    oob.storeInteraction(interaction)
    
    // Log interaction
    log.Printf("[OOB] DNS interaction: %s from %s (token: %s)", 
        queryName, interaction.SourceIP, token)
    
    // Create DNS response
    msg := dns.Msg{}
    msg.SetReply(r)
    
    // Add A record response
    if question.Qtype == dns.TypeA {
        rr := &dns.A{
            Hdr: dns.RR_Header{
                Name:   question.Name,
                Rrtype: dns.TypeA,
                Class:  dns.ClassINET,
                Ttl:    300,
            },
            A: net.ParseIP("127.0.0.1"), // Respond with localhost
        }
        msg.Answer = append(msg.Answer, rr)
    }
    
    w.WriteMsg(&msg)
}

// Generate OOB test token and URL
func (oob *OOBInteractionServer) GenerateOOBTest(testType, targetURL, findingID, sessionID string, metadata map[string]interface{}) (*OOBTest, error) {
    token := fmt.Sprintf("%s_%s_%d", testType, uuid.New().String()[:8], time.Now().Unix())
    
    test := &OOBTest{
        ID:          uuid.New().String(),
        Token:       token,
        TestType:    testType,
        TargetURL:   targetURL,
        CreatedAt:   time.Now(),
        ExpiresAt:   time.Now().Add(5 * time.Minute), // 5 minute expiration
        Metadata:    metadata,
    }
    
    // Generate appropriate payload based on test type
    switch testType {
    case "ssrf":
        test.Payload = fmt.Sprintf("http://%s/%s", oob.domain, token)
        test.ExpectedProtocol = "http"
    case "dns_exfil":
        test.Payload = fmt.Sprintf("%s.%s", token, oob.domain)
        test.ExpectedProtocol = "dns"
    case "blind_xss":
        test.Payload = fmt.Sprintf(`<script src="http://%s/%s.js"></script>`, oob.domain, token)
        test.ExpectedProtocol = "http"
    case "xxe":
        test.Payload = fmt.Sprintf(`<!ENTITY xxe SYSTEM "http://%s/%s">`, oob.domain, token)
        test.ExpectedProtocol = "http"
    case "command_injection":
        test.Payload = fmt.Sprintf(`curl http://%s/%s`, oob.domain, token)
        test.ExpectedProtocol = "http"
    default:
        test.Payload = fmt.Sprintf("http://%s/%s", oob.domain, token)
        test.ExpectedProtocol = "http"
    }
    
    // Store test in database
    if err := oob.storeOOBTest(test, findingID, sessionID); err != nil {
        return nil, fmt.Errorf("failed to store OOB test: %w", err)
    }
    
    log.Printf("[OOB] Generated %s test with token %s", testType, token)
    return test, nil
}

// Check for OOB interactions for a specific token
func (oob *OOBInteractionServer) CheckInteraction(token string, waitTime time.Duration) (*OOBInteraction, error) {
    // Wait for interaction with timeout
    start := time.Now()
    for time.Since(start) < waitTime {
        oob.interactionMutex.RLock()
        if interaction, exists := oob.interactions[token]; exists {
            oob.interactionMutex.RUnlock()
            
            // Mark as validated
            interaction.Validated = true
            oob.updateInteraction(interaction)
            
            return interaction, nil
        }
        oob.interactionMutex.RUnlock()
        
        time.Sleep(500 * time.Millisecond)
    }
    
    return nil, fmt.Errorf("no interaction found for token %s within %v", token, waitTime)
}

// Store interaction in memory and database
func (oob *OOBInteractionServer) storeInteraction(interaction *OOBInteraction) {
    // Store in memory for quick access
    oob.interactionMutex.Lock()
    oob.interactions[interaction.Token] = interaction
    oob.interactionMutex.Unlock()
    
    // Store in database
    query := `
        INSERT INTO oob_interactions (id, token, finding_id, session_id, protocol, source_ip, 
                                    request_data, user_agent, timestamp, validated, test_context)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `
    
    requestDataJSON, _ := json.Marshal(interaction.RequestData)
    testContextJSON, _ := json.Marshal(interaction.TestContext)
    
    _, err := oob.dbPool.Exec(context.Background(), query,
        interaction.ID, interaction.Token, interaction.FindingID, interaction.SessionID,
        interaction.Protocol, interaction.SourceIP, requestDataJSON, interaction.UserAgent,
        interaction.Timestamp, interaction.Validated, testContextJSON)
    
    if err != nil {
        log.Printf("[OOB] Failed to store interaction in database: %v", err)
    }
    
    // Collect evidence
    evidenceData := fmt.Sprintf("OOB Interaction:\nProtocol: %s\nSource IP: %s\nTimestamp: %s\nRequest Data: %s",
        interaction.Protocol, interaction.SourceIP, interaction.Timestamp.Format(time.RFC3339),
        string(requestDataJSON))
    
    if interaction.FindingID != "" {
        oob.evidenceCollector.CollectEvidence(interaction.FindingID, EvidenceTypeJSON, 
            []byte(evidenceData), map[string]interface{}{
                "oob_interaction": true,
                "protocol":       interaction.Protocol,
                "token":          interaction.Token,
            })
    }
}

// Store OOB test in database
func (oob *OOBInteractionServer) storeOOBTest(test *OOBTest, findingID, sessionID string) error {
    query := `
        INSERT INTO oob_tests (id, token, test_type, target_url, payload, expected_protocol,
                              finding_id, session_id, created_at, expires_at, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `
    
    metadataJSON, _ := json.Marshal(test.Metadata)
    
    _, err := oob.dbPool.Exec(context.Background(), query,
        test.ID, test.Token, test.TestType, test.TargetURL, test.Payload,
        test.ExpectedProtocol, findingID, sessionID, test.CreatedAt, test.ExpiresAt, metadataJSON)
    
    return err
}

// Helper methods
func (oob *OOBInteractionServer) extractTokenFromRequest(r *http.Request) string {
    // Try to extract token from URL path
    pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(pathParts) > 0 && pathParts[0] != "" {
        return pathParts[0]
    }
    
    // Try to extract from query parameters
    if token := r.URL.Query().Get("token"); token != "" {
        return token
    }
    
    // Try to extract from headers
    if token := r.Header.Get("X-OOB-Token"); token != "" {
        return token
    }
    
    return ""
}

func (oob *OOBInteractionServer) extractTokenFromDNSQuery(queryName string) string {
    // Extract token from subdomain (e.g., ssrf_abc123_1234.oob.domain.com)
    if strings.HasSuffix(queryName, oob.domain+".") {
        subdomain := strings.TrimSuffix(queryName, "."+oob.domain+".")
        parts := strings.Split(subdomain, ".")
        if len(parts) > 0 {
            return parts[0]
        }
    }
    return "unknown"
}

func (oob *OOBInteractionServer) getRealIP(r *http.Request) string {
    // Check X-Forwarded-For header
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        parts := strings.Split(xff, ",")
        return strings.TrimSpace(parts[0])
    }
    
    // Check X-Real-IP header
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }
    
    // Fall back to RemoteAddr
    ip, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ip
}

func (oob *OOBInteractionServer) getClientIP(w dns.ResponseWriter) string {
    if addr := w.RemoteAddr(); addr != nil {
        ip, _, _ := net.SplitHostPort(addr.String())
        return ip
    }
    return "unknown"
}

func (oob *OOBInteractionServer) formatHeaders(headers http.Header) map[string]interface{} {
    headerMap := make(map[string]interface{})
    for name, values := range headers {
        if len(values) == 1 {
            headerMap[name] = values[0]
        } else {
            headerMap[name] = values
        }
    }
    return headerMap
}

func (oob *OOBInteractionServer) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    response := map[string]interface{}{
        "status": "healthy",
        "domain": oob.domain,
        "timestamp": time.Now(),
        "interactions_count": len(oob.interactions),
    }
    json.NewEncoder(w).Encode(response)
}

func (oob *OOBInteractionServer) handleAdminInteractions(w http.ResponseWriter, r *http.Request) {
    oob.interactionMutex.RLock()
    defer oob.interactionMutex.RUnlock()
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(oob.interactions)
}

func (oob *OOBInteractionServer) updateInteraction(interaction *OOBInteraction) {
    query := `UPDATE oob_interactions SET validated = $1 WHERE id = $2`
    oob.dbPool.Exec(context.Background(), query, interaction.Validated, interaction.ID)
}

func (oob *OOBInteractionServer) cleanupExpiredTests() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        // Clean up expired tests from database
        query := `DELETE FROM oob_tests WHERE expires_at < NOW()`
        result, err := oob.dbPool.Exec(context.Background(), query)
        if err != nil {
            log.Printf("[OOB] Failed to cleanup expired tests: %v", err)
            continue
        }
        
        if count := result.RowsAffected(); count > 0 {
            log.Printf("[OOB] Cleaned up %d expired tests", count)
        }
        
        // Clean up old interactions from memory (keep last 1000)
        oob.interactionMutex.Lock()
        if len(oob.interactions) > 1000 {
            // This is a simple cleanup - in production you'd want more sophisticated management
            oob.interactions = make(map[string]*OOBInteraction)
        }
        oob.interactionMutex.Unlock()
    }
}
```

### 2. Integration with Vulnerability Testing Tools

```go
// server/utils/ssrfTester.go - Enhanced with OOB
package utils

import (
    "fmt"
    "log"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type SSRFTester struct {
    oobServer        *OOBInteractionServer
    evidenceCollector *EvidenceCollector
}

func NewSSRFTester(oobServer *OOBInteractionServer) *SSRFTester {
    return &SSRFTester{
        oobServer:        oobServer,
        evidenceCollector: NewEvidenceCollector(oobServer.dbPool),
    }
}

// Test SSRF with OOB validation
func (st *SSRFTester) TestSSRF(targetURL, findingID, sessionID string) (bool, error) {
    log.Printf("[SSRF] Testing SSRF on %s", targetURL)
    
    // Generate OOB test
    oobTest, err := st.oobServer.GenerateOOBTest("ssrf", targetURL, findingID, sessionID, map[string]interface{}{
        "test_type": "ssrf_validation",
    })
    if err != nil {
        return false, err
    }
    
    // Test common SSRF parameters
    parameters := []string{"url", "link", "src", "target", "redirect", "endpoint", "callback"}
    
    for _, param := range parameters {
        // Construct test URL
        testURL := fmt.Sprintf("%s?%s=%s", targetURL, param, url.QueryEscape(oobTest.Payload))
        
        // Make request
        resp, err := http.Get(testURL)
        if err != nil {
            continue
        }
        resp.Body.Close()
        
        // Wait for OOB interaction
        interaction, err := st.oobServer.CheckInteraction(oobTest.Token, 10*time.Second)
        if err == nil {
            log.Printf("[SSRF] SSRF confirmed via OOB interaction from %s", interaction.SourceIP)
            
            // Collect additional evidence
            evidenceData := fmt.Sprintf("SSRF Test Results:\nTarget URL: %s\nParameter: %s\nOOB URL: %s\nInteraction Source: %s\nInteraction Time: %s",
                testURL, param, oobTest.Payload, interaction.SourceIP, interaction.Timestamp.Format(time.RFC3339))
            
            st.evidenceCollector.CollectEvidence(findingID, EvidenceTypeJSON, []byte(evidenceData), map[string]interface{}{
                "ssrf_test":    true,
                "parameter":    param,
                "oob_validated": true,
            })
            
            return true, nil
        }
    }
    
    log.Printf("[SSRF] No SSRF detected on %s", targetURL)
    return false, nil
}

// Test for XXE with OOB validation
func (st *SSRFTester) TestXXE(targetURL, findingID, sessionID string) (bool, error) {
    log.Printf("[XXE] Testing XXE on %s", targetURL)
    
    // Generate OOB test
    oobTest, err := st.oobServer.GenerateOOBTest("xxe", targetURL, findingID, sessionID, map[string]interface{}{
        "test_type": "xxe_validation",
    })
    if err != nil {
        return false, err
    }
    
    // XXE payload with OOB interaction
    xxePayload := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "%s">
]>
<root>
    <data>&xxe;</data>
</root>`, oobTest.Payload)
    
    // Test XML endpoints
    client := &http.Client{Timeout: 30 * time.Second}
    
    req, err := http.NewRequest("POST", targetURL, strings.NewReader(xxePayload))
    if err != nil {
        return false, err
    }
    
    req.Header.Set("Content-Type", "application/xml")
    
    resp, err := client.Do(req)
    if err != nil {
        return false, err
    }
    resp.Body.Close()
    
    // Wait for OOB interaction
    interaction, err := st.oobServer.CheckInteraction(oobTest.Token, 15*time.Second)
    if err == nil {
        log.Printf("[XXE] XXE confirmed via OOB interaction from %s", interaction.SourceIP)
        
        // Collect evidence
        evidenceData := fmt.Sprintf("XXE Test Results:\nTarget URL: %s\nXXE Payload: %s\nOOB URL: %s\nInteraction Source: %s",
            targetURL, xxePayload, oobTest.Payload, interaction.SourceIP)
        
        st.evidenceCollector.CollectEvidence(findingID, EvidenceTypeJSON, []byte(evidenceData), map[string]interface{}{
            "xxe_test":     true,
            "oob_validated": true,
        })
        
        return true, nil
    }
    
    return false, nil
}
```

### 3. Database Schema Enhancement

```sql
-- OOB interactions table
CREATE TABLE IF NOT EXISTS oob_interactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(200) NOT NULL,
    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
    session_id UUID,
    protocol VARCHAR(10) NOT NULL,  -- 'http', 'dns', 'smtp'
    source_ip INET NOT NULL,
    request_data JSONB NOT NULL DEFAULT '{}',
    user_agent TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    validated BOOLEAN DEFAULT FALSE,
    test_context JSONB DEFAULT '{}',
    
    INDEX(token),
    INDEX(finding_id),
    INDEX(session_id),
    INDEX(protocol),
    INDEX(timestamp)
);

-- OOB tests table
CREATE TABLE IF NOT EXISTS oob_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(200) NOT NULL UNIQUE,
    test_type VARCHAR(50) NOT NULL,  -- 'ssrf', 'xxe', 'dns_exfil', 'blind_xss'
    target_url TEXT NOT NULL,
    payload TEXT NOT NULL,
    expected_protocol VARCHAR(10) NOT NULL,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    session_id UUID,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    metadata JSONB DEFAULT '{}',
    
    INDEX(token),
    INDEX(test_type),
    INDEX(finding_id),
    INDEX(expires_at)
);
```

### 4. Docker Integration

```yaml
# docker-compose.yml - Add OOB server service
services:
  # ... existing services ...
  
  oob-server:
    container_name: ars0n-framework-v2-oob-server-1
    build: ./docker/oob-server
    ports:
      - "8080:8080"  # HTTP OOB interactions
      - "53:53/udp"  # DNS OOB interactions
    environment:
      - OOB_DOMAIN=oob.ars0n.local
      - DATABASE_URL=postgresql://user:pass@postgres:5432/ars0n_db
      - HTTP_PORT=8080
      - DNS_PORT=53
    depends_on:
      - postgres
    networks:
      - ars0n-network
    restart: unless-stopped
```

```dockerfile
# docker/oob-server/Dockerfile
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o oob-server ./cmd/oob-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/oob-server .

EXPOSE 8080 53/udp

CMD ["./oob-server"]
```

### 5. Integration with URL Workflow

```go
// Integration with URL workflow orchestrator
func (orchestrator *ToolOrchestrator) InitializeOOBServer() error {
    oobDomain := os.Getenv("OOB_DOMAIN")
    if oobDomain == "" {
        oobDomain = "oob.ars0n.local"
    }
    
    orchestrator.oobServer = NewOOBInteractionServer(orchestrator.dbPool, oobDomain)
    return orchestrator.oobServer.Start()
}

// Enhanced SSRF testing with OOB
func (orchestrator *ToolOrchestrator) TestSSRFWithOOB(urls []string, sessionID string) error {
    ssrfTester := NewSSRFTester(orchestrator.oobServer)
    
    for _, url := range urls {
        findingID := uuid.New().String()
        
        confirmed, err := ssrfTester.TestSSRF(url, findingID, sessionID)
        if err != nil {
            log.Printf("SSRF test failed for %s: %v", url, err)
            continue
        }
        
        if confirmed {
            // Submit SSRF finding
            orchestrator.submitSSRFFinding(url, findingID, sessionID)
        }
    }
    
    return nil
}
```

This OOB interaction server provides comprehensive out-of-band validation capabilities for blind vulnerability detection, integrating seamlessly with the existing Ars0n Framework containerized architecture and evidence collection system.
