# URL Workflow Technical Architecture - Ars0n Framework Integration

## Overview

This document defines the technical architecture for integrating the automated URL testing workflow into the existing Ars0n Framework v2. The design maintains all existing patterns while adding comprehensive vulnerability testing capabilities.

## Architecture Principles

### 1. Framework Integration
- **Enhance, Don't Replace**: All new functionality integrates into existing Go backend and React frontend
- **Database Continuity**: Add new tables to existing PostgreSQL schema (50+ tables)
- **API Consistency**: Use existing Gorilla Mux router and CORS patterns
- **Container Harmony**: Leverage existing Docker container orchestration

### 2. Workflow Dependency Chain
```
Company Workflow → Wildcard Workflow → URL Workflow
      ↓                    ↓              ↓
ASN Discovery      Subdomain Enum    Automated Testing
Network Ranges     Live Detection    Evidence Collection
Domain Discovery   ROI Scoring       Vulnerability Validation
      ↓                    ↓              ↓
consolidated_attack_surface_assets → Top 10 ROI URLs → Findings Pipeline
```

### 3. Data Flow Architecture
```
Existing Data Sources:
├── consolidated_attack_surface_assets (ROI-scored URLs)
├── target_urls (discovered endpoints)
├── live_web_servers (httpx results)
└── scope_targets (Company/Wildcard targets)
                    ↓
URL Workflow Selection:
├── SELECT TOP 10 BY roi_score WHERE asset_type='live_web_server'
├── Prerequisite validation (Company + Wildcard complete)
└── Multi-identity context preparation
                    ↓
Automated Testing Pipeline:
├── Phase 1: Attack Surface Mapping
├── Phase 2: DAST Execution  
├── Phase 3: Targeted Vulnerability Testing
└── Evidence Collection & Reproduction
                    ↓
Findings Pipeline:
├── Deduplication (key_hash algorithm)
├── Evidence storage (HAR, screenshots, DOM)
├── Reproduction pack generation
└── Export integration (.rs0n compatibility)
```

## Technical Components

### 1. Enhanced Go Backend Structure

```go
server/
├── main.go                          // Enhanced with URL workflow endpoints
├── database.go                      // Enhanced with findings tables
├── types.go                         // Enhanced with URL workflow types
├── utils/                          // Existing utilities enhanced
│   ├── urlWorkflowUtils.go         // NEW: URL workflow orchestrator
│   ├── findingsUtils.go            // NEW: Findings pipeline integration
│   ├── reproPackUtils.go           // NEW: Reproduction pack builder
│   ├── evidenceUtils.go            // NEW: Evidence collection system
│   ├── nucleiUtils.go              // Enhanced with findings integration
│   ├── httpxUtils.go               // Enhanced with findings integration
│   └── [all existing utils...]     // Enhanced with findings submission
├── url_workflow/                   // NEW: URL workflow implementation
│   ├── orchestrator.go             // Main workflow coordinator
│   ├── attack_surface.go           // Phase 1: Attack surface mapping
│   ├── dast_engine.go              // Phase 2: DAST implementation
│   ├── vuln_testing.go             // Phase 3: Targeted vulnerability testing
│   ├── evidence_collector.go       // Evidence collection and storage
│   ├── kill_chain_analyzer.go      // Kill-chain aware vulnerability analysis
│   ├── multi_identity.go           // Multi-identity testing framework
│   └── oob_server.go               // Out-of-band interaction handling
└── [existing structure...]         // All existing files maintained
```

### 2. Database Schema Integration

```sql
-- Add to existing PostgreSQL schema (alongside 50+ existing tables)

-- URL workflow sessions (extends existing auto_scan_sessions pattern)
CREATE TABLE url_workflow_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    prerequisite_workflows_complete BOOLEAN NOT NULL DEFAULT FALSE,
    selected_urls JSONB NOT NULL,  -- Top 10 ROI URLs
    current_phase VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    config_snapshot JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id)
);

-- Findings pipeline tables (integrate with existing evidence patterns)
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    url_workflow_session_id UUID REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    signal JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    kill_chain_score INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Additional tables: vectors, evidence_blobs, contexts, repro_recipes, oob_events
-- (Full schema already defined in findings_service/schema.sql)
```

### 3. API Endpoint Integration

```go
// Add to existing server/main.go router (integrate with existing CORS)
func setupURLWorkflowRoutes(router *mux.Router) {
    // URL Workflow Management (prerequisite validation)
    router.HandleFunc("/api/url-workflow/initiate/{scopeTargetId}", InitiateURLWorkflow).Methods("POST")
    router.HandleFunc("/api/url-workflow/status/{sessionId}", GetURLWorkflowStatus).Methods("GET")
    router.HandleFunc("/api/url-workflow/roi-urls/{scopeTargetId}", GetROIUrls).Methods("GET")
    
    // Findings Pipeline (integrated with existing patterns)
    router.HandleFunc("/api/findings", CreateOrUpdateFinding).Methods("POST")
    router.HandleFunc("/api/findings/{id}", GetFinding).Methods("GET")
    router.HandleFunc("/api/findings", ListFindings).Methods("GET")
    router.HandleFunc("/api/findings/{id}/status", UpdateFindingStatus).Methods("POST")
    router.HandleFunc("/api/findings/export", ExportFindings).Methods("GET")
    router.HandleFunc("/api/findings/{id}/evidence", AddEvidence).Methods("POST")
    router.HandleFunc("/api/findings/{id}/reproduce", GetReproInstructions).Methods("GET")
    
    // Evidence & OOB Integration
    router.HandleFunc("/api/oob/events", RegisterOOBEvent).Methods("POST")
    router.HandleFunc("/api/evidence/upload", UploadEvidence).Methods("POST")
}
```

### 4. React Frontend Integration

```jsx
// Enhance existing client/src/components/ScopeTargetDetails.js
const ScopeTargetDetails = ({ targetId }) => {
    const [workflows, setWorkflows] = useState({
        company: { status: 'pending', progress: 0 },
        wildcard: { status: 'pending', progress: 0 },
        url: { status: 'pending', progress: 0, enabled: false }
    });
    
    // Monitor prerequisite completion
    useEffect(() => {
        const checkPrerequisites = async () => {
            const companyComplete = workflows.company.status === 'completed';
            const wildcardComplete = workflows.wildcard.status === 'completed';
            
            if (companyComplete && wildcardComplete) {
                // Enable URL workflow and fetch ROI URLs
                const roiUrls = await fetchROIUrls(targetId);
                setWorkflows(prev => ({
                    ...prev,
                    url: { ...prev.url, enabled: true, roiUrls }
                }));
            }
        };
        
        checkPrerequisites();
    }, [workflows.company.status, workflows.wildcard.status, targetId]);
    
    return (
        <div className="scope-target-details">
            {/* Existing Company Workflow UI */}
            <WorkflowCard 
                title="Company Workflow"
                status={workflows.company.status}
                progress={workflows.company.progress}
            />
            
            {/* Existing Wildcard Workflow UI */}
            <WorkflowCard 
                title="Wildcard Workflow"
                status={workflows.wildcard.status}
                progress={workflows.wildcard.progress}
            />
            
            {/* NEW URL Workflow UI - only enabled after prerequisites */}
            <URLWorkflowCard
                targetId={targetId}
                enabled={workflows.url.enabled}
                roiUrls={workflows.url.roiUrls}
                status={workflows.url.status}
                progress={workflows.url.progress}
                onStart={handleURLWorkflowStart}
            />
            
            {/* NEW Findings Dashboard */}
            <FindingsDashboard 
                targetId={targetId}
                sessionId={workflows.url.sessionId}
            />
        </div>
    );
};

// New components:
// - client/src/components/URLWorkflowCard.js
// - client/src/components/FindingsDashboard.js  
// - client/src/modals/URLWorkflowConfigModal.js
```

## Implementation Architecture

### Phase 1: Attack Surface Mapping Integration

```go
// server/url_workflow/attack_surface.go
type AttackSurfaceMapper struct {
    ContainerManager  *ContainerManager  // Use existing container patterns
    EvidenceCollector *EvidenceCollector // Integrate with existing evidence
    RateLimiter      *RateLimiter       // Use existing rate limiting
    ScopeValidator   *ScopeValidator    // Use existing scope validation
}

func (asm *AttackSurfaceMapper) MapSurface(sessionID string, urls []string) error {
    for _, url := range urls {
        // 1. Web crawling (enhance existing GoSpider integration)
        if err := asm.crawlWebApplication(url, sessionID); err != nil {
            log.Printf("Crawling failed for %s: %v", url, err)
        }
        
        // 2. Directory brute-forcing (enhance existing FFuf integration)
        if err := asm.bruteForceDirectories(url, sessionID); err != nil {
            log.Printf("Directory brute-force failed for %s: %v", url, err)
        }
        
        // 3. JavaScript endpoint discovery (enhance existing Subdomainizer)
        if err := asm.extractJSEndpoints(url, sessionID); err != nil {
            log.Printf("JS endpoint extraction failed for %s: %v", url, err)
        }
        
        // 4. API discovery (new capability)
        if err := asm.discoverAPIEndpoints(url, sessionID); err != nil {
            log.Printf("API discovery failed for %s: %v", url, err)
        }
        
        // 5. HTTP method enumeration (new capability)
        if err := asm.enumerateHTTPMethods(url, sessionID); err != nil {
            log.Printf("HTTP method enumeration failed for %s: %v", url, err)
        }
    }
    
    return nil
}
```

### Phase 2: DAST Engine Integration

```go
// server/url_workflow/dast_engine.go
type DASTEngine struct {
    NucleiRunner     *NucleiRunner     // Use existing Nuclei integration
    ZAPIntegration   *ZAPIntegration   // Enhance existing ZAP if available
    CustomTests      []VulnTest        // Custom vulnerability tests
    BrowserValidator *BrowserValidator  // Playwright validation
}

func (de *DASTEngine) RunDASTScan(sessionID string, urls []string) error {
    for _, url := range urls {
        // 1. Nuclei comprehensive scan (enhance existing)
        nucleiFindings, err := de.runNucleiScan(url, sessionID)
        if err != nil {
            log.Printf("Nuclei scan failed for %s: %v", url, err)
        }
        
        // 2. Custom vulnerability tests
        customFindings, err := de.runCustomTests(url, sessionID)
        if err != nil {
            log.Printf("Custom tests failed for %s: %v", url, err)
        }
        
        // 3. Browser-based validation (two-stage detection)
        for _, finding := range append(nucleiFindings, customFindings...) {
            if finding.RequiresBrowserValidation {
                validated, err := de.validateWithBrowser(finding)
                if err == nil && validated {
                    submitFinding(finding, sessionID)
                }
            } else {
                submitFinding(finding, sessionID)
            }
        }
    }
    
    return nil
}
```

### Phase 3: Targeted Vulnerability Testing

```go
// server/url_workflow/vuln_testing.go
type VulnTester struct {
    SQLiTester    *SQLiTester
    XSSTester     *XSSTester  
    IDORTester    *IDORTester
    SSRFTester    *SSRFTester
    AuthTester    *AuthTester
    OOBServer     *OOBServer
}

func (vt *VulnTester) RunTargetedTests(sessionID string, urls []string) error {
    for _, url := range urls {
        // Multi-identity testing
        identities := []IdentityContext{
            {Type: "guest", Credentials: nil},
            {Type: "low_priv", Credentials: getTestCredentials("user")},
            {Type: "cross_tenant", Credentials: getTestCredentials("other_tenant")},
        }
        
        for _, identity := range identities {
            // 1. SQL Injection testing
            sqliFindings := vt.testSQLInjection(url, identity, sessionID)
            
            // 2. XSS testing (reflected, stored, DOM)
            xssFindings := vt.testXSS(url, identity, sessionID)
            
            // 3. IDOR testing with object ID fuzzing
            idorFindings := vt.testIDOR(url, identity, sessionID)
            
            // 4. SSRF testing with OOB validation
            ssrfFindings := vt.testSSRF(url, identity, sessionID)
            
            // 5. Authentication bypass testing
            authFindings := vt.testAuthBypass(url, identity, sessionID)
            
            // Submit all findings with kill-chain analysis
            allFindings := append(sqliFindings, xssFindings...)
            allFindings = append(allFindings, idorFindings...)
            allFindings = append(allFindings, ssrfFindings...)
            allFindings = append(allFindings, authFindings...)
            
            vt.analyzeKillChain(allFindings, sessionID)
        }
    }
    
    return nil
}
```

This architecture maintains the existing Ars0n Framework structure while adding comprehensive automated vulnerability testing capabilities. All components integrate seamlessly with existing patterns and leverage the ROI-scored URLs from Company and Wildcard workflows.
