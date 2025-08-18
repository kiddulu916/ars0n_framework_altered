# Security Tools Integration Map - URL Workflow

## Overview

This document maps the required security tools for the URL workflow and their integration patterns with the existing Ars0n Framework v2 architecture.

## Existing Tools Enhancement Strategy

### 1. Currently Integrated Tools (Enhance for URL Workflow)

#### **Nuclei (Existing - Enhance)**
- **Current State**: `server/utils/nucleiUtils.go`, `server/nuclei/executeAndParseNucleiSSLScan.go`
- **Container**: `ars0n-framework-v2-nuclei-1`
- **Enhancement Plan**:
  ```go
  // Enhanced nucleiUtils.go for URL workflow
  func executeNucleiURLWorkflow(sessionID, targetURL string, templates []string) (*NucleiFindings, error) {
      // 1. Execute comprehensive template scan
      // 2. Parse results with kill-chain scoring
      // 3. Submit findings to findings pipeline
      // 4. Generate evidence artifacts (HAR, screenshots)
      // 5. Return structured findings for chaining analysis
  }
  ```

#### **HTTPx (Existing - Enhance)**
- **Current State**: `server/utils/httpxUtils.go` (implied from live web servers)
- **Container**: `ars0n-framework-v2-httpx-1`
- **Enhancement Plan**:
  ```go
  // Enhanced httpxUtils.go for URL workflow
  func executeHTTPxURLAnalysis(sessionID, targetURL string) (*HTTPxAnalysis, error) {
      // 1. Technology detection and fingerprinting
      // 2. Response header analysis
      // 3. Status code validation
      // 4. SSL/TLS configuration assessment
      // 5. Evidence collection (response headers, certificates)
  }
  ```

#### **GoSpider (Existing - Enhance)**
- **Current State**: Container integrated for JavaScript crawling
- **Container**: `ars0n-framework-v2-gospider-1` 
- **Enhancement Plan**:
  ```go
  // Enhanced gospiderUtils.go for URL workflow
  func executeGoSpiderAttackSurface(sessionID, targetURL string) (*CrawlResults, error) {
      // 1. Deep web application crawling
      // 2. Form discovery and parameter extraction
      // 3. JavaScript endpoint extraction
      // 4. Hidden file and directory discovery
      // 5. Submit discovered endpoints to findings pipeline
  }
  ```

#### **Subdomainizer (Existing - Enhance)**
- **Current State**: Container integrated for JavaScript analysis
- **Container**: `ars0n-framework-v2-subdomainizer-1`
- **Enhancement Plan**:
  ```go
  // Enhanced subdomainizerUtils.go for URL workflow
  func executeSubdomainizerJSAnalysis(sessionID, targetURL string) (*JSAnalysisResults, error) {
      // 1. Extract API endpoints from JavaScript
      // 2. Discover hidden parameters and tokens
      // 3. Identify client-side vulnerabilities
      // 4. Extract sensitive data leaks (API keys, secrets)
      // 5. Submit JS-discovered vulnerabilities to findings
  }
  ```

#### **FFuf (Existing - Enhance)**
- **Current State**: `docker/ffuf/Dockerfile`
- **Container**: `ars0n-framework-v2-ffuf-1`
- **Enhancement Plan**:
  ```go
  // Enhanced ffufUtils.go for URL workflow
  func executeFfufDirectoryBruteforce(sessionID, targetURL string, wordlists []string) (*BruteforceResults, error) {
      // 1. Directory and file brute-forcing
      // 2. Parameter fuzzing and discovery
      // 3. HTTP method enumeration
      // 4. Hidden endpoint discovery
      // 5. Submit discovered assets to findings pipeline
  }
  ```

### 2. New Tools Required (Add to Framework)

#### **SQLMap Integration**
- **Purpose**: Advanced SQL injection detection and exploitation
- **Container**: Create `docker/sqlmap/Dockerfile`
- **Integration**:
  ```go
  // server/utils/sqlmapUtils.go
  func executeSQLMapScan(sessionID, targetURL string, params []Parameter) (*SQLiFindings, error) {
      // 1. SQL injection detection across multiple techniques
      // 2. Database fingerprinting and enumeration
      // 3. Data extraction proof-of-concept
      // 4. Generate exploitation proof for findings
  }
  ```

#### **ZAP Automation Framework**
- **Purpose**: Comprehensive DAST scanning with authentication
- **Container**: Create `docker/zap/Dockerfile`
- **Integration**:
  ```go
  // server/utils/zapUtils.go
  func executeZAPAutomationScan(sessionID, targetURL string, authContext AuthContext) (*ZAPFindings, error) {
      // 1. Automated spider and passive scan
      // 2. Active vulnerability scanning
      // 3. AJAX spider for SPA applications
      // 4. Authenticated session management
  }
  ```

#### **Wfuzz**
- **Purpose**: Advanced web application fuzzing
- **Container**: Create `docker/wfuzz/Dockerfile`
- **Integration**:
  ```go
  // server/utils/wfuzzUtils.go
  func executeWfuzzParameterFuzzing(sessionID, targetURL string, payloads []string) (*FuzzingResults, error) {
      // 1. Parameter discovery and fuzzing
      // 2. Header injection testing
      // 3. File upload fuzzing
      // 4. Input validation bypass attempts
  }
  ```

#### **LinkFinder**
- **Purpose**: JavaScript endpoint and parameter discovery
- **Container**: Create `docker/linkfinder/Dockerfile`
- **Integration**:
  ```go
  // server/utils/linkfinderUtils.go
  func executeLinkFinderAnalysis(sessionID, jsFiles []string) (*JSEndpoints, error) {
      // 1. Parse JavaScript files for endpoints
      // 2. Extract API routes and parameters
      // 3. Discover hidden functionality
      // 4. Submit discovered endpoints to attack surface
  }
  ```

#### **DirBuster/Dirsearch**
- **Purpose**: Directory and file enumeration
- **Container**: Create `docker/dirsearch/Dockerfile`
- **Integration**:
  ```go
  // server/utils/dirsearchUtils.go
  func executeDirsearchEnumeration(sessionID, targetURL string, wordlists []string) (*DirectoryResults, error) {
      // 1. Comprehensive directory enumeration
      // 2. File extension fuzzing
      // 3. Backup file discovery
      // 4. Administrative interface discovery
  }
  ```

## Tool Integration Architecture

### 1. Container Management Pattern

```yaml
# Addition to existing docker-compose.yml
  
  # New tool containers following existing patterns
  sqlmap:
    container_name: ars0n-framework-v2-sqlmap-1
    build: ./docker/sqlmap
    entrypoint: ["sleep", "infinity"]
    restart: "no"
    networks:
      - ars0n-network
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1'

  zap:
    container_name: ars0n-framework-v2-zap-1
    build: ./docker/zap
    entrypoint: ["sleep", "infinity"]
    restart: "no"
    networks:
      - ars0n-network
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'

  wfuzz:
    container_name: ars0n-framework-v2-wfuzz-1
    build: ./docker/wfuzz
    entrypoint: ["sleep", "infinity"]
    restart: "no"
    networks:
      - ars0n-network

  linkfinder:
    container_name: ars0n-framework-v2-linkfinder-1
    build: ./docker/linkfinder
    entrypoint: ["sleep", "infinity"]
    restart: "no"
    networks:
      - ars0n-network

  dirsearch:
    container_name: ars0n-framework-v2-dirsearch-1
    build: ./docker/dirsearch
    entrypoint: ["sleep", "infinity"]
    restart: "no"
    networks:
      - ars0n-network
```

### 2. Docker Execution Pattern

```go
// server/utils/containerManager.go
type ContainerManager struct {
    DockerClient  *docker.Client
    RateLimiter   *RateLimiter
    ScopeValidator *ScopeValidator
}

func (cm *ContainerManager) ExecuteInContainer(containerName, command string, args []string, sessionID string) (*ContainerResult, error) {
    // 1. Validate scope and rate limits
    if err := cm.validateExecution(containerName, sessionID); err != nil {
        return nil, err
    }
    
    // 2. Build docker exec command
    cmdArgs := append([]string{"exec", containerName, command}, args...)
    cmd := exec.Command("docker", cmdArgs...)
    
    // 3. Set timeout and execute
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
    defer cancel()
    
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    
    startTime := time.Now()
    err := cmd.Run()
    executionTime := time.Since(startTime)
    
    // 4. Process results
    result := &ContainerResult{
        ContainerName: containerName,
        Command:       command,
        Args:          args,
        Stdout:        stdout.String(),
        Stderr:        stderr.String(),
        ExecutionTime: executionTime,
        Success:       err == nil,
        SessionID:     sessionID,
    }
    
    // 5. Log execution
    cm.logExecution(result)
    
    return result, err
}
```

### 3. Tool Orchestration Pattern

```go
// server/url_workflow/orchestrator.go
type ToolOrchestrator struct {
    ContainerManager *ContainerManager
    FindingsPipeline *FindingsPipeline
    EvidenceCollector *EvidenceCollector
    KillChainAnalyzer *KillChainAnalyzer
}

func (to *ToolOrchestrator) ExecutePhase1AttackSurface(sessionID string, urls []string) error {
    for _, url := range urls {
        // Parallel execution of attack surface mapping tools
        var wg sync.WaitGroup
        results := make(chan PhaseResult, 10)
        
        // 1. Web crawling
        wg.Add(1)
        go func() {
            defer wg.Done()
            result := to.executeCrawling(sessionID, url)
            results <- result
        }()
        
        // 2. Directory brute-forcing
        wg.Add(1)
        go func() {
            defer wg.Done()
            result := to.executeDirectoryBruteforce(sessionID, url)
            results <- result
        }()
        
        // 3. JavaScript analysis
        wg.Add(1)
        go func() {
            defer wg.Done()
            result := to.executeJSAnalysis(sessionID, url)
            results <- result
        }()
        
        // 4. API discovery
        wg.Add(1)
        go func() {
            defer wg.Done()
            result := to.executeAPIDiscovery(sessionID, url)
            results <- result
        }()
        
        // Wait for completion and process results
        go func() {
            wg.Wait()
            close(results)
        }()
        
        // Collect and process results
        for result := range results {
            if err := to.processPhaseResult(result, sessionID); err != nil {
                log.Printf("Failed to process phase result: %v", err)
            }
        }
    }
    
    return nil
}
```

### 4. Database Integration Pattern

```go
// server/utils/findingsUtils.go
func submitToolFinding(finding ToolFinding, sessionID string) error {
    // 1. Generate deduplication key
    keyHash := generateFindingKeyHash(finding)
    
    // 2. Check for existing finding
    existing, err := getFindingByKeyHash(keyHash)
    if err == nil && existing != nil {
        return updateExistingFinding(existing.ID, finding)
    }
    
    // 3. Create new finding
    findingID := uuid.New().String()
    
    query := `
        INSERT INTO findings (id, key_hash, url_workflow_session_id, scope_target_id, 
                             title, category, severity, signal, status, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
    `
    
    _, err = dbPool.Exec(context.Background(), query,
        findingID, keyHash, sessionID, finding.ScopeTargetID,
        finding.Title, finding.Category, finding.Severity,
        finding.Signal, "open")
    
    if err != nil {
        return fmt.Errorf("failed to insert finding: %w", err)
    }
    
    // 4. Store evidence artifacts
    for _, evidence := range finding.Evidence {
        if err := storeEvidenceArtifact(findingID, evidence); err != nil {
            log.Printf("Failed to store evidence for finding %s: %v", findingID, err)
        }
    }
    
    // 5. Generate reproduction pack
    if err := generateReproductionPack(findingID, finding); err != nil {
        log.Printf("Failed to generate repro pack for finding %s: %v", findingID, err)
    }
    
    return nil
}
```

This integration map ensures all security tools work seamlessly within the existing Ars0n Framework architecture while providing comprehensive vulnerability detection capabilities for the URL workflow.
