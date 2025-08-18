# Kill-Chain Aware Vulnerability Detection and Chaining Logic

## Overview

This document outlines the design for kill-chain aware vulnerability detection and chaining logic integrated into the existing Ars0n Framework PostgreSQL schema. The system prioritizes vulnerabilities based on their potential for chaining into complete attack paths, focusing on high-impact exploitation sequences.

## Kill-Chain Philosophy

### Attack Path Prioritization
Instead of treating vulnerabilities in isolation, the system identifies and scores complete attack chains:
- **SSRF → Cloud Metadata → Credentials → Admin Access**
- **IDOR → Data Exfiltration → Privilege Escalation**
- **File Upload → RCE → System Compromise**
- **Auth Bypass → Privilege Escalation → Data Access**
- **XSS → Session Hijacking → Account Takeover**

### Business Impact Focus
Vulnerabilities are evaluated not just by individual severity, but by their role in complete exploitation chains that lead to significant business impact.

## Architecture Integration

### 1. Enhanced Database Schema (Building on Existing)

The kill-chain detection leverages the existing PostgreSQL schema with additional analysis tables:

```sql
-- Kill chain analysis table (extends existing findings schema)
CREATE TABLE IF NOT EXISTS kill_chain_analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url_workflow_session_id UUID NOT NULL REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    
    -- Chain metadata
    chain_name VARCHAR(200) NOT NULL,
    chain_description TEXT,
    total_findings INTEGER NOT NULL DEFAULT 0,
    chain_score INTEGER NOT NULL DEFAULT 0,  -- 0-100 overall chain impact
    exploitation_complexity VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high'
    
    -- Chain validation
    validated BOOLEAN DEFAULT FALSE,
    automation_possible BOOLEAN DEFAULT FALSE,
    proof_of_concept TEXT,
    business_impact TEXT,
    
    -- Chain steps (ordered sequence)
    chain_steps JSONB NOT NULL DEFAULT '[]',
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Kill chain steps table (individual steps in attack chains)
CREATE TABLE IF NOT EXISTS kill_chain_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kill_chain_id UUID NOT NULL REFERENCES kill_chain_analysis(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- Step details
    step_number INTEGER NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    step_description TEXT,
    
    -- Chain relationships
    enables_step_ids UUID[],  -- Which steps this enables
    requires_step_ids UUID[], -- Prerequisites for this step
    
    -- Impact scoring
    individual_score INTEGER DEFAULT 0,  -- 0-10 individual impact
    chain_multiplier DECIMAL(3,2) DEFAULT 1.0,  -- Impact when chained
    
    -- Automation details
    automated_exploit BOOLEAN DEFAULT FALSE,
    exploit_script_path TEXT,
    manual_steps TEXT,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(kill_chain_id, step_number)
);

-- Pre-defined kill chain patterns
CREATE TABLE IF NOT EXISTS kill_chain_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Pattern identification
    pattern_name VARCHAR(100) NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL, -- 'credential_access', 'privilege_escalation', 'data_exfiltration'
    description TEXT NOT NULL,
    
    -- Pattern definition
    required_vulns JSONB NOT NULL,  -- Required vulnerability types and conditions
    optional_vulns JSONB DEFAULT '[]',  -- Optional vulnerabilities that enhance the chain
    
    -- Scoring
    base_score INTEGER NOT NULL,  -- Base impact score (0-100)
    complexity_factor DECIMAL(3,2) DEFAULT 1.0,
    
    -- Pattern metadata
    attack_vector TEXT,
    business_impact_description TEXT,
    mitigation_priority VARCHAR(20) DEFAULT 'high',
    
    -- Pattern validation
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_kill_chain_analysis_session_id ON kill_chain_analysis(url_workflow_session_id);
CREATE INDEX IF NOT EXISTS idx_kill_chain_analysis_scope_target_id ON kill_chain_analysis(scope_target_id);
CREATE INDEX IF NOT EXISTS idx_kill_chain_analysis_chain_score ON kill_chain_analysis(chain_score);
CREATE INDEX IF NOT EXISTS idx_kill_chain_steps_chain_id ON kill_chain_steps(kill_chain_id);
CREATE INDEX IF NOT EXISTS idx_kill_chain_steps_finding_id ON kill_chain_steps(finding_id);
CREATE INDEX IF NOT EXISTS idx_kill_chain_steps_step_number ON kill_chain_steps(step_number);
```

### 2. Kill Chain Pattern Definitions

```go
// server/utils/killChainPatterns.go
package utils

import (
    "encoding/json"
    "fmt"
    "log"
)

type KillChainPattern struct {
    ID                        string                 `json:"id"`
    PatternName              string                 `json:"pattern_name"`
    Category                 string                 `json:"category"`
    Description              string                 `json:"description"`
    RequiredVulns            []VulnRequirement      `json:"required_vulns"`
    OptionalVulns            []VulnRequirement      `json:"optional_vulns"`
    BaseScore                int                    `json:"base_score"`
    ComplexityFactor         float64                `json:"complexity_factor"`
    AttackVector             string                 `json:"attack_vector"`
    BusinessImpactDescription string                 `json:"business_impact_description"`
    MitigationPriority       string                 `json:"mitigation_priority"`
}

type VulnRequirement struct {
    Category    string            `json:"category"`    // 'ssrf', 'idor', 'xss', etc.
    Severity    string            `json:"severity"`    // Minimum severity required
    Context     map[string]string `json:"context"`     // Additional context requirements
    Optional    bool              `json:"optional"`    // Whether this vuln is optional
}

// Pre-defined kill chain patterns
var KillChainPatterns = []KillChainPattern{
    {
        PatternName: "SSRF_to_Cloud_Takeover",
        Category:    "credential_access",
        Description: "SSRF vulnerability leading to cloud metadata access and credential extraction",
        RequiredVulns: []VulnRequirement{
            {Category: "ssrf", Severity: "medium", Context: map[string]string{"allows_internal": "true"}},
        },
        OptionalVulns: []VulnRequirement{
            {Category: "auth_bypass", Severity: "low", Optional: true},
            {Category: "idor", Severity: "medium", Optional: true},
        },
        BaseScore:                85,
        ComplexityFactor:         1.2,
        AttackVector:            "Server-Side Request Forgery → Cloud Metadata → AWS/GCP Credentials → Account Takeover",
        BusinessImpactDescription: "Complete cloud infrastructure compromise, data exfiltration, service disruption",
        MitigationPriority:      "critical",
    },
    {
        PatternName: "IDOR_to_Privilege_Escalation",
        Category:    "privilege_escalation", 
        Description: "IDOR vulnerability enabling access to administrative functions",
        RequiredVulns: []VulnRequirement{
            {Category: "idor", Severity: "medium", Context: map[string]string{"admin_access": "possible"}},
        },
        OptionalVulns: []VulnRequirement{
            {Category: "auth_bypass", Severity: "low", Optional: true},
            {Category: "session_fixation", Severity: "low", Optional: true},
        },
        BaseScore:                75,
        ComplexityFactor:         0.8,
        AttackVector:            "IDOR → Admin Panel Access → User Management → Full Application Control",
        BusinessImpactDescription: "Administrative access, user data manipulation, system configuration changes",
        MitigationPriority:      "high",
    },
    {
        PatternName: "File_Upload_to_RCE",
        Category:    "code_execution",
        Description: "File upload vulnerability leading to remote code execution",
        RequiredVulns: []VulnRequirement{
            {Category: "file_upload", Severity: "medium", Context: map[string]string{"executable": "true"}},
        },
        OptionalVulns: []VulnRequirement{
            {Category: "path_traversal", Severity: "low", Optional: true},
            {Category: "command_injection", Severity: "medium", Optional: true},
        },
        BaseScore:                95,
        ComplexityFactor:         0.9,
        AttackVector:            "File Upload → Webshell → Remote Code Execution → System Compromise",
        BusinessImpactDescription: "Complete server compromise, data theft, service disruption, lateral movement",
        MitigationPriority:      "critical",
    },
    {
        PatternName: "XSS_to_Account_Takeover",
        Category:    "credential_access",
        Description: "XSS vulnerability enabling session hijacking and account compromise",
        RequiredVulns: []VulnRequirement{
            {Category: "xss", Severity: "medium", Context: map[string]string{"stored": "true"}},
        },
        OptionalVulns: []VulnRequirement{
            {Category: "csrf", Severity: "low", Optional: true},
            {Category: "session_fixation", Severity: "low", Optional: true},
        },
        BaseScore:                70,
        ComplexityFactor:         0.7,
        AttackVector:            "Stored XSS → Session Cookie Theft → Account Impersonation → Data Access",
        BusinessImpactDescription: "User account compromise, unauthorized transactions, data exposure",
        MitigationPriority:      "high",
    },
    {
        PatternName: "Auth_Bypass_to_Data_Exfiltration",
        Category:    "data_exfiltration",
        Description: "Authentication bypass leading to unauthorized data access",
        RequiredVulns: []VulnRequirement{
            {Category: "auth_bypass", Severity: "medium", Context: map[string]string{}},
        },
        OptionalVulns: []VulnRequirement{
            {Category: "idor", Severity: "medium", Optional: true},
            {Category: "sqli", Severity: "high", Optional: true},
        },
        BaseScore:                80,
        ComplexityFactor:         0.6,
        AttackVector:            "Authentication Bypass → Unauthorized Access → Data Enumeration → Mass Exfiltration",
        BusinessImpactDescription: "Unauthorized data access, customer information exposure, compliance violations",
        MitigationPriority:      "critical",
    },
}
```

### 3. Kill Chain Detection Engine

```go
// server/utils/killChainDetector.go
package utils

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "sort"
    "time"
    
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type KillChainDetector struct {
    dbPool   *pgxpool.Pool
    patterns []KillChainPattern
}

type DetectedKillChain struct {
    ID                    string            `json:"id"`
    PatternName          string            `json:"pattern_name"`
    SessionID            string            `json:"session_id"`
    ScopeTargetID        string            `json:"scope_target_id"`
    ChainScore           int               `json:"chain_score"`
    Findings             []Finding         `json:"findings"`
    Steps                []KillChainStep   `json:"steps"`
    ExploitationPath     string            `json:"exploitation_path"`
    BusinessImpact       string            `json:"business_impact"`
    AutomationPossible   bool              `json:"automation_possible"`
    Validated            bool              `json:"validated"`
}

type KillChainStep struct {
    StepNumber      int               `json:"step_number"`
    StepName        string            `json:"step_name"`
    Finding         Finding           `json:"finding"`
    IndividualScore int               `json:"individual_score"`
    ChainMultiplier float64           `json:"chain_multiplier"`
    AutomatedExploit bool             `json:"automated_exploit"`
    Prerequisites   []string          `json:"prerequisites"`
    Enables         []string          `json:"enables"`
}

func NewKillChainDetector(dbPool *pgxpool.Pool) *KillChainDetector {
    return &KillChainDetector{
        dbPool:   dbPool,
        patterns: KillChainPatterns,
    }
}

// Analyze findings for kill chain opportunities
func (kcd *KillChainDetector) AnalyzeKillChains(sessionID, scopeTargetID string) ([]DetectedKillChain, error) {
    // Get all findings for the session
    findings, err := kcd.getFindingsForSession(sessionID)
    if err != nil {
        return nil, fmt.Errorf("failed to get findings: %w", err)
    }
    
    if len(findings) == 0 {
        log.Printf("No findings found for session %s", sessionID)
        return []DetectedKillChain{}, nil
    }
    
    log.Printf("Analyzing %d findings for kill chains in session %s", len(findings), sessionID)
    
    var detectedChains []DetectedKillChain
    
    // Check each pattern against available findings
    for _, pattern := range kcd.patterns {
        if chain := kcd.matchPattern(pattern, findings, sessionID, scopeTargetID); chain != nil {
            detectedChains = append(detectedChains, *chain)
        }
    }
    
    // Sort by chain score (highest first)
    sort.Slice(detectedChains, func(i, j int) bool {
        return detectedChains[i].ChainScore > detectedChains[j].ChainScore
    })
    
    // Store detected chains in database
    for _, chain := range detectedChains {
        if err := kcd.storeKillChain(chain); err != nil {
            log.Printf("Failed to store kill chain %s: %v", chain.ID, err)
        }
    }
    
    log.Printf("Detected %d kill chains for session %s", len(detectedChains), sessionID)
    return detectedChains, nil
}

// Match a specific pattern against available findings
func (kcd *KillChainDetector) matchPattern(pattern KillChainPattern, findings []Finding, sessionID, scopeTargetID string) *DetectedKillChain {
    // Check if required vulnerabilities are present
    requiredMatches := kcd.matchVulnRequirements(pattern.RequiredVulns, findings)
    if len(requiredMatches) < len(pattern.RequiredVulns) {
        return nil // Not all required vulns present
    }
    
    // Check for optional vulnerabilities
    optionalMatches := kcd.matchVulnRequirements(pattern.OptionalVulns, findings)
    
    // Calculate chain score
    chainScore := kcd.calculateChainScore(pattern, requiredMatches, optionalMatches)
    
    // Build kill chain steps
    steps := kcd.buildKillChainSteps(pattern, requiredMatches, optionalMatches)
    
    // Combine all matched findings
    allFindings := append(requiredMatches, optionalMatches...)
    
    // Generate exploitation path
    exploitationPath := kcd.generateExploitationPath(pattern, steps)
    
    // Check automation possibilities
    automationPossible := kcd.checkAutomationPossible(steps)
    
    detectedChain := &DetectedKillChain{
        ID:                  uuid.New().String(),
        PatternName:         pattern.PatternName,
        SessionID:           sessionID,
        ScopeTargetID:       scopeTargetID,
        ChainScore:          chainScore,
        Findings:            allFindings,
        Steps:               steps,
        ExploitationPath:    exploitationPath,
        BusinessImpact:      pattern.BusinessImpactDescription,
        AutomationPossible:  automationPossible,
        Validated:           false, // Will be validated later
    }
    
    log.Printf("Detected kill chain: %s (Score: %d, Steps: %d)", 
        pattern.PatternName, chainScore, len(steps))
    
    return detectedChain
}

// Match vulnerability requirements against findings
func (kcd *KillChainDetector) matchVulnRequirements(requirements []VulnRequirement, findings []Finding) []Finding {
    var matches []Finding
    
    for _, req := range requirements {
        for _, finding := range findings {
            if kcd.findingMatchesRequirement(finding, req) {
                matches = append(matches, finding)
                break // One finding per requirement
            }
        }
    }
    
    return matches
}

// Check if a finding matches a vulnerability requirement
func (kcd *KillChainDetector) findingMatchesRequirement(finding Finding, req VulnRequirement) bool {
    // Check category match
    if finding.Category != req.Category {
        return false
    }
    
    // Check severity level
    if !kcd.severityMeetsRequirement(finding.Severity, req.Severity) {
        return false
    }
    
    // Check context requirements
    for key, value := range req.Context {
        if findingValue, exists := finding.Metadata[key]; !exists || fmt.Sprintf("%v", findingValue) != value {
            return false
        }
    }
    
    return true
}

// Check if severity meets minimum requirement
func (kcd *KillChainDetector) severityMeetsRequirement(actualSeverity, requiredSeverity string) bool {
    severityLevels := map[string]int{
        "info":     1,
        "low":      2,
        "medium":   3,
        "high":     4,
        "critical": 5,
    }
    
    actual, ok1 := severityLevels[actualSeverity]
    required, ok2 := severityLevels[requiredSeverity]
    
    if !ok1 || !ok2 {
        return false
    }
    
    return actual >= required
}

// Calculate overall chain score
func (kcd *KillChainDetector) calculateChainScore(pattern KillChainPattern, requiredFindings, optionalFindings []Finding) int {
    baseScore := float64(pattern.BaseScore)
    
    // Bonus for optional vulnerabilities
    optionalBonus := float64(len(optionalFindings)) * 5.0
    
    // Complexity factor adjustment
    complexityAdjustment := baseScore * pattern.ComplexityFactor
    
    // High-severity bonus
    highSeverityCount := 0
    for _, finding := range append(requiredFindings, optionalFindings...) {
        if finding.Severity == "high" || finding.Severity == "critical" {
            highSeverityCount++
        }
    }
    severityBonus := float64(highSeverityCount) * 10.0
    
    finalScore := int(baseScore + optionalBonus + severityBonus + complexityAdjustment)
    
    // Cap at 100
    if finalScore > 100 {
        finalScore = 100
    }
    
    return finalScore
}

// Build kill chain steps from matched findings
func (kcd *KillChainDetector) buildKillChainSteps(pattern KillChainPattern, requiredFindings, optionalFindings []Finding) []KillChainStep {
    var steps []KillChainStep
    stepNumber := 1
    
    // Add required steps
    for i, finding := range requiredFindings {
        step := KillChainStep{
            StepNumber:       stepNumber,
            StepName:         fmt.Sprintf("Exploit %s", finding.Category),
            Finding:          finding,
            IndividualScore:  kcd.getSeverityScore(finding.Severity),
            ChainMultiplier:  1.0 + (float64(i) * 0.2), // Multiplier increases with chain position
            AutomatedExploit: kcd.isAutomatable(finding),
            Prerequisites:    kcd.getPrerequisites(finding, stepNumber),
            Enables:          kcd.getEnables(finding, pattern),
        }
        steps = append(steps, step)
        stepNumber++
    }
    
    // Add optional steps
    for i, finding := range optionalFindings {
        step := KillChainStep{
            StepNumber:       stepNumber,
            StepName:         fmt.Sprintf("Enhance via %s", finding.Category),
            Finding:          finding,
            IndividualScore:  kcd.getSeverityScore(finding.Severity),
            ChainMultiplier:  0.5 + (float64(i) * 0.1), // Lower multiplier for optional steps
            AutomatedExploit: kcd.isAutomatable(finding),
            Prerequisites:    kcd.getPrerequisites(finding, stepNumber),
            Enables:          kcd.getEnables(finding, pattern),
        }
        steps = append(steps, step)
        stepNumber++
    }
    
    return steps
}

// Generate human-readable exploitation path
func (kcd *KillChainDetector) generateExploitationPath(pattern KillChainPattern, steps []KillChainStep) string {
    path := pattern.AttackVector + "\n\nDetailed Steps:\n"
    
    for i, step := range steps {
        path += fmt.Sprintf("%d. %s (%s severity)\n", 
            i+1, step.StepName, step.Finding.Severity)
        path += fmt.Sprintf("   Target: %s\n", step.Finding.Title)
        if step.AutomatedExploit {
            path += "   Automation: Possible\n"
        }
        path += "\n"
    }
    
    return path
}

// Helper methods
func (kcd *KillChainDetector) getSeverityScore(severity string) int {
    scores := map[string]int{
        "info":     1,
        "low":      3,
        "medium":   5,
        "high":     8,
        "critical": 10,
    }
    return scores[severity]
}

func (kcd *KillChainDetector) isAutomatable(finding Finding) bool {
    // Determine if finding can be automatically exploited
    automatableCategories := []string{"sqli", "ssrf", "idor", "auth_bypass"}
    for _, category := range automatableCategories {
        if finding.Category == category {
            return true
        }
    }
    return false
}

func (kcd *KillChainDetector) checkAutomationPossible(steps []KillChainStep) bool {
    automatedSteps := 0
    for _, step := range steps {
        if step.AutomatedExploit {
            automatedSteps++
        }
    }
    return float64(automatedSteps)/float64(len(steps)) >= 0.7 // 70% of steps automatable
}

// Database operations
func (kcd *KillChainDetector) getFindingsForSession(sessionID string) ([]Finding, error) {
    query := `
        SELECT id, title, category, severity, signal, metadata, created_at
        FROM findings 
        WHERE url_workflow_session_id = $1 
        ORDER BY created_at ASC
    `
    
    rows, err := kcd.dbPool.Query(context.Background(), query, sessionID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var findings []Finding
    for rows.Next() {
        var finding Finding
        var signalJSON, metadataJSON []byte
        
        err := rows.Scan(&finding.ID, &finding.Title, &finding.Category, 
                        &finding.Severity, &signalJSON, &metadataJSON, &finding.CreatedAt)
        if err != nil {
            continue
        }
        
        // Parse JSON fields
        if len(signalJSON) > 0 {
            json.Unmarshal(signalJSON, &finding.Signal)
        }
        if len(metadataJSON) > 0 {
            json.Unmarshal(metadataJSON, &finding.Metadata)
        }
        
        findings = append(findings, finding)
    }
    
    return findings, nil
}

func (kcd *KillChainDetector) storeKillChain(chain DetectedKillChain) error {
    // Store kill chain analysis
    query := `
        INSERT INTO kill_chain_analysis (id, url_workflow_session_id, scope_target_id, 
                                       chain_name, chain_description, total_findings, chain_score,
                                       validated, automation_possible, proof_of_concept, business_impact,
                                       chain_steps, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
    `
    
    stepsJSON, _ := json.Marshal(chain.Steps)
    
    _, err := kcd.dbPool.Exec(context.Background(), query,
        chain.ID, chain.SessionID, chain.ScopeTargetID,
        chain.PatternName, chain.BusinessImpact, len(chain.Findings), chain.ChainScore,
        chain.Validated, chain.AutomationPossible, chain.ExploitationPath, chain.BusinessImpact,
        stepsJSON)
    
    if err != nil {
        return err
    }
    
    // Store individual steps
    for _, step := range chain.Steps {
        stepQuery := `
            INSERT INTO kill_chain_steps (id, kill_chain_id, finding_id, step_number, step_name,
                                        individual_score, chain_multiplier, automated_exploit, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        `
        
        _, err := kcd.dbPool.Exec(context.Background(), stepQuery,
            uuid.New().String(), chain.ID, step.Finding.ID, step.StepNumber, step.StepName,
            step.IndividualScore, step.ChainMultiplier, step.AutomatedExploit)
        
        if err != nil {
            log.Printf("Failed to store kill chain step: %v", err)
        }
    }
    
    return nil
}

// Get prerequisites for a step
func (kcd *KillChainDetector) getPrerequisites(finding Finding, stepNumber int) []string {
    prerequisites := []string{}
    
    // Add prerequisites based on vulnerability type
    switch finding.Category {
    case "idor":
        prerequisites = append(prerequisites, "Valid user session")
    case "ssrf":
        prerequisites = append(prerequisites, "Accessible internal network")
    case "file_upload":
        prerequisites = append(prerequisites, "File upload functionality")
    case "xss":
        if stepNumber > 1 {
            prerequisites = append(prerequisites, "User interaction")
        }
    }
    
    return prerequisites
}

// Get what this step enables
func (kcd *KillChainDetector) getEnables(finding Finding, pattern KillChainPattern) []string {
    enables := []string{}
    
    switch finding.Category {
    case "ssrf":
        enables = append(enables, "Internal network access", "Cloud metadata access")
    case "idor":
        enables = append(enables, "Data enumeration", "Privilege escalation")
    case "file_upload":
        enables = append(enables, "Code execution", "System compromise")
    case "auth_bypass":
        enables = append(enables, "Unauthorized access", "Data exfiltration")
    case "xss":
        enables = append(enables, "Session hijacking", "Account takeover")
    }
    
    return enables
}
```

### 4. Integration with URL Workflow

```go
// server/url_workflow/kill_chain_integration.go
package url_workflow

import (
    "log"
    "time"
)

// Integrate kill chain analysis into URL workflow phases
func (orchestrator *ToolOrchestrator) AnalyzeKillChainsAfterPhase(sessionID, scopeTargetID string, phase int) error {
    log.Printf("Analyzing kill chains after phase %d for session %s", phase, sessionID)
    
    // Initialize kill chain detector
    killChainDetector := utils.NewKillChainDetector(orchestrator.dbPool)
    
    // Run kill chain analysis
    detectedChains, err := killChainDetector.AnalyzeKillChains(sessionID, scopeTargetID)
    if err != nil {
        log.Printf("Kill chain analysis failed: %v", err)
        return err
    }
    
    if len(detectedChains) == 0 {
        log.Printf("No kill chains detected for session %s", sessionID)
        return nil
    }
    
    // Prioritize findings based on kill chain scores
    err = orchestrator.prioritizeFindingsByKillChain(sessionID, detectedChains)
    if err != nil {
        log.Printf("Failed to prioritize findings by kill chain: %v", err)
    }
    
    // Update workflow priorities based on kill chain analysis
    err = orchestrator.updateWorkflowPriorities(sessionID, detectedChains)
    if err != nil {
        log.Printf("Failed to update workflow priorities: %v", err)
    }
    
    log.Printf("Kill chain analysis complete: %d chains detected for session %s", 
        len(detectedChains), sessionID)
    
    return nil
}

// Update finding priorities based on kill chain membership
func (orchestrator *ToolOrchestrator) prioritizeFindingsByKillChain(sessionID string, chains []DetectedKillChain) error {
    for _, chain := range chains {
        // Update kill chain score for each finding in the chain
        for _, finding := range chain.Findings {
            query := `
                UPDATE findings 
                SET kill_chain_score = $1, updated_at = NOW()
                WHERE id = $2
            `
            
            _, err := orchestrator.dbPool.Exec(context.Background(), query, 
                chain.ChainScore, finding.ID)
            if err != nil {
                log.Printf("Failed to update kill chain score for finding %s: %v", finding.ID, err)
            }
        }
    }
    
    return nil
}

// Update workflow priorities to focus on high-value kill chains
func (orchestrator *ToolOrchestrator) updateWorkflowPriorities(sessionID string, chains []DetectedKillChain) error {
    // Find the highest scoring kill chain
    highestScore := 0
    var priorityChain *DetectedKillChain
    
    for i, chain := range chains {
        if chain.ChainScore > highestScore {
            highestScore = chain.ChainScore
            priorityChain = &chains[i]
        }
    }
    
    if priorityChain != nil && priorityChain.ChainScore >= 80 {
        // Focus additional testing on high-value chains
        log.Printf("High-value kill chain detected (Score: %d): %s", 
            priorityChain.ChainScore, priorityChain.PatternName)
        
        // Trigger additional targeted testing for this chain
        return orchestrator.triggerAdditionalTestingForChain(*priorityChain)
    }
    
    return nil
}

// Trigger additional testing for high-value kill chains
func (orchestrator *ToolOrchestrator) triggerAdditionalTestingForChain(chain DetectedKillChain) error {
    log.Printf("Triggering additional testing for kill chain: %s", chain.PatternName)
    
    // Additional testing based on chain type
    switch chain.PatternName {
    case "SSRF_to_Cloud_Takeover":
        // Focus on cloud metadata endpoints and internal network scanning
        return orchestrator.enhanceSSRFTesting(chain)
    case "File_Upload_to_RCE":
        // Test various file types and execution contexts
        return orchestrator.enhanceFileUploadTesting(chain)
    case "IDOR_to_Privilege_Escalation":
        // Test administrative endpoints and user enumeration
        return orchestrator.enhanceIDORTesting(chain)
    }
    
    return nil
}
```

This kill-chain aware system transforms the URL workflow from individual vulnerability detection to strategic attack path identification, ensuring that the most impactful security issues are prioritized and validated first.

