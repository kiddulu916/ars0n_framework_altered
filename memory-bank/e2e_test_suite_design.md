# End-to-End Test Suite Design - Company→Wildcard→URL Workflow Sequence

## Overview

This document outlines the comprehensive end-to-end test suite for the complete Ars0n Framework workflow sequence: Company → Wildcard → URL. The test suite validates the entire automated bug bounty hunting pipeline from initial target setup through final vulnerability reporting and evidence collection.

## E2E Testing Philosophy

### Core Principles
- **Complete Workflow Coverage**: Test the entire Company→Wildcard→URL sequence
- **Real-World Scenarios**: Use realistic target data and expected vulnerabilities
- **Integration Validation**: Verify all components work together seamlessly
- **Performance Benchmarking**: Measure execution times and resource usage
- **Evidence Verification**: Validate comprehensive evidence collection
- **Educational Value**: Demonstrate the "Earn While You Learn" philosophy

### Test Sequence Overview
```
Setup Test Environment → Company Workflow → Wildcard Workflow → URL Workflow → Validation → Cleanup
        ↓                      ↓                ↓               ↓           ↓         ↓
Test Database Setup    ASN Discovery    Subdomain Enum    Auto Testing   Evidence    Resource
Test Containers       Network Mapping   Live Detection    Vuln Discovery  Collection  Cleanup
Synthetic Targets     GitHub Recon      ROI Scoring       Kill-Chain      Export      Logs
```

## Test Implementation

### 1. E2E Test Framework

```go
// server/tests/e2e_workflow_test.go
package tests

import (
    "context"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type E2EWorkflowTestSuite struct {
    suite.Suite
    dbPool       *pgxpool.Pool
    apiBaseURL   string
    testDataDir  string
    
    // Test artifacts
    scopeTargetID        string
    companySessionID     string
    wildcardSessionID    string
    urlSessionID         string
    
    // Expected results tracking
    expectedAssets       int
    expectedSubdomains   int
    expectedURLs         int
    expectedFindings     int
    
    // Performance metrics
    startTime            time.Time
    companyDuration      time.Duration
    wildcardDuration     time.Duration
    urlDuration          time.Duration
    totalDuration        time.Duration
    
    // Evidence collection
    collectedEvidence    []string
    exportedData         map[string]interface{}
}

func TestE2EWorkflowSuite(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping E2E tests in short mode")
    }
    
    suite.Run(t, new(E2EWorkflowTestSuite))
}

func (suite *E2EWorkflowTestSuite) SetupSuite() {
    suite.T().Log("Setting up E2E test environment...")
    
    // Initialize test configuration
    suite.apiBaseURL = getEnvOrDefault("E2E_API_URL", "http://localhost:8443")
    suite.testDataDir = getEnvOrDefault("E2E_TEST_DATA", "./test_data")
    
    // Initialize database connection
    suite.dbPool = initializeTestDatabase()
    
    // Ensure clean test environment
    suite.cleanupPreviousTests()
    
    // Create test data directory
    os.MkdirAll(suite.testDataDir, 0755)
    
    suite.T().Log("E2E test environment ready")
}

func (suite *E2EWorkflowTestSuite) TearDownSuite() {
    suite.T().Log("Cleaning up E2E test environment...")
    
    // Export test results
    suite.exportTestResults()
    
    // Cleanup database
    suite.cleanupTestData()
    
    // Close database connection
    if suite.dbPool != nil {
        suite.dbPool.Close()
    }
    
    suite.T().Log("E2E test cleanup complete")
}

// Main E2E test - Complete workflow sequence
func (suite *E2EWorkflowTestSuite) TestCompleteWorkflowSequence() {
    suite.startTime = time.Now()
    
    // Test sequence
    suite.Run("01_CreateScopeTarget", suite.testCreateScopeTarget)
    suite.Run("02_CompanyWorkflow", suite.testCompanyWorkflow)
    suite.Run("03_WildcardWorkflow", suite.testWildcardWorkflow)
    suite.Run("04_URLWorkflow", suite.testURLWorkflow)
    suite.Run("05_ValidateIntegration", suite.testValidateIntegration)
    suite.Run("06_VerifyEvidence", suite.testVerifyEvidence)
    suite.Run("07_ExportResults", suite.testExportResults)
    
    suite.totalDuration = time.Since(suite.startTime)
    suite.T().Logf("Complete E2E workflow completed in %v", suite.totalDuration)
}

// Step 1: Create scope target for testing
func (suite *E2EWorkflowTestSuite) testCreateScopeTarget() {
    suite.T().Log("Creating test scope target...")
    
    // Use a synthetic test target
    targetData := map[string]interface{}{
        "name":        "E2E Test Target",
        "type":        "Company",
        "description": "End-to-end test target for Ars0n Framework",
        "target":      "testcorp.example.com",
        "scope_config": map[string]interface{}{
            "include_subdomains": true,
            "max_depth":         3,
            "rate_limit":        10,
        },
    }
    
    response, err := suite.makeAPIRequest("POST", "/api/scope-targets", targetData)
    require.NoError(suite.T(), err, "Failed to create scope target")
    
    var result map[string]interface{}
    err = json.Unmarshal(response, &result)
    require.NoError(suite.T(), err, "Failed to parse scope target response")
    
    suite.scopeTargetID = result["id"].(string)
    require.NotEmpty(suite.T(), suite.scopeTargetID, "Scope target ID should not be empty")
    
    suite.T().Logf("Created scope target: %s", suite.scopeTargetID)
}

// Step 2: Execute Company workflow
func (suite *E2EWorkflowTestSuite) testCompanyWorkflow() {
    suite.T().Log("Executing Company workflow...")
    companyStart := time.Now()
    
    // Initiate Company workflow
    response, err := suite.makeAPIRequest("POST", 
        fmt.Sprintf("/api/company-workflow/initiate/%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to initiate Company workflow")
    
    var result map[string]interface{}
    err = json.Unmarshal(response, &result)
    require.NoError(suite.T(), err, "Failed to parse Company workflow response")
    
    suite.companySessionID = result["session_id"].(string)
    require.NotEmpty(suite.T(), suite.companySessionID, "Company session ID should not be empty")
    
    // Monitor Company workflow progress
    suite.waitForWorkflowCompletion("company", suite.companySessionID, 10*time.Minute)
    
    // Validate Company workflow results
    suite.validateCompanyResults()
    
    suite.companyDuration = time.Since(companyStart)
    suite.T().Logf("Company workflow completed in %v", suite.companyDuration)
}

// Step 3: Execute Wildcard workflow
func (suite *E2EWorkflowTestSuite) testWildcardWorkflow() {
    suite.T().Log("Executing Wildcard workflow...")
    wildcardStart := time.Now()
    
    // Verify Company workflow completion
    suite.verifyWorkflowPrerequisites("wildcard")
    
    // Initiate Wildcard workflow
    response, err := suite.makeAPIRequest("POST", 
        fmt.Sprintf("/api/wildcard-workflow/initiate/%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to initiate Wildcard workflow")
    
    var result map[string]interface{}
    err = json.Unmarshal(response, &result)
    require.NoError(suite.T(), err, "Failed to parse Wildcard workflow response")
    
    suite.wildcardSessionID = result["session_id"].(string)
    require.NotEmpty(suite.T(), suite.wildcardSessionID, "Wildcard session ID should not be empty")
    
    // Monitor Wildcard workflow progress
    suite.waitForWorkflowCompletion("wildcard", suite.wildcardSessionID, 15*time.Minute)
    
    // Validate Wildcard workflow results
    suite.validateWildcardResults()
    
    suite.wildcardDuration = time.Since(wildcardStart)
    suite.T().Logf("Wildcard workflow completed in %v", suite.wildcardDuration)
}

// Step 4: Execute URL workflow
func (suite *E2EWorkflowTestSuite) testURLWorkflow() {
    suite.T().Log("Executing URL workflow...")
    urlStart := time.Now()
    
    // Verify prerequisites (Company + Wildcard completion)
    suite.verifyWorkflowPrerequisites("url")
    
    // Get ROI-scored URLs
    roiResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/url-workflow/roi-urls/%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to get ROI URLs")
    
    var roiResult map[string]interface{}
    err = json.Unmarshal(roiResponse, &roiResult)
    require.NoError(suite.T(), err, "Failed to parse ROI URLs response")
    
    roiUrls := roiResult["urls"].([]interface{})
    require.GreaterOrEqual(suite.T(), len(roiUrls), 1, "Should have at least 1 ROI URL")
    suite.expectedURLs = len(roiUrls)
    
    // Initiate URL workflow
    response, err := suite.makeAPIRequest("POST", 
        fmt.Sprintf("/api/url-workflow/initiate/%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to initiate URL workflow")
    
    var result map[string]interface{}
    err = json.Unmarshal(response, &result)
    require.NoError(suite.T(), err, "Failed to parse URL workflow response")
    
    suite.urlSessionID = result["session_id"].(string)
    require.NotEmpty(suite.T(), suite.urlSessionID, "URL session ID should not be empty")
    
    // Monitor URL workflow progress (longer timeout for comprehensive testing)
    suite.waitForWorkflowCompletion("url", suite.urlSessionID, 30*time.Minute)
    
    // Validate URL workflow results
    suite.validateURLResults()
    
    suite.urlDuration = time.Since(urlStart)
    suite.T().Logf("URL workflow completed in %v", suite.urlDuration)
}

// Step 5: Validate integration between workflows
func (suite *E2EWorkflowTestSuite) testValidateIntegration() {
    suite.T().Log("Validating workflow integration...")
    
    // Verify data flow between workflows
    suite.validateDataFlow()
    
    // Verify consolidated attack surface
    suite.validateConsolidatedAttackSurface()
    
    // Verify ROI algorithm integration
    suite.validateROIIntegration()
    
    // Verify kill-chain analysis
    suite.validateKillChainAnalysis()
    
    suite.T().Log("Workflow integration validation complete")
}

// Step 6: Verify comprehensive evidence collection
func (suite *E2EWorkflowTestSuite) testVerifyEvidence() {
    suite.T().Log("Verifying evidence collection...")
    
    // Get all findings for the URL workflow session
    findingsResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/findings?session_id=%s", suite.urlSessionID), nil)
    require.NoError(suite.T(), err, "Failed to get findings")
    
    var findingsResult []map[string]interface{}
    err = json.Unmarshal(findingsResponse, &findingsResult)
    require.NoError(suite.T(), err, "Failed to parse findings response")
    
    suite.expectedFindings = len(findingsResult)
    
    // Verify evidence for each finding
    for _, finding := range findingsResult {
        findingID := finding["id"].(string)
        
        // Get evidence for this finding
        evidenceResponse, err := suite.makeAPIRequest("GET", 
            fmt.Sprintf("/api/evidence/finding/%s", findingID), nil)
        require.NoError(suite.T(), err, fmt.Sprintf("Failed to get evidence for finding %s", findingID))
        
        var evidenceResult map[string]interface{}
        err = json.Unmarshal(evidenceResponse, &evidenceResult)
        require.NoError(suite.T(), err, "Failed to parse evidence response")
        
        evidence := evidenceResult["evidence"].([]interface{})
        assert.GreaterOrEqual(suite.T(), len(evidence), 1, 
            fmt.Sprintf("Finding %s should have at least 1 piece of evidence", findingID))
        
        // Verify evidence types
        evidenceTypes := make(map[string]bool)
        for _, e := range evidence {
            evidenceItem := e.(map[string]interface{})
            evidenceTypes[evidenceItem["type"].(string)] = true
        }
        
        // Check for required evidence types
        if finding["category"].(string) == "xss" {
            assert.True(suite.T(), evidenceTypes["screenshot"], "XSS finding should have screenshot evidence")
            assert.True(suite.T(), evidenceTypes["dom"], "XSS finding should have DOM evidence")
        }
        
        suite.collectedEvidence = append(suite.collectedEvidence, findingID)
    }
    
    suite.T().Logf("Verified evidence for %d findings", len(findingsResult))
}

// Step 7: Test export functionality
func (suite *E2EWorkflowTestSuite) testExportResults() {
    suite.T().Log("Testing export functionality...")
    
    // Export findings as JSON
    exportResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/findings/export?session_id=%s&format=json", suite.urlSessionID), nil)
    require.NoError(suite.T(), err, "Failed to export findings")
    
    var exportResult map[string]interface{}
    err = json.Unmarshal(exportResponse, &exportResult)
    require.NoError(suite.T(), err, "Failed to parse export response")
    
    // Validate export structure
    assert.Contains(suite.T(), exportResult, "findings", "Export should contain findings")
    assert.Contains(suite.T(), exportResult, "meta", "Export should contain metadata")
    
    findings := exportResult["findings"].([]interface{})
    assert.Equal(suite.T(), suite.expectedFindings, len(findings), "Export should contain all findings")
    
    // Save export data
    suite.exportedData = exportResult
    
    // Test .rs0n file format export
    rs0nResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/scope-targets/%s/export", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to export .rs0n file")
    
    // Save export file
    exportFile := filepath.Join(suite.testDataDir, "e2e_test_export.rs0n")
    err = ioutil.WriteFile(exportFile, rs0nResponse, 0644)
    require.NoError(suite.T(), err, "Failed to save export file")
    
    suite.T().Logf("Export testing complete - saved to %s", exportFile)
}

// Helper methods for workflow monitoring
func (suite *E2EWorkflowTestSuite) waitForWorkflowCompletion(workflowType, sessionID string, timeout time.Duration) {
    suite.T().Logf("Waiting for %s workflow completion...", workflowType)
    
    deadline := time.Now().Add(timeout)
    checkInterval := 10 * time.Second
    
    for time.Now().Before(deadline) {
        // Check workflow status
        statusResponse, err := suite.makeAPIRequest("GET", 
            fmt.Sprintf("/api/%s-workflow/status/%s", workflowType, sessionID), nil)
        
        if err != nil {
            suite.T().Logf("Error checking workflow status: %v", err)
            time.Sleep(checkInterval)
            continue
        }
        
        var statusResult map[string]interface{}
        err = json.Unmarshal(statusResponse, &statusResult)
        if err != nil {
            suite.T().Logf("Error parsing status response: %v", err)
            time.Sleep(checkInterval)
            continue
        }
        
        status := statusResult["status"].(string)
        progress := statusResult["progress"].(float64)
        
        suite.T().Logf("%s workflow: %s (%.1f%%)", workflowType, status, progress)
        
        if status == "completed" {
            suite.T().Logf("%s workflow completed successfully", workflowType)
            return
        }
        
        if status == "failed" {
            suite.T().Fatalf("%s workflow failed", workflowType)
        }
        
        time.Sleep(checkInterval)
    }
    
    suite.T().Fatalf("%s workflow timed out after %v", workflowType, timeout)
}

// Validation methods
func (suite *E2EWorkflowTestSuite) validateCompanyResults() {
    suite.T().Log("Validating Company workflow results...")
    
    // Check consolidated attack surface assets
    assetsResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/attack-surface/assets?scope_target_id=%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to get attack surface assets")
    
    var assetsResult map[string]interface{}
    err = json.Unmarshal(assetsResponse, &assetsResult)
    require.NoError(suite.T(), err, "Failed to parse assets response")
    
    assets := assetsResult["assets"].([]interface{})
    suite.expectedAssets = len(assets)
    
    assert.GreaterOrEqual(suite.T(), len(assets), 1, "Should discover at least 1 asset")
    
    // Verify asset types
    assetTypes := make(map[string]int)
    for _, asset := range assets {
        assetItem := asset.(map[string]interface{})
        assetType := assetItem["asset_type"].(string)
        assetTypes[assetType]++
    }
    
    suite.T().Logf("Discovered assets: %v", assetTypes)
}

func (suite *E2EWorkflowTestSuite) validateWildcardResults() {
    suite.T().Log("Validating Wildcard workflow results...")
    
    // Check subdomain enumeration results
    subdomainsResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/subdomains/consolidated?scope_target_id=%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to get consolidated subdomains")
    
    var subdomainsResult map[string]interface{}
    err = json.Unmarshal(subdomainsResponse, &subdomainsResult)
    require.NoError(suite.T(), err, "Failed to parse subdomains response")
    
    subdomains := subdomainsResult["subdomains"].([]interface{})
    suite.expectedSubdomains = len(subdomains)
    
    assert.GreaterOrEqual(suite.T(), len(subdomains), 1, "Should discover at least 1 subdomain")
    
    // Verify ROI scoring
    roiScored := 0
    for _, subdomain := range subdomains {
        subdomainItem := subdomain.(map[string]interface{})
        if score, exists := subdomainItem["roi_score"]; exists && score != nil {
            roiScored++
        }
    }
    
    assert.GreaterOrEqual(suite.T(), roiScored, 1, "Should have at least 1 ROI-scored subdomain")
    
    suite.T().Logf("Discovered %d subdomains, %d with ROI scores", len(subdomains), roiScored)
}

func (suite *E2EWorkflowTestSuite) validateURLResults() {
    suite.T().Log("Validating URL workflow results...")
    
    // Get URL workflow session details
    sessionResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/url-workflow/session/%s", suite.urlSessionID), nil)
    require.NoError(suite.T(), err, "Failed to get URL workflow session")
    
    var sessionResult map[string]interface{}
    err = json.Unmarshal(sessionResponse, &sessionResult)
    require.NoError(suite.T(), err, "Failed to parse session response")
    
    assert.Equal(suite.T(), "completed", sessionResult["status"], "URL workflow should be completed")
    
    // Verify all phases were executed
    phases := []string{"attack_surface_mapping", "dast", "targeted_testing", "evidence_collection", "kill_chain_analysis"}
    for _, phase := range phases {
        suite.verifyPhaseExecution(phase)
    }
}

func (suite *E2EWorkflowTestSuite) validateDataFlow() {
    suite.T().Log("Validating data flow between workflows...")
    
    // Verify Company → Wildcard data flow
    // Company workflow should populate consolidated_attack_surface_assets
    // Wildcard workflow should use these assets for subdomain enumeration
    
    // Verify Wildcard → URL data flow  
    // Wildcard workflow should populate ROI-scored URLs
    // URL workflow should use top 10 ROI URLs for testing
    
    roiResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/url-workflow/roi-urls/%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to get ROI URLs")
    
    var roiResult map[string]interface{}
    err = json.Unmarshal(roiResponse, &roiResult)
    require.NoError(suite.T(), err, "Failed to parse ROI URLs")
    
    urls := roiResult["urls"].([]interface{})
    assert.LessOrEqual(suite.T(), len(urls), 10, "Should have at most 10 ROI URLs")
    assert.GreaterOrEqual(suite.T(), len(urls), 1, "Should have at least 1 ROI URL")
    
    // Verify URLs have ROI scores
    for _, url := range urls {
        urlItem := url.(map[string]interface{})
        assert.Contains(suite.T(), urlItem, "roi_score", "URL should have ROI score")
        assert.NotZero(suite.T(), urlItem["roi_score"], "ROI score should not be zero")
    }
}

func (suite *E2EWorkflowTestSuite) validateConsolidatedAttackSurface() {
    // Verify consolidated attack surface contains data from all workflows
    assetsResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/attack-surface/consolidated?scope_target_id=%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to get consolidated attack surface")
    
    var assetsResult map[string]interface{}
    err = json.Unmarshal(assetsResponse, &assetsResult)
    require.NoError(suite.T(), err, "Failed to parse consolidated assets")
    
    assets := assetsResult["assets"].([]interface{})
    assert.GreaterOrEqual(suite.T(), len(assets), suite.expectedAssets, 
        "Consolidated assets should include all discovered assets")
}

func (suite *E2EWorkflowTestSuite) validateROIIntegration() {
    // Verify ROI algorithm properly scored and ranked URLs
    roiResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/roi/analysis?scope_target_id=%s", suite.scopeTargetID), nil)
    require.NoError(suite.T(), err, "Failed to get ROI analysis")
    
    var roiResult map[string]interface{}
    err = json.Unmarshal(roiResponse, &roiResult)
    require.NoError(suite.T(), err, "Failed to parse ROI analysis")
    
    assert.Contains(suite.T(), roiResult, "scored_urls", "ROI analysis should contain scored URLs")
    assert.Contains(suite.T(), roiResult, "algorithm_version", "ROI analysis should contain algorithm version")
}

func (suite *E2EWorkflowTestSuite) validateKillChainAnalysis() {
    // Verify kill-chain analysis was performed
    killChainResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/findings/kill-chains?session_id=%s", suite.urlSessionID), nil)
    require.NoError(suite.T(), err, "Failed to get kill-chain analysis")
    
    var killChainResult map[string]interface{}
    err = json.Unmarshal(killChainResponse, &killChainResult)
    require.NoError(suite.T(), err, "Failed to parse kill-chain analysis")
    
    if chains, exists := killChainResult["chains"]; exists {
        chainList := chains.([]interface{})
        suite.T().Logf("Detected %d kill chains", len(chainList))
        
        // If kill chains were detected, verify they have proper structure
        for _, chain := range chainList {
            chainItem := chain.(map[string]interface{})
            assert.Contains(suite.T(), chainItem, "chain_score", "Kill chain should have score")
            assert.Contains(suite.T(), chainItem, "findings", "Kill chain should have findings")
        }
    }
}

// Helper methods
func (suite *E2EWorkflowTestSuite) makeAPIRequest(method, endpoint string, data interface{}) ([]byte, error) {
    var body []byte
    if data != nil {
        var err error
        body, err = json.Marshal(data)
        if err != nil {
            return nil, err
        }
    }
    
    req, err := http.NewRequest(method, suite.apiBaseURL+endpoint, strings.NewReader(string(body)))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/json")
    
    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    respBody, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    if resp.StatusCode >= 400 {
        return nil, fmt.Errorf("API request failed: %d %s", resp.StatusCode, string(respBody))
    }
    
    return respBody, nil
}

func (suite *E2EWorkflowTestSuite) verifyWorkflowPrerequisites(workflowType string) {
    switch workflowType {
    case "wildcard":
        // Verify Company workflow completed
        suite.verifyWorkflowCompleted("company", suite.companySessionID)
    case "url":
        // Verify both Company and Wildcard workflows completed
        suite.verifyWorkflowCompleted("company", suite.companySessionID)
        suite.verifyWorkflowCompleted("wildcard", suite.wildcardSessionID)
    }
}

func (suite *E2EWorkflowTestSuite) verifyWorkflowCompleted(workflowType, sessionID string) {
    statusResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/%s-workflow/status/%s", workflowType, sessionID), nil)
    require.NoError(suite.T(), err, fmt.Sprintf("Failed to check %s workflow status", workflowType))
    
    var statusResult map[string]interface{}
    err = json.Unmarshal(statusResponse, &statusResult)
    require.NoError(suite.T(), err, fmt.Sprintf("Failed to parse %s workflow status", workflowType))
    
    assert.Equal(suite.T(), "completed", statusResult["status"], 
        fmt.Sprintf("%s workflow should be completed", workflowType))
}

func (suite *E2EWorkflowTestSuite) verifyPhaseExecution(phase string) {
    // Check if phase was executed by looking for task results
    tasksResponse, err := suite.makeAPIRequest("GET", 
        fmt.Sprintf("/api/tasks/results?session_id=%s&phase=%s", suite.urlSessionID, phase), nil)
    
    if err != nil {
        suite.T().Logf("Warning: Could not verify phase %s execution: %v", phase, err)
        return
    }
    
    var tasksResult map[string]interface{}
    err = json.Unmarshal(tasksResponse, &tasksResult)
    if err != nil {
        suite.T().Logf("Warning: Could not parse phase %s results: %v", phase, err)
        return
    }
    
    tasks := tasksResult["tasks"].([]interface{})
    assert.GreaterOrEqual(suite.T(), len(tasks), 1, 
        fmt.Sprintf("Phase %s should have at least 1 executed task", phase))
}

func (suite *E2EWorkflowTestSuite) cleanupPreviousTests() {
    // Clean up any previous test data
    suite.T().Log("Cleaning up previous test data...")
    
    // Delete test scope targets
    cleanup_query := `DELETE FROM scope_targets WHERE name = 'E2E Test Target'`
    suite.dbPool.Exec(context.Background(), cleanup_query)
}

func (suite *E2EWorkflowTestSuite) cleanupTestData() {
    // Clean up test data
    if suite.scopeTargetID != "" {
        suite.makeAPIRequest("DELETE", fmt.Sprintf("/api/scope-targets/%s", suite.scopeTargetID), nil)
    }
}

func (suite *E2EWorkflowTestSuite) exportTestResults() {
    // Export comprehensive test results
    results := map[string]interface{}{
        "test_execution": map[string]interface{}{
            "total_duration":    suite.totalDuration.String(),
            "company_duration":  suite.companyDuration.String(),
            "wildcard_duration": suite.wildcardDuration.String(),
            "url_duration":      suite.urlDuration.String(),
            "started_at":        suite.startTime,
            "completed_at":      time.Now(),
        },
        "discovered_assets": map[string]interface{}{
            "expected_assets":    suite.expectedAssets,
            "expected_subdomains": suite.expectedSubdomains,
            "expected_urls":      suite.expectedURLs,
            "expected_findings":  suite.expectedFindings,
        },
        "evidence_collection": map[string]interface{}{
            "collected_evidence": suite.collectedEvidence,
            "evidence_count":     len(suite.collectedEvidence),
        },
        "exported_data": suite.exportedData,
    }
    
    resultsJSON, _ := json.MarshalIndent(results, "", "  ")
    resultsFile := filepath.Join(suite.testDataDir, "e2e_test_results.json")
    ioutil.WriteFile(resultsFile, resultsJSON, 0644)
    
    suite.T().Logf("Test results exported to %s", resultsFile)
}

// Utility functions
func getEnvOrDefault(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func initializeTestDatabase() *pgxpool.Pool {
    // Initialize test database connection
    // This would use a separate test database
    dbURL := getEnvOrDefault("TEST_DATABASE_URL", "postgresql://user:pass@localhost:5432/ars0n_test_db")
    
    config, err := pgxpool.ParseConfig(dbURL)
    if err != nil {
        panic(fmt.Sprintf("Failed to parse database URL: %v", err))
    }
    
    dbPool, err := pgxpool.ConnectConfig(context.Background(), config)
    if err != nil {
        panic(fmt.Sprintf("Failed to connect to test database: %v", err))
    }
    
    return dbPool
}
```

### 2. Performance Benchmarking

```go
// server/tests/e2e_performance_test.go
package tests

import (
    "testing"
    "time"
)

func BenchmarkCompleteWorkflow(b *testing.B) {
    suite := &E2EWorkflowTestSuite{}
    suite.SetupSuite()
    defer suite.TearDownSuite()
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        suite.TestCompleteWorkflowSequence()
    }
}

func BenchmarkCompanyWorkflow(b *testing.B) {
    // Benchmark individual workflows
    suite := &E2EWorkflowTestSuite{}
    suite.SetupSuite()
    defer suite.TearDownSuite()
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        suite.testCreateScopeTarget()
        suite.testCompanyWorkflow()
    }
}
```

### 3. Test Execution Scripts

```bash
#!/bin/bash
# scripts/run_e2e_tests.sh

set -e

echo "Starting Ars0n Framework E2E Tests..."

# Set test environment variables
export E2E_API_URL="http://localhost:8443"
export E2E_TEST_DATA="./test_data/e2e"
export TEST_DATABASE_URL="postgresql://test_user:test_pass@localhost:5432/ars0n_test_db"

# Create test data directory
mkdir -p ./test_data/e2e

# Start test environment
echo "Starting test services..."
docker-compose -f docker-compose.test.yml up -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 30

# Run database migrations for test database
echo "Setting up test database..."
go run scripts/setup_test_db.go

# Run E2E tests
echo "Running E2E tests..."
go test -v -timeout=45m ./tests -run TestE2EWorkflowSuite

# Run performance benchmarks
echo "Running performance benchmarks..."
go test -v -bench=. -benchtime=1x ./tests -run=^$ -timeout=60m

# Generate test report
echo "Generating test report..."
go run scripts/generate_test_report.go

# Cleanup
echo "Cleaning up test environment..."
docker-compose -f docker-compose.test.yml down

echo "E2E tests completed successfully!"
```

This comprehensive E2E test suite validates the complete Company→Wildcard→URL workflow sequence, ensuring all components work together seamlessly while providing performance benchmarking and comprehensive evidence verification.
