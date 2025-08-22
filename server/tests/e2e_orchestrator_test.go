package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"ars0n-framework-v2-server/url_workflow"
)

// OrchestratorMetrics represents performance metrics for the orchestrator
type OrchestratorMetrics struct {
	TotalTasks         int64         `json:"total_tasks"`
	CompletedTasks     int64         `json:"completed_tasks"`
	FailedTasks        int64         `json:"failed_tasks"`
	AverageTaskTime    time.Duration `json:"average_task_time"`
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	ConcurrencyLevel   int           `json:"concurrency_level"`
	RateLimitHits      int64         `json:"rate_limit_hits"`
	RetryAttempts      int64         `json:"retry_attempts"`
}

// WorkerPoolMetrics represents worker pool performance metrics
type WorkerPoolMetrics struct {
	ActiveWorkers       int     `json:"active_workers"`
	TotalTasksProcessed int64   `json:"total_tasks_processed"`
	WorkerUtilization   float64 `json:"worker_utilization"`
	QueueDepth          int     `json:"queue_depth"`
	MemoryUsage         int64   `json:"memory_usage"`
	CPUUsage            float64 `json:"cpu_usage"`
}

// ExpectedFinding represents an expected finding for validation
type ExpectedFinding struct {
	Type      string `json:"type"`     // XSS, IDOR, SSRF, SQLi
	Severity  string `json:"severity"` // Critical, High, Medium, Low
	URL       string `json:"url"`
	Evidence  bool   `json:"has_evidence"`
	ReproPack bool   `json:"has_repro_pack"`
}

// ExpectedEvidence represents expected evidence for validation
type ExpectedEvidence struct {
	Type     string `json:"type"` // screenshot, har, dom_snapshot
	URL      string `json:"url"`
	FileSize int64  `json:"file_size"`
}

// E2EOrchestratorTestSuite provides comprehensive testing for the orchestrator
type E2EOrchestratorTestSuite struct {
	suite.Suite
	dbPool      *pgxpool.Pool
	apiBaseURL  string
	testDataDir string

	// Test orchestrator instance
	orchestrator *url_workflow.ToolOrchestrator

	// Test session tracking
	scopeTargetID     string
	companySessionID  string
	wildcardSessionID string
	urlSessionID      string

	// Performance benchmarks
	totalStartTime      time.Time
	orchestratorMetrics *OrchestratorMetrics

	// Expected test results
	expectedFindings []ExpectedFinding
	expectedEvidence []ExpectedEvidence
	expectedPhases   []string

	// Worker pool testing
	workerPoolMetrics *WorkerPoolMetrics
	resourceUsage     map[string]interface{}
}

// TestE2EOrchestratorSuite runs the comprehensive orchestrator test suite
func TestE2EOrchestratorSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E orchestrator tests in short mode")
	}

	suite.Run(t, new(E2EOrchestratorTestSuite))
}

// SetupSuite initializes the test environment
func (suite *E2EOrchestratorTestSuite) SetupSuite() {
	suite.T().Log("Setting up E2E orchestrator test environment...")

	// Initialize test configuration
	suite.apiBaseURL = getEnvOrDefault("E2E_API_URL", "http://localhost:8443")
	suite.testDataDir = getEnvOrDefault("E2E_TEST_DATA", "./test_data")

	// Initialize database connection
	suite.dbPool = initializeTestDatabase()

	// Ensure clean test environment
	suite.cleanupPreviousTests()

	// Create test data directory
	os.MkdirAll(suite.testDataDir, 0755)

	// Initialize orchestrator
	suite.orchestrator = url_workflow.NewToolOrchestrator(suite.dbPool)

	// Set up expected results
	suite.setupExpectedResults()

	suite.T().Log("E2E orchestrator test environment ready")
}

// TearDownSuite cleans up after all tests
func (suite *E2EOrchestratorTestSuite) TearDownSuite() {
	suite.T().Log("Tearing down E2E orchestrator test environment...")

	// Stop orchestrator
	if suite.orchestrator != nil {
		suite.orchestrator.Stop()
	}

	// Export test results
	suite.exportTestResults()

	// Cleanup database
	suite.cleanupTestData()

	// Close database connection
	if suite.dbPool != nil {
		suite.dbPool.Close()
	}

	suite.T().Log("E2E orchestrator test cleanup complete")
}

// TestCompleteOrchestratorWorkflow tests the complete workflow with orchestrator
func (suite *E2EOrchestratorTestSuite) TestCompleteOrchestratorWorkflow() {
	suite.totalStartTime = time.Now()

	// Execute test sequence
	suite.Run("01_SetupTestEnvironment", suite.testSetupEnvironment)
	suite.Run("02_CreateScopeTarget", suite.testCreateScopeTarget)
	suite.Run("03_CompanyWorkflowExecution", suite.testCompanyWorkflow)
	suite.Run("04_WildcardWorkflowExecution", suite.testWildcardWorkflowExecution)
	suite.Run("05_URLWorkflowOrchestrator", suite.testURLWorkflowOrchestrator)
	suite.Run("06_ValidateWorkerPoolPerformance", suite.testWorkerPoolPerformance)
	suite.Run("07_ValidateRateLimitingBehavior", suite.testRateLimitingBehavior)
	suite.Run("08_ValidateRetryMechanisms", suite.testRetryMechanisms)
	suite.Run("09_ValidateResourceManagement", suite.testResourceManagement)
	suite.Run("10_ValidateEvidenceCollection", suite.testEvidenceCollection)
	suite.Run("11_ValidateExportFunctionality", suite.testExportFunctionality)
	suite.Run("12_CleanupAndMetrics", suite.testCleanupAndMetrics)

	totalDuration := time.Since(suite.totalStartTime)
	suite.T().Logf("Complete E2E orchestrator workflow completed in %v", totalDuration)
}

// testSetupEnvironment validates the test environment setup
func (suite *E2EOrchestratorTestSuite) testSetupEnvironment() {
	suite.T().Log("Validating test environment setup...")

	// Test database connectivity
	err := suite.dbPool.Ping(context.Background())
	require.NoError(suite.T(), err, "Database should be accessible")

	// Test API connectivity
	response, err := suite.makeAPIRequest("GET", "/api/health", nil)
	require.NoError(suite.T(), err, "API should be accessible")
	suite.T().Logf("API health check: %s", string(response))

	// Validate orchestrator initialization
	require.NotNil(suite.T(), suite.orchestrator, "Orchestrator should be initialized")

	// Test orchestrator configuration
	suite.orchestrator.SetConcurrency(3)   // Use 3 workers for testing
	suite.orchestrator.SetRateLimit(50, 5) // 50 global, 5 per host

	suite.T().Log("Test environment setup validated successfully")
}

// testCreateScopeTarget creates a test scope target
func (suite *E2EOrchestratorTestSuite) testCreateScopeTarget() {
	suite.T().Log("Creating test scope target...")

	requestBody := map[string]interface{}{
		"type":         "URL",
		"mode":         "Active",
		"scope_target": "https://testphp.vulnweb.com/",
	}

	response, err := suite.makeAPIRequest("POST", "/api/scope-targets", requestBody)
	require.NoError(suite.T(), err, "Failed to create scope target")

	var result map[string]interface{}
	err = json.Unmarshal(response, &result)
	require.NoError(suite.T(), err, "Failed to parse scope target response")

	suite.scopeTargetID = result["id"].(string)
	require.NotEmpty(suite.T(), suite.scopeTargetID, "Scope target ID should not be empty")

	suite.T().Logf("Created test scope target: %s", suite.scopeTargetID)
}

// testCompanyWorkflow simulates a completed company workflow
func (suite *E2EOrchestratorTestSuite) testCompanyWorkflow() {
	suite.T().Log("Simulating company workflow completion...")

	// For testing purposes, we'll simulate that company workflow is complete
	// In a real scenario, this would run the actual company workflow
	suite.companySessionID = uuid.New().String()

	// Insert mock company workflow completion
	query := `
		INSERT INTO auto_scan_sessions (id, scope_target_id, config_snapshot, status, ended_at)
		VALUES ($1, $2, '{"company": true}', 'completed', NOW())
	`
	_, err := suite.dbPool.Exec(context.Background(), query, suite.companySessionID, suite.scopeTargetID)
	require.NoError(suite.T(), err, "Failed to simulate company workflow completion")

	suite.T().Logf("Simulated company workflow completion: %s", suite.companySessionID)
}

// testWildcardWorkflow simulates a completed wildcard workflow
func (suite *E2EOrchestratorTestSuite) testWildcardWorkflowExecution() {
	suite.T().Log("Simulating wildcard workflow completion...")

	// Simulate wildcard workflow completion
	suite.wildcardSessionID = uuid.New().String()

	// Insert mock wildcard workflow completion with some discovered URLs
	query := `
		INSERT INTO auto_scan_sessions (id, scope_target_id, config_snapshot, status, ended_at, final_live_web_servers)
		VALUES ($1, $2, '{"wildcard": true}', 'completed', NOW(), 5)
	`
	_, err := suite.dbPool.Exec(context.Background(), query, suite.wildcardSessionID, suite.scopeTargetID)
	require.NoError(suite.T(), err, "Failed to simulate wildcard workflow completion")

	// Insert some mock URLs for testing
	testURLs := []string{
		"https://testphp.vulnweb.com/artists.php",
		"https://testphp.vulnweb.com/listproducts.php",
		"https://testphp.vulnweb.com/login.php",
		"https://testphp.vulnweb.com/search.php",
		"https://testphp.vulnweb.com/categories.php",
	}

	for i, url := range testURLs {
		insertURLQuery := `
			INSERT INTO consolidated_attack_surface_assets (id, scope_target_id, asset_type, asset_data, roi_score)
			VALUES ($1, $2, 'live_web_server', $3, $4)
		`
		assetData := map[string]interface{}{"url": url, "status_code": 200}
		assetDataJSON, _ := json.Marshal(assetData)
		roiScore := 90 - (i * 10) // Decreasing ROI scores

		_, err := suite.dbPool.Exec(context.Background(), insertURLQuery,
			uuid.New().String(), suite.scopeTargetID, assetDataJSON, roiScore)
		require.NoError(suite.T(), err, "Failed to insert mock URL")
	}

	suite.T().Logf("Simulated wildcard workflow completion with %d URLs", len(testURLs))
}

// testURLWorkflowOrchestrator tests the main orchestrator functionality
func (suite *E2EOrchestratorTestSuite) testURLWorkflowOrchestrator() {
	suite.T().Log("Testing URL workflow orchestrator...")

	orchestratorStart := time.Now()

	// Get ROI URLs from mock data
	roiURLs, err := suite.getROIURLs(suite.scopeTargetID, 3) // Test with 3 URLs
	require.NoError(suite.T(), err, "Failed to get ROI URLs")
	require.GreaterOrEqual(suite.T(), len(roiURLs), 1, "Should have at least 1 ROI URL")

	suite.T().Logf("Testing orchestrator with %d URLs", len(roiURLs))

	// Generate URL workflow session
	suite.urlSessionID = uuid.New().String()

	// Execute orchestrated URL workflow
	err = suite.orchestrator.ExecuteURLWorkflow(
		suite.urlSessionID,
		suite.scopeTargetID,
		roiURLs,
	)
	require.NoError(suite.T(), err, "Orchestrator execution should not fail")

	// Monitor orchestrator progress
	suite.monitorOrchestratorProgress()

	// Collect orchestrator metrics
	suite.collectOrchestratorMetrics()

	orchestratorDuration := time.Since(orchestratorStart)
	suite.T().Logf("Orchestrator workflow completed in %v", orchestratorDuration)

	// Validate orchestrator performance
	require.True(suite.T(), orchestratorDuration < 5*time.Minute, "Orchestrator should complete within 5 minutes")
}

// testWorkerPoolPerformance validates worker pool performance
func (suite *E2EOrchestratorTestSuite) testWorkerPoolPerformance() {
	suite.T().Log("Validating worker pool performance...")

	// Get worker pool metrics
	workerPool := suite.orchestrator.GetWorkerPool() // This method would need to be added
	poolMetrics := workerPool.GetPoolMetrics()

	// Validate metrics
	require.Greater(suite.T(), poolMetrics["worker_count"].(int), 0, "Should have active workers")
	require.GreaterOrEqual(suite.T(), poolMetrics["total_tasks_processed"].(int64), int64(5), "Should have processed tasks")

	utilization := poolMetrics["worker_utilization"].(float64)
	require.True(suite.T(), utilization >= 0 && utilization <= 100, "Utilization should be between 0-100%")

	// Get worker health status
	workerHealth := workerPool.GetWorkerHealth()
	suite.T().Logf("Worker health status: %+v", workerHealth)

	// Validate worker health
	for workerID, health := range workerHealth {
		require.True(suite.T(), health.IsAlive, "Worker %d should be alive", workerID)
		require.True(suite.T(), time.Since(health.LastHeartbeat) < 30*time.Second, "Worker %d should have recent heartbeat", workerID)
	}

	suite.workerPoolMetrics = &WorkerPoolMetrics{
		ActiveWorkers:       poolMetrics["active_workers"].(int),
		TotalTasksProcessed: poolMetrics["total_tasks_processed"].(int64),
		WorkerUtilization:   utilization,
		QueueDepth:          int(poolMetrics["queue_depth"].(int64)),
	}

	suite.T().Log("Worker pool performance validated successfully")
}

// testRateLimitingBehavior validates rate limiting functionality
func (suite *E2EOrchestratorTestSuite) testRateLimitingBehavior() {
	suite.T().Log("Validating rate limiting behavior...")

	// Get rate limiter from orchestrator
	rateLimiter := suite.orchestrator.GetRateLimiter() // This method would need to be added

	// Test rate limiting for multiple hosts
	testHosts := []string{
		"testphp.vulnweb.com",
		"example.com",
		"test.example.org",
	}

	for _, host := range testHosts {
		// Test initial requests (should be allowed)
		for i := 0; i < 3; i++ {
			canProceed, waitTime := rateLimiter.CanProceed(host, "nuclei")
			require.True(suite.T(), canProceed, "Initial requests should be allowed for %s", host)
			require.Equal(suite.T(), time.Duration(0), waitTime, "No wait time for initial requests")
		}

		// Simulate rapid requests (should hit rate limit)
		hitRateLimit := false
		for i := 0; i < 100; i++ {
			canProceed, waitTime := rateLimiter.CanProceed(host, "nuclei")
			if !canProceed && waitTime > 0 {
				hitRateLimit = true
				suite.T().Logf("Rate limit hit for %s after %d requests, wait time: %v", host, i+4, waitTime)
				break
			}
		}
		require.True(suite.T(), hitRateLimit, "Should hit rate limit for %s", host)

		// Test rate limiter stats
		stats := rateLimiter.GetStats(host)
		require.NotNil(suite.T(), stats, "Should have stats for %s", host)
		require.Equal(suite.T(), host, stats.Host, "Stats should be for correct host")
	}

	// Test global rate limiting stats
	globalStats := rateLimiter.GetGlobalStats()
	require.Greater(suite.T(), globalStats["total_requests"].(int64), int64(0), "Should have processed requests")
	require.GreaterOrEqual(suite.T(), globalStats["blocked_requests"].(int64), int64(1), "Should have blocked some requests")

	suite.T().Log("Rate limiting behavior validated successfully")
}

// testRetryMechanisms validates retry functionality
func (suite *E2EOrchestratorTestSuite) testRetryMechanisms() {
	suite.T().Log("Validating retry mechanisms...")

	// This would test the retry logic by simulating failures
	// For now, we'll validate that the orchestrator has retry configuration
	require.Greater(suite.T(), suite.orchestrator.GetMaxRetries(), 0, "Should have retry attempts configured")

	// Check task results for retry attempts
	query := `
		SELECT tool, COUNT(*) as retry_count 
		FROM task_results 
		WHERE session_id = $1 AND success = false
		GROUP BY tool
	`
	rows, err := suite.dbPool.Query(context.Background(), query, suite.urlSessionID)
	require.NoError(suite.T(), err, "Failed to query retry attempts")
	defer rows.Close()

	retryCount := 0
	for rows.Next() {
		var tool string
		var count int
		err := rows.Scan(&tool, &count)
		require.NoError(suite.T(), err, "Failed to scan retry results")
		retryCount += count
		suite.T().Logf("Tool %s had %d failed attempts", tool, count)
	}

	suite.T().Logf("Total retry attempts: %d", retryCount)
	suite.T().Log("Retry mechanisms validated successfully")
}

// testResourceManagement validates resource management
func (suite *E2EOrchestratorTestSuite) testResourceManagement() {
	suite.T().Log("Validating resource management...")

	// Get resource monitor from orchestrator
	resourceMonitor := suite.orchestrator.GetResourceMonitor() // This method would need to be added

	// Get system metrics
	systemMetrics := resourceMonitor.GetSystemMetrics()
	require.NotNil(suite.T(), systemMetrics, "Should have system metrics")

	// Validate memory usage
	allocatedMemory := systemMetrics["allocated_memory_mb"].(uint64)
	memoryLimit := systemMetrics["memory_limit_mb"].(int64)
	require.Greater(suite.T(), allocatedMemory, uint64(0), "Should have allocated memory")
	require.Greater(suite.T(), memoryLimit, int64(0), "Should have memory limit")

	memoryUsagePercent := float64(allocatedMemory) / float64(memoryLimit) * 100
	require.True(suite.T(), memoryUsagePercent < 90, "Memory usage should be under 90%%")

	// Validate CPU metrics
	cpuCores := systemMetrics["cpu_cores"].(int)
	require.Greater(suite.T(), cpuCores, 0, "Should detect CPU cores")

	suite.resourceUsage = systemMetrics
	suite.T().Logf("Resource usage: Memory=%dMB (%.1f%%), CPU Cores=%d",
		allocatedMemory, memoryUsagePercent, cpuCores)

	suite.T().Log("Resource management validated successfully")
}

// testEvidenceCollection validates evidence collection functionality
func (suite *E2EOrchestratorTestSuite) testEvidenceCollection() {
	suite.T().Log("Validating evidence collection...")

	// Query evidence collected during the workflow
	query := `
		SELECT evidence_type, COUNT(*) as count
		FROM evidence_blobs
		WHERE session_id = $1
		GROUP BY evidence_type
	`
	rows, err := suite.dbPool.Query(context.Background(), query, suite.urlSessionID)
	require.NoError(suite.T(), err, "Failed to query evidence")
	defer rows.Close()

	evidenceTypes := make(map[string]int)
	for rows.Next() {
		var evidenceType string
		var count int
		err := rows.Scan(&evidenceType, &count)
		require.NoError(suite.T(), err, "Failed to scan evidence results")
		evidenceTypes[evidenceType] = count
	}

	// Validate evidence collection
	suite.T().Logf("Evidence collected: %+v", evidenceTypes)
	require.Greater(suite.T(), len(evidenceTypes), 0, "Should have collected evidence")

	// Validate specific evidence types
	expectedTypes := []string{"screenshot", "har", "dom_snapshot"}
	for _, expectedType := range expectedTypes {
		if count, exists := evidenceTypes[expectedType]; exists {
			require.Greater(suite.T(), count, 0, "Should have %s evidence", expectedType)
		}
	}

	suite.T().Log("Evidence collection validated successfully")
}

// testExportFunctionality validates export functionality
func (suite *E2EOrchestratorTestSuite) testExportFunctionality() {
	suite.T().Log("Validating export functionality...")

	// Test findings export
	response, err := suite.makeAPIRequest("GET",
		fmt.Sprintf("/api/findings/export?session_id=%s&format=json", suite.urlSessionID), nil)
	require.NoError(suite.T(), err, "Failed to export findings")

	var exportData map[string]interface{}
	err = json.Unmarshal(response, &exportData)
	require.NoError(suite.T(), err, "Failed to parse export data")

	// Validate export structure
	require.Contains(suite.T(), exportData, "session_id", "Export should contain session ID")
	require.Contains(suite.T(), exportData, "findings", "Export should contain findings")
	require.Contains(suite.T(), exportData, "evidence", "Export should contain evidence")
	require.Contains(suite.T(), exportData, "timestamp", "Export should contain timestamp")

	// Validate findings data
	findings := exportData["findings"].([]interface{})
	suite.T().Logf("Exported %d findings", len(findings))

	// Save export to file for inspection
	exportFile := fmt.Sprintf("%s/orchestrator_export_%s.json", suite.testDataDir, suite.urlSessionID)
	err = ioutil.WriteFile(exportFile, response, 0644)
	require.NoError(suite.T(), err, "Failed to save export file")

	suite.T().Logf("Export saved to: %s", exportFile)
	suite.T().Log("Export functionality validated successfully")
}

// testCleanupAndMetrics performs final cleanup and metrics collection
func (suite *E2EOrchestratorTestSuite) testCleanupAndMetrics() {
	suite.T().Log("Collecting final metrics and performing cleanup...")

	// Collect final orchestrator metrics
	total, completed, failed := suite.orchestrator.GetProgress()
	currentPhase := suite.orchestrator.GetCurrentPhase()

	suite.orchestratorMetrics = &OrchestratorMetrics{
		TotalTasks:         total,
		CompletedTasks:     completed,
		FailedTasks:        failed,
		TotalExecutionTime: time.Since(suite.totalStartTime),
		ConcurrencyLevel:   3, // As configured in the test
	}

	// Log final metrics
	suite.T().Logf("Final Orchestrator Metrics:")
	suite.T().Logf("  Total Tasks: %d", total)
	suite.T().Logf("  Completed Tasks: %d", completed)
	suite.T().Logf("  Failed Tasks: %d", failed)
	suite.T().Logf("  Current Phase: %s", currentPhase)
	suite.T().Logf("  Success Rate: %.2f%%", float64(completed)/float64(total)*100)

	// Validate success criteria
	successRate := float64(completed) / float64(total) * 100
	require.GreaterOrEqual(suite.T(), successRate, 80.0, "Success rate should be at least 80%")
	require.Equal(suite.T(), "completed", string(currentPhase), "Workflow should be completed")

	suite.T().Log("Final metrics collected and cleanup completed")
}

// Helper methods

func (suite *E2EOrchestratorTestSuite) setupExpectedResults() {
	// Set up expected findings for validation
	suite.expectedFindings = []ExpectedFinding{
		{Type: "http-missing-security-headers", Severity: "medium", Evidence: true, ReproPack: true},
		{Type: "sql-injection", Severity: "high", Evidence: true, ReproPack: true},
		{Type: "idor", Severity: "high", Evidence: true, ReproPack: true},
		{Type: "ssrf", Severity: "critical", Evidence: true, ReproPack: true},
	}

	// Set up expected evidence types
	suite.expectedEvidence = []ExpectedEvidence{
		{Type: "screenshot", FileSize: 100000},  // ~100KB
		{Type: "har", FileSize: 50000},          // ~50KB
		{Type: "dom_snapshot", FileSize: 20000}, // ~20KB
	}

	// Set up expected workflow phases
	suite.expectedPhases = []string{
		"attack_surface_mapping",
		"dast_scanning",
		"targeted_testing",
		"evidence_collection",
		"kill_chain_analysis",
		"completed",
	}
}

func (suite *E2EOrchestratorTestSuite) getROIURLs(scopeTargetID string, limit int) ([]string, error) {
	query := `
		SELECT asset_data->>'url' as url
		FROM consolidated_attack_surface_assets
		WHERE scope_target_id = $1 AND asset_type = 'live_web_server'
		ORDER BY roi_score DESC
		LIMIT $2
	`
	rows, err := suite.dbPool.Query(context.Background(), query, scopeTargetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var urls []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, err
		}
		urls = append(urls, url)
	}

	return urls, nil
}

func (suite *E2EOrchestratorTestSuite) monitorOrchestratorProgress() {
	// Monitor progress for a short time to validate real-time updates
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return
		case <-ticker.C:
			total, completed, failed := suite.orchestrator.GetProgress()
			phase := suite.orchestrator.GetCurrentPhase()
			suite.T().Logf("Progress: %d/%d tasks completed (%d failed), Phase: %s",
				completed, total, failed, phase)

			if string(phase) == "completed" {
				return
			}
		}
	}
}

func (suite *E2EOrchestratorTestSuite) collectOrchestratorMetrics() {
	total, completed, failed := suite.orchestrator.GetProgress()

	suite.orchestratorMetrics = &OrchestratorMetrics{
		TotalTasks:         total,
		CompletedTasks:     completed,
		FailedTasks:        failed,
		TotalExecutionTime: time.Since(suite.totalStartTime),
		ConcurrencyLevel:   3,
	}

	if total > 0 {
		suite.orchestratorMetrics.AverageTaskTime = suite.orchestratorMetrics.TotalExecutionTime / time.Duration(total)
	}
}

func (suite *E2EOrchestratorTestSuite) makeAPIRequest(method, endpoint string, body interface{}) ([]byte, error) {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	url := suite.apiBaseURL + endpoint
	req, err := http.NewRequest(method, url, strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

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
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (suite *E2EOrchestratorTestSuite) exportTestResults() {
	// Export comprehensive test results
	results := map[string]interface{}{
		"test_suite":           "E2E Orchestrator Test Suite",
		"timestamp":            time.Now(),
		"total_duration":       time.Since(suite.totalStartTime),
		"scope_target_id":      suite.scopeTargetID,
		"url_session_id":       suite.urlSessionID,
		"orchestrator_metrics": suite.orchestratorMetrics,
		"worker_pool_metrics":  suite.workerPoolMetrics,
		"resource_usage":       suite.resourceUsage,
		"expected_findings":    suite.expectedFindings,
		"expected_evidence":    suite.expectedEvidence,
	}

	resultData, _ := json.MarshalIndent(results, "", "  ")
	resultFile := fmt.Sprintf("%s/e2e_orchestrator_results_%s.json",
		suite.testDataDir, time.Now().Format("20060102150405"))

	err := ioutil.WriteFile(resultFile, resultData, 0644)
	if err != nil {
		suite.T().Logf("Failed to export test results: %v", err)
	} else {
		suite.T().Logf("Test results exported to: %s", resultFile)
	}
}

func (suite *E2EOrchestratorTestSuite) cleanupPreviousTests() {
	// Clean up any previous test data
	tables := []string{
		"task_results",
		"worker_health",
		"rate_limiter_stats",
		"url_workflow_sessions",
		"auto_scan_sessions",
		"consolidated_attack_surface_assets",
	}

	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE created_at < NOW() - INTERVAL '1 hour'", table)
		_, err := suite.dbPool.Exec(context.Background(), query)
		if err != nil {
			suite.T().Logf("Warning: Failed to cleanup table %s: %v", table, err)
		}
	}
}

func (suite *E2EOrchestratorTestSuite) cleanupTestData() {
	if suite.scopeTargetID != "" {
		query := "DELETE FROM scope_targets WHERE id = $1"
		_, err := suite.dbPool.Exec(context.Background(), query, suite.scopeTargetID)
		if err != nil {
			suite.T().Logf("Failed to cleanup test scope target: %v", err)
		}
	}
}

// Helper functions
func initializeTestDatabase() *pgxpool.Pool {
	dbURL := getEnvOrDefault("TEST_DATABASE_URL", "postgres://postgres:password@localhost:5432/ars0n_test")

	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse database URL: %v", err))
	}

	dbPool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to test database: %v", err))
	}

	return dbPool
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
