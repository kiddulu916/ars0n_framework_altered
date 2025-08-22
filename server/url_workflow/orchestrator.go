package url_workflow

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"ars0n-framework-v2-server/utils"
)

// WorkflowPhase represents the current phase of the URL workflow
type WorkflowPhase string

const (
	PhaseAttackSurfaceMapping WorkflowPhase = "attack_surface_mapping"
	PhaseDAST                 WorkflowPhase = "dast_scanning"
	PhaseTargetedTesting      WorkflowPhase = "targeted_testing"
	PhaseEvidenceCollection   WorkflowPhase = "evidence_collection"
	PhaseKillChainAnalysis    WorkflowPhase = "kill_chain_analysis"
	PhaseCompleted            WorkflowPhase = "completed"
)

// TaskType represents the type of task to be executed
type TaskType string

const (
	TaskTypeWebCrawling       TaskType = "web_crawling"
	TaskTypeDirectoryBrute    TaskType = "directory_brute"
	TaskTypeJSEndpoints       TaskType = "js_endpoints"
	TaskTypeAPIDiscovery      TaskType = "api_discovery"
	TaskTypeNuclei            TaskType = "nuclei_scan"
	TaskTypeCustomBrowser     TaskType = "custom_browser"
	TaskTypeVulnTesting       TaskType = "vuln_testing"
	TaskTypeEvidenceCollect   TaskType = "evidence_collection"
	TaskTypeKillChainAnalysis TaskType = "kill_chain_analysis"
)

// TaskParams represents parameters for task execution
type TaskParams struct {
	Target        string                 `json:"target"`
	Tool          string                 `json:"tool"`
	Parameters    map[string]interface{} `json:"parameters"`
	SessionID     string                 `json:"session_id"`
	ScopeTargetID string                 `json:"scope_target_id"`
}

// Task represents a unit of work in the orchestrator
type Task struct {
	ID         string        `json:"id"`
	Type       TaskType      `json:"type"`
	Tool       string        `json:"tool"`
	Target     string        `json:"target"`
	Parameters TaskParams    `json:"parameters"`
	Priority   int           `json:"priority"`
	MaxRetries int           `json:"max_retries"`
	Retries    int           `json:"retries"`
	Timeout    time.Duration `json:"timeout"`
	CreatedAt  time.Time     `json:"created_at"`
	StartedAt  *time.Time    `json:"started_at,omitempty"`
}

// TaskResult represents the result of a task execution
type TaskResult struct {
	TaskID      string        `json:"task_id"`
	Tool        string        `json:"tool"`
	Target      string        `json:"target"`
	Success     bool          `json:"success"`
	Error       error         `json:"error,omitempty"`
	Output      string        `json:"output,omitempty"`
	Findings    []interface{} `json:"findings,omitempty"`
	Evidence    []interface{} `json:"evidence,omitempty"`
	Duration    time.Duration `json:"duration"`
	CompletedAt time.Time     `json:"completed_at"`
}

// ToolOrchestrator manages the execution of URL workflow phases with worker pools
type ToolOrchestrator struct {
	// Core components
	dbPool *pgxpool.Pool
	ctx    context.Context
	cancel context.CancelFunc

	// Worker pool management
	workerPool       *WorkerPool
	taskQueue        chan *Task
	resultChannel    chan *TaskResult
	completionSignal chan bool

	// Rate limiting & resource management
	rateLimiter     *utils.IntelligentRateLimiter
	resourceMonitor *ResourceMonitor

	// Progress tracking
	totalTasks     int64
	completedTasks int64
	failedTasks    int64
	currentPhase   WorkflowPhase

	// Session management
	activeSessionID string
	scopeTargetID   string
	selectedURLs    []string

	// Tool management
	tools        map[string]ToolInterface
	toolConfigs  map[string]ToolConfig
	enabledTools []string

	// Configuration
	concurrentTools  int           // 5 concurrent tool executions
	globalRateLimit  int           // 100 requests per minute
	perHostRateLimit int           // 10 requests per minute per host
	maxRetries       int           // 3 retry attempts per task
	taskTimeout      time.Duration // 10 minute timeout per task

	// Synchronization
	mu sync.RWMutex
}

// ToolInterface defines the interface that all security tools must implement
type ToolInterface interface {
	Execute(ctx context.Context, params TaskParams) (*TaskResult, error)
	Validate(params TaskParams) error
	GetName() string
	GetType() TaskType
	RequiresScope() bool
	RequiresAuth() bool
	GetRateLimit() int // Requests per minute
}

// ToolConfig represents configuration for a specific tool
type ToolConfig struct {
	Enabled        bool                   `json:"enabled"`
	RateLimit      int                    `json:"rate_limit"`
	MaxConcurrency int                    `json:"max_concurrency"`
	Timeout        time.Duration          `json:"timeout"`
	RetryAttempts  int                    `json:"retry_attempts"`
	Parameters     map[string]interface{} `json:"parameters"`
}

// NewToolOrchestrator creates a new orchestrator instance
func NewToolOrchestrator(dbPool *pgxpool.Pool) *ToolOrchestrator {
	ctx, cancel := context.WithCancel(context.Background())

	orchestrator := &ToolOrchestrator{
		dbPool:           dbPool,
		ctx:              ctx,
		cancel:           cancel,
		taskQueue:        make(chan *Task, 1000),
		resultChannel:    make(chan *TaskResult, 1000),
		completionSignal: make(chan bool, 1),
		tools:            make(map[string]ToolInterface),
		toolConfigs:      make(map[string]ToolConfig),
		globalRateLimit:  100,              // 100 requests per minute globally
		perHostRateLimit: 10,               // 10 requests per minute per host
		concurrentTools:  5,                // 5 concurrent tool executions
		maxRetries:       3,                // 3 retry attempts
		taskTimeout:      10 * time.Minute, // 10 minute timeout
	}

	// Initialize components
	orchestrator.initializeComponents()
	orchestrator.registerTools()

	return orchestrator
}

// initializeComponents initializes all orchestrator components
func (to *ToolOrchestrator) initializeComponents() {
	to.rateLimiter = utils.NewIntelligentRateLimiter(to.dbPool)
	to.resourceMonitor = NewResourceMonitor(to.dbPool)
	to.workerPool = NewWorkerPool(to.concurrentTools, to.taskQueue, to.resultChannel)

	log.Printf("[ORCHESTRATOR] Initialized components: rate limiter, resource monitor, worker pool")
}

// registerTools registers all available security tools
func (to *ToolOrchestrator) registerTools() {
	// Phase 1: Attack Surface Mapping tools
	to.tools["gospider"] = NewGoSpiderTool()
	to.tools["ffuf"] = NewFFufTool()
	to.tools["subdomainizer"] = NewSubdomainizerTool()

	// Phase 2: DAST Scanning tools
	to.tools["nuclei"] = NewNucleiTool()
	to.tools["zap"] = NewZAPTool()

	// Phase 3: Targeted Testing tools
	to.tools["custom_browser"] = NewCustomBrowserTool()
	to.tools["multi_identity"] = NewMultiIdentityTool()
	to.tools["oob_validator"] = NewOOBValidatorTool()

	// Phase 4: Evidence Collection tools
	to.tools["evidence_collector"] = NewEvidenceCollectorTool()
	to.tools["kill_chain_analyzer"] = NewKillChainAnalyzerTool()

	// Set default tool configurations
	to.setDefaultToolConfigs()

	log.Printf("[ORCHESTRATOR] Registered %d security tools", len(to.tools))
}

// setDefaultToolConfigs sets default configurations for all tools
func (to *ToolOrchestrator) setDefaultToolConfigs() {
	defaultConfig := ToolConfig{
		Enabled:        true,
		RateLimit:      10,
		MaxConcurrency: 2,
		Timeout:        5 * time.Minute,
		RetryAttempts:  3,
		Parameters:     make(map[string]interface{}),
	}

	for toolName := range to.tools {
		to.toolConfigs[toolName] = defaultConfig
	}

	// Override specific tool configurations
	to.toolConfigs["nuclei"] = ToolConfig{
		Enabled:        true,
		RateLimit:      20,
		MaxConcurrency: 3,
		Timeout:        10 * time.Minute,
		RetryAttempts:  2,
		Parameters:     map[string]interface{}{"severity": "medium,high,critical"},
	}

	to.toolConfigs["ffuf"] = ToolConfig{
		Enabled:        true,
		RateLimit:      50,
		MaxConcurrency: 2,
		Timeout:        8 * time.Minute,
		RetryAttempts:  3,
		Parameters:     map[string]interface{}{"threads": "10"},
	}
}

// ExecuteURLWorkflow executes the complete URL workflow with orchestrator management
func (to *ToolOrchestrator) ExecuteURLWorkflow(sessionID, scopeTargetID string, urls []string) error {
	log.Printf("[ORCHESTRATOR] Starting URL workflow for session %s with %d URLs", sessionID, len(urls))

	to.mu.Lock()
	to.activeSessionID = sessionID
	to.scopeTargetID = scopeTargetID
	to.selectedURLs = urls
	to.mu.Unlock()

	// Reset counters
	atomic.StoreInt64(&to.totalTasks, 0)
	atomic.StoreInt64(&to.completedTasks, 0)
	atomic.StoreInt64(&to.failedTasks, 0)

	// Start worker pool
	to.workerPool.Start(to.ctx)
	defer to.workerPool.Stop()

	// Start result processor
	go to.processResults()

	// Execute phases sequentially with internal concurrency
	phases := []WorkflowPhase{
		PhaseAttackSurfaceMapping,
		PhaseDAST,
		PhaseTargetedTesting,
		PhaseEvidenceCollection,
		PhaseKillChainAnalysis,
	}

	for _, phase := range phases {
		to.mu.Lock()
		to.currentPhase = phase
		to.mu.Unlock()

		log.Printf("[ORCHESTRATOR] Starting phase: %s", phase)

		if err := to.executePhase(phase, urls); err != nil {
			log.Printf("[ORCHESTRATOR] Phase %s failed: %v", phase, err)
			return fmt.Errorf("phase %s failed: %w", phase, err)
		}

		log.Printf("[ORCHESTRATOR] Completed phase: %s", phase)

		// Update progress in database
		to.updatePhaseProgress(sessionID, string(phase), "completed")
	}

	to.mu.Lock()
	to.currentPhase = PhaseCompleted
	to.mu.Unlock()

	log.Printf("[ORCHESTRATOR] URL workflow completed for session %s", sessionID)
	return nil
}

// executePhase executes a specific workflow phase
func (to *ToolOrchestrator) executePhase(phase WorkflowPhase, urls []string) error {
	tasks := to.createTasksForPhase(phase, urls)
	if len(tasks) == 0 {
		log.Printf("[ORCHESTRATOR] No tasks to execute for phase %s", phase)
		return nil
	}

	atomic.StoreInt64(&to.totalTasks, int64(len(tasks)))
	atomic.StoreInt64(&to.completedTasks, 0)
	atomic.StoreInt64(&to.failedTasks, 0)

	log.Printf("[ORCHESTRATOR] Queuing %d tasks for phase %s", len(tasks), phase)

	// Queue all tasks for this phase
	for _, task := range tasks {
		select {
		case to.taskQueue <- task:
			log.Printf("[ORCHESTRATOR] Queued task %s (%s) for %s", task.ID, task.Tool, task.Target)
		case <-to.ctx.Done():
			return fmt.Errorf("orchestrator cancelled during task queuing")
		}
	}

	// Wait for phase completion
	return to.waitForPhaseCompletion(tasks)
}

// createTasksForPhase creates tasks based on the workflow phase
func (to *ToolOrchestrator) createTasksForPhase(phase WorkflowPhase, urls []string) []*Task {
	var tasks []*Task

	switch phase {
	case PhaseAttackSurfaceMapping:
		tasks = to.createAttackSurfaceTasks(urls)
	case PhaseDAST:
		tasks = to.createDASTasks(urls)
	case PhaseTargetedTesting:
		tasks = to.createTargetedTestingTasks(urls)
	case PhaseEvidenceCollection:
		tasks = to.createEvidenceCollectionTasks(urls)
	case PhaseKillChainAnalysis:
		tasks = to.createKillChainAnalysisTasks(urls)
	}

	return tasks
}

// createAttackSurfaceTasks creates tasks for attack surface mapping phase
func (to *ToolOrchestrator) createAttackSurfaceTasks(urls []string) []*Task {
	var tasks []*Task

	for _, url := range urls {
		// Web crawling task
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeWebCrawling,
			Tool:   "gospider",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "gospider",
				Parameters:    map[string]interface{}{"depth": "3", "concurrent": "10"},
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   1,
			MaxRetries: to.maxRetries,
			Timeout:    to.taskTimeout,
			CreatedAt:  time.Now(),
		})

		// Directory brute forcing task
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeDirectoryBrute,
			Tool:   "ffuf",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "ffuf",
				Parameters:    map[string]interface{}{"wordlist": "common.txt", "threads": "10"},
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   2,
			MaxRetries: to.maxRetries,
			Timeout:    to.taskTimeout,
			CreatedAt:  time.Now(),
		})

		// JavaScript endpoint discovery task
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeJSEndpoints,
			Tool:   "subdomainizer",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "subdomainizer",
				Parameters:    map[string]interface{}{"js_analysis": "true"},
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   3,
			MaxRetries: to.maxRetries,
			Timeout:    to.taskTimeout,
			CreatedAt:  time.Now(),
		})
	}

	return tasks
}

// createDASTasks creates tasks for DAST scanning phase
func (to *ToolOrchestrator) createDASTasks(urls []string) []*Task {
	var tasks []*Task

	for _, url := range urls {
		// Nuclei vulnerability scanning
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeNuclei,
			Tool:   "nuclei",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "nuclei",
				Parameters:    to.toolConfigs["nuclei"].Parameters,
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   1,
			MaxRetries: to.maxRetries,
			Timeout:    to.toolConfigs["nuclei"].Timeout,
			CreatedAt:  time.Now(),
		})

		// ZAP active scanning
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeNuclei,
			Tool:   "zap",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "zap",
				Parameters:    map[string]interface{}{"scan_policy": "default"},
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   2,
			MaxRetries: to.maxRetries,
			Timeout:    to.taskTimeout,
			CreatedAt:  time.Now(),
		})
	}

	return tasks
}

// createTargetedTestingTasks creates tasks for targeted vulnerability testing
func (to *ToolOrchestrator) createTargetedTestingTasks(urls []string) []*Task {
	var tasks []*Task

	for _, url := range urls {
		// Custom browser-based validation
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeCustomBrowser,
			Tool:   "custom_browser",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "custom_browser",
				Parameters:    map[string]interface{}{"validation_mode": "full"},
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   1,
			MaxRetries: to.maxRetries,
			Timeout:    to.taskTimeout,
			CreatedAt:  time.Now(),
		})

		// Multi-identity testing
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeVulnTesting,
			Tool:   "multi_identity",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "multi_identity",
				Parameters:    map[string]interface{}{"identities": []string{"guest", "low_priv", "admin"}},
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   2,
			MaxRetries: to.maxRetries,
			Timeout:    to.taskTimeout,
			CreatedAt:  time.Now(),
		})

		// OOB interaction validation
		tasks = append(tasks, &Task{
			ID:     uuid.New().String(),
			Type:   TaskTypeVulnTesting,
			Tool:   "oob_validator",
			Target: url,
			Parameters: TaskParams{
				Target:        url,
				Tool:          "oob_validator",
				Parameters:    map[string]interface{}{"protocols": []string{"http", "dns"}},
				SessionID:     to.activeSessionID,
				ScopeTargetID: to.scopeTargetID,
			},
			Priority:   3,
			MaxRetries: to.maxRetries,
			Timeout:    to.taskTimeout,
			CreatedAt:  time.Now(),
		})
	}

	return tasks
}

// createEvidenceCollectionTasks creates tasks for evidence collection
func (to *ToolOrchestrator) createEvidenceCollectionTasks(urls []string) []*Task {
	var tasks []*Task

	// Evidence consolidation task (applies to all URLs)
	tasks = append(tasks, &Task{
		ID:     uuid.New().String(),
		Type:   TaskTypeEvidenceCollect,
		Tool:   "evidence_collector",
		Target: "all_urls",
		Parameters: TaskParams{
			Target:        "all_urls",
			Tool:          "evidence_collector",
			Parameters:    map[string]interface{}{"urls": urls},
			SessionID:     to.activeSessionID,
			ScopeTargetID: to.scopeTargetID,
		},
		Priority:   1,
		MaxRetries: to.maxRetries,
		Timeout:    to.taskTimeout,
		CreatedAt:  time.Now(),
	})

	return tasks
}

// createKillChainAnalysisTasks creates tasks for kill chain analysis
func (to *ToolOrchestrator) createKillChainAnalysisTasks(urls []string) []*Task {
	var tasks []*Task

	// Kill chain analysis task (applies to all findings)
	tasks = append(tasks, &Task{
		ID:     uuid.New().String(),
		Type:   TaskTypeKillChainAnalysis,
		Tool:   "kill_chain_analyzer",
		Target: "all_findings",
		Parameters: TaskParams{
			Target:        "all_findings",
			Tool:          "kill_chain_analyzer",
			Parameters:    map[string]interface{}{"session_id": to.activeSessionID},
			SessionID:     to.activeSessionID,
			ScopeTargetID: to.scopeTargetID,
		},
		Priority:   1,
		MaxRetries: to.maxRetries,
		Timeout:    to.taskTimeout,
		CreatedAt:  time.Now(),
	})

	return tasks
}

// processResults processes task results from the worker pool
func (to *ToolOrchestrator) processResults() {
	for {
		select {
		case result := <-to.resultChannel:
			to.handleTaskResult(result)
		case <-to.ctx.Done():
			log.Printf("[ORCHESTRATOR] Result processor stopping...")
			return
		}
	}
}

// handleTaskResult handles individual task results
func (to *ToolOrchestrator) handleTaskResult(result *TaskResult) {
	if result.Success {
		atomic.AddInt64(&to.completedTasks, 1)
		log.Printf("[ORCHESTRATOR] Task %s completed successfully in %v",
			result.TaskID, result.Duration)

		// Store findings and evidence if any
		if len(result.Findings) > 0 {
			to.storeFindingsFromResult(result)
		}
		if len(result.Evidence) > 0 {
			to.storeEvidenceFromResult(result)
		}

	} else {
		atomic.AddInt64(&to.failedTasks, 1)
		log.Printf("[ORCHESTRATOR] Task %s failed: %v", result.TaskID, result.Error)
	}

	// Update progress in database
	to.updateTaskProgress(result)

	// Check if all tasks completed
	total := atomic.LoadInt64(&to.totalTasks)
	completed := atomic.LoadInt64(&to.completedTasks)
	failed := atomic.LoadInt64(&to.failedTasks)

	if completed+failed >= total {
		select {
		case to.completionSignal <- true:
		default:
		}
	}
}

// waitForPhaseCompletion waits for all tasks in a phase to complete
func (to *ToolOrchestrator) waitForPhaseCompletion(tasks []*Task) error {
	timeout := time.After(30 * time.Minute) // 30 minute timeout per phase

	for {
		select {
		case <-to.completionSignal:
			log.Printf("[ORCHESTRATOR] Phase %s completed", to.currentPhase)
			return nil
		case <-timeout:
			return fmt.Errorf("phase %s timed out", to.currentPhase)
		case <-to.ctx.Done():
			return fmt.Errorf("orchestrator cancelled")
		}
	}
}

// GetProgress returns real-time progress information
func (to *ToolOrchestrator) GetProgress() (int64, int64, int64) {
	total := atomic.LoadInt64(&to.totalTasks)
	completed := atomic.LoadInt64(&to.completedTasks)
	failed := atomic.LoadInt64(&to.failedTasks)
	return total, completed, failed
}

// GetCurrentPhase returns the current workflow phase
func (to *ToolOrchestrator) GetCurrentPhase() WorkflowPhase {
	to.mu.RLock()
	defer to.mu.RUnlock()
	return to.currentPhase
}

// GetWorkerPool returns the worker pool instance for testing and monitoring
func (to *ToolOrchestrator) GetWorkerPool() *WorkerPool {
	return to.workerPool
}

// GetRateLimiter returns the rate limiter instance for testing and monitoring
func (to *ToolOrchestrator) GetRateLimiter() *utils.IntelligentRateLimiter {
	return to.rateLimiter
}

// GetResourceMonitor returns the resource monitor instance for testing and monitoring
func (to *ToolOrchestrator) GetResourceMonitor() *ResourceMonitor {
	return to.resourceMonitor
}

// GetMaxRetries returns the maximum retry attempts configuration
func (to *ToolOrchestrator) GetMaxRetries() int {
	return to.maxRetries
}

// SetConcurrency sets the number of concurrent workers
func (to *ToolOrchestrator) SetConcurrency(workers int) {
	to.mu.Lock()
	defer to.mu.Unlock()
	to.concurrentTools = workers
}

// SetRateLimit sets the global and per-host rate limits
func (to *ToolOrchestrator) SetRateLimit(globalLimit, hostLimit int) {
	to.mu.Lock()
	defer to.mu.Unlock()
	to.globalRateLimit = globalLimit
	to.perHostRateLimit = hostLimit
}

// Stop stops the orchestrator and all its components
func (to *ToolOrchestrator) Stop() {
	log.Printf("[ORCHESTRATOR] Stopping orchestrator...")
	to.cancel()
	close(to.taskQueue)
	close(to.resultChannel)
	close(to.completionSignal)
}

// Helper methods for database operations
func (to *ToolOrchestrator) updatePhaseProgress(sessionID, phase, status string) {
	query := `
		UPDATE url_workflow_sessions 
		SET current_phase = $1, updated_at = NOW()
		WHERE session_id = $2
	`
	_, err := to.dbPool.Exec(context.Background(), query, phase, sessionID)
	if err != nil {
		log.Printf("[ORCHESTRATOR] Failed to update phase progress: %v", err)
	}
}

func (to *ToolOrchestrator) updateTaskProgress(result *TaskResult) {
	query := `
		INSERT INTO task_results (id, session_id, task_type, tool, target, success, error, duration, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	errorMsg := ""
	if result.Error != nil {
		errorMsg = result.Error.Error()
	}

	_, err := to.dbPool.Exec(context.Background(), query,
		result.TaskID, to.activeSessionID, result.Tool, result.Tool, result.Target,
		result.Success, errorMsg, result.Duration.Milliseconds(), result.CompletedAt)

	if err != nil {
		log.Printf("[ORCHESTRATOR] Failed to update task progress: %v", err)
	}
}

func (to *ToolOrchestrator) storeFindingsFromResult(result *TaskResult) {
	// Implementation for storing findings from task results
	// This will integrate with the existing findingsUtils.go
	log.Printf("[ORCHESTRATOR] Storing %d findings from task %s", len(result.Findings), result.TaskID)
}

func (to *ToolOrchestrator) storeEvidenceFromResult(result *TaskResult) {
	// Implementation for storing evidence from task results
	// This will integrate with the existing evidenceCollectionService.go
	log.Printf("[ORCHESTRATOR] Storing %d evidence items from task %s", len(result.Evidence), result.TaskID)
}
