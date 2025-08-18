# Orchestrator Architecture Design - Ars0n Framework Go Concurrency

## Overview

This document outlines the design for a robust orchestrator architecture using existing Go concurrency patterns in the Ars0n Framework. The orchestrator coordinates all phases of the URL workflow, manages tool execution, handles rate limiting, and ensures proper sequencing of vulnerability testing activities.

## Orchestrator Philosophy

### Core Principles
- **Concurrent Execution**: Leverage Go's goroutines for parallel tool execution
- **Rate-Aware Coordination**: Intelligent rate limiting across all tools and targets
- **Fault Tolerance**: Graceful handling of tool failures and network issues
- **Progress Tracking**: Real-time status updates and completion monitoring
- **Resource Management**: Efficient use of system resources and Docker containers
- **Scope Compliance**: Continuous validation against defined target scope

### Orchestration Flow
```
Session Initiation → Phase Planning → Concurrent Execution → Progress Monitoring → Completion
        ↓                ↓               ↓                   ↓                  ↓
  Prerequisites     Tool Selection   Goroutine Pool      Status Updates    Evidence Consolidation
  Validation       Rate Planning    Error Handling      Kill-Chain Analysis    Report Generation
```

## Architecture Implementation

### 1. Core Orchestrator Structure

```go
// server/url_workflow/orchestrator.go
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
)

type ToolOrchestrator struct {
    // Core dependencies
    dbPool            *pgxpool.Pool
    rateLimiter       *RateLimiter
    evidenceCollector *EvidenceCollector
    findingsSubmitter *FindingsSubmitter
    killChainAnalyzer *KillChainDetector
    multiIdentityFramework *MultiIdentityFramework
    oobServer         *OOBInteractionServer
    twoStageDetector  *TwoStageDetector
    
    // Orchestration state
    activeSessionID   string
    scopeTargetID     string
    selectedURLs      []string
    currentPhase      WorkflowPhase
    
    // Concurrency management
    workerPool        *WorkerPool
    taskQueue         chan *Task
    resultChannel     chan *TaskResult
    completionSignal  chan bool
    
    // Progress tracking
    totalTasks        int64
    completedTasks    int64
    failedTasks       int64
    progressMutex     sync.RWMutex
    
    // Tool integrations
    tools             map[string]ToolInterface
    toolConfigs       map[string]ToolConfig
    
    // Rate limiting
    globalRateLimit   int   // Global requests per minute
    perHostRateLimit  int   // Per-host requests per minute
    concurrentTools   int   // Maximum concurrent tool executions
    
    // Context and cancellation
    ctx               context.Context
    cancel            context.CancelFunc
}

type WorkflowPhase string

const (
    PhaseAttackSurfaceMapping WorkflowPhase = "attack_surface_mapping"
    PhaseDAST                WorkflowPhase = "dast"
    PhaseTargetedTesting     WorkflowPhase = "targeted_testing"
    PhaseEvidenceCollection  WorkflowPhase = "evidence_collection"
    PhaseKillChainAnalysis   WorkflowPhase = "kill_chain_analysis"
    PhaseCompleted           WorkflowPhase = "completed"
)

type Task struct {
    ID          string      `json:"id"`
    Type        TaskType    `json:"type"`
    Tool        string      `json:"tool"`
    Target      string      `json:"target"`
    Parameters  TaskParams  `json:"parameters"`
    Priority    int         `json:"priority"`    // 1-10, higher = more important
    Phase       WorkflowPhase `json:"phase"`
    Dependencies []string   `json:"dependencies"` // Task IDs this task depends on
    CreatedAt   time.Time   `json:"created_at"`
    StartedAt   *time.Time  `json:"started_at"`
    Retries     int         `json:"retries"`
    MaxRetries  int         `json:"max_retries"`
}

type TaskType string

const (
    TaskWebCrawling        TaskType = "web_crawling"
    TaskDirectoryBrute     TaskType = "directory_brute" 
    TaskJSEndpointExtract  TaskType = "js_endpoint_extract"
    TaskAPIDiscovery       TaskType = "api_discovery"
    TaskNucleiScan         TaskType = "nuclei_scan"
    TaskCustomVulnTest     TaskType = "custom_vuln_test"
    TaskMultiIdentityTest  TaskType = "multi_identity_test"
    TaskOOBValidation      TaskType = "oob_validation"
    TaskEvidenceCollection TaskType = "evidence_collection"
    TaskKillChainAnalysis  TaskType = "kill_chain_analysis"
)

type TaskParams map[string]interface{}

type TaskResult struct {
    TaskID       string        `json:"task_id"`
    Tool         string        `json:"tool"`
    Target       string        `json:"target"`
    Success      bool          `json:"success"`
    Error        error         `json:"error,omitempty"`
    Output       interface{}   `json:"output,omitempty"`
    Findings     []Finding     `json:"findings,omitempty"`
    Evidence     []string      `json:"evidence,omitempty"`  // Evidence IDs
    Duration     time.Duration `json:"duration"`
    CompletedAt  time.Time     `json:"completed_at"`
}

type ToolInterface interface {
    Execute(ctx context.Context, params TaskParams) (*TaskResult, error)
    Validate(params TaskParams) error
    GetName() string
    GetType() TaskType
    RequiresScope() bool
    RequiresAuth() bool
    GetRateLimit() int  // Requests per minute
}

type ToolConfig struct {
    Enabled         bool                   `json:"enabled"`
    RateLimit       int                    `json:"rate_limit"`
    MaxConcurrency  int                    `json:"max_concurrency"`
    Timeout         time.Duration          `json:"timeout"`
    RetryAttempts   int                    `json:"retry_attempts"`
    Parameters      map[string]interface{} `json:"parameters"`
}

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
        globalRateLimit:  100,  // 100 requests per minute globally
        perHostRateLimit: 10,   // 10 requests per minute per host
        concurrentTools:  5,    // 5 concurrent tool executions
    }
    
    // Initialize components
    orchestrator.initializeComponents()
    orchestrator.registerTools()
    orchestrator.workerPool = NewWorkerPool(orchestrator.concurrentTools, orchestrator.taskQueue, orchestrator.resultChannel)
    
    return orchestrator
}

// Initialize all orchestrator components
func (to *ToolOrchestrator) initializeComponents() {
    to.rateLimiter = NewRateLimiter(to.dbPool)
    to.evidenceCollector = NewEvidenceCollector(to.dbPool)
    to.findingsSubmitter = NewFindingsSubmitter(to.dbPool)
    to.killChainAnalyzer = NewKillChainDetector(to.dbPool)
    to.multiIdentityFramework = NewMultiIdentityFramework(to.dbPool)
    to.oobServer = NewOOBInteractionServer(to.dbPool, "oob.ars0n.local")
    to.twoStageDetector = NewTwoStageDetector(to.dbPool)
    
    // Start OOB server
    go to.oobServer.Start()
}

// Main orchestration workflow
func (to *ToolOrchestrator) ExecuteURLWorkflow(sessionID, scopeTargetID string, urls []string) error {
    log.Printf("[ORCHESTRATOR] Starting URL workflow for session %s", sessionID)
    
    to.activeSessionID = sessionID
    to.scopeTargetID = scopeTargetID
    to.selectedURLs = urls
    
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
        to.currentPhase = phase
        
        log.Printf("[ORCHESTRATOR] Starting phase: %s", phase)
        
        if err := to.executePhase(phase, urls); err != nil {
            log.Printf("[ORCHESTRATOR] Phase %s failed: %v", phase, err)
            return err
        }
        
        log.Printf("[ORCHESTRATOR] Completed phase: %s", phase)
        
        // Update progress in database
        to.updatePhaseProgress(sessionID, string(phase), "completed")
    }
    
    to.currentPhase = PhaseCompleted
    log.Printf("[ORCHESTRATOR] URL workflow completed for session %s", sessionID)
    
    return nil
}

// Execute a specific workflow phase
func (to *ToolOrchestrator) executePhase(phase WorkflowPhase, urls []string) error {
    // Generate tasks for this phase
    tasks := to.generatePhaseTasks(phase, urls)
    
    if len(tasks) == 0 {
        log.Printf("[ORCHESTRATOR] No tasks generated for phase %s", phase)
        return nil
    }
    
    // Update total task count
    atomic.AddInt64(&to.totalTasks, int64(len(tasks)))
    
    // Submit tasks to queue (respecting dependencies)
    to.submitTasksWithDependencies(tasks)
    
    // Wait for phase completion
    return to.waitForPhaseCompletion(tasks)
}

// Generate tasks for a specific phase
func (to *ToolOrchestrator) generatePhaseTasks(phase WorkflowPhase, urls []string) []*Task {
    var tasks []*Task
    
    switch phase {
    case PhaseAttackSurfaceMapping:
        tasks = to.generateAttackSurfaceTasks(urls)
    case PhaseDAST:
        tasks = to.generateDASTTasks(urls)
    case PhaseTargetedTesting:
        tasks = to.generateTargetedTestingTasks(urls)
    case PhaseEvidenceCollection:
        tasks = to.generateEvidenceCollectionTasks()
    case PhaseKillChainAnalysis:
        tasks = to.generateKillChainAnalysisTasks()
    }
    
    return tasks
}

// Generate attack surface mapping tasks
func (to *ToolOrchestrator) generateAttackSurfaceTasks(urls []string) []*Task {
    var tasks []*Task
    
    for _, url := range urls {
        // Web crawling task
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskWebCrawling,
            Tool:       "gospider",
            Target:     url,
            Parameters: TaskParams{"depth": 3, "timeout": 300},
            Priority:   8,
            Phase:      PhaseAttackSurfaceMapping,
            MaxRetries: 2,
            CreatedAt:  time.Now(),
        })
        
        // Directory brute force task
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskDirectoryBrute,
            Tool:       "ffuf",
            Target:     url,
            Parameters: TaskParams{"wordlist": "common", "threads": 10},
            Priority:   7,
            Phase:      PhaseAttackSurfaceMapping,
            MaxRetries: 2,
            CreatedAt:  time.Now(),
        })
        
        // JavaScript endpoint extraction
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskJSEndpointExtract,
            Tool:       "subdomainizer",
            Target:     url,
            Parameters: TaskParams{"scope": to.scopeTargetID},
            Priority:   6,
            Phase:      PhaseAttackSurfaceMapping,
            MaxRetries: 1,
            CreatedAt:  time.Now(),
        })
        
        // API discovery
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskAPIDiscovery,
            Tool:       "custom_api_scanner",
            Target:     url,
            Parameters: TaskParams{"methods": []string{"GET", "POST", "PUT", "DELETE"}},
            Priority:   6,
            Phase:      PhaseAttackSurfaceMapping,
            MaxRetries: 1,
            CreatedAt:  time.Now(),
        })
    }
    
    return tasks
}

// Generate DAST tasks
func (to *ToolOrchestrator) generateDASTTasks(urls []string) []*Task {
    var tasks []*Task
    
    for _, url := range urls {
        // Nuclei comprehensive scan
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskNucleiScan,
            Tool:       "nuclei",
            Target:     url,
            Parameters: TaskParams{"templates": "all", "severity": "medium,high,critical"},
            Priority:   9,
            Phase:      PhaseDAST,
            MaxRetries: 2,
            CreatedAt:  time.Now(),
        })
        
        // Two-stage detection
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskCustomVulnTest,
            Tool:       "two_stage_detector",
            Target:     url,
            Parameters: TaskParams{"categories": []string{"xss", "idor", "ssrf"}},
            Priority:   8,
            Phase:      PhaseDAST,
            MaxRetries: 1,
            CreatedAt:  time.Now(),
        })
    }
    
    return tasks
}

// Generate targeted testing tasks
func (to *ToolOrchestrator) generateTargetedTestingTasks(urls []string) []*Task {
    var tasks []*Task
    
    for _, url := range urls {
        // Multi-identity testing
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskMultiIdentityTest,
            Tool:       "multi_identity_framework",
            Target:     url,
            Parameters: TaskParams{"identities": []string{"guest", "user", "admin", "cross_tenant"}},
            Priority:   7,
            Phase:      PhaseTargetedTesting,
            MaxRetries: 1,
            CreatedAt:  time.Now(),
        })
        
        // OOB validation for blind vulnerabilities
        tasks = append(tasks, &Task{
            ID:         uuid.New().String(),
            Type:       TaskOOBValidation,
            Tool:       "oob_validator",
            Target:     url,
            Parameters: TaskParams{"test_types": []string{"ssrf", "xxe", "blind_xss"}},
            Priority:   6,
            Phase:      PhaseTargetedTesting,
            MaxRetries: 2,
            CreatedAt:  time.Now(),
        })
    }
    
    return tasks
}

// Generate evidence collection tasks
func (to *ToolOrchestrator) generateEvidenceCollectionTasks() []*Task {
    return []*Task{
        {
            ID:         uuid.New().String(),
            Type:       TaskEvidenceCollection,
            Tool:       "evidence_consolidator",
            Target:     "session",
            Parameters: TaskParams{"session_id": to.activeSessionID},
            Priority:   5,
            Phase:      PhaseEvidenceCollection,
            MaxRetries: 1,
            CreatedAt:  time.Now(),
        },
    }
}

// Generate kill-chain analysis tasks
func (to *ToolOrchestrator) generateKillChainAnalysisTasks() []*Task {
    return []*Task{
        {
            ID:         uuid.New().String(),
            Type:       TaskKillChainAnalysis,
            Tool:       "kill_chain_analyzer",
            Target:     "session",
            Parameters: TaskParams{"session_id": to.activeSessionID, "scope_target_id": to.scopeTargetID},
            Priority:   10,
            Phase:      PhaseKillChainAnalysis,
            MaxRetries: 1,
            CreatedAt:  time.Now(),
        },
    }
}

// Submit tasks respecting dependencies
func (to *ToolOrchestrator) submitTasksWithDependencies(tasks []*Task) {
    // Simple dependency resolution - submit tasks without dependencies first
    noDependencyTasks := []*Task{}
    dependentTasks := []*Task{}
    
    for _, task := range tasks {
        if len(task.Dependencies) == 0 {
            noDependencyTasks = append(noDependencyTasks, task)
        } else {
            dependentTasks = append(dependentTasks, task)
        }
    }
    
    // Submit independent tasks first
    for _, task := range noDependencyTasks {
        select {
        case to.taskQueue <- task:
            log.Printf("[ORCHESTRATOR] Submitted task %s (%s)", task.ID, task.Type)
        case <-to.ctx.Done():
            return
        }
    }
    
    // TODO: Implement proper dependency resolution for dependent tasks
    // For now, submit them after a delay
    go func() {
        time.Sleep(30 * time.Second) // Wait for initial tasks to complete
        for _, task := range dependentTasks {
            select {
            case to.taskQueue <- task:
                log.Printf("[ORCHESTRATOR] Submitted dependent task %s (%s)", task.ID, task.Type)
            case <-to.ctx.Done():
                return
            }
        }
    }()
}

// Process task results
func (to *ToolOrchestrator) processResults() {
    for {
        select {
        case result := <-to.resultChannel:
            to.handleTaskResult(result)
        case <-to.ctx.Done():
            return
        }
    }
}

// Handle individual task result
func (to *ToolOrchestrator) handleTaskResult(result *TaskResult) {
    if result.Success {
        atomic.AddInt64(&to.completedTasks, 1)
        log.Printf("[ORCHESTRATOR] Task %s completed successfully in %v", 
            result.TaskID, result.Duration)
        
        // Submit findings if any
        for _, finding := range result.Findings {
            if err := to.findingsSubmitter.SubmitFinding(finding); err != nil {
                log.Printf("[ORCHESTRATOR] Failed to submit finding: %v", err)
            }
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

// Wait for phase completion
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

// Get real-time progress
func (to *ToolOrchestrator) GetProgress() (int64, int64, int64) {
    total := atomic.LoadInt64(&to.totalTasks)
    completed := atomic.LoadInt64(&to.completedTasks)
    failed := atomic.LoadInt64(&to.failedTasks)
    return total, completed, failed
}

// Update progress in database
func (to *ToolOrchestrator) updatePhaseProgress(sessionID, phase, status string) {
    query := `
        UPDATE url_workflow_sessions 
        SET current_phase = $1, updated_at = NOW()
        WHERE id = $2
    `
    to.dbPool.Exec(context.Background(), query, phase, sessionID)
}

func (to *ToolOrchestrator) updateTaskProgress(result *TaskResult) {
    // Store task result in database for progress tracking
    query := `
        INSERT INTO task_results (id, session_id, task_type, tool, target, success, error, duration, completed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `
    
    errorMsg := ""
    if result.Error != nil {
        errorMsg = result.Error.Error()
    }
    
    to.dbPool.Exec(context.Background(), query,
        result.TaskID, to.activeSessionID, result.Tool, result.Tool, result.Target,
        result.Success, errorMsg, result.Duration.Milliseconds(), result.CompletedAt)
}

// Stop orchestrator
func (to *ToolOrchestrator) Stop() {
    log.Printf("[ORCHESTRATOR] Stopping orchestrator...")
    to.cancel()
    close(to.taskQueue)
    close(to.resultChannel)
}
```

### 2. Worker Pool Implementation

```go
// server/url_workflow/worker_pool.go
package url_workflow

import (
    "context"
    "log"
    "sync"
    "time"
)

type WorkerPool struct {
    workerCount   int
    taskQueue     <-chan *Task
    resultChannel chan<- *TaskResult
    workers       []*Worker
    wg            sync.WaitGroup
}

type Worker struct {
    id            int
    taskQueue     <-chan *Task
    resultChannel chan<- *TaskResult
    quit          chan bool
    tools         map[string]ToolInterface
}

func NewWorkerPool(workerCount int, taskQueue <-chan *Task, resultChannel chan<- *TaskResult) *WorkerPool {
    return &WorkerPool{
        workerCount:   workerCount,
        taskQueue:     taskQueue,
        resultChannel: resultChannel,
        workers:       make([]*Worker, workerCount),
    }
}

func (wp *WorkerPool) Start(ctx context.Context) {
    log.Printf("[WORKER_POOL] Starting %d workers", wp.workerCount)
    
    for i := 0; i < wp.workerCount; i++ {
        worker := &Worker{
            id:            i,
            taskQueue:     wp.taskQueue,
            resultChannel: wp.resultChannel,
            quit:          make(chan bool),
            tools:         make(map[string]ToolInterface),
        }
        
        // Initialize worker tools
        worker.initializeTools()
        
        wp.workers[i] = worker
        wp.wg.Add(1)
        
        go worker.start(ctx, &wp.wg)
    }
}

func (wp *WorkerPool) Stop() {
    log.Printf("[WORKER_POOL] Stopping workers...")
    
    for _, worker := range wp.workers {
        worker.quit <- true
    }
    
    wp.wg.Wait()
    log.Printf("[WORKER_POOL] All workers stopped")
}

func (w *Worker) start(ctx context.Context, wg *sync.WaitGroup) {
    defer wg.Done()
    
    log.Printf("[WORKER_%d] Worker started", w.id)
    
    for {
        select {
        case task := <-w.taskQueue:
            w.executeTask(ctx, task)
        case <-w.quit:
            log.Printf("[WORKER_%d] Worker stopping", w.id)
            return
        case <-ctx.Done():
            log.Printf("[WORKER_%d] Worker cancelled", w.id)
            return
        }
    }
}

func (w *Worker) executeTask(ctx context.Context, task *Task) {
    log.Printf("[WORKER_%d] Executing task %s (%s) on %s", w.id, task.ID, task.Type, task.Target)
    
    startTime := time.Now()
    task.StartedAt = &startTime
    
    // Get appropriate tool
    tool, exists := w.tools[task.Tool]
    if !exists {
        w.sendResult(&TaskResult{
            TaskID:      task.ID,
            Tool:        task.Tool,
            Target:      task.Target,
            Success:     false,
            Error:       fmt.Errorf("tool %s not found", task.Tool),
            Duration:    time.Since(startTime),
            CompletedAt: time.Now(),
        })
        return
    }
    
    // Create task context with timeout
    taskCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
    defer cancel()
    
    // Execute tool
    result, err := tool.Execute(taskCtx, task.Parameters)
    if err != nil {
        // Handle retries
        if task.Retries < task.MaxRetries {
            task.Retries++
            log.Printf("[WORKER_%d] Task %s failed, retrying (%d/%d): %v", 
                w.id, task.ID, task.Retries, task.MaxRetries, err)
            
            // Requeue task for retry
            go func() {
                time.Sleep(time.Duration(task.Retries) * 30 * time.Second) // Exponential backoff
                w.taskQueue <- task
            }()
            return
        }
        
        // Max retries exceeded
        w.sendResult(&TaskResult{
            TaskID:      task.ID,
            Tool:        task.Tool,
            Target:      task.Target,
            Success:     false,
            Error:       err,
            Duration:    time.Since(startTime),
            CompletedAt: time.Now(),
        })
        return
    }
    
    // Success
    result.TaskID = task.ID
    result.Tool = task.Tool
    result.Target = task.Target
    result.Success = true
    result.Duration = time.Since(startTime)
    result.CompletedAt = time.Now()
    
    w.sendResult(result)
}

func (w *Worker) sendResult(result *TaskResult) {
    select {
    case w.resultChannel <- result:
        log.Printf("[WORKER_%d] Result sent for task %s", w.id, result.TaskID)
    default:
        log.Printf("[WORKER_%d] Result channel full, dropping result for task %s", w.id, result.TaskID)
    }
}

func (w *Worker) initializeTools() {
    // Initialize all available tools
    w.tools["gospider"] = NewGoSpiderTool()
    w.tools["ffuf"] = NewFFufTool()
    w.tools["nuclei"] = NewNucleiTool()
    w.tools["subdomainizer"] = NewSubdomainizerTool()
    w.tools["two_stage_detector"] = NewTwoStageDetectorTool()
    w.tools["multi_identity_framework"] = NewMultiIdentityTool()
    w.tools["oob_validator"] = NewOOBValidatorTool()
    w.tools["evidence_consolidator"] = NewEvidenceConsolidatorTool()
    w.tools["kill_chain_analyzer"] = NewKillChainAnalyzerTool()
    w.tools["custom_api_scanner"] = NewCustomAPITool()
}
```

### 3. Rate Limiter Implementation

```go
// server/utils/rateLimiter.go
package utils

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    "github.com/jackc/pgx/v5/pgxpool"
    "golang.org/x/time/rate"
)

type RateLimiter struct {
    dbPool        *pgxpool.Pool
    globalLimiter *rate.Limiter
    hostLimiters  map[string]*rate.Limiter
    hostMutex     sync.RWMutex
    
    // Rate limiting configuration
    globalRate    rate.Limit  // Global requests per second
    hostRate      rate.Limit  // Per-host requests per second
    burstSize     int         // Burst allowance
}

func NewRateLimiter(dbPool *pgxpool.Pool) *RateLimiter {
    return &RateLimiter{
        dbPool:        dbPool,
        globalLimiter: rate.NewLimiter(rate.Limit(100.0/60.0), 10), // 100/min with burst of 10
        hostLimiters:  make(map[string]*rate.Limiter),
        globalRate:    rate.Limit(100.0 / 60.0), // 100 requests per minute
        hostRate:      rate.Limit(10.0 / 60.0),  // 10 requests per minute per host
        burstSize:     5,
    }
}

// Check if request can proceed globally
func (rl *RateLimiter) CanProceedGlobally(ctx context.Context) error {
    if !rl.globalLimiter.Allow() {
        // Wait for next available slot
        return rl.globalLimiter.Wait(ctx)
    }
    return nil
}

// Check if request can proceed for specific host
func (rl *RateLimiter) CanProceedForHost(ctx context.Context, host string) error {
    // Get or create host-specific limiter
    rl.hostMutex.RLock()
    hostLimiter, exists := rl.hostLimiters[host]
    rl.hostMutex.RUnlock()
    
    if !exists {
        rl.hostMutex.Lock()
        // Double-check after acquiring write lock
        if hostLimiter, exists = rl.hostLimiters[host]; !exists {
            hostLimiter = rate.NewLimiter(rl.hostRate, rl.burstSize)
            rl.hostLimiters[host] = hostLimiter
        }
        rl.hostMutex.Unlock()
    }
    
    if !hostLimiter.Allow() {
        return hostLimiter.Wait(ctx)
    }
    return nil
}

// Check if request can proceed with both global and host limits
func (rl *RateLimiter) CanProceedWithRequest(ctx context.Context, host string) error {
    // Check global rate limit first
    if err := rl.CanProceedGlobally(ctx); err != nil {
        return fmt.Errorf("global rate limit: %w", err)
    }
    
    // Check host-specific rate limit
    if err := rl.CanProceedForHost(ctx, host); err != nil {
        return fmt.Errorf("host rate limit for %s: %w", host, err)
    }
    
    return nil
}

// Update rate limits dynamically
func (rl *RateLimiter) UpdateGlobalRate(requestsPerMinute int) {
    newRate := rate.Limit(float64(requestsPerMinute) / 60.0)
    rl.globalLimiter.SetLimit(newRate)
    rl.globalRate = newRate
}

func (rl *RateLimiter) UpdateHostRate(requestsPerMinute int) {
    newRate := rate.Limit(float64(requestsPerMinute) / 60.0)
    rl.hostRate = newRate
    
    // Update existing host limiters
    rl.hostMutex.Lock()
    defer rl.hostMutex.Unlock()
    
    for _, limiter := range rl.hostLimiters {
        limiter.SetLimit(newRate)
    }
}

// Get current rate limit statistics
func (rl *RateLimiter) GetStatistics() map[string]interface{} {
    rl.hostMutex.RLock()
    defer rl.hostMutex.RUnlock()
    
    stats := map[string]interface{}{
        "global_rate":    float64(rl.globalRate) * 60, // Convert to per-minute
        "host_rate":      float64(rl.hostRate) * 60,   // Convert to per-minute
        "burst_size":     rl.burstSize,
        "tracked_hosts":  len(rl.hostLimiters),
    }
    
    return stats
}
```

### 4. Database Schema Enhancement

```sql
-- Task execution tracking
CREATE TABLE IF NOT EXISTS task_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,
    task_type VARCHAR(50) NOT NULL,
    tool VARCHAR(50) NOT NULL,
    target TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    error TEXT,
    duration BIGINT,  -- Duration in milliseconds
    completed_at TIMESTAMP DEFAULT NOW(),
    
    INDEX(session_id),
    INDEX(task_type),
    INDEX(tool),
    INDEX(completed_at)
);

-- URL workflow session status tracking
ALTER TABLE url_workflow_sessions ADD COLUMN IF NOT EXISTS current_phase VARCHAR(50);
ALTER TABLE url_workflow_sessions ADD COLUMN IF NOT EXISTS total_tasks INTEGER DEFAULT 0;
ALTER TABLE url_workflow_sessions ADD COLUMN IF NOT EXISTS completed_tasks INTEGER DEFAULT 0;
ALTER TABLE url_workflow_sessions ADD COLUMN IF NOT EXISTS failed_tasks INTEGER DEFAULT 0;
ALTER TABLE url_workflow_sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW();
```

This orchestrator architecture provides robust, concurrent execution of the URL workflow while maintaining proper rate limiting, error handling, and progress tracking throughout the entire testing process.
