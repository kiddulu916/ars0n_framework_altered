package url_workflow

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WorkerHealth represents the health status of a worker
type WorkerHealth struct {
	IsAlive            bool          `json:"is_alive"`
	LastHeartbeat      time.Time     `json:"last_heartbeat"`
	TasksCompleted     int64         `json:"tasks_completed"`
	TasksFailed        int64         `json:"tasks_failed"`
	MemoryUsage        int64         `json:"memory_usage"`
	CPUUsage           float64       `json:"cpu_usage"`
	ActiveTask         string        `json:"active_task,omitempty"`
	WorkerID           int           `json:"worker_id"`
	StartTime          time.Time     `json:"start_time"`
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	AverageTaskTime    time.Duration `json:"average_task_time"`
}

// ResourceMonitor monitors system resources for workers
type ResourceMonitor struct {
	dbPool         *pgxpool.Pool
	memoryLimit    int64   // Memory limit per worker in bytes
	cpuLimit       float64 // CPU limit per worker as percentage
	checkInterval  time.Duration
	alertThreshold float64 // Alert when usage exceeds this percentage
	workerMetrics  map[int]*WorkerHealth
	metricsMutex   sync.RWMutex
}

// WorkerPool manages a pool of workers for task execution
type WorkerPool struct {
	workerCount   int
	taskQueue     <-chan *Task
	resultChannel chan<- *TaskResult
	workers       []*Worker
	wg            sync.WaitGroup

	// Resource management
	resourceMonitor *ResourceMonitor
	memoryLimit     int64   // 2GB memory limit per worker
	cpuLimit        float64 // 50% CPU limit per worker

	// Health monitoring
	workerHealth map[int]*WorkerHealth
	healthMutex  sync.RWMutex
	healthTicker *time.Ticker

	// Metrics
	totalTasksProcessed int64
	activeWorkers       int64
	queueDepth          int64
	metricsStartTime    time.Time
	metricsMutex        sync.RWMutex
}

// Worker represents a single worker in the pool
type Worker struct {
	id            int
	taskQueue     <-chan *Task
	resultChannel chan<- *TaskResult
	quit          chan bool

	// Tool management
	tools         map[string]ToolInterface
	activeTask    *Task
	lastHeartbeat time.Time
	startTime     time.Time

	// Performance tracking
	tasksCompleted     int64
	tasksFailed        int64
	totalExecutionTime time.Duration
	resourceMonitor    *ResourceMonitor

	// Resource limits
	memoryLimit int64
	cpuLimit    float64

	// Synchronization
	taskMutex    sync.RWMutex
	metricsMutex sync.RWMutex
	healthMutex  sync.RWMutex
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(dbPool *pgxpool.Pool) *ResourceMonitor {
	return &ResourceMonitor{
		dbPool:         dbPool,
		memoryLimit:    2 * 1024 * 1024 * 1024, // 2GB
		cpuLimit:       50.0,                   // 50%
		checkInterval:  30 * time.Second,
		alertThreshold: 0.8, // 80%
		workerMetrics:  make(map[int]*WorkerHealth),
	}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workerCount int, taskQueue <-chan *Task, resultChannel chan<- *TaskResult) *WorkerPool {
	return &WorkerPool{
		workerCount:      workerCount,
		taskQueue:        taskQueue,
		resultChannel:    resultChannel,
		workers:          make([]*Worker, workerCount),
		workerHealth:     make(map[int]*WorkerHealth),
		memoryLimit:      2 * 1024 * 1024 * 1024, // 2GB per worker
		cpuLimit:         50.0,                   // 50% CPU per worker
		metricsStartTime: time.Now(),
	}
}

// Start starts the worker pool with resource monitoring
func (wp *WorkerPool) Start(ctx context.Context) {
	log.Printf("[WORKER_POOL] Starting %d workers with resource monitoring", wp.workerCount)

	// Initialize resource monitor
	wp.resourceMonitor = NewResourceMonitor(nil) // Will be set by orchestrator
	go wp.resourceMonitor.Start(ctx)

	// Start health monitoring
	wp.healthTicker = time.NewTicker(10 * time.Second)
	go wp.monitorWorkerHealth(ctx)

	// Start workers
	for i := 0; i < wp.workerCount; i++ {
		worker := &Worker{
			id:              i,
			taskQueue:       wp.taskQueue,
			resultChannel:   wp.resultChannel,
			quit:            make(chan bool),
			tools:           make(map[string]ToolInterface),
			lastHeartbeat:   time.Now(),
			startTime:       time.Now(),
			memoryLimit:     wp.memoryLimit,
			cpuLimit:        wp.cpuLimit,
			resourceMonitor: wp.resourceMonitor,
		}

		// Initialize worker with resource limits
		worker.initializeTools()
		wp.setWorkerResourceLimits(worker)

		wp.workers[i] = worker
		wp.workerHealth[i] = &WorkerHealth{
			IsAlive:       true,
			LastHeartbeat: time.Now(),
			WorkerID:      i,
			StartTime:     time.Now(),
		}

		wp.wg.Add(1)
		atomic.AddInt64(&wp.activeWorkers, 1)

		go worker.start(ctx, &wp.wg, wp.workerHealth[i])
	}

	log.Printf("[WORKER_POOL] All %d workers started successfully", wp.workerCount)
}

// Stop stops all workers in the pool
func (wp *WorkerPool) Stop() {
	log.Printf("[WORKER_POOL] Stopping workers...")

	// Stop health monitoring
	if wp.healthTicker != nil {
		wp.healthTicker.Stop()
	}

	// Signal all workers to quit
	for _, worker := range wp.workers {
		if worker != nil {
			select {
			case worker.quit <- true:
			case <-time.After(1 * time.Second):
				log.Printf("[WORKER_POOL] Timeout signaling worker %d to quit", worker.id)
			}
		}
	}

	// Wait for all workers to finish
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[WORKER_POOL] All workers stopped")
	case <-time.After(30 * time.Second):
		log.Printf("[WORKER_POOL] Timeout waiting for workers to stop")
	}

	atomic.StoreInt64(&wp.activeWorkers, 0)
}

// start starts a single worker
func (w *Worker) start(ctx context.Context, wg *sync.WaitGroup, health *WorkerHealth) {
	defer wg.Done()
	defer atomic.AddInt64(&w.resourceMonitor.workerMetrics[w.id].TasksCompleted, -1)

	log.Printf("[WORKER_%d] Worker started", w.id)

	// Start heartbeat
	heartbeatTicker := time.NewTicker(5 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case task := <-w.taskQueue:
			w.executeTask(ctx, task, health)

		case <-heartbeatTicker.C:
			w.sendHeartbeat(health)

		case <-w.quit:
			log.Printf("[WORKER_%d] Worker stopping", w.id)
			return

		case <-ctx.Done():
			log.Printf("[WORKER_%d] Worker cancelled", w.id)
			return
		}
	}
}

// executeTask executes a single task
func (w *Worker) executeTask(ctx context.Context, task *Task, health *WorkerHealth) {
	log.Printf("[WORKER_%d] Executing task %s (%s) on %s", w.id, task.ID, task.Type, task.Target)

	startTime := time.Now()
	w.taskMutex.Lock()
	w.activeTask = task
	task.StartedAt = &startTime
	w.taskMutex.Unlock()

	// Update health status
	w.healthMutex.Lock()
	health.ActiveTask = fmt.Sprintf("%s:%s", task.Tool, task.Target)
	w.healthMutex.Unlock()

	// Check resource limits before execution
	if !w.checkResourceLimits() {
		w.sendResult(&TaskResult{
			TaskID:      task.ID,
			Tool:        task.Tool,
			Target:      task.Target,
			Success:     false,
			Error:       fmt.Errorf("worker %d exceeded resource limits", w.id),
			Duration:    time.Since(startTime),
			CompletedAt: time.Now(),
		})
		w.incrementFailedTasks()
		return
	}

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
		w.incrementFailedTasks()
		return
	}

	// Create task context with timeout
	taskCtx, cancel := context.WithTimeout(ctx, task.Timeout)
	defer cancel()

	// Execute tool with resource monitoring
	result, err := w.executeWithMonitoring(taskCtx, tool, task)
	duration := time.Since(startTime)

	if err != nil {
		// Handle retries
		if task.Retries < task.MaxRetries {
			task.Retries++
			log.Printf("[WORKER_%d] Task %s failed, retrying (%d/%d): %v",
				w.id, task.ID, task.Retries, task.MaxRetries, err)

			// Log retry attempt (actual retry logic should be handled by orchestrator)
			log.Printf("[WORKER_%d] Task %s will be retried by orchestrator (%d/%d)",
				w.id, task.ID, task.Retries, task.MaxRetries)
			return
		}

		// Max retries exceeded
		w.sendResult(&TaskResult{
			TaskID:      task.ID,
			Tool:        task.Tool,
			Target:      task.Target,
			Success:     false,
			Error:       err,
			Duration:    duration,
			CompletedAt: time.Now(),
		})
		w.incrementFailedTasks()
		return
	}

	// Success
	result.TaskID = task.ID
	result.Tool = task.Tool
	result.Target = task.Target
	result.Success = true
	result.Duration = duration
	result.CompletedAt = time.Now()

	w.sendResult(result)
	w.incrementCompletedTasks()
	w.updateExecutionTime(duration)

	// Clear active task
	w.taskMutex.Lock()
	w.activeTask = nil
	w.taskMutex.Unlock()

	w.healthMutex.Lock()
	health.ActiveTask = ""
	w.healthMutex.Unlock()
}

// executeWithMonitoring executes a tool with resource monitoring
func (w *Worker) executeWithMonitoring(ctx context.Context, tool ToolInterface, task *Task) (*TaskResult, error) {
	// Monitor resource usage during execution
	done := make(chan struct{})
	var result *TaskResult
	var err error

	go func() {
		defer close(done)

		// Check resource usage periodically during execution
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if !w.checkResourceLimits() {
					err = fmt.Errorf("resource limits exceeded during task execution")
					return
				}
			case <-done:
				return
			case <-ctx.Done():
				err = ctx.Err()
				return
			}
		}
	}()

	// Execute the tool
	go func() {
		result, err = tool.Execute(ctx, task.Parameters)
		done <- struct{}{}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		return result, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// checkResourceLimits checks if the worker is within resource limits
func (w *Worker) checkResourceLimits() bool {
	// Get current memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	currentMemory := int64(m.Alloc)

	// Check memory limit
	if currentMemory > w.memoryLimit {
		log.Printf("[WORKER_%d] Memory limit exceeded: %d > %d", w.id, currentMemory, w.memoryLimit)
		return false
	}

	// CPU usage check would require additional system monitoring
	// For now, we'll implement a basic check based on goroutine count
	if runtime.NumGoroutine() > 1000 { // Arbitrary threshold
		log.Printf("[WORKER_%d] Too many goroutines: %d", w.id, runtime.NumGoroutine())
		return false
	}

	return true
}

// sendResult sends a task result to the result channel
func (w *Worker) sendResult(result *TaskResult) {
	select {
	case w.resultChannel <- result:
		log.Printf("[WORKER_%d] Result sent for task %s", w.id, result.TaskID)
	case <-time.After(5 * time.Second):
		log.Printf("[WORKER_%d] Timeout sending result for task %s", w.id, result.TaskID)
	}
}

// sendHeartbeat sends a heartbeat update
func (w *Worker) sendHeartbeat(health *WorkerHealth) {
	w.healthMutex.Lock()
	w.lastHeartbeat = time.Now()
	health.LastHeartbeat = w.lastHeartbeat
	health.IsAlive = true

	// Update metrics
	health.TasksCompleted = atomic.LoadInt64(&w.tasksCompleted)
	health.TasksFailed = atomic.LoadInt64(&w.tasksFailed)

	// Calculate average task time
	if health.TasksCompleted > 0 {
		health.TotalExecutionTime = w.totalExecutionTime
		health.AverageTaskTime = w.totalExecutionTime / time.Duration(health.TasksCompleted)
	}

	// Get current memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	health.MemoryUsage = int64(m.Alloc)

	// Simple CPU usage estimation based on task activity
	health.CPUUsage = w.calculateCPUUsage()

	w.healthMutex.Unlock()
}

// calculateCPUUsage provides a simple CPU usage estimation
func (w *Worker) calculateCPUUsage() float64 {
	w.taskMutex.RLock()
	hasActiveTask := w.activeTask != nil
	w.taskMutex.RUnlock()

	if hasActiveTask {
		return 75.0 // Assume 75% usage when actively executing
	}
	return 5.0 // Assume 5% idle usage
}

// initializeTools initializes all available tools for the worker
func (w *Worker) initializeTools() {
	// Initialize tool implementations
	w.tools["gospider"] = NewGoSpiderTool()
	w.tools["ffuf"] = NewFFufTool()
	w.tools["nuclei"] = NewNucleiTool()
	w.tools["subdomainizer"] = NewSubdomainizerTool()
	w.tools["zap"] = NewZAPTool()
	w.tools["custom_browser"] = NewCustomBrowserTool()
	w.tools["multi_identity"] = NewMultiIdentityTool()
	w.tools["oob_validator"] = NewOOBValidatorTool()
	w.tools["evidence_collector"] = NewEvidenceCollectorTool()
	w.tools["kill_chain_analyzer"] = NewKillChainAnalyzerTool()

	log.Printf("[WORKER_%d] Initialized %d tools", w.id, len(w.tools))
}

// setWorkerResourceLimits sets resource limits for a worker
func (wp *WorkerPool) setWorkerResourceLimits(worker *Worker) {
	worker.memoryLimit = wp.memoryLimit
	worker.cpuLimit = wp.cpuLimit
	log.Printf("[WORKER_POOL] Set resource limits for worker %d: memory=%dMB, cpu=%.1f%%",
		worker.id, wp.memoryLimit/(1024*1024), wp.cpuLimit)
}

// monitorWorkerHealth monitors the health of all workers
func (wp *WorkerPool) monitorWorkerHealth(ctx context.Context) {
	for {
		select {
		case <-wp.healthTicker.C:
			wp.checkWorkerHealth()
		case <-ctx.Done():
			return
		}
	}
}

// checkWorkerHealth checks the health of all workers and takes action if needed
func (wp *WorkerPool) checkWorkerHealth() {
	wp.healthMutex.RLock()
	defer wp.healthMutex.RUnlock()

	now := time.Now()
	for workerID, health := range wp.workerHealth {
		if health == nil {
			continue
		}

		// Check if worker missed heartbeat (consider dead after 30 seconds)
		if now.Sub(health.LastHeartbeat) > 30*time.Second {
			log.Printf("[WORKER_POOL] Worker %d appears to be dead (last heartbeat: %v)",
				workerID, health.LastHeartbeat)
			health.IsAlive = false

			// In a production system, you might want to restart the worker here
			// For now, we'll just log the issue
		}

		// Check resource usage
		memoryUsagePercent := float64(health.MemoryUsage) / float64(wp.memoryLimit) * 100
		if memoryUsagePercent > 80 {
			log.Printf("[WORKER_POOL] Worker %d high memory usage: %.1f%%",
				workerID, memoryUsagePercent)
		}

		if health.CPUUsage > 90 {
			log.Printf("[WORKER_POOL] Worker %d high CPU usage: %.1f%%",
				workerID, health.CPUUsage)
		}
	}
}

// GetWorkerHealth returns the health status of all workers
func (wp *WorkerPool) GetWorkerHealth() map[int]*WorkerHealth {
	wp.healthMutex.RLock()
	defer wp.healthMutex.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[int]*WorkerHealth)
	for id, health := range wp.workerHealth {
		if health != nil {
			healthCopy := *health
			result[id] = &healthCopy
		}
	}
	return result
}

// GetPoolMetrics returns overall pool metrics
func (wp *WorkerPool) GetPoolMetrics() map[string]interface{} {
	wp.metricsMutex.RLock()
	defer wp.metricsMutex.RUnlock()

	uptime := time.Since(wp.metricsStartTime)
	activeWorkers := atomic.LoadInt64(&wp.activeWorkers)
	totalTasks := atomic.LoadInt64(&wp.totalTasksProcessed)
	queueDepth := int64(len(wp.taskQueue))

	// Calculate utilization
	utilization := 0.0
	if wp.workerCount > 0 {
		busyWorkers := 0
		wp.healthMutex.RLock()
		for _, health := range wp.workerHealth {
			if health != nil && health.ActiveTask != "" {
				busyWorkers++
			}
		}
		wp.healthMutex.RUnlock()
		utilization = float64(busyWorkers) / float64(wp.workerCount) * 100
	}

	return map[string]interface{}{
		"worker_count":          wp.workerCount,
		"active_workers":        activeWorkers,
		"total_tasks_processed": totalTasks,
		"queue_depth":           queueDepth,
		"worker_utilization":    utilization,
		"uptime_seconds":        uptime.Seconds(),
		"tasks_per_second":      float64(totalTasks) / uptime.Seconds(),
	}
}

// Performance tracking methods for workers
func (w *Worker) incrementCompletedTasks() {
	atomic.AddInt64(&w.tasksCompleted, 1)
}

func (w *Worker) incrementFailedTasks() {
	atomic.AddInt64(&w.tasksFailed, 1)
}

func (w *Worker) updateExecutionTime(duration time.Duration) {
	w.metricsMutex.Lock()
	defer w.metricsMutex.Unlock()
	w.totalExecutionTime += duration
}

// Start starts the resource monitor
func (rm *ResourceMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(rm.checkInterval)
	defer ticker.Stop()

	log.Printf("[RESOURCE_MONITOR] Started with %d second intervals", int(rm.checkInterval.Seconds()))

	for {
		select {
		case <-ticker.C:
			rm.checkSystemResources()
		case <-ctx.Done():
			log.Printf("[RESOURCE_MONITOR] Stopping...")
			return
		}
	}
}

// checkSystemResources checks overall system resource usage
func (rm *ResourceMonitor) checkSystemResources() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Log system metrics periodically
	if time.Now().Unix()%60 == 0 { // Every minute
		log.Printf("[RESOURCE_MONITOR] System: Alloc=%dMB, Sys=%dMB, NumGC=%d, Goroutines=%d",
			m.Alloc/(1024*1024), m.Sys/(1024*1024), m.NumGC, runtime.NumGoroutine())
	}

	// Check for memory pressure
	if m.Alloc > 4*1024*1024*1024 { // 4GB threshold for warnings
		log.Printf("[RESOURCE_MONITOR] High system memory usage: %dMB", m.Alloc/(1024*1024))
	}

	// Check for goroutine leaks
	if runtime.NumGoroutine() > 2000 {
		log.Printf("[RESOURCE_MONITOR] High goroutine count: %d", runtime.NumGoroutine())
	}
}

// GetSystemMetrics returns current system metrics
func (rm *ResourceMonitor) GetSystemMetrics() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"allocated_memory_mb": m.Alloc / (1024 * 1024),
		"system_memory_mb":    m.Sys / (1024 * 1024),
		"gc_cycles":           m.NumGC,
		"goroutines":          runtime.NumGoroutine(),
		"cpu_cores":           runtime.NumCPU(),
		"memory_limit_mb":     rm.memoryLimit / (1024 * 1024),
		"cpu_limit_percent":   rm.cpuLimit,
	}
}
