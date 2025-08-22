package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Log levels
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
	LogLevelFatal = "fatal"
)

// Log categories
const (
	LogCategorySystem       = "system"
	LogCategoryWorkflow     = "workflow"
	LogCategoryTool         = "tool"
	LogCategoryFinding      = "finding"
	LogCategoryEvidence     = "evidence"
	LogCategoryAuth         = "auth"
	LogCategoryAPI          = "api"
	LogCategoryDatabase     = "database"
	LogCategoryOrchestrator = "orchestrator"
	LogCategoryKillChain    = "kill_chain"
)

type LogEntry struct {
	ID              string                 `json:"id"`
	SessionID       sql.NullString         `json:"session_id,omitempty"`
	FindingID       sql.NullString         `json:"finding_id,omitempty"`
	WorkflowStage   sql.NullString         `json:"workflow_stage,omitempty"`
	LogLevel        string                 `json:"log_level"`
	LogCategory     string                 `json:"log_category"`
	Message         string                 `json:"message"`
	LogData         map[string]interface{} `json:"log_data"`
	ErrorDetails    sql.NullString         `json:"error_details,omitempty"`
	StackTrace      sql.NullString         `json:"stack_trace,omitempty"`
	ExecutionTimeMs sql.NullInt64          `json:"execution_time_ms,omitempty"`
	SourceFunction  sql.NullString         `json:"source_function,omitempty"`
	SourceFile      sql.NullString         `json:"source_file,omitempty"`
	SourceLine      sql.NullInt32          `json:"source_line,omitempty"`
	UserAgent       sql.NullString         `json:"user_agent,omitempty"`
	IPAddress       sql.NullString         `json:"ip_address,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
}

type LogFilter struct {
	SessionID   string    `json:"session_id"`
	FindingID   string    `json:"finding_id"`
	Level       string    `json:"level"`
	Category    string    `json:"category"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Limit       int       `json:"limit"`
	Offset      int       `json:"offset"`
	IncludeData bool      `json:"include_data"`
}

type LogMetrics struct {
	TotalLogs   int64             `json:"total_logs"`
	ByLevel     map[string]int64  `json:"by_level"`
	ByCategory  map[string]int64  `json:"by_category"`
	ErrorRate   float64           `json:"error_rate"`
	AvgExecTime float64           `json:"avg_execution_time_ms"`
	TimeRange   map[string]string `json:"time_range"`
}

// Logger instance
type Logger struct {
	SessionID       string
	WorkflowStage   string
	DefaultCategory string
}

func NewLogger(sessionID, workflowStage, category string) *Logger {
	return &Logger{
		SessionID:       sessionID,
		WorkflowStage:   workflowStage,
		DefaultCategory: category,
	}
}

// Core logging methods
func (l *Logger) Debug(message string, data map[string]interface{}) {
	l.log(LogLevelDebug, l.DefaultCategory, message, data, nil, 0)
}

func (l *Logger) Info(message string, data map[string]interface{}) {
	l.log(LogLevelInfo, l.DefaultCategory, message, data, nil, 0)
}

func (l *Logger) Warn(message string, data map[string]interface{}) {
	l.log(LogLevelWarn, l.DefaultCategory, message, data, nil, 0)
}

func (l *Logger) Error(message string, err error, data map[string]interface{}) {
	l.log(LogLevelError, l.DefaultCategory, message, data, err, 0)
}

func (l *Logger) Fatal(message string, err error, data map[string]interface{}) {
	l.log(LogLevelFatal, l.DefaultCategory, message, data, err, 0)
}

// Category-specific logging
func (l *Logger) LogTool(level, toolName, message string, executionTime time.Duration, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["tool_name"] = toolName
	l.log(level, LogCategoryTool, message, data, nil, executionTime.Milliseconds())
}

func (l *Logger) LogFinding(level, findingID, message string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["finding_id"] = findingID
	l.log(level, LogCategoryFinding, message, data, nil, 0)
}

func (l *Logger) LogEvidence(level, evidenceID, evidenceType, message string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["evidence_id"] = evidenceID
	data["evidence_type"] = evidenceType
	l.log(level, LogCategoryEvidence, message, data, nil, 0)
}

func (l *Logger) LogWorkflow(level, stage, message string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["stage"] = stage
	l.log(level, LogCategoryWorkflow, message, data, nil, 0)
}

func (l *Logger) log(level, category, message string, data map[string]interface{}, err error, execTimeMs int64) {
	entry := LogEntry{
		ID:          uuid.New().String(),
		LogLevel:    level,
		LogCategory: category,
		Message:     message,
		LogData:     data,
		CreatedAt:   time.Now(),
	}

	if l.SessionID != "" {
		entry.SessionID = sql.NullString{String: l.SessionID, Valid: true}
	}

	if l.WorkflowStage != "" {
		entry.WorkflowStage = sql.NullString{String: l.WorkflowStage, Valid: true}
	}

	if err != nil {
		entry.ErrorDetails = sql.NullString{String: err.Error(), Valid: true}
	}

	if execTimeMs > 0 {
		entry.ExecutionTimeMs = sql.NullInt64{Int64: execTimeMs, Valid: true}
	}

	// Store to database
	go func() {
		if err := storeLogEntry(entry); err != nil {
			log.Printf("[ERROR] Failed to store log entry: %v", err)
		}
	}()

	// Also log to standard logger for immediate visibility
	logMsg := fmt.Sprintf("[%s][%s][%s] %s", level, category, l.SessionID, message)
	if err != nil {
		logMsg += fmt.Sprintf(" | Error: %v", err)
	}
	log.Println(logMsg)
}

// API Handlers for log management
func GetLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	filter := LogFilter{
		Limit:       100, // Default limit
		IncludeData: true,
	}

	if sessionID := r.URL.Query().Get("session_id"); sessionID != "" {
		filter.SessionID = sessionID
	}

	if findingID := r.URL.Query().Get("finding_id"); findingID != "" {
		filter.FindingID = findingID
	}

	if level := r.URL.Query().Get("level"); level != "" {
		filter.Level = level
	}

	if category := r.URL.Query().Get("category"); category != "" {
		filter.Category = category
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 1000 {
			filter.Limit = limit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	if includeDataStr := r.URL.Query().Get("include_data"); includeDataStr == "false" {
		filter.IncludeData = false
	}

	// Parse time range
	if startTimeStr := r.URL.Query().Get("start_time"); startTimeStr != "" {
		if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filter.StartTime = startTime
		}
	}

	if endTimeStr := r.URL.Query().Get("end_time"); endTimeStr != "" {
		if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filter.EndTime = endTime
		}
	}

	logs, err := queryLogs(filter)
	if err != nil {
		log.Printf("[ERROR] Failed to query logs: %v", err)
		http.Error(w, "Failed to retrieve logs", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"logs":   logs,
		"count":  len(logs),
		"filter": filter,
	}

	json.NewEncoder(w).Encode(response)
}

func GetLogMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	timeRange := "24h" // Default
	if tr := r.URL.Query().Get("time_range"); tr != "" {
		timeRange = tr
	}

	metrics, err := calculateLogMetrics(sessionID, timeRange)
	if err != nil {
		log.Printf("[ERROR] Failed to calculate log metrics: %v", err)
		http.Error(w, "Failed to calculate metrics", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(metrics)
}

func ExportLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=logs.json")

	vars := mux.Vars(r)
	sessionID := vars["sessionId"]

	filter := LogFilter{
		SessionID:   sessionID,
		Limit:       10000,
		IncludeData: true,
	}

	logs, err := queryLogs(filter)
	if err != nil {
		log.Printf("[ERROR] Failed to export logs: %v", err)
		http.Error(w, "Failed to export logs", http.StatusInternalServerError)
		return
	}

	exportData := map[string]interface{}{
		"session_id":  sessionID,
		"exported_at": time.Now(),
		"total_logs":  len(logs),
		"logs":        logs,
	}

	json.NewEncoder(w).Encode(exportData)
}

// Database operations
func storeLogEntry(entry LogEntry) error {
	dataJSON, _ := json.Marshal(entry.LogData)

	query := `
		INSERT INTO logs (
			id, session_id, finding_id, workflow_stage, log_level, log_category,
			message, log_data, error_details, execution_time_ms, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
		)
	`

	_, err := dbPool.Exec(context.Background(), query,
		entry.ID, entry.SessionID, entry.FindingID, entry.WorkflowStage,
		entry.LogLevel, entry.LogCategory, entry.Message, dataJSON,
		entry.ErrorDetails, entry.ExecutionTimeMs, entry.CreatedAt,
	)

	return err
}

func queryLogs(filter LogFilter) ([]LogEntry, error) {
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if filter.SessionID != "" {
		whereClause += fmt.Sprintf(" AND session_id = $%d", argIndex)
		args = append(args, filter.SessionID)
		argIndex++
	}

	if filter.FindingID != "" {
		whereClause += fmt.Sprintf(" AND finding_id = $%d", argIndex)
		args = append(args, filter.FindingID)
		argIndex++
	}

	if filter.Level != "" {
		whereClause += fmt.Sprintf(" AND log_level = $%d", argIndex)
		args = append(args, filter.Level)
		argIndex++
	}

	if filter.Category != "" {
		whereClause += fmt.Sprintf(" AND log_category = $%d", argIndex)
		args = append(args, filter.Category)
		argIndex++
	}

	if !filter.StartTime.IsZero() {
		whereClause += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, filter.StartTime)
		argIndex++
	}

	if !filter.EndTime.IsZero() {
		whereClause += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, filter.EndTime)
		argIndex++
	}

	selectFields := `id, session_id, finding_id, workflow_stage, log_level, 
	                log_category, message, error_details, execution_time_ms, created_at`

	if filter.IncludeData {
		selectFields += ", log_data"
	}

	query := fmt.Sprintf(`
		SELECT %s
		FROM logs
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, selectFields, whereClause, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := dbPool.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		entry := LogEntry{}
		var dataStr sql.NullString

		if filter.IncludeData {
			err = rows.Scan(
				&entry.ID, &entry.SessionID, &entry.FindingID, &entry.WorkflowStage,
				&entry.LogLevel, &entry.LogCategory, &entry.Message,
				&entry.ErrorDetails, &entry.ExecutionTimeMs, &entry.CreatedAt,
				&dataStr,
			)
		} else {
			err = rows.Scan(
				&entry.ID, &entry.SessionID, &entry.FindingID, &entry.WorkflowStage,
				&entry.LogLevel, &entry.LogCategory, &entry.Message,
				&entry.ErrorDetails, &entry.ExecutionTimeMs, &entry.CreatedAt,
			)
		}

		if err != nil {
			log.Printf("[WARN] Failed to scan log row: %v", err)
			continue
		}

		// Parse log data if included
		if filter.IncludeData && dataStr.Valid {
			json.Unmarshal([]byte(dataStr.String), &entry.LogData)
		}

		logs = append(logs, entry)
	}

	return logs, nil
}

func calculateLogMetrics(sessionID, timeRange string) (*LogMetrics, error) {
	// Parse time range
	var startTime time.Time
	switch timeRange {
	case "1h":
		startTime = time.Now().Add(-1 * time.Hour)
	case "24h":
		startTime = time.Now().Add(-24 * time.Hour)
	case "7d":
		startTime = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		startTime = time.Now().Add(-30 * 24 * time.Hour)
	default:
		startTime = time.Now().Add(-24 * time.Hour)
	}

	whereClause := "WHERE created_at >= $1"
	args := []interface{}{startTime}
	argIndex := 2

	if sessionID != "" {
		whereClause += fmt.Sprintf(" AND session_id = $%d", argIndex)
		args = append(args, sessionID)
	}

	// Total logs count
	totalQuery := fmt.Sprintf("SELECT COUNT(*) FROM logs %s", whereClause)
	var totalLogs int64
	err := dbPool.QueryRow(context.Background(), totalQuery, args...).Scan(&totalLogs)
	if err != nil {
		return nil, err
	}

	// Count by level
	levelQuery := fmt.Sprintf(`
		SELECT log_level, COUNT(*) 
		FROM logs %s 
		GROUP BY log_level
	`, whereClause)

	levelRows, err := dbPool.Query(context.Background(), levelQuery, args...)
	if err != nil {
		return nil, err
	}
	defer levelRows.Close()

	byLevel := make(map[string]int64)
	for levelRows.Next() {
		var level string
		var count int64
		levelRows.Scan(&level, &count)
		byLevel[level] = count
	}

	// Count by category
	categoryQuery := fmt.Sprintf(`
		SELECT log_category, COUNT(*) 
		FROM logs %s 
		GROUP BY log_category
	`, whereClause)

	categoryRows, err := dbPool.Query(context.Background(), categoryQuery, args...)
	if err != nil {
		return nil, err
	}
	defer categoryRows.Close()

	byCategory := make(map[string]int64)
	for categoryRows.Next() {
		var category string
		var count int64
		categoryRows.Scan(&category, &count)
		byCategory[category] = count
	}

	// Calculate error rate
	errorLogs := byLevel["error"] + byLevel["fatal"]
	var errorRate float64
	if totalLogs > 0 {
		errorRate = float64(errorLogs) / float64(totalLogs) * 100
	}

	// Average execution time
	avgExecQuery := fmt.Sprintf(`
		SELECT AVG(execution_time_ms) 
		FROM logs %s 
		AND execution_time_ms IS NOT NULL
	`, whereClause)

	var avgExecTime sql.NullFloat64
	err = dbPool.QueryRow(context.Background(), avgExecQuery, args...).Scan(&avgExecTime)
	if err != nil {
		avgExecTime.Float64 = 0
	}

	metrics := &LogMetrics{
		TotalLogs:   totalLogs,
		ByLevel:     byLevel,
		ByCategory:  byCategory,
		ErrorRate:   errorRate,
		AvgExecTime: avgExecTime.Float64,
		TimeRange: map[string]string{
			"start": startTime.Format(time.RFC3339),
			"end":   time.Now().Format(time.RFC3339),
			"range": timeRange,
		},
	}

	return metrics, nil
}
