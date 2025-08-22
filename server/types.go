package main

import (
	"database/sql"
	"time"
)

type ASN struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Number    string    `json:"number"`
	RawData   string    `json:"raw_data"`
	CreatedAt time.Time `json:"created_at"`
}

type Subnet struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	CIDR      string    `json:"cidr"`
	RawData   string    `json:"raw_data"`
	CreatedAt time.Time `json:"created_at"`
}

type IPAddress struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"created_at"`
}

type Subdomain struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Subdomain string    `json:"subdomain"`
	CreatedAt time.Time `json:"created_at"`
}

type CloudDomain struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type RequestPayload struct {
	Type        string `json:"type"`
	ScopeTarget string `json:"scope_target"`
	Active      bool   `json:"active"`
}

type ResponsePayload struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	ScopeTarget string `json:"scope_target"`
	Active      bool   `json:"active"`
}

type ServiceProvider struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Provider  string    `json:"provider"`
	RawData   string    `json:"raw_data"`
	CreatedAt time.Time `json:"created_at"`
}

type ScanSummary struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"`
	Result    string    `json:"result,omitempty"`
	Error     string    `json:"error,omitempty"`
	StdOut    string    `json:"stdout,omitempty"`
	StdErr    string    `json:"stderr,omitempty"`
	Command   string    `json:"command,omitempty"`
	ExecTime  string    `json:"execution_time,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ScanType  string    `json:"scan_type"`
}

type GauScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type Sublist3rScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type AssetfinderScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type CTLScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type SubfinderScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type ShuffleDNSScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

type CeWLScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	URL               string         `json:"url"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type MetaDataStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type ASNResponse struct {
	Number  string `json:"number"`
	RawData string `json:"raw_data"`
}

type ServiceProviderResponse struct {
	Provider string `json:"provider"`
	RawData  string `json:"raw_data"`
}

type CertEntry struct {
	NameValue string `json:"name_value"`
}

// URL Workflow Session Types
type URLWorkflowSession struct {
	ID                 string         `json:"id"`
	SessionID          string         `json:"session_id"`
	ScopeTargetID      string         `json:"scope_target_id"`
	SelectedURLs       []string       `json:"selected_urls"`
	Status             string         `json:"status"`
	CurrentPhase       string         `json:"current_phase"`
	PhaseProgress      map[string]any `json:"phase_progress"`
	ResultsSummary     map[string]any `json:"results_summary"`
	ErrorMessage       sql.NullString `json:"error_message,omitempty"`
	StartedAt          time.Time      `json:"started_at"`
	CompletedAt        sql.NullTime   `json:"completed_at,omitempty"`
	TotalFindings      int            `json:"total_findings"`
	TotalEvidenceItems int            `json:"total_evidence_items"`
	AutoScanSessionID  sql.NullString `json:"auto_scan_session_id,omitempty"`
}

// Core Findings Pipeline Types
type Finding struct {
	ID                             string          `json:"id"`
	KeyHash                        string          `json:"key_hash"`
	Title                          string          `json:"title"`
	Description                    sql.NullString  `json:"description,omitempty"`
	Category                       string          `json:"category"`
	Severity                       string          `json:"severity"`
	Confidence                     string          `json:"confidence"`
	Signal                         string          `json:"signal"`
	Status                         string          `json:"status"`
	URL                            string          `json:"url"`
	Method                         string          `json:"method"`
	Parameters                     map[string]any  `json:"parameters"`
	VulnerabilityClass             sql.NullString  `json:"vulnerability_class,omitempty"`
	AffectedComponent              sql.NullString  `json:"affected_component,omitempty"`
	ImpactDescription              sql.NullString  `json:"impact_description,omitempty"`
	RemediationNotes               sql.NullString  `json:"remediation_notes,omitempty"`
	References                     []string        `json:"references"`
	CVSSScore                      sql.NullFloat64 `json:"cvss_score,omitempty"`
	CVSSVector                     sql.NullString  `json:"cvss_vector,omitempty"`
	CWEID                          sql.NullString  `json:"cwe_id,omitempty"`
	OWASPCategory                  sql.NullString  `json:"owasp_category,omitempty"`
	ManualVerificationRequired     bool            `json:"manual_verification_required"`
	AutomatedReproductionAvailable bool            `json:"automated_reproduction_available"`
	URLWorkflowSessionID           sql.NullString  `json:"url_workflow_session_id,omitempty"`
	ScopeTargetID                  string          `json:"scope_target_id"`
	DiscoveredAt                   time.Time       `json:"discovered_at"`
	LastUpdated                    time.Time       `json:"last_updated"`
	LastVerified                   sql.NullTime    `json:"last_verified,omitempty"`
	VerifiedBy                     sql.NullString  `json:"verified_by,omitempty"`
	Tags                           []string        `json:"tags"`
	Metadata                       map[string]any  `json:"metadata"`
}

type Vector struct {
	ID                  string         `json:"id"`
	FindingID           string         `json:"finding_id"`
	VectorType          string         `json:"vector_type"`
	VectorData          string         `json:"vector_data"`
	VectorMetadata      map[string]any `json:"vector_metadata"`
	ExecutionContext    sql.NullString `json:"execution_context,omitempty"`
	ValidationStatus    string         `json:"validation_status"`
	ValidationTimestamp sql.NullTime   `json:"validation_timestamp,omitempty"`
	ValidationResult    sql.NullString `json:"validation_result,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
}

type EvidenceBlob struct {
	ID                 string         `json:"id"`
	FindingID          string         `json:"finding_id"`
	BlobType           string         `json:"blob_type"`
	FilePath           sql.NullString `json:"file_path,omitempty"`
	FileSizeBytes      sql.NullInt64  `json:"file_size_bytes,omitempty"`
	MimeType           sql.NullString `json:"mime_type,omitempty"`
	BlobData           []byte         `json:"blob_data,omitempty"`
	BlobMetadata       map[string]any `json:"blob_metadata"`
	StorageType        string         `json:"storage_type"`
	CompressionType    sql.NullString `json:"compression_type,omitempty"`
	HashSHA256         sql.NullString `json:"hash_sha256,omitempty"`
	IsRedacted         bool           `json:"is_redacted"`
	RetentionExpiresAt sql.NullTime   `json:"retention_expires_at,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
}

type Context struct {
	ID              string         `json:"id"`
	FindingID       string         `json:"finding_id"`
	ContextType     string         `json:"context_type"`
	ContextName     string         `json:"context_name"`
	ContextValue    sql.NullString `json:"context_value,omitempty"`
	ContextMetadata map[string]any `json:"context_metadata"`
	IsActive        bool           `json:"is_active"`
	CreatedAt       time.Time      `json:"created_at"`
}

type ReproRecipe struct {
	ID                    string         `json:"id"`
	FindingID             string         `json:"finding_id"`
	RecipeType            string         `json:"recipe_type"`
	RecipeData            string         `json:"recipe_data"`
	RecipeMetadata        map[string]any `json:"recipe_metadata"`
	ExecutionEnvironment  sql.NullString `json:"execution_environment,omitempty"`
	Prerequisites         []string       `json:"prerequisites"`
	ExpectedOutcome       sql.NullString `json:"expected_outcome,omitempty"`
	ExecutionTimeEstimate sql.NullInt32  `json:"execution_time_estimate,omitempty"`
	SuccessCriteria       sql.NullString `json:"success_criteria,omitempty"`
	TroubleshootingNotes  sql.NullString `json:"troubleshooting_notes,omitempty"`
	IsValidated           bool           `json:"is_validated"`
	ValidationTimestamp   sql.NullTime   `json:"validation_timestamp,omitempty"`
	ValidationNotes       sql.NullString `json:"validation_notes,omitempty"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
}

type OOBEvent struct {
	ID                    string         `json:"id"`
	EventID               string         `json:"event_id"`
	FindingID             sql.NullString `json:"finding_id,omitempty"`
	EventType             string         `json:"event_type"`
	SourceIP              sql.NullString `json:"source_ip,omitempty"`
	DestinationHost       sql.NullString `json:"destination_host,omitempty"`
	DestinationPort       sql.NullInt32  `json:"destination_port,omitempty"`
	Protocol              sql.NullString `json:"protocol,omitempty"`
	Payload               sql.NullString `json:"payload,omitempty"`
	EventData             map[string]any `json:"event_data"`
	UserAgent             sql.NullString `json:"user_agent,omitempty"`
	Referrer              sql.NullString `json:"referrer,omitempty"`
	Timestamp             time.Time      `json:"timestamp"`
	IsAssociated          bool           `json:"is_associated"`
	AssociationConfidence float64        `json:"association_confidence"`
	URLWorkflowSessionID  sql.NullString `json:"url_workflow_session_id,omitempty"`
	ScopeTargetID         sql.NullString `json:"scope_target_id,omitempty"`
}

// Kill Chain Analysis Types
type KillChainAnalysis struct {
	ID                   string         `json:"id"`
	SessionID            string         `json:"session_id"`
	ChainType            string         `json:"chain_type"`
	ChainStatus          string         `json:"chain_status"`
	RiskScore            int            `json:"risk_score"`
	AttackVectorSummary  sql.NullString `json:"attack_vector_summary,omitempty"`
	BusinessImpact       sql.NullString `json:"business_impact,omitempty"`
	TechnicalImpact      sql.NullString `json:"technical_impact,omitempty"`
	ExploitabilityRating sql.NullString `json:"exploitability_rating,omitempty"`
	AttackComplexity     sql.NullString `json:"attack_complexity,omitempty"`
	RequiredPrivileges   sql.NullString `json:"required_privileges,omitempty"`
	UserInteraction      sql.NullString `json:"user_interaction,omitempty"`
	AttackSurface        sql.NullString `json:"attack_surface,omitempty"`
	PotentialImpactAreas []string       `json:"potential_impact_areas"`
	MitigationPriority   sql.NullString `json:"mitigation_priority,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

type KillChainStep struct {
	ID                         string         `json:"id"`
	KillChainID                string         `json:"kill_chain_id"`
	StepOrder                  int            `json:"step_order"`
	StepType                   string         `json:"step_type"`
	FindingID                  sql.NullString `json:"finding_id,omitempty"`
	StepDescription            string         `json:"step_description"`
	TechnicalDetails           sql.NullString `json:"technical_details,omitempty"`
	Prerequisites              []string       `json:"prerequisites"`
	Outcomes                   []string       `json:"outcomes"`
	ConfidenceLevel            float64        `json:"confidence_level"`
	VerificationStatus         string         `json:"verification_status"`
	AutomationPossible         bool           `json:"automation_possible"`
	ManualVerificationRequired bool           `json:"manual_verification_required"`
	EstimatedExecutionTime     sql.NullInt32  `json:"estimated_execution_time,omitempty"`
	CreatedAt                  time.Time      `json:"created_at"`
}

type KillChainPattern struct {
	ID                 string         `json:"id"`
	PatternName        string         `json:"pattern_name"`
	PatternDescription sql.NullString `json:"pattern_description,omitempty"`
	AttackCategory     string         `json:"attack_category"`
	PatternSteps       map[string]any `json:"pattern_steps"`
	RequiredFindings   []string       `json:"required_findings"`
	OptionalFindings   []string       `json:"optional_findings"`
	MinimumSeverity    string         `json:"minimum_severity"`
	ComplexityRating   string         `json:"complexity_rating"`
	SuccessCriteria    sql.NullString `json:"success_criteria,omitempty"`
	DetectionLogic     sql.NullString `json:"detection_logic,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// Enhanced Target URL with ROI integration
type EnhancedTargetURL struct {
	ID                       string         `json:"id"`
	URL                      string         `json:"url"`
	Screenshot               sql.NullString `json:"screenshot,omitempty"`
	StatusCode               sql.NullInt32  `json:"status_code,omitempty"`
	Title                    sql.NullString `json:"title,omitempty"`
	WebServer                sql.NullString `json:"web_server,omitempty"`
	Technologies             []string       `json:"technologies"`
	ContentLength            sql.NullInt32  `json:"content_length,omitempty"`
	NewlyDiscovered          bool           `json:"newly_discovered"`
	NoLongerLive             bool           `json:"no_longer_live"`
	ScopeTargetID            sql.NullString `json:"scope_target_id,omitempty"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
	ROIScore                 int            `json:"roi_score"`
	ROIFactors               map[string]any `json:"roi_factors"`
	ROILastCalculated        sql.NullTime   `json:"roi_last_calculated,omitempty"`
	URLWorkflowEligible      bool           `json:"url_workflow_eligible"`
	URLWorkflowLastTested    sql.NullTime   `json:"url_workflow_last_tested,omitempty"`
	URLWorkflowFindingsCount int            `json:"url_workflow_findings_count"`
	IPAddress                sql.NullString `json:"ip_address,omitempty"`
}

// URL Workflow Request/Response Types
type URLWorkflowInitiateRequest struct {
	ScopeTargetID string   `json:"scope_target_id"`
	SelectedURLs  []string `json:"selected_urls,omitempty"`
	MaxURLs       int      `json:"max_urls,omitempty"`
}

type URLWorkflowInitiateResponse struct {
	SessionID     string   `json:"session_id"`
	Status        string   `json:"status"`
	SelectedURLs  []string `json:"selected_urls"`
	EstimatedTime string   `json:"estimated_time"`
	Message       string   `json:"message"`
}

type URLWorkflowStatusResponse struct {
	SessionID          string                 `json:"session_id"`
	Status             string                 `json:"status"`
	CurrentPhase       string                 `json:"current_phase"`
	PhaseProgress      map[string]interface{} `json:"phase_progress"`
	ResultsSummary     map[string]interface{} `json:"results_summary"`
	TotalFindings      int                    `json:"total_findings"`
	TotalEvidenceItems int                    `json:"total_evidence_items"`
	StartedAt          time.Time              `json:"started_at"`
	CompletedAt        *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage       string                 `json:"error_message,omitempty"`
}

// Findings Management Types
type FindingsListRequest struct {
	ScopeTargetID        string   `json:"scope_target_id,omitempty"`
	URLWorkflowSessionID string   `json:"url_workflow_session_id,omitempty"`
	Category             string   `json:"category,omitempty"`
	Severity             []string `json:"severity,omitempty"`
	Status               []string `json:"status,omitempty"`
	Limit                int      `json:"limit,omitempty"`
	Offset               int      `json:"offset,omitempty"`
	SortBy               string   `json:"sort_by,omitempty"`
	SortOrder            string   `json:"sort_order,omitempty"`
}

type FindingsListResponse struct {
	Findings []Finding `json:"findings"`
	Total    int       `json:"total"`
	Limit    int       `json:"limit"`
	Offset   int       `json:"offset"`
	HasMore  bool      `json:"has_more"`
}

type CreateFindingRequest struct {
	Title                string         `json:"title"`
	Description          string         `json:"description,omitempty"`
	Category             string         `json:"category"`
	Severity             string         `json:"severity"`
	Confidence           string         `json:"confidence,omitempty"`
	Signal               string         `json:"signal"`
	URL                  string         `json:"url"`
	Method               string         `json:"method,omitempty"`
	Parameters           map[string]any `json:"parameters,omitempty"`
	VulnerabilityClass   string         `json:"vulnerability_class,omitempty"`
	URLWorkflowSessionID string         `json:"url_workflow_session_id,omitempty"`
	ScopeTargetID        string         `json:"scope_target_id"`
	Tags                 []string       `json:"tags,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

type UpdateFindingStatusRequest struct {
	Status     string `json:"status"`
	VerifiedBy string `json:"verified_by,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// ROI Algorithm Types
type ROICalculationRequest struct {
	ScopeTargetID    string `json:"scope_target_id"`
	MaxURLs          int    `json:"max_urls,omitempty"`
	ForceRecalculate bool   `json:"force_recalculate,omitempty"`
}

type ROICalculationResponse struct {
	TotalURLs    int                 `json:"total_urls"`
	EligibleURLs int                 `json:"eligible_urls"`
	TopURLs      []EnhancedTargetURL `json:"top_urls"`
	CalculatedAt time.Time           `json:"calculated_at"`
	Message      string              `json:"message"`
}
