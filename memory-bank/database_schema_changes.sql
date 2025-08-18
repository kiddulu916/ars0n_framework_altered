-- Database Schema Changes for URL Workflow Integration
-- Adds URL workflow and findings pipeline tables to existing Ars0n Framework schema

-- ============================================================================
-- URL WORKFLOW TABLES (Extend existing workflow patterns)
-- ============================================================================

-- URL workflow sessions table (follows existing auto_scan_sessions pattern)
CREATE TABLE IF NOT EXISTS url_workflow_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    
    -- Prerequisite validation
    prerequisite_workflows_complete BOOLEAN NOT NULL DEFAULT FALSE,
    company_workflow_complete BOOLEAN NOT NULL DEFAULT FALSE,
    wildcard_workflow_complete BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- URL selection from ROI algorithm
    selected_urls JSONB NOT NULL DEFAULT '[]',  -- Top 10 ROI URLs from consolidated_attack_surface_assets
    roi_threshold DECIMAL(5,2) DEFAULT 0.0,
    
    -- Workflow state management
    current_phase VARCHAR(50) NOT NULL DEFAULT 'pending',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    progress INTEGER DEFAULT 0,  -- 0-100 percentage
    
    -- Configuration and metadata
    config_snapshot JSONB NOT NULL DEFAULT '{}',
    phase_results JSONB DEFAULT '{}',  -- Results from each phase
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    
    -- Constraints
    CHECK (current_phase IN ('pending', 'attack_surface_mapping', 'dast_scanning', 'targeted_testing', 'completed', 'failed')),
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    CHECK (progress >= 0 AND progress <= 100)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_url_workflow_sessions_scope_target_id ON url_workflow_sessions(scope_target_id);
CREATE INDEX IF NOT EXISTS idx_url_workflow_sessions_status ON url_workflow_sessions(status);
CREATE INDEX IF NOT EXISTS idx_url_workflow_sessions_phase ON url_workflow_sessions(current_phase);
CREATE INDEX IF NOT EXISTS idx_url_workflow_sessions_created_at ON url_workflow_sessions(created_at);

-- ============================================================================
-- FINDINGS PIPELINE TABLES (Core evidence and vulnerability management)
-- ============================================================================

-- Main findings table with deduplication support
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Deduplication and relationship
    key_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 hash for deduplication
    url_workflow_session_id UUID REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
    
    -- Finding metadata
    title VARCHAR(500) NOT NULL,
    description TEXT,
    category VARCHAR(100) NOT NULL,  -- 'xss', 'sqli', 'idor', 'ssrf', 'auth_bypass', etc.
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (confidence IN ('confirmed', 'high', 'medium', 'low')),
    
    -- Signal and evidence data
    signal JSONB NOT NULL DEFAULT '{}',  -- Raw detection signal
    metadata JSONB DEFAULT '{}',  -- Additional metadata
    
    -- Status and workflow
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'triaged', 'confirmed', 'closed', 'false_positive')),
    
    -- Kill-chain analysis
    kill_chain_score INTEGER DEFAULT 0,  -- 0-10 scoring for chaining potential
    kill_chain_tags TEXT[] DEFAULT '{}',  -- Tags like 'credential_access', 'privilege_escalation'
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for findings
CREATE INDEX IF NOT EXISTS idx_findings_key_hash ON findings(key_hash);
CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(url_workflow_session_id);
CREATE INDEX IF NOT EXISTS idx_findings_scope_target_id ON findings(scope_target_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_kill_chain_score ON findings(kill_chain_score);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);

-- Vectors table: Request/response patterns for vulnerability reproduction
CREATE TABLE IF NOT EXISTS vectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- HTTP request details
    method VARCHAR(10) NOT NULL,  -- 'GET', 'POST', 'PUT', 'DELETE', etc.
    url_template TEXT NOT NULL,  -- Parameterized URL pattern
    base_url TEXT NOT NULL,  -- Original base URL
    path TEXT,  -- URL path component
    
    -- Parameter and payload information
    params_shape JSONB NOT NULL DEFAULT '{}',  -- Parameter structure and types
    headers_shape JSONB NOT NULL DEFAULT '{}',  -- Header structure and types
    body_template TEXT,  -- Request body template
    content_type VARCHAR(100),  -- Request content type
    
    -- Payload information
    payload_type VARCHAR(50),  -- 'xss', 'sqli', 'command_injection', etc.
    payload_value TEXT,  -- Actual payload used
    injection_point VARCHAR(100),  -- Where payload was injected
    
    -- Response validation
    response_pattern TEXT,  -- Expected response pattern
    validation_method VARCHAR(50),  -- How to validate the vulnerability
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for vectors
CREATE INDEX IF NOT EXISTS idx_vectors_finding_id ON vectors(finding_id);
CREATE INDEX IF NOT EXISTS idx_vectors_method ON vectors(method);
CREATE INDEX IF NOT EXISTS idx_vectors_payload_type ON vectors(payload_type);
CREATE INDEX IF NOT EXISTS idx_vectors_content_type ON vectors(content_type);

-- Evidence blobs table: Artifact storage metadata
CREATE TABLE IF NOT EXISTS evidence_blobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- Artifact information
    type VARCHAR(20) NOT NULL CHECK (type IN ('har', 'screenshot', 'dom', 'pcap', 'log', 'response', 'video')),
    filename VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,  -- Storage path (e.g., /data/findings/uuid/artifact_type/file.ext)
    
    -- File integrity and metadata
    sha256 VARCHAR(64) NOT NULL,  -- File integrity hash
    size BIGINT NOT NULL,  -- File size in bytes
    mime_type VARCHAR(100),  -- MIME type
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',  -- Dimensions for images, duration for videos, etc.
    compression VARCHAR(20),  -- Compression method if applicable
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for evidence blobs
CREATE INDEX IF NOT EXISTS idx_evidence_blobs_finding_id ON evidence_blobs(finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_blobs_type ON evidence_blobs(type);
CREATE INDEX IF NOT EXISTS idx_evidence_blobs_sha256 ON evidence_blobs(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_blobs_size ON evidence_blobs(size);

-- Contexts table: Identity and tenant context for findings
CREATE TABLE IF NOT EXISTS contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- Identity context
    identity VARCHAR(20) NOT NULL CHECK (identity IN ('guest', 'user', 'admin', 'cross_tenant')),
    identity_details JSONB DEFAULT '{}',  -- Credentials, permissions, etc.
    
    -- Tenant and session context
    tenant VARCHAR(100),  -- Tenant identifier for multi-tenant testing
    session_id VARCHAR(100),  -- Session identifier for correlation
    user_agent TEXT,  -- User agent used
    
    -- Testing context
    test_phase VARCHAR(50),  -- Which phase discovered this finding
    tool_used VARCHAR(50),  -- Which tool discovered this
    
    -- Additional context metadata
    metadata JSONB DEFAULT '{}',  -- Additional context data
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for contexts
CREATE INDEX IF NOT EXISTS idx_contexts_finding_id ON contexts(finding_id);
CREATE INDEX IF NOT EXISTS idx_contexts_identity ON contexts(identity);
CREATE INDEX IF NOT EXISTS idx_contexts_tenant ON contexts(tenant);
CREATE INDEX IF NOT EXISTS idx_contexts_session_id ON contexts(session_id);
CREATE INDEX IF NOT EXISTS idx_contexts_test_phase ON contexts(test_phase);
CREATE INDEX IF NOT EXISTS idx_contexts_tool_used ON contexts(tool_used);

-- Repro recipes table: Reproduction instructions and scripts
CREATE TABLE IF NOT EXISTS repro_recipes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    
    -- Reproduction methods
    curl_json JSONB NOT NULL DEFAULT '{}',  -- Minimal curl command as JSON
    playwright_script_path TEXT,  -- Path to Playwright reproduction script
    burp_request_path TEXT,  -- Path to Burp Suite request file
    
    -- Instructions and documentation
    notes TEXT,  -- Human-readable reproduction notes
    prerequisites TEXT,  -- Required setup or conditions
    expected_outcome TEXT,  -- What should happen when reproduced
    
    -- Reliability and validation
    success_rate DECIMAL(3,2) DEFAULT 1.0,  -- Reproduction success rate (0.0-1.0)
    last_validated TIMESTAMP,  -- When reproduction was last validated
    validation_status VARCHAR(20) DEFAULT 'untested',  -- 'untested', 'working', 'broken'
    
    -- Automation flags
    automated_repro BOOLEAN DEFAULT FALSE,  -- Whether reproduction is automated
    browser_required BOOLEAN DEFAULT FALSE,  -- Whether browser is required
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for repro recipes
CREATE INDEX IF NOT EXISTS idx_repro_recipes_finding_id ON repro_recipes(finding_id);
CREATE INDEX IF NOT EXISTS idx_repro_recipes_success_rate ON repro_recipes(success_rate);
CREATE INDEX IF NOT EXISTS idx_repro_recipes_validation_status ON repro_recipes(validation_status);
CREATE INDEX IF NOT EXISTS idx_repro_recipes_automated_repro ON repro_recipes(automated_repro);

-- OOB events table: Out-of-band interaction logs
CREATE TABLE IF NOT EXISTS oob_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,  -- Nullable for unmatched events
    url_workflow_session_id UUID REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
    
    -- Interaction details
    channel VARCHAR(10) NOT NULL CHECK (channel IN ('dns', 'http', 'https', 'smtp', 'ftp')),
    token VARCHAR(100) NOT NULL,  -- Unique interaction token
    payload_id VARCHAR(100),  -- ID linking to original payload
    
    -- Event data
    source_ip INET,  -- Source IP address
    user_agent TEXT,  -- User agent if HTTP
    headers JSONB DEFAULT '{}',  -- HTTP headers or protocol-specific data
    body TEXT,  -- Request body or payload data
    
    -- Timing and status
    ts TIMESTAMP NOT NULL,  -- Event timestamp
    matched BOOLEAN DEFAULT FALSE,  -- Whether event was matched to a finding
    processed BOOLEAN DEFAULT FALSE,  -- Whether event was processed
    
    -- Additional metadata
    meta JSONB NOT NULL DEFAULT '{}',  -- Event metadata (DNS queries, HTTP requests, etc.)
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for OOB events
CREATE INDEX IF NOT EXISTS idx_oob_events_finding_id ON oob_events(finding_id);
CREATE INDEX IF NOT EXISTS idx_oob_events_session_id ON oob_events(url_workflow_session_id);
CREATE INDEX IF NOT EXISTS idx_oob_events_channel ON oob_events(channel);
CREATE INDEX IF NOT EXISTS idx_oob_events_token ON oob_events(token);
CREATE INDEX IF NOT EXISTS idx_oob_events_payload_id ON oob_events(payload_id);
CREATE INDEX IF NOT EXISTS idx_oob_events_ts ON oob_events(ts);
CREATE INDEX IF NOT EXISTS idx_oob_events_matched ON oob_events(matched);
CREATE INDEX IF NOT EXISTS idx_oob_events_source_ip ON oob_events(source_ip);

-- ============================================================================
-- KILL CHAIN ANALYSIS TABLES
-- ============================================================================

-- Kill chain relationships table
CREATE TABLE IF NOT EXISTS kill_chain_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Relationship details
    parent_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    child_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    relationship_type VARCHAR(50) NOT NULL,  -- 'leads_to', 'enables', 'combines_with'
    
    -- Chain analysis
    chain_sequence INTEGER NOT NULL,  -- Order in the kill chain
    exploitation_path TEXT,  -- Description of how vulnerabilities chain
    impact_multiplier DECIMAL(3,2) DEFAULT 1.0,  -- Impact multiplier when chained
    
    -- Validation
    validated BOOLEAN DEFAULT FALSE,  -- Whether chain was validated
    automation_possible BOOLEAN DEFAULT FALSE,  -- Whether chain can be automated
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    UNIQUE(parent_finding_id, child_finding_id),
    CHECK (parent_finding_id != child_finding_id)
);

-- Create indexes for kill chain relationships
CREATE INDEX IF NOT EXISTS idx_kill_chain_parent_finding ON kill_chain_relationships(parent_finding_id);
CREATE INDEX IF NOT EXISTS idx_kill_chain_child_finding ON kill_chain_relationships(child_finding_id);
CREATE INDEX IF NOT EXISTS idx_kill_chain_relationship_type ON kill_chain_relationships(relationship_type);
CREATE INDEX IF NOT EXISTS idx_kill_chain_sequence ON kill_chain_relationships(chain_sequence);

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Function to generate finding key hash for deduplication
CREATE OR REPLACE FUNCTION generate_finding_key_hash(
    vuln_category TEXT,
    url_template TEXT,
    method TEXT,
    param_keys TEXT[],
    identity TEXT,
    tenant TEXT DEFAULT NULL
) RETURNS VARCHAR(64) AS $$
BEGIN
    RETURN encode(
        digest(
            vuln_category || '|' || 
            url_template || '|' || 
            method || '|' || 
            COALESCE(array_to_string(param_keys, ','), '') || '|' ||
            identity || '|' ||
            COALESCE(tenant, 'default'),
            'sha256'
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql;

-- Function to check prerequisite workflows completion
CREATE OR REPLACE FUNCTION check_prerequisite_workflows_complete(scope_target_uuid UUID) 
RETURNS BOOLEAN AS $$
DECLARE
    company_complete BOOLEAN DEFAULT FALSE;
    wildcard_complete BOOLEAN DEFAULT FALSE;
BEGIN
    -- Check if Company workflow completed (look for consolidated attack surface assets)
    SELECT EXISTS(
        SELECT 1 FROM consolidated_attack_surface_assets 
        WHERE scope_target_id = scope_target_uuid 
          AND asset_type = 'company_domain'
        LIMIT 1
    ) INTO company_complete;
    
    -- Check if Wildcard workflow completed (look for ROI-scored live web servers)
    SELECT EXISTS(
        SELECT 1 FROM consolidated_attack_surface_assets 
        WHERE scope_target_id = scope_target_uuid 
          AND asset_type = 'live_web_server' 
          AND roi_score IS NOT NULL
        LIMIT 1
    ) INTO wildcard_complete;
    
    RETURN company_complete AND wildcard_complete;
END;
$$ LANGUAGE plpgsql;

-- Function to get top ROI URLs for URL workflow
CREATE OR REPLACE FUNCTION get_top_roi_urls(scope_target_uuid UUID, url_limit INTEGER DEFAULT 10)
RETURNS TABLE(url TEXT, roi_score DECIMAL, metadata JSONB) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        casa.url::TEXT,
        casa.roi_score,
        casa.metadata
    FROM consolidated_attack_surface_assets casa
    WHERE casa.scope_target_id = scope_target_uuid
      AND casa.asset_type = 'live_web_server'
      AND casa.roi_score IS NOT NULL
      AND casa.url IS NOT NULL
    ORDER BY casa.roi_score DESC
    LIMIT url_limit;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- UPDATE TRIGGERS
-- ============================================================================

-- Update trigger for findings table
CREATE OR REPLACE FUNCTION update_findings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER findings_updated_at_trigger
    BEFORE UPDATE ON findings
    FOR EACH ROW
    EXECUTE FUNCTION update_findings_updated_at();

-- Update trigger for repro_recipes table
CREATE TRIGGER repro_recipes_updated_at_trigger
    BEFORE UPDATE ON repro_recipes
    FOR EACH ROW
    EXECUTE FUNCTION update_findings_updated_at();

-- ============================================================================
-- INTEGRATION WITH EXISTING TABLES
-- ============================================================================

-- Add URL workflow reference to existing auto_scan_sessions table (if needed)
-- ALTER TABLE auto_scan_sessions ADD COLUMN IF NOT EXISTS url_workflow_session_id UUID REFERENCES url_workflow_sessions(id);

-- Add findings reference to existing scan tables for cross-referencing
-- This allows existing tool scans to reference findings they discovered
ALTER TABLE nuclei_scans ADD COLUMN IF NOT EXISTS findings_submitted INTEGER DEFAULT 0;
ALTER TABLE httpx_scans ADD COLUMN IF NOT EXISTS findings_submitted INTEGER DEFAULT 0;

-- ============================================================================
-- SAMPLE DATA FOR TESTING
-- ============================================================================

-- Sample URL workflow session
-- INSERT INTO url_workflow_sessions (scope_target_id, prerequisite_workflows_complete, selected_urls, current_phase, status, config_snapshot)
-- SELECT 
--     id,
--     TRUE,
--     '["https://example.com", "https://api.example.com", "https://admin.example.com"]'::jsonb,
--     'attack_surface_mapping',
--     'running',
--     '{"phase_1_enabled": true, "phase_2_enabled": true, "phase_3_enabled": true}'::jsonb
-- FROM scope_targets 
-- WHERE type = 'Company' 
-- LIMIT 1;

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ars0n_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ars0n_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ars0n_user;
