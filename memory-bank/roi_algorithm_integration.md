# ROI Algorithm Integration for URL Workflow

## Overview

This document outlines the integration plan for leveraging the existing ROI (Return on Investment) algorithm in the Ars0n Framework to select the top 10 highest-scoring URLs for the automated URL workflow testing.

## Current ROI System Analysis

### Existing ROI Infrastructure

The Ars0n Framework already has a sophisticated ROI scoring system integrated into the Company and Wildcard workflows:

```sql
-- Existing table structure (from current framework)
consolidated_attack_surface_assets (
    id UUID PRIMARY KEY,
    scope_target_id UUID REFERENCES scope_targets(id),
    asset_type VARCHAR(50),  -- 'live_web_server', 'subdomain', 'ip_address', etc.
    url TEXT,                -- The actual URL/endpoint
    roi_score DECIMAL(5,2),  -- ROI score (likely 0.00-100.00)
    metadata JSONB,          -- Additional ROI calculation metadata
    created_at TIMESTAMP,
    -- ... other columns
)
```

### ROI Scoring Factors (Inferred from Framework)

Based on the existing architecture, the ROI algorithm likely considers:

1. **Technology Stack Detection** (HTTPx results)
2. **Response Patterns** (status codes, headers, content)
3. **Endpoint Accessibility** (authentication requirements)
4. **Content Analysis** (forms, inputs, file uploads)
5. **Framework Fingerprinting** (known vulnerabilities)
6. **Port and Service Analysis** (non-standard ports, services)
7. **SSL/TLS Configuration** (certificate details, security)
8. **Directory Structure** (admin panels, APIs, sensitive paths)

## ROI Integration Architecture

### 1. Prerequisite Validation Function

```go
// server/utils/urlWorkflowUtils.go
func validatePrerequisitesAndGetROIUrls(scopeTargetID string) (*URLWorkflowPrerequisites, error) {
    // 1. Check Company workflow completion
    companyComplete, err := isCompanyWorkflowComplete(scopeTargetID)
    if err != nil {
        return nil, fmt.Errorf("failed to check Company workflow status: %w", err)
    }
    
    // 2. Check Wildcard workflow completion
    wildcardComplete, err := isWildcardWorkflowComplete(scopeTargetID)
    if err != nil {
        return nil, fmt.Errorf("failed to check Wildcard workflow status: %w", err)
    }
    
    // 3. Both workflows must be complete
    if !companyComplete || !wildcardComplete {
        return &URLWorkflowPrerequisites{
            CompanyComplete:  companyComplete,
            WildcardComplete: wildcardComplete,
            CanProceed:       false,
            Message:         "Company and Wildcard workflows must complete before URL workflow",
        }, nil
    }
    
    // 4. Get ROI-scored URLs
    roiUrls, err := getTop10ROIUrls(scopeTargetID)
    if err != nil {
        return nil, fmt.Errorf("failed to get ROI URLs: %w", err)
    }
    
    if len(roiUrls) == 0 {
        return &URLWorkflowPrerequisites{
            CompanyComplete:  true,
            WildcardComplete: true,
            CanProceed:       false,
            Message:         "No ROI-scored URLs found. Run Company and Wildcard workflows first.",
        }, nil
    }
    
    return &URLWorkflowPrerequisites{
        CompanyComplete:  true,
        WildcardComplete: true,
        CanProceed:      true,
        ROIUrls:         roiUrls,
        Message:         fmt.Sprintf("Found %d ROI-scored URLs ready for testing", len(roiUrls)),
    }, nil
}

type URLWorkflowPrerequisites struct {
    CompanyComplete  bool      `json:"company_complete"`
    WildcardComplete bool      `json:"wildcard_complete"`
    CanProceed      bool      `json:"can_proceed"`
    ROIUrls         []ROIUrl  `json:"roi_urls"`
    Message         string    `json:"message"`
}

type ROIUrl struct {
    URL         string             `json:"url"`
    ROIScore    float64           `json:"roi_score"`
    AssetType   string            `json:"asset_type"`
    Metadata    map[string]interface{} `json:"metadata"`
    Priority    int               `json:"priority"`  // 1-10 ranking
}
```

### 2. ROI URL Selection Logic

```go
// server/utils/roiUtils.go
func getTop10ROIUrls(scopeTargetID string) ([]ROIUrl, error) {
    query := `
        SELECT 
            url,
            roi_score,
            asset_type,
            metadata,
            ROW_NUMBER() OVER (ORDER BY roi_score DESC) as priority
        FROM consolidated_attack_surface_assets 
        WHERE scope_target_id = $1 
          AND asset_type = 'live_web_server'
          AND roi_score IS NOT NULL
          AND url IS NOT NULL
          AND url != ''
        ORDER BY roi_score DESC 
        LIMIT 10
    `
    
    rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
    if err != nil {
        return nil, fmt.Errorf("failed to query ROI URLs: %w", err)
    }
    defer rows.Close()
    
    var roiUrls []ROIUrl
    for rows.Next() {
        var roiUrl ROIUrl
        var metadataJSON []byte
        
        err := rows.Scan(
            &roiUrl.URL,
            &roiUrl.ROIScore,
            &roiUrl.AssetType,
            &metadataJSON,
            &roiUrl.Priority,
        )
        if err != nil {
            log.Printf("Failed to scan ROI URL row: %v", err)
            continue
        }
        
        // Parse metadata JSON
        if len(metadataJSON) > 0 {
            if err := json.Unmarshal(metadataJSON, &roiUrl.Metadata); err != nil {
                log.Printf("Failed to parse metadata for URL %s: %v", roiUrl.URL, err)
                roiUrl.Metadata = make(map[string]interface{})
            }
        } else {
            roiUrl.Metadata = make(map[string]interface{})
        }
        
        roiUrls = append(roiUrls, roiUrl)
    }
    
    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("error iterating ROI URL rows: %w", err)
    }
    
    log.Printf("Retrieved %d ROI-scored URLs for scope target %s", len(roiUrls), scopeTargetID)
    return roiUrls, nil
}
```

### 3. Enhanced ROI Scoring for URL Workflow

```go
// server/utils/roiEnhancement.go
func enhanceROIForURLWorkflow(roiUrls []ROIUrl) []ROIUrl {
    for i, roiUrl := range roiUrls {
        // Add URL workflow specific scoring factors
        enhancedScore := roiUrl.ROIScore
        
        // Bonus for authentication endpoints
        if isAuthenticationEndpoint(roiUrl.URL) {
            enhancedScore += 15.0
            roiUrl.Metadata["auth_endpoint"] = true
        }
        
        // Bonus for API endpoints
        if isAPIEndpoint(roiUrl.URL) {
            enhancedScore += 10.0
            roiUrl.Metadata["api_endpoint"] = true
        }
        
        // Bonus for admin/management interfaces
        if isAdminInterface(roiUrl.URL) {
            enhancedScore += 20.0
            roiUrl.Metadata["admin_interface"] = true
        }
        
        // Bonus for file upload endpoints
        if hasFileUploadCapability(roiUrl.Metadata) {
            enhancedScore += 12.0
            roiUrl.Metadata["file_upload"] = true
        }
        
        // Bonus for form-heavy endpoints
        if hasMultipleForms(roiUrl.Metadata) {
            enhancedScore += 8.0
            roiUrl.Metadata["form_heavy"] = true
        }
        
        // Bonus for non-standard ports
        if hasNonStandardPort(roiUrl.URL) {
            enhancedScore += 5.0
            roiUrl.Metadata["non_standard_port"] = true
        }
        
        // Cap the enhanced score
        if enhancedScore > 100.0 {
            enhancedScore = 100.0
        }
        
        roiUrls[i].ROIScore = enhancedScore
        roiUrls[i].Metadata["original_roi_score"] = roiUrl.ROIScore
        roiUrls[i].Metadata["enhanced_for_url_workflow"] = true
    }
    
    // Re-sort by enhanced score
    sort.Slice(roiUrls, func(i, j int) bool {
        return roiUrls[i].ROIScore > roiUrls[j].ROIScore
    })
    
    // Update priorities
    for i := range roiUrls {
        roiUrls[i].Priority = i + 1
    }
    
    return roiUrls
}

func isAuthenticationEndpoint(url string) bool {
    authPatterns := []string{
        "/login", "/signin", "/auth", "/oauth", "/sso",
        "/authenticate", "/session", "/token", "/api/auth",
    }
    
    urlLower := strings.ToLower(url)
    for _, pattern := range authPatterns {
        if strings.Contains(urlLower, pattern) {
            return true
        }
    }
    return false
}

func isAPIEndpoint(url string) bool {
    apiPatterns := []string{
        "/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/",
        ".json", ".xml", "/endpoint", "/service",
    }
    
    urlLower := strings.ToLower(url)
    for _, pattern := range apiPatterns {
        if strings.Contains(urlLower, pattern) {
            return true
        }
    }
    return false
}

func isAdminInterface(url string) bool {
    adminPatterns := []string{
        "/admin", "/administrator", "/management", "/console",
        "/dashboard", "/panel", "/control", "/manage",
    }
    
    urlLower := strings.ToLower(url)
    for _, pattern := range adminPatterns {
        if strings.Contains(urlLower, pattern) {
            return true
        }
    }
    return false
}
```

### 4. Database Integration Functions

```sql
-- Add these functions to database_schema_changes.sql

-- Function to get workflow completion status
CREATE OR REPLACE FUNCTION is_company_workflow_complete(scope_target_uuid UUID) 
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS(
        SELECT 1 FROM consolidated_attack_surface_assets 
        WHERE scope_target_id = scope_target_uuid 
          AND asset_type IN ('company_domain', 'network_range', 'asn')
        LIMIT 1
    );
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION is_wildcard_workflow_complete(scope_target_uuid UUID) 
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS(
        SELECT 1 FROM consolidated_attack_surface_assets 
        WHERE scope_target_id = scope_target_uuid 
          AND asset_type = 'live_web_server' 
          AND roi_score IS NOT NULL
        LIMIT 1
    );
END;
$$ LANGUAGE plpgsql;

-- Enhanced function to get top ROI URLs with metadata
CREATE OR REPLACE FUNCTION get_enhanced_roi_urls(
    scope_target_uuid UUID, 
    url_limit INTEGER DEFAULT 10,
    min_roi_score DECIMAL DEFAULT 0.0
)
RETURNS TABLE(
    url TEXT, 
    roi_score DECIMAL, 
    asset_type TEXT,
    metadata JSONB,
    priority INTEGER,
    is_auth_endpoint BOOLEAN,
    is_api_endpoint BOOLEAN,
    is_admin_interface BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        casa.url::TEXT,
        casa.roi_score,
        casa.asset_type::TEXT,
        casa.metadata,
        ROW_NUMBER() OVER (ORDER BY casa.roi_score DESC)::INTEGER as priority,
        -- Enhanced categorization
        (LOWER(casa.url) ~ '.*(login|signin|auth|oauth|sso|authenticate|session|token).*')::BOOLEAN as is_auth_endpoint,
        (LOWER(casa.url) ~ '.*(api/|rest/|graphql|/v[0-9]+/|\.json|\.xml).*')::BOOLEAN as is_api_endpoint,
        (LOWER(casa.url) ~ '.*(admin|administrator|management|console|dashboard|panel|control|manage).*')::BOOLEAN as is_admin_interface
    FROM consolidated_attack_surface_assets casa
    WHERE casa.scope_target_id = scope_target_uuid
      AND casa.asset_type = 'live_web_server'
      AND casa.roi_score IS NOT NULL
      AND casa.roi_score >= min_roi_score
      AND casa.url IS NOT NULL
      AND casa.url != ''
    ORDER BY casa.roi_score DESC
    LIMIT url_limit;
END;
$$ LANGUAGE plpgsql;
```

### 5. API Endpoint Integration

```go
// server/main.go - Add to existing router
func setupROIEndpoints(router *mux.Router) {
    // Get ROI URLs for a scope target
    router.HandleFunc("/api/roi/urls/{scopeTargetId}", GetROIUrls).Methods("GET")
    
    // Check prerequisite workflows status
    router.HandleFunc("/api/roi/prerequisites/{scopeTargetId}", CheckPrerequisites).Methods("GET")
    
    // Get enhanced ROI analysis
    router.HandleFunc("/api/roi/analysis/{scopeTargetId}", GetROIAnalysis).Methods("GET")
}

func GetROIUrls(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    scopeTargetID := vars["scopeTargetId"]
    
    if scopeTargetID == "" {
        http.Error(w, "Missing scope target ID", http.StatusBadRequest)
        return
    }
    
    // Get query parameters for filtering
    minROIScore := 0.0
    if scoreStr := r.URL.Query().Get("min_score"); scoreStr != "" {
        if score, err := strconv.ParseFloat(scoreStr, 64); err == nil {
            minROIScore = score
        }
    }
    
    limit := 10
    if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
        if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 50 {
            limit = l
        }
    }
    
    // Get ROI URLs
    roiUrls, err := getTop10ROIUrls(scopeTargetID)
    if err != nil {
        log.Printf("Failed to get ROI URLs for scope %s: %v", scopeTargetID, err)
        http.Error(w, "Failed to retrieve ROI URLs", http.StatusInternalServerError)
        return
    }
    
    // Apply filtering and enhancement
    filteredUrls := []ROIUrl{}
    for _, roiUrl := range roiUrls {
        if roiUrl.ROIScore >= minROIScore {
            filteredUrls = append(filteredUrls, roiUrl)
        }
    }
    
    // Enhance for URL workflow
    enhancedUrls := enhanceROIForURLWorkflow(filteredUrls)
    
    // Limit results
    if len(enhancedUrls) > limit {
        enhancedUrls = enhancedUrls[:limit]
    }
    
    response := map[string]interface{}{
        "scope_target_id": scopeTargetID,
        "roi_urls":       enhancedUrls,
        "total_count":    len(enhancedUrls),
        "min_score":      minROIScore,
        "enhanced":       true,
    }
    
    if err := json.NewEncoder(w).Encode(response); err != nil {
        log.Printf("Failed to encode ROI URLs response: %v", err)
        http.Error(w, "Encoding error", http.StatusInternalServerError)
    }
}

func CheckPrerequisites(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Content-Type", "application/json")
    
    vars := mux.Vars(r)
    scopeTargetID := vars["scopeTargetId"]
    
    prerequisites, err := validatePrerequisitesAndGetROIUrls(scopeTargetID)
    if err != nil {
        log.Printf("Failed to check prerequisites for scope %s: %v", scopeTargetID, err)
        http.Error(w, "Failed to check prerequisites", http.StatusInternalServerError)
        return
    }
    
    if err := json.NewEncoder(w).Encode(prerequisites); err != nil {
        log.Printf("Failed to encode prerequisites response: %v", err)
        http.Error(w, "Encoding error", http.StatusInternalServerError)
    }
}
```

### 6. Frontend Integration

```jsx
// client/src/utils/fetchROIUrls.js
export const fetchROIUrls = async (scopeTargetId, options = {}) => {
    const { minScore = 0, limit = 10 } = options;
    
    try {
        const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
        const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
        const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
        
        const queryParams = new URLSearchParams({
            min_score: minScore.toString(),
            limit: limit.toString()
        });
        
        const response = await fetch(
            `${serverProtocol}://${serverIP}:${serverPort}/api/roi/urls/${scopeTargetId}?${queryParams}`
        );
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Failed to fetch ROI URLs:', error);
        throw error;
    }
};

export const checkURLWorkflowPrerequisites = async (scopeTargetId) => {
    try {
        const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
        const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
        const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
        
        const response = await fetch(
            `${serverProtocol}://${serverIP}:${serverPort}/api/roi/prerequisites/${scopeTargetId}`
        );
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Failed to check URL workflow prerequisites:', error);
        throw error;
    }
};
```

This integration plan ensures that the URL workflow seamlessly leverages the existing ROI algorithm while adding URL-specific enhancements for optimal target selection and testing prioritization.
