# Multi-Identity Testing Framework Design - Ars0n Framework Integration

## Overview

This document outlines the design for a comprehensive multi-identity testing framework integrated with the existing Ars0n Framework scope management. The framework enables testing vulnerabilities across different user roles and tenants to uncover access control vulnerabilities that are invisible to single-context testing.

## Multi-Identity Philosophy

### Core Concepts
- **Identity Contexts**: Different user roles (guest, user, admin, cross-tenant)
- **Privilege Escalation Detection**: Identify when lower privileges can access higher privilege resources
- **Cross-Tenant Leakage**: Detect when one tenant can access another tenant's data
- **Authorization Bypass**: Find endpoints that don't properly validate user permissions
- **Session Management Flaws**: Identify weak session handling across different user types

### Testing Strategy
```
Guest Context → User Context → Admin Context → Cross-Tenant Context
     ↓              ↓              ↓                   ↓
No Authentication  Standard User   Administrative   Different Tenant
     ↓              ↓              ↓                   ↓
Basic Access     Protected Res.   Admin Functions   Tenant Isolation
     ↓              ↓              ↓                   ↓
Public Endpoints  User Profile    User Management   Data Segregation
```

## Architecture Integration

### 1. Multi-Identity Framework Core

```go
// server/utils/multiIdentityTesting.go
package utils

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"
    
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type MultiIdentityFramework struct {
    dbPool           *pgxpool.Pool
    scopeValidator   *ScopeValidator
    sessionManager   *SessionManager
    identityProvider *IdentityProvider
    evidenceCollector *EvidenceCollector
}

type IdentityContext struct {
    ID               string                 `json:"id"`
    Type             IdentityType          `json:"type"`
    Username         string                 `json:"username"`
    Role             string                 `json:"role"`
    Tenant           string                 `json:"tenant"`
    Permissions      []string               `json:"permissions"`
    Credentials      map[string]interface{} `json:"credentials"`
    SessionData      map[string]interface{} `json:"session_data"`
    AuthMethod       string                 `json:"auth_method"`
    Headers          map[string]string      `json:"headers"`
    Cookies          map[string]string      `json:"cookies"`
    Active           bool                   `json:"active"`
    CreatedAt        time.Time             `json:"created_at"`
    ExpiresAt        *time.Time            `json:"expires_at"`
}

type IdentityType string

const (
    IdentityGuest       IdentityType = "guest"
    IdentityUser        IdentityType = "user"
    IdentityAdmin       IdentityType = "admin"
    IdentityCrossTenant IdentityType = "cross_tenant"
    IdentityService     IdentityType = "service"
    IdentityLowPriv     IdentityType = "low_priv"
    IdentityHighPriv    IdentityType = "high_priv"
)

type AccessControlTest struct {
    ID                string           `json:"id"`
    SessionID         string           `json:"session_id"`
    URL               string           `json:"url"`
    Method            string           `json:"method"`
    TestedIdentities  []IdentityContext `json:"tested_identities"`
    Results           []TestResult     `json:"results"`
    ViolationsFound   []AccessViolation `json:"violations_found"`
    CreatedAt         time.Time        `json:"created_at"`
    CompletedAt       *time.Time       `json:"completed_at"`
}

type TestResult struct {
    IdentityID       string    `json:"identity_id"`
    IdentityType     IdentityType `json:"identity_type"`
    StatusCode       int       `json:"status_code"`
    ResponseSize     int       `json:"response_size"`
    ResponseHash     string    `json:"response_hash"`
    AccessGranted    bool      `json:"access_granted"`
    DataExposed      bool      `json:"data_exposed"`
    FunctionalityAccess bool   `json:"functionality_access"`
    ErrorMessages    []string  `json:"error_messages"`
    Timestamp        time.Time `json:"timestamp"`
}

type AccessViolation struct {
    ID               string       `json:"id"`
    Type             ViolationType `json:"type"`
    Severity         string       `json:"severity"`
    Description      string       `json:"description"`
    LowerPrivIdentity IdentityType `json:"lower_priv_identity"`
    HigherPrivIdentity IdentityType `json:"higher_priv_identity"`
    URL              string       `json:"url"`
    Evidence         []string     `json:"evidence"`
    Impact           string       `json:"impact"`
    Recommendation   string       `json:"recommendation"`
}

type ViolationType string

const (
    ViolationPrivilegeEscalation ViolationType = "privilege_escalation"
    ViolationHorizontalAccess    ViolationType = "horizontal_access"
    ViolationDataLeakage        ViolationType = "data_leakage"
    ViolationFunctionBypass     ViolationType = "function_bypass"
    ViolationTenantLeakage      ViolationType = "tenant_leakage"
    ViolationAuthBypass         ViolationType = "auth_bypass"
)

func NewMultiIdentityFramework(dbPool *pgxpool.Pool) *MultiIdentityFramework {
    return &MultiIdentityFramework{
        dbPool:           dbPool,
        scopeValidator:   NewScopeValidator(dbPool),
        sessionManager:   NewSessionManager(dbPool),
        identityProvider: NewIdentityProvider(dbPool),
        evidenceCollector: NewEvidenceCollector(dbPool),
    }
}

// Main multi-identity testing workflow
func (mif *MultiIdentityFramework) TestAccessControl(url, method, sessionID string) (*AccessControlTest, error) {
    log.Printf("[MULTI-IDENTITY] Starting access control test for %s %s", method, url)
    
    // 1. Validate URL is in scope
    if !mif.scopeValidator.IsInScope(url) {
        return nil, fmt.Errorf("URL %s is out of scope", url)
    }
    
    // 2. Get all available identity contexts
    identities, err := mif.identityProvider.GetActiveIdentities(sessionID)
    if err != nil {
        return nil, fmt.Errorf("failed to get identities: %w", err)
    }
    
    // 3. Create access control test
    test := &AccessControlTest{
        ID:               uuid.New().String(),
        SessionID:        sessionID,
        URL:              url,
        Method:           method,
        TestedIdentities: identities,
        Results:          []TestResult{},
        ViolationsFound:  []AccessViolation{},
        CreatedAt:        time.Now(),
    }
    
    // 4. Test each identity context
    for _, identity := range identities {
        result, err := mif.testWithIdentity(url, method, identity, test.ID)
        if err != nil {
            log.Printf("[MULTI-IDENTITY] Failed to test with identity %s: %v", identity.Type, err)
            continue
        }
        
        test.Results = append(test.Results, *result)
    }
    
    // 5. Analyze results for violations
    violations := mif.analyzeForViolations(test.Results, url, method)
    test.ViolationsFound = violations
    
    // 6. Store test results
    now := time.Now()
    test.CompletedAt = &now
    
    if err := mif.storeAccessControlTest(test); err != nil {
        log.Printf("[MULTI-IDENTITY] Failed to store test results: %v", err)
    }
    
    log.Printf("[MULTI-IDENTITY] Completed test: %d identities tested, %d violations found", 
        len(test.Results), len(violations))
    
    return test, nil
}

// Test with specific identity context
func (mif *MultiIdentityFramework) testWithIdentity(url, method string, identity IdentityContext, testID string) (*TestResult, error) {
    log.Printf("[MULTI-IDENTITY] Testing %s with identity %s (%s)", url, identity.Type, identity.Username)
    
    // 1. Create HTTP client with identity context
    client := mif.createAuthenticatedClient(identity)
    
    // 2. Build request
    req, err := http.NewRequest(method, url, nil)
    if err != nil {
        return nil, err
    }
    
    // 3. Add authentication headers/cookies
    mif.applyIdentityAuth(req, identity)
    
    // 4. Execute request
    startTime := time.Now()
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    // 5. Read response
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    // 6. Analyze response
    result := &TestResult{
        IdentityID:       identity.ID,
        IdentityType:     identity.Type,
        StatusCode:       resp.StatusCode,
        ResponseSize:     len(body),
        ResponseHash:     mif.calculateResponseHash(body),
        AccessGranted:    mif.isAccessGranted(resp.StatusCode, body),
        DataExposed:      mif.isDataExposed(body, identity),
        FunctionalityAccess: mif.isFunctionalityAccessible(body, resp.StatusCode),
        ErrorMessages:    mif.extractErrorMessages(body),
        Timestamp:        time.Now(),
    }
    
    // 7. Collect evidence
    evidenceData := map[string][]byte{
        "response": body,
        "headers":  []byte(mif.formatHeaders(resp.Header)),
    }
    
    findingID := uuid.New().String()
    mif.evidenceCollector.CollectEvidence(findingID, EvidenceTypeResponse, body, map[string]interface{}{
        "test_id":       testID,
        "identity_type": string(identity.Type),
        "url":           url,
        "method":        method,
        "status_code":   resp.StatusCode,
    })
    
    return result, nil
}

// Analyze test results for access control violations
func (mif *MultiIdentityFramework) analyzeForViolations(results []TestResult, url, method string) []AccessViolation {
    var violations []AccessViolation
    
    // Group results by identity type for comparison
    resultsByType := make(map[IdentityType]TestResult)
    for _, result := range results {
        resultsByType[result.IdentityType] = result
    }
    
    // 1. Check for privilege escalation (lower privilege accessing higher privilege resources)
    if guestResult, hasGuest := resultsByType[IdentityGuest]; hasGuest {
        if userResult, hasUser := resultsByType[IdentityUser]; hasUser {
            if mif.isPrivilegeEscalation(guestResult, userResult) {
                violations = append(violations, AccessViolation{
                    ID:                uuid.New().String(),
                    Type:              ViolationPrivilegeEscalation,
                    Severity:          "high",
                    Description:       "Guest user can access user-only resources",
                    LowerPrivIdentity: IdentityGuest,
                    HigherPrivIdentity: IdentityUser,
                    URL:               url,
                    Impact:            "Unauthorized access to user data and functionality",
                    Recommendation:    "Implement proper authentication checks",
                })
            }
        }
        
        if adminResult, hasAdmin := resultsByType[IdentityAdmin]; hasAdmin {
            if mif.isPrivilegeEscalation(guestResult, adminResult) {
                violations = append(violations, AccessViolation{
                    ID:                uuid.New().String(),
                    Type:              ViolationPrivilegeEscalation,
                    Severity:          "critical",
                    Description:       "Guest user can access administrative resources",
                    LowerPrivIdentity: IdentityGuest,
                    HigherPrivIdentity: IdentityAdmin,
                    URL:               url,
                    Impact:            "Complete administrative access bypass",
                    Recommendation:    "Implement role-based access control",
                })
            }
        }
    }
    
    // 2. Check for horizontal access violations (same privilege level, different users)
    if userResult, hasUser := resultsByType[IdentityUser]; hasUser {
        if crossTenantResult, hasCrossTenant := resultsByType[IdentityCrossTenant]; hasCrossTenant {
            if mif.isHorizontalAccess(userResult, crossTenantResult) {
                violations = append(violations, AccessViolation{
                    ID:                uuid.New().String(),
                    Type:              ViolationHorizontalAccess,
                    Severity:          "high",
                    Description:       "User can access cross-tenant resources",
                    LowerPrivIdentity: IdentityUser,
                    HigherPrivIdentity: IdentityCrossTenant,
                    URL:               url,
                    Impact:            "Cross-tenant data leakage",
                    Recommendation:    "Implement tenant isolation checks",
                })
            }
        }
    }
    
    // 3. Check for data leakage (sensitive data visible to unauthorized users)
    for _, result := range results {
        if result.DataExposed && (result.IdentityType == IdentityGuest || result.IdentityType == IdentityCrossTenant) {
            violations = append(violations, AccessViolation{
                ID:                uuid.New().String(),
                Type:              ViolationDataLeakage,
                Severity:          "high",
                Description:       fmt.Sprintf("Sensitive data exposed to %s identity", result.IdentityType),
                LowerPrivIdentity: result.IdentityType,
                HigherPrivIdentity: IdentityUser,
                URL:               url,
                Impact:            "Unauthorized data disclosure",
                Recommendation:    "Implement data access controls",
            })
        }
    }
    
    // 4. Check for authentication bypass
    if guestResult, hasGuest := resultsByType[IdentityGuest]; hasGuest {
        if guestResult.AccessGranted && guestResult.StatusCode == 200 {
            // Check if this should require authentication
            if mif.shouldRequireAuth(url) {
                violations = append(violations, AccessViolation{
                    ID:                uuid.New().String(),
                    Type:              ViolationAuthBypass,
                    Severity:          "medium",
                    Description:       "Protected resource accessible without authentication",
                    LowerPrivIdentity: IdentityGuest,
                    HigherPrivIdentity: IdentityUser,
                    URL:               url,
                    Impact:            "Bypass of authentication mechanisms",
                    Recommendation:    "Enforce authentication for protected resources",
                })
            }
        }
    }
    
    return violations
}

// Helper methods for violation detection
func (mif *MultiIdentityFramework) isPrivilegeEscalation(lowerPriv, higherPriv TestResult) bool {
    // Lower privilege identity gets same or similar access as higher privilege
    return lowerPriv.AccessGranted && 
           lowerPriv.StatusCode == 200 && 
           higherPriv.StatusCode == 200 &&
           mif.areSimilarResponses(lowerPriv.ResponseHash, higherPriv.ResponseHash)
}

func (mif *MultiIdentityFramework) isHorizontalAccess(user1, user2 TestResult) bool {
    // Different users at same privilege level accessing each other's data
    return user1.AccessGranted && user2.AccessGranted &&
           user1.StatusCode == 200 && user2.StatusCode == 200 &&
           mif.areSimilarResponses(user1.ResponseHash, user2.ResponseHash)
}

func (mif *MultiIdentityFramework) areSimilarResponses(hash1, hash2 string) bool {
    // In practice, this would be more sophisticated
    // Could compare response structure, data patterns, etc.
    return hash1 == hash2
}

func (mif *MultiIdentityFramework) isAccessGranted(statusCode int, body []byte) bool {
    // Successful status codes
    if statusCode >= 200 && statusCode < 300 {
        return true
    }
    
    // Check for access granted indicators in body
    accessIndicators := []string{
        "success", "welcome", "dashboard", "profile", "settings",
        "account", "admin", "user", "data", "results",
    }
    
    bodyStr := strings.ToLower(string(body))
    for _, indicator := range accessIndicators {
        if strings.Contains(bodyStr, indicator) {
            return true
        }
    }
    
    return false
}

func (mif *MultiIdentityFramework) isDataExposed(body []byte, identity IdentityContext) bool {
    // Check for sensitive data patterns
    sensitivePatterns := []string{
        `"user_id":`, `"email":`, `"phone":`, `"address":`,
        `"password":`, `"token":`, `"secret":`, `"key":`,
        `"credit_card":`, `"ssn":`, `"account_number":`,
    }
    
    bodyStr := strings.ToLower(string(body))
    for _, pattern := range sensitivePatterns {
        if strings.Contains(bodyStr, pattern) {
            return true
        }
    }
    
    return false
}

func (mif *MultiIdentityFramework) isFunctionalityAccessible(body []byte, statusCode int) bool {
    // Check if administrative or sensitive functionality is accessible
    functionalityPatterns := []string{
        "delete", "admin", "manage", "configure", "settings",
        "users", "permissions", "roles", "access", "control",
    }
    
    if statusCode != 200 {
        return false
    }
    
    bodyStr := strings.ToLower(string(body))
    for _, pattern := range functionalityPatterns {
        if strings.Contains(bodyStr, pattern) {
            return true
        }
    }
    
    return false
}

func (mif *MultiIdentityFramework) extractErrorMessages(body []byte) []string {
    var messages []string
    
    // Common error patterns
    errorPatterns := []string{
        "error", "forbidden", "unauthorized", "access denied",
        "permission denied", "not allowed", "invalid",
    }
    
    bodyStr := strings.ToLower(string(body))
    for _, pattern := range errorPatterns {
        if strings.Contains(bodyStr, pattern) {
            messages = append(messages, pattern)
        }
    }
    
    return messages
}

func (mif *MultiIdentityFramework) shouldRequireAuth(url string) bool {
    // URLs that should require authentication
    protectedPaths := []string{
        "/admin", "/dashboard", "/profile", "/account",
        "/settings", "/api/user", "/api/admin", "/manage",
    }
    
    for _, path := range protectedPaths {
        if strings.Contains(url, path) {
            return true
        }
    }
    
    return false
}

func (mif *MultiIdentityFramework) calculateResponseHash(body []byte) string {
    // Simple hash for response comparison
    hash := sha256.Sum256(body)
    return hex.EncodeToString(hash[:])
}

func (mif *MultiIdentityFramework) createAuthenticatedClient(identity IdentityContext) *http.Client {
    // Create HTTP client with appropriate configuration for identity
    return &http.Client{
        Timeout: 30 * time.Second,
    }
}

func (mif *MultiIdentityFramework) applyIdentityAuth(req *http.Request, identity IdentityContext) {
    // Apply authentication based on identity type
    switch identity.AuthMethod {
    case "bearer":
        if token, exists := identity.Credentials["token"]; exists {
            req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
        }
    case "basic":
        if username, exists := identity.Credentials["username"]; exists {
            if password, exists := identity.Credentials["password"]; exists {
                req.SetBasicAuth(fmt.Sprintf("%v", username), fmt.Sprintf("%v", password))
            }
        }
    case "cookie":
        for name, value := range identity.Cookies {
            req.AddCookie(&http.Cookie{
                Name:  name,
                Value: value,
            })
        }
    }
    
    // Apply custom headers
    for name, value := range identity.Headers {
        req.Header.Set(name, value)
    }
}

func (mif *MultiIdentityFramework) formatHeaders(headers http.Header) string {
    var headerStrs []string
    for name, values := range headers {
        for _, value := range values {
            headerStrs = append(headerStrs, fmt.Sprintf("%s: %s", name, value))
        }
    }
    return strings.Join(headerStrs, "\n")
}

func (mif *MultiIdentityFramework) storeAccessControlTest(test *AccessControlTest) error {
    // Store test results in database
    query := `
        INSERT INTO access_control_tests (id, session_id, url, method, tested_identities, 
                                        results, violations_found, created_at, completed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `
    
    identitiesJSON, _ := json.Marshal(test.TestedIdentities)
    resultsJSON, _ := json.Marshal(test.Results)
    violationsJSON, _ := json.Marshal(test.ViolationsFound)
    
    _, err := mif.dbPool.Exec(context.Background(), query,
        test.ID, test.SessionID, test.URL, test.Method,
        identitiesJSON, resultsJSON, violationsJSON,
        test.CreatedAt, test.CompletedAt)
    
    return err
}
```

### 2. Identity Provider System

```go
// server/utils/identityProvider.go
package utils

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "time"
    
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type IdentityProvider struct {
    dbPool *pgxpool.Pool
}

func NewIdentityProvider(dbPool *pgxpool.Pool) *IdentityProvider {
    return &IdentityProvider{
        dbPool: dbPool,
    }
}

// Get all active identity contexts for a session
func (ip *IdentityProvider) GetActiveIdentities(sessionID string) ([]IdentityContext, error) {
    query := `
        SELECT id, type, username, role, tenant, permissions, credentials, 
               session_data, auth_method, headers, cookies, active, created_at, expires_at
        FROM identity_contexts 
        WHERE session_id = $1 AND active = true
        ORDER BY type
    `
    
    rows, err := ip.dbPool.Query(context.Background(), query, sessionID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var identities []IdentityContext
    for rows.Next() {
        var identity IdentityContext
        var permissionsJSON, credentialsJSON, sessionDataJSON, headersJSON, cookiesJSON []byte
        
        err := rows.Scan(&identity.ID, &identity.Type, &identity.Username, &identity.Role,
                        &identity.Tenant, &permissionsJSON, &credentialsJSON, &sessionDataJSON,
                        &identity.AuthMethod, &headersJSON, &cookiesJSON, &identity.Active,
                        &identity.CreatedAt, &identity.ExpiresAt)
        if err != nil {
            continue
        }
        
        // Parse JSON fields
        json.Unmarshal(permissionsJSON, &identity.Permissions)
        json.Unmarshal(credentialsJSON, &identity.Credentials)
        json.Unmarshal(sessionDataJSON, &identity.SessionData)
        json.Unmarshal(headersJSON, &identity.Headers)
        json.Unmarshal(cookiesJSON, &identity.Cookies)
        
        identities = append(identities, identity)
    }
    
    // If no identities exist, create default set
    if len(identities) == 0 {
        identities = ip.createDefaultIdentities(sessionID)
    }
    
    return identities, nil
}

// Create default identity contexts for testing
func (ip *IdentityProvider) createDefaultIdentities(sessionID string) []IdentityContext {
    defaultIdentities := []IdentityContext{
        // Guest identity (no authentication)
        {
            ID:           uuid.New().String(),
            Type:         IdentityGuest,
            Username:     "guest",
            Role:         "anonymous",
            Tenant:       "",
            Permissions:  []string{"read_public"},
            Credentials:  map[string]interface{}{},
            SessionData:  map[string]interface{}{},
            AuthMethod:   "none",
            Headers:      map[string]string{},
            Cookies:      map[string]string{},
            Active:       true,
            CreatedAt:    time.Now(),
        },
        // Regular user identity
        {
            ID:           uuid.New().String(),
            Type:         IdentityUser,
            Username:     "testuser",
            Role:         "user",
            Tenant:       "tenant1",
            Permissions:  []string{"read", "write", "profile"},
            Credentials: map[string]interface{}{
                "username": "testuser",
                "password": "testpass123",
                "token":    "user_test_token_" + uuid.New().String()[:8],
            },
            SessionData: map[string]interface{}{
                "user_id": "123",
                "session_id": uuid.New().String(),
            },
            AuthMethod: "bearer",
            Headers: map[string]string{
                "User-Agent": "Ars0n-Framework-MultiIdentity-Test",
            },
            Cookies: map[string]string{
                "session": "user_session_" + uuid.New().String()[:16],
            },
            Active:    true,
            CreatedAt: time.Now(),
        },
        // Admin identity
        {
            ID:           uuid.New().String(),
            Type:         IdentityAdmin,
            Username:     "admin",
            Role:         "administrator",
            Tenant:       "tenant1",
            Permissions:  []string{"read", "write", "delete", "admin", "manage_users"},
            Credentials: map[string]interface{}{
                "username": "admin",
                "password": "adminpass123",
                "token":    "admin_test_token_" + uuid.New().String()[:8],
            },
            SessionData: map[string]interface{}{
                "user_id": "1",
                "admin": true,
                "session_id": uuid.New().String(),
            },
            AuthMethod: "bearer",
            Headers: map[string]string{
                "User-Agent": "Ars0n-Framework-MultiIdentity-Test",
                "X-Admin-Access": "true",
            },
            Cookies: map[string]string{
                "session": "admin_session_" + uuid.New().String()[:16],
                "admin": "true",
            },
            Active:    true,
            CreatedAt: time.Now(),
        },
        // Cross-tenant user identity
        {
            ID:           uuid.New().String(),
            Type:         IdentityCrossTenant,
            Username:     "crossuser",
            Role:         "user",
            Tenant:       "tenant2",
            Permissions:  []string{"read", "write", "profile"},
            Credentials: map[string]interface{}{
                "username": "crossuser",
                "password": "crosspass123",
                "token":    "cross_test_token_" + uuid.New().String()[:8],
            },
            SessionData: map[string]interface{}{
                "user_id": "456",
                "tenant_id": "tenant2",
                "session_id": uuid.New().String(),
            },
            AuthMethod: "bearer",
            Headers: map[string]string{
                "User-Agent": "Ars0n-Framework-MultiIdentity-Test",
                "X-Tenant": "tenant2",
            },
            Cookies: map[string]string{
                "session": "cross_session_" + uuid.New().String()[:16],
                "tenant": "tenant2",
            },
            Active:    true,
            CreatedAt: time.Now(),
        },
    }
    
    // Store default identities
    for _, identity := range defaultIdentities {
        if err := ip.storeIdentity(identity, sessionID); err != nil {
            log.Printf("Failed to store default identity %s: %v", identity.Type, err)
        }
    }
    
    return defaultIdentities
}

// Store identity context in database
func (ip *IdentityProvider) storeIdentity(identity IdentityContext, sessionID string) error {
    query := `
        INSERT INTO identity_contexts (id, session_id, type, username, role, tenant, 
                                     permissions, credentials, session_data, auth_method, 
                                     headers, cookies, active, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        ON CONFLICT (id) DO UPDATE SET
            active = EXCLUDED.active,
            credentials = EXCLUDED.credentials,
            session_data = EXCLUDED.session_data
    `
    
    permissionsJSON, _ := json.Marshal(identity.Permissions)
    credentialsJSON, _ := json.Marshal(identity.Credentials)
    sessionDataJSON, _ := json.Marshal(identity.SessionData)
    headersJSON, _ := json.Marshal(identity.Headers)
    cookiesJSON, _ := json.Marshal(identity.Cookies)
    
    _, err := ip.dbPool.Exec(context.Background(), query,
        identity.ID, sessionID, string(identity.Type), identity.Username, identity.Role,
        identity.Tenant, permissionsJSON, credentialsJSON, sessionDataJSON,
        identity.AuthMethod, headersJSON, cookiesJSON, identity.Active,
        identity.CreatedAt, identity.ExpiresAt)
    
    return err
}

// Create custom identity for specific testing needs
func (ip *IdentityProvider) CreateCustomIdentity(sessionID string, identityType IdentityType, 
                                               username, role, tenant string, 
                                               credentials map[string]interface{}) (*IdentityContext, error) {
    identity := &IdentityContext{
        ID:           uuid.New().String(),
        Type:         identityType,
        Username:     username,
        Role:         role,
        Tenant:       tenant,
        Permissions:  ip.getDefaultPermissions(role),
        Credentials:  credentials,
        SessionData:  map[string]interface{}{},
        AuthMethod:   ip.getDefaultAuthMethod(credentials),
        Headers:      map[string]string{"User-Agent": "Ars0n-Framework-Custom-Identity"},
        Cookies:      map[string]string{},
        Active:       true,
        CreatedAt:    time.Now(),
    }
    
    if err := ip.storeIdentity(*identity, sessionID); err != nil {
        return nil, err
    }
    
    return identity, nil
}

func (ip *IdentityProvider) getDefaultPermissions(role string) []string {
    permissionMap := map[string][]string{
        "anonymous":     {"read_public"},
        "user":          {"read", "write", "profile"},
        "admin":         {"read", "write", "delete", "admin", "manage_users"},
        "service":       {"api_access", "system_read"},
        "limited":       {"read_limited"},
    }
    
    if perms, exists := permissionMap[role]; exists {
        return perms
    }
    return []string{"read_public"}
}

func (ip *IdentityProvider) getDefaultAuthMethod(credentials map[string]interface{}) string {
    if _, hasToken := credentials["token"]; hasToken {
        return "bearer"
    }
    if _, hasUsername := credentials["username"]; hasUsername {
        if _, hasPassword := credentials["password"]; hasPassword {
            return "basic"
        }
    }
    return "none"
}
```

### 3. Database Schema Enhancement

```sql
-- Identity contexts table
CREATE TABLE IF NOT EXISTS identity_contexts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,  -- Links to url_workflow_sessions
    type VARCHAR(20) NOT NULL,  -- 'guest', 'user', 'admin', 'cross_tenant', etc.
    username VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL,
    tenant VARCHAR(100),
    permissions JSONB DEFAULT '[]',
    credentials JSONB DEFAULT '{}',  -- Encrypted authentication data
    session_data JSONB DEFAULT '{}', -- Session-specific data
    auth_method VARCHAR(20) NOT NULL DEFAULT 'none',  -- 'none', 'basic', 'bearer', 'cookie'
    headers JSONB DEFAULT '{}',      -- Custom headers
    cookies JSONB DEFAULT '{}',      -- Session cookies
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    
    INDEX(session_id),
    INDEX(type),
    INDEX(active)
);

-- Access control tests table
CREATE TABLE IF NOT EXISTS access_control_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,
    url TEXT NOT NULL,
    method VARCHAR(10) NOT NULL,
    tested_identities JSONB NOT NULL DEFAULT '[]',
    results JSONB NOT NULL DEFAULT '[]',
    violations_found JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    
    INDEX(session_id),
    INDEX(created_at),
    INDEX(url)
);

-- Access violation findings (integrates with main findings table)
CREATE TABLE IF NOT EXISTS access_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    test_id UUID REFERENCES access_control_tests(id) ON DELETE CASCADE,
    violation_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    lower_priv_identity VARCHAR(20) NOT NULL,
    higher_priv_identity VARCHAR(20) NOT NULL,
    url TEXT NOT NULL,
    impact TEXT,
    recommendation TEXT,
    evidence JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    
    INDEX(finding_id),
    INDEX(test_id),
    INDEX(violation_type),
    INDEX(severity)
);
```

### 4. Integration with URL Workflow

```go
// server/url_workflow/multi_identity_integration.go
package url_workflow

import (
    "log"
    "fmt"
)

// Integrate multi-identity testing into URL workflow phases
func (orchestrator *ToolOrchestrator) RunMultiIdentityTesting(sessionID, scopeTargetID string, urls []string) error {
    log.Printf("Starting multi-identity testing for session %s", sessionID)
    
    // Initialize multi-identity framework
    multiIdentity := utils.NewMultiIdentityFramework(orchestrator.dbPool)
    
    var allViolations []utils.AccessViolation
    
    // Test each URL with all identity contexts
    for _, url := range urls {
        // Test common HTTP methods
        methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
        
        for _, method := range methods {
            test, err := multiIdentity.TestAccessControl(url, method, sessionID)
            if err != nil {
                log.Printf("Multi-identity test failed for %s %s: %v", method, url, err)
                continue
            }
            
            // Collect violations
            allViolations = append(allViolations, test.ViolationsFound...)
            
            // Submit significant violations as findings
            for _, violation := range test.ViolationsFound {
                if violation.Severity == "high" || violation.Severity == "critical" {
                    err := orchestrator.submitAccessViolationFinding(violation, sessionID, scopeTargetID)
                    if err != nil {
                        log.Printf("Failed to submit violation finding: %v", err)
                    }
                }
            }
        }
    }
    
    log.Printf("Multi-identity testing completed: %d total violations found", len(allViolations))
    return nil
}

// Submit access violation as a finding
func (orchestrator *ToolOrchestrator) submitAccessViolationFinding(violation utils.AccessViolation, sessionID, scopeTargetID string) error {
    findingID := uuid.New().String()
    
    // Create finding record
    finding := utils.CreateFindingRequest{
        Title:                fmt.Sprintf("Access Control Violation: %s", violation.Description),
        Category:             string(violation.Type),
        Severity:             violation.Severity,
        URLWorkflowSessionID: sessionID,
        ScopeTargetID:        scopeTargetID,
        Signal: map[string]interface{}{
            "violation_type":        string(violation.Type),
            "lower_priv_identity":   string(violation.LowerPrivIdentity),
            "higher_priv_identity":  string(violation.HigherPrivIdentity),
            "url":                   violation.URL,
            "impact":                violation.Impact,
            "recommendation":        violation.Recommendation,
            "multi_identity_test":   true,
        },
        Metadata: map[string]interface{}{
            "violation_id": violation.ID,
            "test_type":    "multi_identity",
        },
    }
    
    // Submit to findings pipeline
    _, err := utils.CreateOrUpdateFindingInternal(finding)
    return err
}
```

This multi-identity testing framework provides comprehensive access control testing across different user roles and tenants, integrating seamlessly with the existing Ars0n Framework scope management and findings pipeline.
