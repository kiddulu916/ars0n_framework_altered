# Two-Stage Detection Architecture Design - Ars0n Framework Integration

## Overview

This document outlines the design for implementing two-stage detection architecture (signaling → validation) within the existing Ars0n Framework tool utilities. This approach reduces false positives by implementing a cheap, wide "signaling" stage followed by an expensive, browser-backed "validation" stage.

## Two-Stage Philosophy

### Stage 1: Signaling (Fast & Wide)
- **Goal**: Cast a wide net to detect potential vulnerabilities quickly
- **Method**: Pattern matching, string detection, HTTP response analysis
- **Speed**: Fast execution, low resource consumption
- **Coverage**: High throughput, many targets processed
- **False Positive Rate**: Higher (acceptable for initial detection)

### Stage 2: Validation (Slow & Precise)
- **Goal**: Confirm genuine vulnerabilities through behavioral verification
- **Method**: Browser automation, interactive testing, proof-of-concept execution
- **Speed**: Slower execution, higher resource consumption
- **Coverage**: Lower throughput, focused on promising candidates
- **False Positive Rate**: Very low (critical for final confirmation)

## Architecture Integration

### 1. Two-Stage Detection Framework

```go
// server/utils/twoStageDetection.go
package utils

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

type TwoStageDetector struct {
    dbPool           *pgxpool.Pool
    signaler         *VulnerabilitySignaler
    validator        *BrowserValidator
    evidenceCollector *EvidenceCollector
    rateLimiter      *RateLimiter
}

type DetectionStage string

const (
    StageSignaling   DetectionStage = "signaling"
    StageValidation  DetectionStage = "validation"
    StageConfirmed   DetectionStage = "confirmed"
    StageFalsePositive DetectionStage = "false_positive"
)

type DetectionCandidate struct {
    ID               string                 `json:"id"`
    FindingID        string                 `json:"finding_id"`
    SessionID        string                 `json:"session_id"`
    Category         string                 `json:"category"`
    Title            string                 `json:"title"`
    Severity         string                 `json:"severity"`
    URL              string                 `json:"url"`
    Method           string                 `json:"method"`
    Payload          string                 `json:"payload"`
    Signal           map[string]interface{} `json:"signal"`
    Stage            DetectionStage         `json:"stage"`
    Confidence       float64                `json:"confidence"`     // 0.0-1.0
    RequiresValidation bool                `json:"requires_validation"`
    ValidationMethod string                 `json:"validation_method"`
    Evidence         []string               `json:"evidence"`
    CreatedAt        time.Time              `json:"created_at"`
    ValidatedAt      *time.Time             `json:"validated_at"`
}

func NewTwoStageDetector(dbPool *pgxpool.Pool) *TwoStageDetector {
    return &TwoStageDetector{
        dbPool:           dbPool,
        signaler:         NewVulnerabilitySignaler(),
        validator:        NewBrowserValidator(dbPool),
        evidenceCollector: NewEvidenceCollector(dbPool),
        rateLimiter:      NewRateLimiter(),
    }
}

// Main two-stage detection workflow
func (tsd *TwoStageDetector) ProcessTarget(target string, sessionID string, toolName string) ([]DetectionCandidate, error) {
    log.Printf("[TWO-STAGE] Processing target %s with %s", target, toolName)
    
    // Stage 1: Signaling (Fast Detection)
    signals, err := tsd.runSignalingStage(target, sessionID, toolName)
    if err != nil {
        return nil, fmt.Errorf("signaling stage failed: %w", err)
    }
    
    log.Printf("[TWO-STAGE] Signaling stage found %d potential vulnerabilities", len(signals))
    
    var confirmedFindings []DetectionCandidate
    
    // Stage 2: Validation (Selective Validation)
    for _, signal := range signals {
        if signal.RequiresValidation {
            validated, err := tsd.runValidationStage(signal)
            if err != nil {
                log.Printf("[TWO-STAGE] Validation failed for %s: %v", signal.ID, err)
                signal.Stage = StageFalsePositive
            } else if validated {
                signal.Stage = StageConfirmed
                signal.ValidatedAt = &time.Time{}
                *signal.ValidatedAt = time.Now()
                confirmedFindings = append(confirmedFindings, signal)
            } else {
                signal.Stage = StageFalsePositive
            }
        } else {
            // High confidence signals skip validation
            signal.Stage = StageConfirmed
            confirmedFindings = append(confirmedFindings, signal)
        }
        
        // Store detection candidate
        if err := tsd.storeDetectionCandidate(signal); err != nil {
            log.Printf("[TWO-STAGE] Failed to store candidate %s: %v", signal.ID, err)
        }
    }
    
    log.Printf("[TWO-STAGE] Confirmed %d/%d vulnerabilities after validation", 
        len(confirmedFindings), len(signals))
    
    return confirmedFindings, nil
}

// Stage 1: Fast signaling detection
func (tsd *TwoStageDetector) runSignalingStage(target, sessionID, toolName string) ([]DetectionCandidate, error) {
    var candidates []DetectionCandidate
    
    // Route to appropriate signaling method based on tool
    switch toolName {
    case "nuclei":
        nucleiCandidates, err := tsd.signaler.NucleiSignaling(target, sessionID)
        if err != nil {
            return nil, err
        }
        candidates = append(candidates, nucleiCandidates...)
        
    case "custom_xss":
        xssCandidates, err := tsd.signaler.XSSSignaling(target, sessionID)
        if err != nil {
            return nil, err
        }
        candidates = append(candidates, xssCandidates...)
        
    case "custom_idor":
        idorCandidates, err := tsd.signaler.IDORSignaling(target, sessionID)
        if err != nil {
            return nil, err
        }
        candidates = append(candidates, idorCandidates...)
        
    case "custom_ssrf":
        ssrfCandidates, err := tsd.signaler.SSRFSignaling(target, sessionID)
        if err != nil {
            return nil, err
        }
        candidates = append(candidates, ssrfCandidates...)
        
    default:
        return nil, fmt.Errorf("unsupported tool for two-stage detection: %s", toolName)
    }
    
    return candidates, nil
}

// Stage 2: Browser-based validation
func (tsd *TwoStageDetector) runValidationStage(candidate DetectionCandidate) (bool, error) {
    log.Printf("[VALIDATION] Validating %s vulnerability: %s", candidate.Category, candidate.Title)
    
    // Rate limiting for expensive validation
    if !tsd.rateLimiter.CanProceedWithValidation(candidate.URL) {
        return false, fmt.Errorf("validation rate limit exceeded for %s", candidate.URL)
    }
    
    // Route to appropriate validation method
    switch candidate.Category {
    case "xss":
        return tsd.validator.ValidateXSS(candidate)
    case "idor":
        return tsd.validator.ValidateIDOR(candidate)
    case "ssrf":
        return tsd.validator.ValidateSSRF(candidate)
    case "sqli":
        return tsd.validator.ValidateSQLi(candidate)
    case "auth_bypass":
        return tsd.validator.ValidateAuthBypass(candidate)
    default:
        // Generic validation for unknown types
        return tsd.validator.ValidateGeneric(candidate)
    }
}

func (tsd *TwoStageDetector) storeDetectionCandidate(candidate DetectionCandidate) error {
    query := `
        INSERT INTO detection_candidates (id, finding_id, session_id, category, title, severity, 
                                        url, method, payload, signal, stage, confidence, 
                                        requires_validation, validation_method, evidence, 
                                        created_at, validated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
        ON CONFLICT (id) DO UPDATE SET
            stage = EXCLUDED.stage,
            confidence = EXCLUDED.confidence,
            validated_at = EXCLUDED.validated_at
    `
    
    signalJSON, _ := json.Marshal(candidate.Signal)
    evidenceJSON, _ := json.Marshal(candidate.Evidence)
    
    _, err := tsd.dbPool.Exec(context.Background(), query,
        candidate.ID, candidate.FindingID, candidate.SessionID, candidate.Category,
        candidate.Title, candidate.Severity, candidate.URL, candidate.Method,
        candidate.Payload, signalJSON, string(candidate.Stage), candidate.Confidence,
        candidate.RequiresValidation, candidate.ValidationMethod, evidenceJSON,
        candidate.CreatedAt, candidate.ValidatedAt)
    
    return err
}
```

### 2. Vulnerability Signaling Engine

```go
// server/utils/vulnerabilitySignaler.go
package utils

import (
    "fmt"
    "log"
    "regexp"
    "strings"
    "time"
    
    "github.com/google/uuid"
)

type VulnerabilitySignaler struct {
    patterns map[string][]SignalingPattern
}

type SignalingPattern struct {
    Category         string   `json:"category"`
    Pattern          string   `json:"pattern"`
    ConfidenceScore  float64  `json:"confidence_score"`
    RequiresValidation bool   `json:"requires_validation"`
    ValidationMethod string   `json:"validation_method"`
    Description      string   `json:"description"`
}

func NewVulnerabilitySignaler() *VulnerabilitySignaler {
    vs := &VulnerabilitySignaler{
        patterns: make(map[string][]SignalingPattern),
    }
    vs.initializePatterns()
    return vs
}

func (vs *VulnerabilitySignaler) initializePatterns() {
    // XSS signaling patterns
    vs.patterns["xss"] = []SignalingPattern{
        {
            Category:         "xss",
            Pattern:          `<script[^>]*>.*</script>`,
            ConfidenceScore:  0.8,
            RequiresValidation: true,
            ValidationMethod: "browser_execution",
            Description:      "Script tag reflection detected",
        },
        {
            Category:         "xss",
            Pattern:          `javascript:.*\(`,
            ConfidenceScore:  0.7,
            RequiresValidation: true,
            ValidationMethod: "browser_execution",
            Description:      "JavaScript protocol detected",
        },
        {
            Category:         "xss",
            Pattern:          `on\w+\s*=\s*["'][^"']*["']`,
            ConfidenceScore:  0.6,
            RequiresValidation: true,
            ValidationMethod: "browser_execution",
            Description:      "Event handler reflection detected",
        },
    }
    
    // SQL Injection signaling patterns
    vs.patterns["sqli"] = []SignalingPattern{
        {
            Category:         "sqli",
            Pattern:          `SQL syntax.*near`,
            ConfidenceScore:  0.9,
            RequiresValidation: false, // High confidence
            ValidationMethod: "none",
            Description:      "SQL syntax error message",
        },
        {
            Category:         "sqli",
            Pattern:          `mysql_fetch_array\(\)`,
            ConfidenceScore:  0.8,
            RequiresValidation: false,
            ValidationMethod: "none",
            Description:      "MySQL error function detected",
        },
        {
            Category:         "sqli",
            Pattern:          `ORA-\d{5}`,
            ConfidenceScore:  0.8,
            RequiresValidation: false,
            ValidationMethod: "none",
            Description:      "Oracle error code detected",
        },
    }
    
    // SSRF signaling patterns
    vs.patterns["ssrf"] = []SignalingPattern{
        {
            Category:         "ssrf",
            Pattern:          `curl: \(\d+\)`,
            ConfidenceScore:  0.7,
            RequiresValidation: true,
            ValidationMethod: "oob_verification",
            Description:      "Curl error in response indicates SSRF",
        },
        {
            Category:         "ssrf",
            Pattern:          `Connection refused`,
            ConfidenceScore:  0.6,
            RequiresValidation: true,
            ValidationMethod: "oob_verification",
            Description:      "Connection error suggests internal request",
        },
    }
    
    // IDOR signaling patterns
    vs.patterns["idor"] = []SignalingPattern{
        {
            Category:         "idor",
            Pattern:          `"user_id":\s*\d+`,
            ConfidenceScore:  0.7,
            RequiresValidation: true,
            ValidationMethod: "parameter_manipulation",
            Description:      "User ID in response suggests IDOR",
        },
        {
            Category:         "idor",
            Pattern:          `"id":\s*"\d+"`,
            ConfidenceScore:  0.6,
            RequiresValidation: true,
            ValidationMethod: "parameter_manipulation",
            Description:      "Generic ID in response",
        },
    }
}

// XSS signaling implementation
func (vs *VulnerabilitySignaler) XSSSignaling(target, sessionID string) ([]DetectionCandidate, error) {
    var candidates []DetectionCandidate
    
    // XSS test payloads for signaling
    payloads := []string{
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "\"><script>alert('xss')</script>",
        "'><script>alert('xss')</script>",
    }
    
    for _, payload := range payloads {
        // Test various injection points
        injectionPoints := []string{
            fmt.Sprintf("%s?q=%s", target, payload),
            fmt.Sprintf("%s?search=%s", target, payload),
            fmt.Sprintf("%s?name=%s", target, payload),
        }
        
        for _, testURL := range injectionPoints {
            response, err := vs.makeRequest(testURL)
            if err != nil {
                continue
            }
            
            // Check for XSS signals in response
            for _, pattern := range vs.patterns["xss"] {
                if matched, _ := regexp.MatchString(pattern.Pattern, response.Body); matched {
                    candidate := DetectionCandidate{
                        ID:               uuid.New().String(),
                        SessionID:        sessionID,
                        Category:         "xss",
                        Title:            fmt.Sprintf("Potential XSS via %s parameter", vs.extractParam(testURL)),
                        Severity:         vs.calculateSeverity(pattern.ConfidenceScore),
                        URL:              testURL,
                        Method:           "GET",
                        Payload:          payload,
                        Signal: map[string]interface{}{
                            "pattern_matched": pattern.Pattern,
                            "response_contains": payload,
                            "injection_point": vs.extractParam(testURL),
                        },
                        Stage:            StageSignaling,
                        Confidence:       pattern.ConfidenceScore,
                        RequiresValidation: pattern.RequiresValidation,
                        ValidationMethod: pattern.ValidationMethod,
                        CreatedAt:        time.Now(),
                    }
                    
                    candidates = append(candidates, candidate)
                    log.Printf("[SIGNALING] XSS candidate found: %s (confidence: %.2f)", 
                        candidate.Title, candidate.Confidence)
                }
            }
        }
    }
    
    return candidates, nil
}

// IDOR signaling implementation
func (vs *VulnerabilitySignaler) IDORSignaling(target, sessionID string) ([]DetectionCandidate, error) {
    var candidates []DetectionCandidate
    
    // IDOR test patterns
    testPatterns := []struct {
        path   string
        method string
    }{
        {"/api/users/1", "GET"},
        {"/api/users/2", "GET"},
        {"/api/profile/1", "GET"},
        {"/api/profile/2", "GET"},
        {"/admin/users/1", "GET"},
        {"/admin/users/2", "GET"},
    }
    
    for _, pattern := range testPatterns {
        testURL := target + pattern.path
        response, err := vs.makeRequest(testURL)
        if err != nil {
            continue
        }
        
        // Check for IDOR signals
        for _, sigPattern := range vs.patterns["idor"] {
            if matched, _ := regexp.MatchString(sigPattern.Pattern, response.Body); matched {
                candidate := DetectionCandidate{
                    ID:               uuid.New().String(),
                    SessionID:        sessionID,
                    Category:         "idor",
                    Title:            fmt.Sprintf("Potential IDOR in %s", pattern.path),
                    Severity:         vs.calculateSeverity(sigPattern.ConfidenceScore),
                    URL:              testURL,
                    Method:           pattern.method,
                    Payload:          pattern.path,
                    Signal: map[string]interface{}{
                        "pattern_matched": sigPattern.Pattern,
                        "endpoint": pattern.path,
                        "status_code": response.StatusCode,
                    },
                    Stage:            StageSignaling,
                    Confidence:       sigPattern.ConfidenceScore,
                    RequiresValidation: sigPattern.RequiresValidation,
                    ValidationMethod: sigPattern.ValidationMethod,
                    CreatedAt:        time.Now(),
                }
                
                candidates = append(candidates, candidate)
                log.Printf("[SIGNALING] IDOR candidate found: %s (confidence: %.2f)", 
                    candidate.Title, candidate.Confidence)
            }
        }
    }
    
    return candidates, nil
}

// SSRF signaling implementation
func (vs *VulnerabilitySignaler) SSRFSignaling(target, sessionID string) ([]DetectionCandidate, error) {
    var candidates []DetectionCandidate
    
    // SSRF test payloads
    payloads := []string{
        "http://127.0.0.1:80",
        "http://localhost:22",
        "http://169.254.169.254/metadata",
        "http://[::1]:80",
        "file:///etc/passwd",
    }
    
    // Common SSRF parameters
    params := []string{"url", "link", "src", "target", "redirect", "endpoint"}
    
    for _, payload := range payloads {
        for _, param := range params {
            testURL := fmt.Sprintf("%s?%s=%s", target, param, payload)
            response, err := vs.makeRequest(testURL)
            if err != nil {
                continue
            }
            
            // Check for SSRF signals
            for _, pattern := range vs.patterns["ssrf"] {
                if matched, _ := regexp.MatchString(pattern.Pattern, response.Body); matched {
                    candidate := DetectionCandidate{
                        ID:               uuid.New().String(),
                        SessionID:        sessionID,
                        Category:         "ssrf",
                        Title:            fmt.Sprintf("Potential SSRF via %s parameter", param),
                        Severity:         vs.calculateSeverity(pattern.ConfidenceScore),
                        URL:              testURL,
                        Method:           "GET",
                        Payload:          payload,
                        Signal: map[string]interface{}{
                            "pattern_matched": pattern.Pattern,
                            "parameter": param,
                            "target_url": payload,
                        },
                        Stage:            StageSignaling,
                        Confidence:       pattern.ConfidenceScore,
                        RequiresValidation: pattern.RequiresValidation,
                        ValidationMethod: pattern.ValidationMethod,
                        CreatedAt:        time.Now(),
                    }
                    
                    candidates = append(candidates, candidate)
                    log.Printf("[SIGNALING] SSRF candidate found: %s (confidence: %.2f)", 
                        candidate.Title, candidate.Confidence)
                }
            }
        }
    }
    
    return candidates, nil
}

// Nuclei signaling (enhance existing Nuclei output parsing)
func (vs *VulnerabilitySignaler) NucleiSignaling(target, sessionID string) ([]DetectionCandidate, error) {
    // Execute Nuclei and parse output for signals
    // This integrates with existing nucleiUtils.go
    nucleiOutput, err := vs.executeNuclei(target)
    if err != nil {
        return nil, err
    }
    
    var candidates []DetectionCandidate
    
    // Parse Nuclei JSON output
    nucleiResults := vs.parseNucleiOutput(nucleiOutput)
    
    for _, result := range nucleiResults {
        confidence := vs.calculateNucleiConfidence(result)
        requiresValidation := vs.shouldValidateNucleiResult(result)
        
        candidate := DetectionCandidate{
            ID:        uuid.New().String(),
            SessionID: sessionID,
            Category:  result.Category,
            Title:     result.Title,
            Severity:  result.Severity,
            URL:       result.URL,
            Method:    result.Method,
            Payload:   result.Payload,
            Signal: map[string]interface{}{
                "template_id":   result.TemplateID,
                "matcher_name":  result.MatcherName,
                "nuclei_result": true,
            },
            Stage:            StageSignaling,
            Confidence:       confidence,
            RequiresValidation: requiresValidation,
            ValidationMethod: vs.getValidationMethod(result.Category),
            CreatedAt:        time.Now(),
        }
        
        candidates = append(candidates, candidate)
    }
    
    return candidates, nil
}

// Helper methods
func (vs *VulnerabilitySignaler) calculateSeverity(confidence float64) string {
    if confidence >= 0.8 {
        return "high"
    } else if confidence >= 0.6 {
        return "medium"
    } else {
        return "low"
    }
}

func (vs *VulnerabilitySignaler) extractParam(url string) string {
    parts := strings.Split(url, "?")
    if len(parts) < 2 {
        return "unknown"
    }
    
    params := strings.Split(parts[1], "&")
    if len(params) > 0 {
        paramParts := strings.Split(params[0], "=")
        if len(paramParts) > 0 {
            return paramParts[0]
        }
    }
    
    return "unknown"
}

func (vs *VulnerabilitySignaler) makeRequest(url string) (*HTTPResponse, error) {
    // Implement HTTP request with timeout and error handling
    // This would integrate with existing HTTP client patterns
    return nil, nil
}
```

### 3. Browser Validator Implementation

```go
// server/utils/browserValidator.go
package utils

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/playwright-community/playwright-go"
)

type BrowserValidator struct {
    dbPool          *pgxpool.Pool
    evidenceCollector *EvidenceCollector
    playwright      *playwright.Playwright
    browserType     playwright.BrowserType
}

func NewBrowserValidator(dbPool *pgxpool.Pool) *BrowserValidator {
    // Initialize Playwright
    pw, err := playwright.Run()
    if err != nil {
        log.Printf("Failed to start Playwright: %v", err)
        return nil
    }
    
    return &BrowserValidator{
        dbPool:           dbPool,
        evidenceCollector: NewEvidenceCollector(dbPool),
        playwright:       pw,
        browserType:      pw.Chromium,
    }
}

// XSS validation through browser execution
func (bv *BrowserValidator) ValidateXSS(candidate DetectionCandidate) (bool, error) {
    log.Printf("[VALIDATION] Validating XSS: %s", candidate.URL)
    
    browser, err := bv.browserType.Launch(playwright.BrowserTypeLaunchOptions{
        Headless: playwright.Bool(true),
    })
    if err != nil {
        return false, err
    }
    defer browser.Close()
    
    page, err := browser.NewPage()
    if err != nil {
        return false, err
    }
    
    // Set up JavaScript dialog handler
    dialogDetected := false
    page.OnDialog(func(dialog playwright.Dialog) {
        dialogDetected = true
        dialog.Accept()
    })
    
    // Navigate to the URL
    response, err := page.Goto(candidate.URL, playwright.PageGotoOptions{
        Timeout: playwright.Float(30000),
    })
    if err != nil {
        return false, err
    }
    
    // Wait for potential JavaScript execution
    page.WaitForTimeout(2000)
    
    // Take screenshot as evidence
    screenshotBytes, err := page.Screenshot(playwright.PageScreenshotOptions{
        FullPage: playwright.Bool(true),
    })
    if err == nil {
        bv.evidenceCollector.CollectEvidence(candidate.FindingID, EvidenceTypeScreenshot, screenshotBytes, map[string]interface{}{
            "validation_stage": "xss_validation",
            "url": candidate.URL,
            "payload": candidate.Payload,
        })
    }
    
    // Get DOM content as evidence
    domContent, err := page.Content()
    if err == nil {
        bv.evidenceCollector.CollectEvidence(candidate.FindingID, EvidenceTypeDOM, []byte(domContent), map[string]interface{}{
            "validation_stage": "xss_validation",
            "url": candidate.URL,
        })
    }
    
    // Check if XSS was executed
    if dialogDetected {
        log.Printf("[VALIDATION] XSS confirmed - JavaScript dialog detected")
        return true, nil
    }
    
    // Check for reflected payload in DOM
    if strings.Contains(domContent, candidate.Payload) {
        // Additional checks for actual execution context
        consoleMessages := []string{}
        page.OnConsole(func(msg playwright.ConsoleMessage) {
            consoleMessages = append(consoleMessages, msg.Text())
        })
        
        // Re-evaluate to catch console messages
        page.WaitForTimeout(1000)
        
        for _, msg := range consoleMessages {
            if strings.Contains(msg, "xss") || strings.Contains(msg, "alert") {
                log.Printf("[VALIDATION] XSS confirmed - Console message: %s", msg)
                return true, nil
            }
        }
    }
    
    log.Printf("[VALIDATION] XSS not confirmed - no execution detected")
    return false, nil
}

// IDOR validation through parameter manipulation
func (bv *BrowserValidator) ValidateIDOR(candidate DetectionCandidate) (bool, error) {
    log.Printf("[VALIDATION] Validating IDOR: %s", candidate.URL)
    
    browser, err := bv.browserType.Launch(playwright.BrowserTypeLaunchOptions{
        Headless: playwright.Bool(true),
    })
    if err != nil {
        return false, err
    }
    defer browser.Close()
    
    page, err := browser.NewPage()
    if err != nil {
        return false, err
    }
    
    // First request - original URL
    response1, err := page.Goto(candidate.URL)
    if err != nil {
        return false, err
    }
    
    content1, _ := page.Content()
    
    // Second request - manipulated parameter
    manipulatedURL := bv.manipulateIDParameter(candidate.URL)
    response2, err := page.Goto(manipulatedURL)
    if err != nil {
        return false, err
    }
    
    content2, _ := page.Content()
    
    // Compare responses
    if response2.Status() == 200 && content1 != content2 {
        // Check if we're accessing different user data
        if bv.containsUserData(content2) && !bv.isSameUserData(content1, content2) {
            log.Printf("[VALIDATION] IDOR confirmed - different user data accessible")
            
            // Collect evidence
            bv.evidenceCollector.CollectEvidence(candidate.FindingID, EvidenceTypeResponse, []byte(content2), map[string]interface{}{
                "validation_stage": "idor_validation",
                "original_url": candidate.URL,
                "manipulated_url": manipulatedURL,
                "response_status": response2.Status(),
            })
            
            return true, nil
        }
    }
    
    log.Printf("[VALIDATION] IDOR not confirmed - no unauthorized access detected")
    return false, nil
}

// SSRF validation through out-of-band verification
func (bv *BrowserValidator) ValidateSSRF(candidate DetectionCandidate) (bool, error) {
    log.Printf("[VALIDATION] Validating SSRF: %s", candidate.URL)
    
    // Generate unique OOB token
    oobToken := fmt.Sprintf("ssrf_%s_%d", candidate.ID[:8], time.Now().Unix())
    
    // Create OOB URL (this would integrate with your OOB server)
    oobURL := fmt.Sprintf("http://oob.example.com/%s", oobToken)
    
    // Replace the payload with OOB URL
    testURL := strings.Replace(candidate.URL, candidate.Payload, oobURL, 1)
    
    browser, err := bv.browserType.Launch(playwright.BrowserTypeLaunchOptions{
        Headless: playwright.Bool(true),
    })
    if err != nil {
        return false, err
    }
    defer browser.Close()
    
    page, err := browser.NewPage()
    if err != nil {
        return false, err
    }
    
    // Make the request
    response, err := page.Goto(testURL)
    if err != nil {
        return false, err
    }
    
    // Wait for potential SSRF interaction
    time.Sleep(5 * time.Second)
    
    // Check OOB server for interaction
    if bv.checkOOBInteraction(oobToken) {
        log.Printf("[VALIDATION] SSRF confirmed - OOB interaction detected")
        
        // Store OOB event
        bv.storeOOBEvent(candidate.FindingID, "http", oobToken, map[string]interface{}{
            "validation_stage": "ssrf_validation",
            "test_url": testURL,
            "oob_url": oobURL,
        })
        
        return true, nil
    }
    
    log.Printf("[VALIDATION] SSRF not confirmed - no OOB interaction detected")
    return false, nil
}

// Generic validation for unknown vulnerability types
func (bv *BrowserValidator) ValidateGeneric(candidate DetectionCandidate) (bool, error) {
    log.Printf("[VALIDATION] Generic validation for %s: %s", candidate.Category, candidate.URL)
    
    browser, err := bv.browserType.Launch(playwright.BrowserTypeLaunchOptions{
        Headless: playwright.Bool(true),
    })
    if err != nil {
        return false, err
    }
    defer browser.Close()
    
    page, err := browser.NewPage()
    if err != nil {
        return false, err
    }
    
    // Navigate and collect evidence
    response, err := page.Goto(candidate.URL)
    if err != nil {
        return false, err
    }
    
    // Take screenshot
    screenshotBytes, _ := page.Screenshot()
    if screenshotBytes != nil {
        bv.evidenceCollector.CollectEvidence(candidate.FindingID, EvidenceTypeScreenshot, screenshotBytes, map[string]interface{}{
            "validation_stage": "generic_validation",
            "category": candidate.Category,
        })
    }
    
    // Get page content
    content, _ := page.Content()
    if content != "" {
        bv.evidenceCollector.CollectEvidence(candidate.FindingID, EvidenceTypeDOM, []byte(content), map[string]interface{}{
            "validation_stage": "generic_validation",
            "category": candidate.Category,
        })
    }
    
    // For generic validation, we rely on the signaling confidence
    // High confidence signals are considered validated
    if candidate.Confidence >= 0.8 {
        log.Printf("[VALIDATION] Generic validation passed based on high confidence")
        return true, nil
    }
    
    return false, nil
}

// Helper methods
func (bv *BrowserValidator) manipulateIDParameter(url string) string {
    // Simple ID manipulation logic
    // This would be more sophisticated in practice
    if strings.Contains(url, "/1") {
        return strings.Replace(url, "/1", "/2", 1)
    } else if strings.Contains(url, "/2") {
        return strings.Replace(url, "/2", "/1", 1)
    } else if strings.Contains(url, "id=1") {
        return strings.Replace(url, "id=1", "id=2", 1)
    } else if strings.Contains(url, "id=2") {
        return strings.Replace(url, "id=2", "id=1", 1)
    }
    return url
}

func (bv *BrowserValidator) containsUserData(content string) bool {
    // Check for user data patterns
    userDataPatterns := []string{
        `"user_id"`,
        `"username"`,
        `"email"`,
        `"profile"`,
        `"account"`,
    }
    
    for _, pattern := range userDataPatterns {
        if strings.Contains(content, pattern) {
            return true
        }
    }
    return false
}

func (bv *BrowserValidator) isSameUserData(content1, content2 string) bool {
    // Simple comparison - in practice this would be more sophisticated
    return content1 == content2
}

func (bv *BrowserValidator) checkOOBInteraction(token string) bool {
    // Check with OOB server for interaction
    // This would integrate with your OOB server implementation
    return false // Placeholder
}

func (bv *BrowserValidator) storeOOBEvent(findingID, channel, token string, metadata map[string]interface{}) error {
    // Store OOB event in database
    query := `
        INSERT INTO oob_events (id, finding_id, channel, token, timestamp, validated, meta, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
    `
    
    metaJSON, _ := json.Marshal(metadata)
    
    _, err := bv.dbPool.Exec(context.Background(), query,
        uuid.New().String(), findingID, channel, token, time.Now(), true, metaJSON)
    
    return err
}
```

### 4. Integration with Existing Tool Utils

```go
// Enhanced existing tool utils with two-stage detection
// Example: server/utils/nucleiUtils.go (Enhancement)

func executeNucleiWithTwoStageDetection(scanID, target, sessionID string) error {
    // Initialize two-stage detector
    detector := NewTwoStageDetector(dbPool)
    
    // Run two-stage detection
    confirmedFindings, err := detector.ProcessTarget(target, sessionID, "nuclei")
    if err != nil {
        log.Printf("Two-stage detection failed: %v", err)
        return err
    }
    
    // Submit confirmed findings to findings pipeline
    for _, finding := range confirmedFindings {
        if err := submitConfirmedFinding(finding, scanID); err != nil {
            log.Printf("Failed to submit confirmed finding: %v", err)
        }
    }
    
    log.Printf("Two-stage detection completed: %d confirmed findings", len(confirmedFindings))
    return nil
}

// Custom vulnerability testing with two-stage detection
func runCustomXSSTestingWithTwoStage(target, sessionID string) error {
    detector := NewTwoStageDetector(dbPool)
    confirmedFindings, err := detector.ProcessTarget(target, sessionID, "custom_xss")
    if err != nil {
        return err
    }
    
    log.Printf("XSS two-stage testing: %d confirmed findings", len(confirmedFindings))
    return nil
}
```

### 5. Database Schema Addition

```sql
-- Detection candidates table for two-stage tracking
CREATE TABLE IF NOT EXISTS detection_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID,
    session_id UUID NOT NULL,
    category VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    url TEXT NOT NULL,
    method VARCHAR(10) NOT NULL,
    payload TEXT,
    signal JSONB NOT NULL,
    stage VARCHAR(20) NOT NULL,  -- 'signaling', 'validation', 'confirmed', 'false_positive'
    confidence DECIMAL(3,2) NOT NULL,  -- 0.00-1.00
    requires_validation BOOLEAN NOT NULL DEFAULT TRUE,
    validation_method VARCHAR(50),
    evidence JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    validated_at TIMESTAMP,
    
    INDEX(session_id),
    INDEX(stage),
    INDEX(confidence),
    INDEX(category)
);
```

This two-stage detection architecture significantly reduces false positives while maintaining comprehensive vulnerability coverage, ensuring that only validated vulnerabilities reach the findings pipeline and subsequent kill-chain analysis.
