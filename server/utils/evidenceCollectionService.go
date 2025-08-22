package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

type EvidenceCollectionService struct {
	collector *EvidenceCollector
	logger    *Logger
}

type CollectionRequest struct {
	FindingID    string                 `json:"finding_id"`
	URL          string                 `json:"url"`
	Method       string                 `json:"method"`
	Headers      map[string]string      `json:"headers"`
	Body         string                 `json:"body"`
	CollectTypes []string               `json:"collect_types"`
	Context      map[string]interface{} `json:"context"`
	Timeout      time.Duration          `json:"timeout"`
}

type CollectionResult struct {
	FindingID   string            `json:"finding_id"`
	EvidenceIDs map[string]string `json:"evidence_ids"`
	Errors      map[string]string `json:"errors"`
	CollectedAt time.Time         `json:"collected_at"`
	Duration    time.Duration     `json:"duration"`
}

func NewEvidenceCollectionService() *EvidenceCollectionService {
	return &EvidenceCollectionService{
		collector: NewEvidenceCollector(),
		logger:    NewLogger("", "evidence_collection", LogCategoryEvidence),
	}
}

// CollectComprehensiveEvidence collects all types of evidence for a finding
func (ecs *EvidenceCollectionService) CollectComprehensiveEvidence(req CollectionRequest) (*CollectionResult, error) {
	startTime := time.Now()

	ecs.logger.Info("Starting comprehensive evidence collection", map[string]interface{}{
		"finding_id": req.FindingID,
		"url":        req.URL,
		"types":      req.CollectTypes,
	})

	result := &CollectionResult{
		FindingID:   req.FindingID,
		EvidenceIDs: make(map[string]string),
		Errors:      make(map[string]string),
		CollectedAt: startTime,
	}

	// Set default timeout if not provided
	if req.Timeout == 0 {
		req.Timeout = 5 * time.Minute
	}

	// If no specific types requested, collect all
	if len(req.CollectTypes) == 0 {
		req.CollectTypes = []string{
			EvidenceTypeScreenshot,
			EvidenceTypeHAR,
			EvidenceTypeDOM,
			EvidenceTypeRequest,
			EvidenceTypeConsole,
		}
	}

	// Use sync.WaitGroup for concurrent collection
	var wg sync.WaitGroup
	var mu sync.Mutex

	ctx, cancel := context.WithTimeout(context.Background(), req.Timeout)
	defer cancel()

	for _, evidenceType := range req.CollectTypes {
		wg.Add(1)
		go func(eType string) {
			defer wg.Done()

			evidenceID, err := ecs.collectSpecificEvidence(ctx, req, eType)

			mu.Lock()
			if err != nil {
				result.Errors[eType] = err.Error()
				ecs.logger.Error(fmt.Sprintf("Failed to collect %s evidence", eType), err, map[string]interface{}{
					"finding_id": req.FindingID,
					"url":        req.URL,
					"type":       eType,
				})
			} else {
				result.EvidenceIDs[eType] = evidenceID
				ecs.logger.Info(fmt.Sprintf("Successfully collected %s evidence", eType), map[string]interface{}{
					"finding_id":  req.FindingID,
					"evidence_id": evidenceID,
					"type":        eType,
				})
			}
			mu.Unlock()
		}(evidenceType)
	}

	wg.Wait()
	result.Duration = time.Since(startTime)

	ecs.logger.Info("Completed comprehensive evidence collection", map[string]interface{}{
		"finding_id":  req.FindingID,
		"collected":   len(result.EvidenceIDs),
		"errors":      len(result.Errors),
		"duration_ms": result.Duration.Milliseconds(),
	})

	return result, nil
}

func (ecs *EvidenceCollectionService) collectSpecificEvidence(ctx context.Context, req CollectionRequest, evidenceType string) (string, error) {
	metadata := map[string]interface{}{
		"url":           req.URL,
		"method":        req.Method,
		"headers":       req.Headers,
		"context":       req.Context,
		"timestamp":     time.Now().Unix(),
		"evidence_type": evidenceType,
	}

	switch evidenceType {
	case EvidenceTypeScreenshot:
		return ecs.collectScreenshotEvidence(ctx, req, metadata)
	case EvidenceTypeHAR:
		return ecs.collectHAREvidence(ctx, req, metadata)
	case EvidenceTypeDOM:
		return ecs.collectDOMEvidence(ctx, req, metadata)
	case EvidenceTypeRequest:
		return ecs.collectRequestResponseEvidence(ctx, req, metadata)
	case EvidenceTypeConsole:
		return ecs.collectConsoleLogsEvidence(ctx, req, metadata)
	case EvidenceTypeSource:
		return ecs.collectSourceCodeEvidence(ctx, req, metadata)
	case EvidenceTypeNetTrace:
		return ecs.collectNetworkTraceEvidence(ctx, req, metadata)
	default:
		return "", fmt.Errorf("unsupported evidence type: %s", evidenceType)
	}
}

func (ecs *EvidenceCollectionService) collectScreenshotEvidence(ctx context.Context, req CollectionRequest, metadata map[string]interface{}) (string, error) {
	// Enhanced screenshot with viewport settings and wait conditions
	playwrightScript := fmt.Sprintf(`
		const { chromium } = require('playwright');
		(async () => {
			try {
				const browser = await chromium.launch({ 
					headless: true,
					args: ['--no-sandbox', '--disable-setuid-sandbox']
				});
				const page = await browser.newPage({
					viewport: { width: 1920, height: 1080 }
				});
				
				// Set custom headers if provided
				const headers = %s;
				if (Object.keys(headers).length > 0) {
					await page.setExtraHTTPHeaders(headers);
				}
				
				await page.goto('%s', { 
					timeout: 30000,
					waitUntil: 'networkidle' 
				});
				
				// Wait for potential dynamic content
				await page.waitForTimeout(3000);
				
				// Take full page screenshot
				const screenshot = await page.screenshot({ 
					fullPage: true,
					type: 'png'
				});
				
				process.stdout.write(screenshot);
				await browser.close();
			} catch (error) {
				console.error('Screenshot error:', error.message);
				process.exit(1);
			}
		})();
	`, formatJSONForPlaywright(req.Headers), req.URL)

	cmd := exec.CommandContext(ctx, "docker", "exec", "ars0n-framework-v2-playwright-1", "node", "-e", playwrightScript)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("screenshot capture failed: %w", err)
	}

	metadata["viewport"] = map[string]int{"width": 1920, "height": 1080}
	metadata["screenshot_type"] = "full_page"

	return ecs.collector.StoreEvidence(req.FindingID, EvidenceTypeScreenshot, output, "screenshot.png", metadata)
}

func (ecs *EvidenceCollectionService) collectHAREvidence(ctx context.Context, req CollectionRequest, metadata map[string]interface{}) (string, error) {
	playwrightScript := fmt.Sprintf(`
		const { chromium } = require('playwright');
		const fs = require('fs');
		(async () => {
			try {
				const browser = await chromium.launch({ headless: true });
				const context = await browser.newContext({
					recordHar: { 
						path: '/tmp/evidence.har',
						recordVideo: false
					}
				});
				
				const page = await context.newPage();
				
				const headers = %s;
				if (Object.keys(headers).length > 0) {
					await page.setExtraHTTPHeaders(headers);
				}
				
				await page.goto('%s', { 
					timeout: 30000,
					waitUntil: 'networkidle'
				});
				
				// Wait for additional network activity
				await page.waitForTimeout(5000);
				
				await context.close();
				await browser.close();
				
				const harContent = fs.readFileSync('/tmp/evidence.har', 'utf8');
				console.log(harContent);
			} catch (error) {
				console.error('HAR capture error:', error.message);
				process.exit(1);
			}
		})();
	`, formatJSONForPlaywright(req.Headers), req.URL)

	cmd := exec.CommandContext(ctx, "docker", "exec", "ars0n-framework-v2-playwright-1", "node", "-e", playwrightScript)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("HAR capture failed: %w", err)
	}

	metadata["capture_duration"] = "5s"
	metadata["wait_condition"] = "networkidle"

	return ecs.collector.StoreEvidence(req.FindingID, EvidenceTypeHAR, output, "traffic.har", metadata)
}

func (ecs *EvidenceCollectionService) collectDOMEvidence(ctx context.Context, req CollectionRequest, metadata map[string]interface{}) (string, error) {
	playwrightScript := fmt.Sprintf(`
		const { chromium } = require('playwright');
		(async () => {
			try {
				const browser = await chromium.launch({ headless: true });
				const page = await browser.newPage();
				
				const headers = %s;
				if (Object.keys(headers).length > 0) {
					await page.setExtraHTTPHeaders(headers);
				}
				
				await page.goto('%s', { timeout: 30000 });
				await page.waitForTimeout(3000);
				
				// Get both outer HTML and computed styles
				const content = await page.content();
				const title = await page.title();
				const url = page.url();
				
				const domData = {
					html: content,
					title: title,
					url: url,
					timestamp: new Date().toISOString(),
					scripts: await page.$$eval('script', scripts => scripts.map(s => s.src).filter(Boolean)),
					stylesheets: await page.$$eval('link[rel="stylesheet"]', links => links.map(l => l.href)),
					forms: await page.$$eval('form', forms => forms.map(f => ({
						action: f.action,
						method: f.method,
						inputs: Array.from(f.querySelectorAll('input')).map(i => ({
							name: i.name,
							type: i.type,
							value: i.value
						}))
					})))
				};
				
				console.log(JSON.stringify(domData, null, 2));
				await browser.close();
			} catch (error) {
				console.error('DOM capture error:', error.message);
				process.exit(1);
			}
		})();
	`, formatJSONForPlaywright(req.Headers), req.URL)

	cmd := exec.CommandContext(ctx, "docker", "exec", "ars0n-framework-v2-playwright-1", "node", "-e", playwrightScript)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("DOM capture failed: %w", err)
	}

	metadata["includes_scripts"] = true
	metadata["includes_stylesheets"] = true
	metadata["includes_forms"] = true

	return ecs.collector.StoreEvidence(req.FindingID, EvidenceTypeDOM, output, "dom.json", metadata)
}

func (ecs *EvidenceCollectionService) collectRequestResponseEvidence(ctx context.Context, req CollectionRequest, metadata map[string]interface{}) (string, error) {
	// Use curl to capture detailed request/response
	curlArgs := []string{"exec", "ars0n-framework-v2-curl-1", "curl", "-v", "-s"}

	// Add method
	if req.Method != "" && req.Method != "GET" {
		curlArgs = append(curlArgs, "-X", req.Method)
	}

	// Add headers
	for key, value := range req.Headers {
		curlArgs = append(curlArgs, "-H", fmt.Sprintf("%s: %s", key, value))
	}

	// Add body if present
	if req.Body != "" {
		curlArgs = append(curlArgs, "-d", req.Body)
	}

	// Add URL
	curlArgs = append(curlArgs, req.URL)

	cmd := exec.CommandContext(ctx, "docker", curlArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Continue even if curl fails, we want the error output
	}

	requestData := map[string]interface{}{
		"url":       req.URL,
		"method":    req.Method,
		"headers":   req.Headers,
		"body":      req.Body,
		"response":  string(output),
		"timestamp": time.Now().Unix(),
	}

	requestJSON, _ := json.MarshalIndent(requestData, "", "  ")
	metadata["tool"] = "curl"
	metadata["includes_response"] = true

	return ecs.collector.StoreEvidence(req.FindingID, EvidenceTypeRequest, requestJSON, "request_response.json", metadata)
}

func (ecs *EvidenceCollectionService) collectConsoleLogsEvidence(ctx context.Context, req CollectionRequest, metadata map[string]interface{}) (string, error) {
	playwrightScript := fmt.Sprintf(`
		const { chromium } = require('playwright');
		(async () => {
			try {
				const browser = await chromium.launch({ headless: true });
				const page = await browser.newPage();
				
				const logs = [];
				const errors = [];
				
				page.on('console', msg => {
					logs.push({
						type: msg.type(),
						text: msg.text(),
						location: msg.location(),
						timestamp: new Date().toISOString()
					});
				});
				
				page.on('pageerror', error => {
					errors.push({
						message: error.message,
						stack: error.stack,
						timestamp: new Date().toISOString()
					});
				});
				
				const headers = %s;
				if (Object.keys(headers).length > 0) {
					await page.setExtraHTTPHeaders(headers);
				}
				
				await page.goto('%s', { timeout: 30000 });
				await page.waitForTimeout(5000);
				
				const consoleData = {
					console_logs: logs,
					page_errors: errors,
					url: '%s',
					timestamp: new Date().toISOString()
				};
				
				console.log(JSON.stringify(consoleData, null, 2));
				await browser.close();
			} catch (error) {
				console.error('Console capture error:', error.message);
				process.exit(1);
			}
		})();
	`, formatJSONForPlaywright(req.Headers), req.URL, req.URL)

	cmd := exec.CommandContext(ctx, "docker", "exec", "ars0n-framework-v2-playwright-1", "node", "-e", playwrightScript)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("console capture failed: %w", err)
	}

	metadata["includes_errors"] = true
	metadata["capture_duration"] = "5s"

	return ecs.collector.StoreEvidence(req.FindingID, EvidenceTypeConsole, output, "console_logs.json", metadata)
}

func (ecs *EvidenceCollectionService) collectSourceCodeEvidence(ctx context.Context, req CollectionRequest, metadata map[string]interface{}) (string, error) {
	// Simple source code fetch
	cmd := exec.CommandContext(ctx, "docker", "exec", "ars0n-framework-v2-curl-1", "curl", "-s", req.URL)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("source code fetch failed: %w", err)
	}

	metadata["fetch_method"] = "curl"
	metadata["content_type"] = "text/html"

	return ecs.collector.StoreEvidence(req.FindingID, EvidenceTypeSource, output, "source.html", metadata)
}

func (ecs *EvidenceCollectionService) collectNetworkTraceEvidence(ctx context.Context, req CollectionRequest, metadata map[string]interface{}) (string, error) {
	playwrightScript := fmt.Sprintf(`
		const { chromium } = require('playwright');
		(async () => {
			try {
				const browser = await chromium.launch({ headless: true });
				const page = await browser.newPage();
				
				const networkEvents = [];
				
				page.on('request', request => {
					networkEvents.push({
						type: 'request',
						url: request.url(),
						method: request.method(),
						headers: request.headers(),
						timestamp: new Date().toISOString()
					});
				});
				
				page.on('response', response => {
					networkEvents.push({
						type: 'response',
						url: response.url(),
						status: response.status(),
						headers: response.headers(),
						timestamp: new Date().toISOString()
					});
				});
				
				const headers = %s;
				if (Object.keys(headers).length > 0) {
					await page.setExtraHTTPHeaders(headers);
				}
				
				await page.goto('%s', { timeout: 30000 });
				await page.waitForTimeout(3000);
				
				const traceData = {
					events: networkEvents,
					url: '%s',
					timestamp: new Date().toISOString()
				};
				
				console.log(JSON.stringify(traceData, null, 2));
				await browser.close();
			} catch (error) {
				console.error('Network trace error:', error.message);
				process.exit(1);
			}
		})();
	`, formatJSONForPlaywright(req.Headers), req.URL, req.URL)

	cmd := exec.CommandContext(ctx, "docker", "exec", "ars0n-framework-v2-playwright-1", "node", "-e", playwrightScript)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("network trace failed: %w", err)
	}

	metadata["events_captured"] = true
	metadata["includes_requests"] = true
	metadata["includes_responses"] = true

	return ecs.collector.StoreEvidence(req.FindingID, EvidenceTypeNetTrace, output, "network_trace.json", metadata)
}

func formatJSONForPlaywright(data map[string]string) string {
	if data == nil {
		return "{}"
	}
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

// Helper function to validate if a tool container is available
func (ecs *EvidenceCollectionService) isToolAvailable(toolContainer string) bool {
	cmd := exec.Command("docker", "inspect", toolContainer)
	err := cmd.Run()
	return err == nil
}
