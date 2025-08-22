package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

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

// PII redaction patterns
var PIIPatterns = map[string]*regexp.Regexp{
	"email":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
	"ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"credit_card": regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
	"phone":       regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
	"ip_address":  regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
	"api_key":     regexp.MustCompile(`(?i)(api[_-]?key|token|secret)["\s]*[:=]["\s]*([a-zA-Z0-9+/=]{20,})`),
}

type ReproPackBuilder struct {
	BlobStoragePath string
	Templates       map[string]string
}

func NewReproPackBuilder() *ReproPackBuilder {
	return &ReproPackBuilder{
		BlobStoragePath: "/tmp/repro_packs",
		Templates: map[string]string{
			"curl_json": `{
  "method": "{{.Method}}",
  "url": "{{.URL}}",
  "headers": {{.Headers}},
  "body": "{{.Body}}",
  "follow_redirects": true,
  "timeout": 30
}`,
			"playwright_script": `const { chromium } = require('playwright');

async function reproduce() {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    try {
        // Navigate to target URL
        await page.goto('{{.URL}}', { timeout: 30000 });
        
        {{if .Payload}}
        // Execute payload
        await page.evaluate(() => {
            {{.Payload}}
        });
        {{end}}
        
        // Wait for potential response
        await page.waitForTimeout(2000);
        
        // Take screenshot
        const screenshot = await page.screenshot({ fullPage: true });
        
        // Get page content
        const content = await page.content();
        
        console.log('Reproduction completed');
        console.log('Screenshot size:', screenshot.length);
        console.log('Content length:', content.length);
        
    } catch (error) {
        console.error('Reproduction failed:', error);
    } finally {
        await browser.close();
    }
}

reproduce();`,
			"manual_steps": `# Manual Reproduction Steps

## Target Information
- **URL**: {{.URL}}
- **Method**: {{.Method}}
- **Vulnerability**: {{.Category}}

## Prerequisites
{{range .Prerequisites}}
- {{.}}
{{end}}

## Reproduction Steps
1. Navigate to: {{.URL}}
{{if .Payload}}
2. Execute the following payload:
   ` + "```" + `
   {{.Payload}}
   ` + "```" + `
{{end}}
3. Observe the response
4. Verify that {{.ExpectedOutcome}}

## Expected Outcome
{{.ExpectedOutcome}}

## Success Criteria
{{.SuccessCriteria}}

## Troubleshooting
{{.TroubleshootingNotes}}`,
		},
	}
}

// Get Reproduction Instructions
func GetReproInstructions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	findingID := vars["id"]

	if findingID == "" {
		http.Error(w, "Missing finding ID", http.StatusBadRequest)
		return
	}

	// Get finding details
	finding, err := getFindingByID(findingID)
	if err != nil {
		log.Printf("[ERROR] Failed to get finding: %v", err)
		http.Error(w, "Finding not found", http.StatusNotFound)
		return
	}

	// Get or generate reproduction recipes
	recipes, err := getReproRecipes(findingID)
	if err != nil {
		log.Printf("[ERROR] Failed to get repro recipes: %v", err)
		http.Error(w, "Failed to retrieve reproduction instructions", http.StatusInternalServerError)
		return
	}

	// If no recipes exist, generate them
	if len(recipes) == 0 {
		builder := NewReproPackBuilder()
		generatedRecipes, err := builder.GenerateReproRecipes(finding)
		if err != nil {
			log.Printf("[ERROR] Failed to generate repro recipes: %v", err)
			http.Error(w, "Failed to generate reproduction instructions", http.StatusInternalServerError)
			return
		}
		recipes = generatedRecipes
	}

	response := map[string]interface{}{
		"finding_id": findingID,
		"recipes":    recipes,
		"count":      len(recipes),
	}

	json.NewEncoder(w).Encode(response)
}

// Generate reproduction recipes for a finding
func (rpb *ReproPackBuilder) GenerateReproRecipes(finding *Finding) ([]ReproRecipe, error) {
	var recipes []ReproRecipe

	// Generate curl command recipe
	curlRecipe, err := rpb.generateCurlRecipe(finding)
	if err == nil {
		recipes = append(recipes, *curlRecipe)
	}

	// Generate Playwright script if XSS or client-side vulnerability
	if strings.Contains(strings.ToLower(finding.Category), "xss") ||
		strings.Contains(strings.ToLower(finding.Category), "client") {
		playwrightRecipe, err := rpb.generatePlaywrightRecipe(finding)
		if err == nil {
			recipes = append(recipes, *playwrightRecipe)
		}
	}

	// Generate manual steps
	manualRecipe, err := rpb.generateManualStepsRecipe(finding)
	if err == nil {
		recipes = append(recipes, *manualRecipe)
	}

	// Store recipes in database
	for i := range recipes {
		recipeID, err := rpb.storeReproRecipe(finding.ID, &recipes[i])
		if err != nil {
			log.Printf("[WARN] Failed to store repro recipe: %v", err)
		} else {
			recipes[i].ID = recipeID
		}
	}

	return recipes, nil
}

func (rpb *ReproPackBuilder) generateCurlRecipe(finding *Finding) (*ReproRecipe, error) {
	// Extract relevant data from finding
	method := finding.Method
	if method == "" {
		method = "GET"
	}

	// Build curl command data
	curlData := map[string]interface{}{
		"Method": method,
		"URL":    finding.URL,
		"Headers": map[string]string{
			"User-Agent": "ars0n-framework-repro/1.0",
			"Accept":     "*/*",
		},
		"Body": "",
	}

	// Add parameters based on method
	if method == "POST" || method == "PUT" {
		if finding.Parameters != nil {
			if body, exists := finding.Parameters["body"]; exists {
				curlData["Body"] = body
			}
		}
	}

	// Apply template
	curlJSON, err := rpb.applyTemplate("curl_json", curlData)
	if err != nil {
		return nil, fmt.Errorf("failed to apply curl template: %w", err)
	}

	// Redact PII
	redactedCurl := rpb.redactPII(curlJSON)

	recipe := &ReproRecipe{
		RecipeType:            "curl_command",
		RecipeData:            redactedCurl,
		ExecutionEnvironment:  sql.NullString{String: "command_line", Valid: true},
		Prerequisites:         []string{"curl", "jq (optional for JSON formatting)"},
		ExpectedOutcome:       sql.NullString{String: "HTTP response containing vulnerability evidence", Valid: true},
		ExecutionTimeEstimate: sql.NullInt32{Int32: 5, Valid: true},
		SuccessCriteria:       sql.NullString{String: "Response contains expected vulnerability indicators", Valid: true},
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	return recipe, nil
}

func (rpb *ReproPackBuilder) generatePlaywrightRecipe(finding *Finding) (*ReproRecipe, error) {
	// Extract payload from finding
	payload := ""
	if finding.Parameters != nil {
		if p, exists := finding.Parameters["payload"]; exists {
			payload = fmt.Sprintf("%v", p)
		}
	}

	playwrightData := map[string]interface{}{
		"URL":             finding.URL,
		"Method":          finding.Method,
		"Category":        finding.Category,
		"Payload":         payload,
		"ExpectedOutcome": "Visual confirmation of vulnerability execution",
	}

	// Apply template
	playwrightScript, err := rpb.applyTemplate("playwright_script", playwrightData)
	if err != nil {
		return nil, fmt.Errorf("failed to apply playwright template: %w", err)
	}

	// Redact PII
	redactedScript := rpb.redactPII(playwrightScript)

	recipe := &ReproRecipe{
		RecipeType:            "playwright_script",
		RecipeData:            redactedScript,
		ExecutionEnvironment:  sql.NullString{String: "node.js", Valid: true},
		Prerequisites:         []string{"Node.js", "Playwright", "Browser (Chromium/Firefox/WebKit)"},
		ExpectedOutcome:       sql.NullString{String: "Screenshot showing vulnerability execution", Valid: true},
		ExecutionTimeEstimate: sql.NullInt32{Int32: 30, Valid: true},
		SuccessCriteria:       sql.NullString{String: "Screenshot captures visual evidence of vulnerability", Valid: true},
		TroubleshootingNotes:  sql.NullString{String: "Ensure target application is accessible and payload is properly encoded", Valid: true},
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	return recipe, nil
}

func (rpb *ReproPackBuilder) generateManualStepsRecipe(finding *Finding) (*ReproRecipe, error) {
	manualData := map[string]interface{}{
		"URL":                  finding.URL,
		"Method":               finding.Method,
		"Category":             finding.Category,
		"Prerequisites":        []string{"Web browser", "Developer tools (optional)"},
		"ExpectedOutcome":      "Manual verification of vulnerability",
		"SuccessCriteria":      "Vulnerability can be manually reproduced",
		"TroubleshootingNotes": "If reproduction fails, verify target accessibility and parameter values",
	}

	// Add payload if available
	if finding.Parameters != nil {
		if payload, exists := finding.Parameters["payload"]; exists {
			manualData["Payload"] = payload
		}
	}

	// Apply template
	manualSteps, err := rpb.applyTemplate("manual_steps", manualData)
	if err != nil {
		return nil, fmt.Errorf("failed to apply manual steps template: %w", err)
	}

	// Redact PII
	redactedSteps := rpb.redactPII(manualSteps)

	recipe := &ReproRecipe{
		RecipeType:            "manual_steps",
		RecipeData:            redactedSteps,
		ExecutionEnvironment:  sql.NullString{String: "manual", Valid: true},
		Prerequisites:         []string{"Web browser", "Basic understanding of web application testing"},
		ExpectedOutcome:       sql.NullString{String: "Manual confirmation of vulnerability", Valid: true},
		ExecutionTimeEstimate: sql.NullInt32{Int32: 300, Valid: true}, // 5 minutes
		SuccessCriteria:       sql.NullString{String: "Vulnerability successfully reproduced manually", Valid: true},
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	return recipe, nil
}

func (rpb *ReproPackBuilder) applyTemplate(templateName string, data map[string]interface{}) (string, error) {
	template, exists := rpb.Templates[templateName]
	if !exists {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	// Simple template replacement (for production, use proper template engine)
	result := template
	for key, value := range data {
		placeholder := fmt.Sprintf("{{.%s}}", key)
		valueStr := fmt.Sprintf("%v", value)
		result = strings.ReplaceAll(result, placeholder, valueStr)
	}

	// Handle conditional blocks (basic implementation)
	result = rpb.processConditionals(result, data)

	return result, nil
}

func (rpb *ReproPackBuilder) processConditionals(template string, data map[string]interface{}) string {
	// Process {{if .Field}} blocks
	ifPattern := regexp.MustCompile(`{{if \.(\w+)}}(.*?){{end}}`)
	result := ifPattern.ReplaceAllStringFunc(template, func(match string) string {
		matches := ifPattern.FindStringSubmatch(match)
		if len(matches) == 3 {
			field := matches[1]
			content := matches[2]

			if value, exists := data[field]; exists && value != nil && value != "" {
				return content
			}
		}
		return ""
	})

	// Process {{range .Field}} blocks
	rangePattern := regexp.MustCompile(`{{range \.(\w+)}}(.*?){{end}}`)
	result = rangePattern.ReplaceAllStringFunc(result, func(match string) string {
		matches := rangePattern.FindStringSubmatch(match)
		if len(matches) == 3 {
			field := matches[1]
			content := matches[2]

			if value, exists := data[field]; exists {
				if slice, ok := value.([]string); ok {
					var items []string
					for _, item := range slice {
						itemContent := strings.ReplaceAll(content, "{{.}}", item)
						items = append(items, itemContent)
					}
					return strings.Join(items, "")
				}
			}
		}
		return ""
	})

	return result
}

func (rpb *ReproPackBuilder) redactPII(content string) string {
	result := content

	for patternName, pattern := range PIIPatterns {
		switch patternName {
		case "email":
			result = pattern.ReplaceAllString(result, "[REDACTED_EMAIL]")
		case "ssn":
			result = pattern.ReplaceAllString(result, "[REDACTED_SSN]")
		case "credit_card":
			result = pattern.ReplaceAllString(result, "[REDACTED_CARD]")
		case "phone":
			result = pattern.ReplaceAllString(result, "[REDACTED_PHONE]")
		case "ip_address":
			result = pattern.ReplaceAllString(result, "[REDACTED_IP]")
		case "api_key":
			result = pattern.ReplaceAllString(result, "${1}=[REDACTED_KEY]")
		}
	}

	return result
}

func (rpb *ReproPackBuilder) storeReproRecipe(findingID string, recipe *ReproRecipe) (string, error) {
	recipeID := uuid.New().String()

	metadataJSON, _ := json.Marshal(recipe.RecipeMetadata)
	prerequisitesJSON, _ := json.Marshal(recipe.Prerequisites)

	query := `
		INSERT INTO repro_recipes (
			id, finding_id, recipe_type, recipe_data, recipe_metadata,
			execution_environment, prerequisites, expected_outcome,
			execution_time_estimate, success_criteria, troubleshooting_notes,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW()
		)
	`

	_, err := dbPool.Exec(context.Background(), query,
		recipeID, findingID, recipe.RecipeType, recipe.RecipeData, metadataJSON,
		recipe.ExecutionEnvironment, prerequisitesJSON, recipe.ExpectedOutcome,
		recipe.ExecutionTimeEstimate, recipe.SuccessCriteria, recipe.TroubleshootingNotes,
	)

	if err != nil {
		return "", fmt.Errorf("failed to store repro recipe: %w", err)
	}

	return recipeID, nil
}

func getReproRecipes(findingID string) ([]ReproRecipe, error) {
	query := `
		SELECT id, recipe_type, recipe_data, execution_environment,
		       prerequisites, expected_outcome, execution_time_estimate,
		       success_criteria, troubleshooting_notes, is_validated,
		       created_at, updated_at
		FROM repro_recipes 
		WHERE finding_id = $1
		ORDER BY created_at ASC
	`

	rows, err := dbPool.Query(context.Background(), query, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recipes []ReproRecipe
	for rows.Next() {
		recipe := ReproRecipe{}
		var prerequisitesStr string

		err := rows.Scan(
			&recipe.ID, &recipe.RecipeType, &recipe.RecipeData,
			&recipe.ExecutionEnvironment, &prerequisitesStr, &recipe.ExpectedOutcome,
			&recipe.ExecutionTimeEstimate, &recipe.SuccessCriteria,
			&recipe.TroubleshootingNotes, &recipe.IsValidated,
			&recipe.CreatedAt, &recipe.UpdatedAt,
		)

		if err != nil {
			log.Printf("[WARN] Failed to scan repro recipe row: %v", err)
			continue
		}

		// Parse prerequisites
		json.Unmarshal([]byte(prerequisitesStr), &recipe.Prerequisites)

		recipes = append(recipes, recipe)
	}

	return recipes, nil
}
