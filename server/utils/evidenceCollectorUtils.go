package utils

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Evidence types
const (
	EvidenceTypeHAR        = "har_file"
	EvidenceTypeScreenshot = "screenshot"
	EvidenceTypeDOM        = "dom_snapshot"
	EvidenceTypePCAP       = "pcap_file"
	EvidenceTypeRequest    = "request_response"
	EvidenceTypeVideo      = "video_recording"
	EvidenceTypeNetTrace   = "network_trace"
	EvidenceTypeConsole    = "console_logs"
	EvidenceTypeError      = "error_logs"
	EvidenceTypeSource     = "source_code"
)

type EvidenceCollector struct {
	StoragePath string
	MaxFileSize int64 // in bytes
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

func NewEvidenceCollector() *EvidenceCollector {
	storagePath := os.Getenv("EVIDENCE_STORAGE_PATH")
	if storagePath == "" {
		storagePath = "/tmp/evidence"
	}

	// Create storage directory if it doesn't exist
	os.MkdirAll(storagePath, 0755)

	return &EvidenceCollector{
		StoragePath: storagePath,
		MaxFileSize: 50 * 1024 * 1024, // 50MB default limit
	}
}

// Store Evidence
func StoreEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	findingID := vars["findingId"]

	if findingID == "" {
		http.Error(w, "Missing finding ID", http.StatusBadRequest)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(50 << 20) // 50MB max
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	blobType := r.FormValue("blob_type")
	if blobType == "" {
		http.Error(w, "Missing blob_type", http.StatusBadRequest)
		return
	}

	metadataStr := r.FormValue("metadata")
	var metadata map[string]any
	if metadataStr != "" {
		json.Unmarshal([]byte(metadataStr), &metadata)
	}

	collector := NewEvidenceCollector()

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file data
	fileData, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Store evidence
	evidenceID, err := collector.StoreEvidence(findingID, blobType, fileData, header.Filename, metadata)
	if err != nil {
		log.Printf("[ERROR] Failed to store evidence: %v", err)
		http.Error(w, "Failed to store evidence", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"evidence_id": evidenceID,
		"finding_id":  findingID,
		"blob_type":   blobType,
		"file_size":   len(fileData),
		"status":      "stored",
	}

	json.NewEncoder(w).Encode(response)
}

// Get Evidence
func GetEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	vars := mux.Vars(r)
	evidenceID := vars["evidenceId"]

	if evidenceID == "" {
		http.Error(w, "Missing evidence ID", http.StatusBadRequest)
		return
	}

	evidence, err := getEvidenceByID(evidenceID)
	if err != nil {
		log.Printf("[ERROR] Failed to get evidence: %v", err)
		http.Error(w, "Evidence not found", http.StatusNotFound)
		return
	}

	// Set appropriate headers based on evidence type
	if evidence.MimeType.Valid {
		w.Header().Set("Content-Type", evidence.MimeType.String)
	}

	if evidence.FilePath.Valid {
		// Serve file from filesystem
		filename := filepath.Base(evidence.FilePath.String)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		http.ServeFile(w, r, evidence.FilePath.String)
	} else if evidence.BlobData != nil {
		// Serve data from database
		w.Header().Set("Content-Length", strconv.Itoa(len(evidence.BlobData)))
		w.Write(evidence.BlobData)
	} else {
		http.Error(w, "Evidence data not available", http.StatusNotFound)
	}
}

// List Evidence for Finding
func ListEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	findingID := vars["findingId"]

	if findingID == "" {
		http.Error(w, "Missing finding ID", http.StatusBadRequest)
		return
	}

	evidence, err := getEvidenceByFindingID(findingID)
	if err != nil {
		log.Printf("[ERROR] Failed to get evidence list: %v", err)
		http.Error(w, "Failed to retrieve evidence", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"finding_id": findingID,
		"evidence":   evidence,
		"count":      len(evidence),
	}

	json.NewEncoder(w).Encode(response)
}

// StoreEvidence stores evidence data and returns evidence ID
func (ec *EvidenceCollector) StoreEvidence(findingID, blobType string, data []byte, filename string, metadata map[string]any) (string, error) {
	if len(data) > int(ec.MaxFileSize) {
		return "", fmt.Errorf("file size exceeds limit: %d bytes", len(data))
	}

	evidenceID := uuid.New().String()
	hash := sha256.Sum256(data)
	hashStr := fmt.Sprintf("%x", hash)

	// Determine storage strategy based on file size
	var storageType string
	var filePath sql.NullString
	var blobData []byte

	if len(data) > 1024*1024 { // Files > 1MB go to filesystem
		storageType = "filesystem"

		// Create directory structure
		findingDir := filepath.Join(ec.StoragePath, findingID)
		os.MkdirAll(findingDir, 0755)

		// Generate unique filename
		ext := filepath.Ext(filename)
		if ext == "" {
			ext = ec.getExtensionForBlobType(blobType)
		}
		fileName := fmt.Sprintf("%s%s", evidenceID, ext)
		fullPath := filepath.Join(findingDir, fileName)

		// Write file
		err := ioutil.WriteFile(fullPath, data, 0644)
		if err != nil {
			return "", fmt.Errorf("failed to write evidence file: %w", err)
		}

		filePath = sql.NullString{String: fullPath, Valid: true}
	} else {
		// Small files go to database
		storageType = "database"
		blobData = data
	}

	// Detect MIME type
	mimeType := http.DetectContentType(data)

	// Store metadata in database
	metadataJSON, _ := json.Marshal(metadata)

	query := `
		INSERT INTO evidence_blobs (
			id, finding_id, blob_type, file_path, file_size_bytes, mime_type,
			blob_data, blob_metadata, storage_type, hash_sha256, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()
		)
	`

	_, err := dbPool.Exec(context.Background(), query,
		evidenceID, findingID, blobType, filePath, len(data), mimeType,
		blobData, metadataJSON, storageType, hashStr,
	)

	if err != nil {
		// Clean up file if database insert fails
		if filePath.Valid {
			os.Remove(filePath.String)
		}
		return "", fmt.Errorf("failed to store evidence metadata: %w", err)
	}

	log.Printf("[INFO] Stored evidence %s for finding %s (%d bytes, %s)", evidenceID, findingID, len(data), storageType)
	return evidenceID, nil
}

// CollectScreenshot captures a screenshot of a URL using Playwright
func (ec *EvidenceCollector) CollectScreenshot(findingID, url string, metadata map[string]any) (string, error) {
	// Execute Playwright screenshot in container
	cmd := exec.Command("docker", "exec", "ars0n-framework-v2-playwright-1",
		"node", "-e", fmt.Sprintf(`
			const { chromium } = require('playwright');
			(async () => {
				const browser = await chromium.launch({ headless: true });
				const page = await browser.newPage();
				await page.goto('%s', { timeout: 30000 });
				await page.waitForTimeout(2000);
				const screenshot = await page.screenshot({ fullPage: true });
				process.stdout.write(screenshot);
				await browser.close();
			})();
		`, url))

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}

	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["url"] = url
	metadata["capture_method"] = "playwright"
	metadata["timestamp"] = time.Now().Unix()

	return ec.StoreEvidence(findingID, EvidenceTypeScreenshot, output, "screenshot.png", metadata)
}

// CollectHAR captures HTTP traffic for a URL
func (ec *EvidenceCollector) CollectHAR(findingID, url string, metadata map[string]any) (string, error) {
	// Execute Playwright with HAR capture
	cmd := exec.Command("docker", "exec", "ars0n-framework-v2-playwright-1",
		"node", "-e", fmt.Sprintf(`
			const { chromium } = require('playwright');
			(async () => {
				const browser = await chromium.launch({ headless: true });
				const context = await browser.newContext({
					recordHar: { path: '/tmp/output.har' }
				});
				const page = await context.newPage();
				await page.goto('%s', { timeout: 30000 });
				await page.waitForTimeout(3000);
				await context.close();
				await browser.close();
				
				const fs = require('fs');
				const harContent = fs.readFileSync('/tmp/output.har', 'utf8');
				console.log(harContent);
			})();
		`, url))

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to capture HAR: %w", err)
	}

	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["url"] = url
	metadata["capture_method"] = "playwright"
	metadata["timestamp"] = time.Now().Unix()

	return ec.StoreEvidence(findingID, EvidenceTypeHAR, output, "traffic.har", metadata)
}

// CollectDOMSnapshot captures the DOM state of a page
func (ec *EvidenceCollector) CollectDOMSnapshot(findingID, url string, metadata map[string]any) (string, error) {
	// Execute Playwright to get DOM content
	cmd := exec.Command("docker", "exec", "ars0n-framework-v2-playwright-1",
		"node", "-e", fmt.Sprintf(`
			const { chromium } = require('playwright');
			(async () => {
				const browser = await chromium.launch({ headless: true });
				const page = await browser.newPage();
				await page.goto('%s', { timeout: 30000 });
				await page.waitForTimeout(2000);
				const content = await page.content();
				console.log(content);
				await browser.close();
			})();
		`, url))

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to capture DOM: %w", err)
	}

	if metadata == nil {
		metadata = make(map[string]any)
	}
	metadata["url"] = url
	metadata["capture_method"] = "playwright"
	metadata["timestamp"] = time.Now().Unix()

	return ec.StoreEvidence(findingID, EvidenceTypeDOM, output, "dom.html", metadata)
}

func (ec *EvidenceCollector) getExtensionForBlobType(blobType string) string {
	extensions := map[string]string{
		EvidenceTypeHAR:        ".har",
		EvidenceTypeScreenshot: ".png",
		EvidenceTypeDOM:        ".html",
		EvidenceTypePCAP:       ".pcap",
		EvidenceTypeRequest:    ".txt",
		EvidenceTypeVideo:      ".mp4",
		EvidenceTypeNetTrace:   ".json",
		EvidenceTypeConsole:    ".log",
		EvidenceTypeError:      ".log",
		EvidenceTypeSource:     ".txt",
	}

	if ext, exists := extensions[blobType]; exists {
		return ext
	}
	return ".dat"
}

func getEvidenceByID(evidenceID string) (*EvidenceBlob, error) {
	query := `
		SELECT id, finding_id, blob_type, file_path, file_size_bytes, mime_type,
		       blob_data, blob_metadata, storage_type, hash_sha256, is_redacted,
		       created_at
		FROM evidence_blobs 
		WHERE id = $1
	`

	evidence := &EvidenceBlob{}
	var metadataStr string

	err := dbPool.QueryRow(context.Background(), query, evidenceID).Scan(
		&evidence.ID, &evidence.FindingID, &evidence.BlobType, &evidence.FilePath,
		&evidence.FileSizeBytes, &evidence.MimeType, &evidence.BlobData,
		&metadataStr, &evidence.StorageType, &evidence.HashSHA256,
		&evidence.IsRedacted, &evidence.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Parse metadata
	json.Unmarshal([]byte(metadataStr), &evidence.BlobMetadata)

	return evidence, nil
}

func getEvidenceByFindingID(findingID string) ([]EvidenceBlob, error) {
	query := `
		SELECT id, finding_id, blob_type, file_path, file_size_bytes, mime_type,
		       storage_type, hash_sha256, is_redacted, created_at
		FROM evidence_blobs 
		WHERE finding_id = $1
		ORDER BY created_at DESC
	`

	rows, err := dbPool.Query(context.Background(), query, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var evidenceList []EvidenceBlob
	for rows.Next() {
		evidence := EvidenceBlob{}

		err := rows.Scan(
			&evidence.ID, &evidence.FindingID, &evidence.BlobType, &evidence.FilePath,
			&evidence.FileSizeBytes, &evidence.MimeType, &evidence.StorageType,
			&evidence.HashSHA256, &evidence.IsRedacted, &evidence.CreatedAt,
		)

		if err != nil {
			log.Printf("[WARN] Failed to scan evidence row: %v", err)
			continue
		}

		evidenceList = append(evidenceList, evidence)
	}

	return evidenceList, nil
}
