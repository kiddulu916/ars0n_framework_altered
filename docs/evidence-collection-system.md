# Evidence Collection System

## Overview

The Evidence Collection System is a comprehensive suite designed to capture, store, and manage digital evidence for security findings in the Ars0n Framework v2. It provides automated evidence collection capabilities across multiple data types and formats.

## Architecture

### Core Components

1. **EvidenceCollector** (`evidenceCollectorUtils.go`)
   - Low-level evidence storage and retrieval
   - File system and database hybrid storage
   - Evidence deduplication via SHA256 hashing
   - Automated compression and retention policies

2. **EvidenceCollectionService** (`evidenceCollectionService.go`)
   - High-level orchestration of evidence collection
   - Multi-threaded parallel collection
   - Tool integration (Playwright, curl, etc.)
   - Context-aware evidence gathering

3. **Logging System** (`loggingSystemUtils.go`)
   - Structured logging with categorization
   - Performance metrics and error tracking
   - Session-based log aggregation
   - Export and audit capabilities

### Database Schema

#### Evidence Storage
```sql
evidence_blobs (
    id UUID PRIMARY KEY,
    finding_id UUID,
    blob_type VARCHAR(50),
    file_path TEXT,
    file_size_bytes BIGINT,
    mime_type VARCHAR(100),
    blob_data BYTEA,
    blob_metadata JSONB,
    storage_type VARCHAR(20),
    hash_sha256 VARCHAR(64),
    is_redacted BOOLEAN,
    retention_expires_at TIMESTAMP,
    created_at TIMESTAMP
)
```

#### Logging System
```sql
logs (
    id UUID PRIMARY KEY,
    session_id UUID,
    finding_id UUID,
    workflow_stage VARCHAR(100),
    log_level VARCHAR(20),
    log_category VARCHAR(50),
    message TEXT,
    log_data JSONB,
    error_details TEXT,
    execution_time_ms BIGINT,
    created_at TIMESTAMP
)
```

## Evidence Types

### Supported Evidence Types

1. **Screenshot Evidence** (`screenshot`)
   - Full-page screenshots via Playwright
   - Custom viewport configurations
   - High-resolution PNG format
   - Automatic retry on failure

2. **HTTP Archive (HAR)** (`har_file`)
   - Complete network traffic capture
   - Request/response headers and bodies
   - Timing information
   - Resource loading analysis

3. **DOM Snapshots** (`dom_snapshot`)
   - Complete HTML structure
   - Computed styles and scripts
   - Form data and input values
   - Dynamic content state

4. **Request/Response** (`request_response`)
   - Raw HTTP exchanges
   - curl-based capture
   - Headers and body content
   - Error state preservation

5. **Console Logs** (`console_logs`)
   - JavaScript console output
   - Error messages and stack traces
   - Performance warnings
   - Debug information

6. **Network Traces** (`network_trace`)
   - Detailed network event logs
   - Request/response timing
   - Protocol-level information
   - Connection details

7. **Source Code** (`source_code`)
   - Raw HTML/JavaScript content
   - Server response data
   - Content-type detection
   - Encoding preservation

### Storage Strategy

#### Hybrid Storage Model
- **Small files (< 1MB)**: Database storage (BYTEA)
- **Large files (≥ 1MB)**: Filesystem storage with metadata in database
- **Automatic compression**: Optional gzip compression for text-based evidence
- **Retention policies**: Configurable evidence expiration

#### Security Features
- **SHA256 checksums**: Evidence integrity verification
- **PII redaction**: Automatic sensitive data removal
- **Access controls**: Evidence retrieval authorization
- **Audit trails**: Complete access logging

## API Endpoints

### Evidence Management

#### Store Evidence
```http
POST /api/evidence/{findingId}
Content-Type: multipart/form-data

{
  "file": [binary data],
  "blob_type": "screenshot",
  "metadata": "{\"viewport\": {\"width\": 1920, \"height\": 1080}}"
}
```

#### Retrieve Evidence
```http
GET /api/evidence/{evidenceId}
```

#### List Evidence for Finding
```http
GET /api/evidence/finding/{findingId}
```

### Logging System

#### Query Logs
```http
GET /api/logs?session_id={sessionId}&level=error&limit=100
```

#### Log Metrics
```http
GET /api/logs/metrics/{sessionId}?time_range=24h
```

#### Export Logs
```http
GET /api/logs/export/{sessionId}
```

## Usage Examples

### Automated Evidence Collection

```go
// Initialize collection service
service := NewEvidenceCollectionService()

// Define collection request
request := CollectionRequest{
    FindingID: "finding-uuid",
    URL: "https://target.com/vulnerable-endpoint",
    Method: "POST",
    Headers: map[string]string{
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
    },
    Body: `{"test": "payload"}`,
    CollectTypes: []string{
        EvidenceTypeScreenshot,
        EvidenceTypeHAR,
        EvidenceTypeDOM,
        EvidenceTypeRequest,
    },
    Timeout: 5 * time.Minute,
}

// Collect evidence
result, err := service.CollectComprehensiveEvidence(request)
if err != nil {
    log.Printf("Collection failed: %v", err)
    return
}

// Process results
for evidenceType, evidenceID := range result.EvidenceIDs {
    log.Printf("Collected %s evidence: %s", evidenceType, evidenceID)
}
```

### Structured Logging

```go
// Initialize logger for session
logger := NewLogger("session-uuid", "attack_surface_mapping", LogCategoryWorkflow)

// Log tool execution
logger.LogTool(LogLevelInfo, "nuclei", "Vulnerability scan initiated", 
    2*time.Minute, map[string]interface{}{
        "target_count": 50,
        "templates": 300,
    })

// Log finding creation
logger.LogFinding(LogLevelInfo, "finding-uuid", "XSS vulnerability detected",
    map[string]interface{}{
        "severity": "high",
        "confidence": 95,
        "vector": "reflected",
    })

// Log evidence collection
logger.LogEvidence(LogLevelInfo, "evidence-uuid", "screenshot", 
    "Screenshot captured successfully", map[string]interface{}{
        "file_size": 1024000,
        "resolution": "1920x1080",
    })
```

## Configuration

### Environment Variables

```bash
# Evidence storage
EVIDENCE_STORAGE_PATH=/data/evidence
EVIDENCE_MAX_FILE_SIZE=52428800  # 50MB
EVIDENCE_RETENTION_DAYS=90

# Database connection
DATABASE_URL=postgresql://user:pass@localhost:5432/ars0n

# Tool containers
PLAYWRIGHT_CONTAINER=ars0n-framework-v2-playwright-1
CURL_CONTAINER=ars0n-framework-v2-curl-1
```

### Docker Container Requirements

The evidence collection system requires these containers:

1. **Playwright Container** - Browser automation
   ```dockerfile
   FROM mcr.microsoft.com/playwright/go:v1.40.0-jammy
   RUN playwright install --with-deps chromium firefox webkit
   ```

2. **curl Container** - HTTP request capture
   ```dockerfile
   FROM alpine:latest
   RUN apk add --no-cache curl
   ```

## Performance Considerations

### Concurrent Collection
- Parallel evidence collection using goroutines
- Configurable timeout per evidence type
- Resource-aware collection limiting
- Failed collection retry mechanisms

### Storage Optimization
- Automatic file compression for text-based evidence
- Deduplication via content hashing
- Configurable retention policies
- Background cleanup processes

### Database Performance
- Optimized indexes for common queries
- JSONB for flexible metadata storage
- Batch operations for bulk evidence
- Connection pooling for high throughput

## Monitoring and Alerting

### Key Metrics
- Evidence collection success/failure rates
- Storage utilization and growth
- Collection duration and performance
- Error categorization and trends

### Log Categories
- `evidence`: Evidence collection operations
- `workflow`: Workflow stage transitions
- `tool`: Security tool executions
- `finding`: Finding lifecycle events
- `system`: System-level operations

### Health Checks
- Container availability validation
- Storage space monitoring
- Database connectivity checks
- Evidence integrity verification

## Security Considerations

### Data Protection
- PII redaction for screenshots and DOM captures
- Secure evidence storage with encryption at rest
- Access control for evidence retrieval
- Audit trails for all evidence operations

### Container Security
- Read-only container filesystems where possible
- Non-root user execution
- Network isolation between containers
- Resource limits to prevent DoS

## Troubleshooting

### Common Issues

1. **Container Not Available**
   ```bash
   docker ps | grep playwright
   docker logs ars0n-framework-v2-playwright-1
   ```

2. **Storage Space Issues**
   ```bash
   df -h /data/evidence
   find /data/evidence -type f -mtime +90 -delete
   ```

3. **Database Connection**
   ```bash
   psql $DATABASE_URL -c "SELECT COUNT(*) FROM evidence_blobs;"
   ```

4. **Evidence Collection Timeout**
   - Increase timeout in collection request
   - Check container resource limits
   - Verify network connectivity

### Debug Logging
Enable debug logging by setting log level to `debug`:

```go
logger := NewLogger(sessionID, stage, LogCategoryEvidence)
logger.Debug("Detailed collection information", metadata)
```

## Extending the System

### Adding New Evidence Types

1. Define new evidence type constant
2. Implement collection method in `EvidenceCollectionService`
3. Add file extension mapping in `getExtensionForBlobType`
4. Update API documentation and validation

### Custom Storage Backends

Implement the `EvidenceStore` interface for alternative storage:

```go
type EvidenceStore interface {
    Store(evidence *EvidenceBlob) error
    Retrieve(evidenceID string) (*EvidenceBlob, error)
    Delete(evidenceID string) error
}
```

This comprehensive evidence collection system ensures that all security findings are properly documented with rich, actionable evidence for analysis and reporting.
