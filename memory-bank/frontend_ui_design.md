# Frontend UI/UX Design for URL Workflow Integration

## Overview

This document outlines the frontend UI/UX design for integrating the automated URL testing workflow into the existing Ars0n Framework React application, maintaining consistency with existing patterns while adding new functionality.

## Design Principles

### 1. Framework Consistency
- **Maintain existing Bootstrap styling** and component patterns
- **Preserve existing workflow paradigm** (Company → Wildcard → URL)
- **Use existing modal system** for configuration and detailed views
- **Follow existing color scheme** and iconography (Bootstrap icons)

### 2. Progressive Enablement
- **Sequential workflow dependency**: URL workflow only enabled after Company + Wildcard completion
- **Visual prerequisite indicators**: Clear status of prerequisite workflows
- **ROI-driven selection**: Top 10 URLs prominently displayed with scores
- **Progressive disclosure**: Basic → Advanced configuration options

### 3. Real-time Feedback
- **Live progress tracking** for each testing phase
- **Real-time findings display** as vulnerabilities are discovered
- **Evidence preview** (screenshots, HAR files) in findings
- **Status indicators** for each URL being tested

## Component Architecture

### 1. Enhanced ScopeTargetDetails Component

```jsx
// client/src/components/ScopeTargetDetails.js (Enhanced)
import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Button, Badge, ProgressBar, Alert } from 'react-bootstrap';
import { checkURLWorkflowPrerequisites, fetchROIUrls } from '../utils/roiUtils';
import URLWorkflowCard from './URLWorkflowCard';
import FindingsDashboard from './FindingsDashboard';

const ScopeTargetDetails = ({ scopeTarget }) => {
    const [workflows, setWorkflows] = useState({
        company: { status: 'pending', progress: 0 },
        wildcard: { status: 'pending', progress: 0 },
        url: { 
            status: 'pending', 
            progress: 0, 
            enabled: false,
            prerequisites: null,
            roiUrls: []
        }
    });
    
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    
    // Check prerequisites and ROI URLs
    useEffect(() => {
        const checkURLWorkflowReadiness = async () => {
            if (!scopeTarget?.id) return;
            
            try {
                setLoading(true);
                
                // Check if Company and Wildcard workflows are complete
                const prerequisites = await checkURLWorkflowPrerequisites(scopeTarget.id);
                
                if (prerequisites.can_proceed) {
                    // Fetch ROI URLs if prerequisites are met
                    const roiData = await fetchROIUrls(scopeTarget.id, { limit: 10 });
                    
                    setWorkflows(prev => ({
                        ...prev,
                        company: { ...prev.company, status: 'completed' },
                        wildcard: { ...prev.wildcard, status: 'completed' },
                        url: {
                            ...prev.url,
                            enabled: true,
                            prerequisites,
                            roiUrls: roiData.roi_urls
                        }
                    }));
                } else {
                    setWorkflows(prev => ({
                        ...prev,
                        company: { ...prev.company, status: prerequisites.company_complete ? 'completed' : 'pending' },
                        wildcard: { ...prev.wildcard, status: prerequisites.wildcard_complete ? 'completed' : 'pending' },
                        url: { ...prev.url, enabled: false, prerequisites }
                    }));
                }
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };
        
        checkURLWorkflowReadiness();
    }, [scopeTarget.id]);
    
    const handleURLWorkflowStart = async (selectedUrls) => {
        try {
            setWorkflows(prev => ({
                ...prev,
                url: { ...prev.url, status: 'running', progress: 0 }
            }));
            
            // Start URL workflow via existing API patterns
            // Implementation similar to existing workflow initiation
        } catch (err) {
            setError(err.message);
            setWorkflows(prev => ({
                ...prev,
                url: { ...prev.url, status: 'failed' }
            }));
        }
    };
    
    return (
        <div className="scope-target-details">
            <Row>
                <Col md={12}>
                    <h2>{scopeTarget.name} - Security Workflows</h2>
                    {error && <Alert variant="danger">{error}</Alert>}
                </Col>
            </Row>
            
            <Row>
                {/* Existing Company Workflow Card */}
                <Col md={4} className="mb-3">
                    <WorkflowCard
                        title="Company Workflow"
                        description="ASN discovery, network scanning, domain discovery"
                        status={workflows.company.status}
                        progress={workflows.company.progress}
                        icon="building"
                        variant="primary"
                    />
                </Col>
                
                {/* Existing Wildcard Workflow Card */}
                <Col md={4} className="mb-3">
                    <WorkflowCard
                        title="Wildcard Workflow"
                        description="Subdomain enumeration, live detection, ROI scoring"
                        status={workflows.wildcard.status}
                        progress={workflows.wildcard.progress}
                        icon="globe"
                        variant="success"
                        enabled={workflows.company.status === 'completed'}
                    />
                </Col>
                
                {/* NEW URL Workflow Card */}
                <Col md={4} className="mb-3">
                    <URLWorkflowCard
                        title="URL Workflow"
                        description="Automated vulnerability testing on top 10 ROI URLs"
                        status={workflows.url.status}
                        progress={workflows.url.progress}
                        enabled={workflows.url.enabled}
                        prerequisites={workflows.url.prerequisites}
                        roiUrls={workflows.url.roiUrls}
                        onStart={handleURLWorkflowStart}
                        icon="shield-check"
                        variant="warning"
                    />
                </Col>
            </Row>
            
            {/* URL Workflow Details Section */}
            {workflows.url.enabled && (
                <Row className="mt-4">
                    <Col md={12}>
                        <URLWorkflowDetails
                            scopeTargetId={scopeTarget.id}
                            roiUrls={workflows.url.roiUrls}
                            status={workflows.url.status}
                            onStatusUpdate={(status, progress) => {
                                setWorkflows(prev => ({
                                    ...prev,
                                    url: { ...prev.url, status, progress }
                                }));
                            }}
                        />
                    </Col>
                </Row>
            )}
            
            {/* Findings Dashboard */}
            {workflows.url.status === 'running' || workflows.url.status === 'completed' && (
                <Row className="mt-4">
                    <Col md={12}>
                        <FindingsDashboard
                            scopeTargetId={scopeTarget.id}
                            workflowType="url"
                        />
                    </Col>
                </Row>
            )}
        </div>
    );
};

export default ScopeTargetDetails;
```

### 2. URL Workflow Card Component

```jsx
// client/src/components/URLWorkflowCard.js (NEW)
import React, { useState } from 'react';
import { Card, Button, Badge, ProgressBar, ListGroup, OverlayTrigger, Tooltip } from 'react-bootstrap';
import URLWorkflowConfigModal from '../modals/URLWorkflowConfigModal';

const URLWorkflowCard = ({ 
    title, 
    description, 
    status, 
    progress, 
    enabled, 
    prerequisites, 
    roiUrls, 
    onStart, 
    icon, 
    variant 
}) => {
    const [showConfigModal, setShowConfigModal] = useState(false);
    
    const getStatusBadge = () => {
        const statusConfig = {
            pending: { variant: 'secondary', text: 'Pending' },
            running: { variant: 'primary', text: 'Running' },
            completed: { variant: 'success', text: 'Completed' },
            failed: { variant: 'danger', text: 'Failed' }
        };
        
        const config = statusConfig[status] || statusConfig.pending;
        return <Badge bg={config.variant}>{config.text}</Badge>;
    };
    
    const getActionButton = () => {
        if (!enabled) {
            return (
                <OverlayTrigger
                    placement="top"
                    overlay={
                        <Tooltip>
                            {prerequisites?.message || "Complete Company and Wildcard workflows first"}
                        </Tooltip>
                    }
                >
                    <Button variant="outline-secondary" disabled>
                        <i className="bi bi-lock"></i> Locked
                    </Button>
                </OverlayTrigger>
            );
        }
        
        if (status === 'running') {
            return (
                <Button variant="outline-warning" disabled>
                    <i className="bi bi-hourglass-split"></i> Running...
                </Button>
            );
        }
        
        if (status === 'completed') {
            return (
                <Button variant="outline-success" onClick={() => setShowConfigModal(true)}>
                    <i className="bi bi-arrow-clockwise"></i> Re-run
                </Button>
            );
        }
        
        return (
            <Button variant={variant} onClick={() => setShowConfigModal(true)}>
                <i className={`bi bi-${icon}`}></i> Configure & Start
            </Button>
        );
    };
    
    return (
        <>
            <Card className={`h-100 ${!enabled ? 'text-muted' : ''}`}>
                <Card.Header className="d-flex justify-content-between align-items-center">
                    <h5 className="mb-0">
                        <i className={`bi bi-${icon} me-2`}></i>
                        {title}
                    </h5>
                    {getStatusBadge()}
                </Card.Header>
                
                <Card.Body>
                    <p className="text-muted">{description}</p>
                    
                    {/* Progress Bar */}
                    {status === 'running' && (
                        <div className="mb-3">
                            <div className="d-flex justify-content-between mb-1">
                                <small>Progress</small>
                                <small>{progress}%</small>
                            </div>
                            <ProgressBar now={progress} variant={variant} />
                        </div>
                    )}
                    
                    {/* ROI URLs Preview */}
                    {enabled && roiUrls && roiUrls.length > 0 && (
                        <div className="mb-3">
                            <h6>Top ROI URLs ({roiUrls.length})</h6>
                            <ListGroup variant="flush" className="small">
                                {roiUrls.slice(0, 3).map((roiUrl, index) => (
                                    <ListGroup.Item key={index} className="px-0 py-1">
                                        <div className="d-flex justify-content-between">
                                            <span className="text-truncate" style={{maxWidth: '200px'}}>
                                                {roiUrl.url}
                                            </span>
                                            <Badge bg="info" pill>{roiUrl.roi_score}</Badge>
                                        </div>
                                    </ListGroup.Item>
                                ))}
                                {roiUrls.length > 3 && (
                                    <ListGroup.Item className="px-0 py-1 text-center text-muted">
                                        +{roiUrls.length - 3} more URLs
                                    </ListGroup.Item>
                                )}
                            </ListGroup>
                        </div>
                    )}
                    
                    {/* Prerequisites Warning */}
                    {!enabled && prerequisites && (
                        <div className="mb-3">
                            <small className="text-muted">
                                <i className="bi bi-info-circle me-1"></i>
                                {prerequisites.message}
                            </small>
                        </div>
                    )}
                </Card.Body>
                
                <Card.Footer>
                    {getActionButton()}
                </Card.Footer>
            </Card>
            
            {/* Configuration Modal */}
            <URLWorkflowConfigModal
                show={showConfigModal}
                onHide={() => setShowConfigModal(false)}
                roiUrls={roiUrls}
                onStart={onStart}
            />
        </>
    );
};

export default URLWorkflowCard;
```

### 3. URL Workflow Configuration Modal

```jsx
// client/src/modals/URLWorkflowConfigModal.js (NEW)
import React, { useState } from 'react';
import { Modal, Button, Form, Table, Badge, Alert, Accordion, Card } from 'react-bootstrap';

const URLWorkflowConfigModal = ({ show, onHide, roiUrls, onStart }) => {
    const [selectedUrls, setSelectedUrls] = useState(new Set());
    const [phaseConfig, setPhaseConfig] = useState({
        phase1_enabled: true,    // Attack Surface Mapping
        phase2_enabled: true,    // DAST Scanning
        phase3_enabled: true,    // Targeted Vulnerability Testing
        multi_identity_testing: true,
        oob_testing: true,
        browser_validation: true
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    
    // Select all URLs by default
    useState(() => {
        if (roiUrls && roiUrls.length > 0) {
            setSelectedUrls(new Set(roiUrls.map((_, index) => index)));
        }
    }, [roiUrls]);
    
    const handleUrlSelection = (index, checked) => {
        const newSelected = new Set(selectedUrls);
        if (checked) {
            newSelected.add(index);
        } else {
            newSelected.delete(index);
        }
        setSelectedUrls(newSelected);
    };
    
    const handleSelectAll = (checked) => {
        if (checked) {
            setSelectedUrls(new Set(roiUrls.map((_, index) => index)));
        } else {
            setSelectedUrls(new Set());
        }
    };
    
    const handleStart = async () => {
        if (selectedUrls.size === 0) {
            setError('Please select at least one URL for testing');
            return;
        }
        
        try {
            setLoading(true);
            setError(null);
            
            const selectedUrlsData = Array.from(selectedUrls).map(index => roiUrls[index]);
            await onStart(selectedUrlsData, phaseConfig);
            onHide();
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };
    
    return (
        <Modal show={show} onHide={onHide} size="lg">
            <Modal.Header closeButton>
                <Modal.Title>
                    <i className="bi bi-shield-check me-2"></i>
                    Configure URL Workflow
                </Modal.Title>
            </Modal.Header>
            
            <Modal.Body>
                {error && <Alert variant="danger">{error}</Alert>}
                
                {/* URL Selection */}
                <div className="mb-4">
                    <div className="d-flex justify-content-between align-items-center mb-3">
                        <h5>Select URLs for Testing</h5>
                        <Form.Check
                            type="checkbox"
                            label="Select All"
                            checked={selectedUrls.size === roiUrls?.length}
                            onChange={(e) => handleSelectAll(e.target.checked)}
                        />
                    </div>
                    
                    <Table striped bordered hover size="sm">
                        <thead>
                            <tr>
                                <th width="5%">Select</th>
                                <th width="50%">URL</th>
                                <th width="15%">ROI Score</th>
                                <th width="15%">Priority</th>
                                <th width="15%">Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            {roiUrls?.map((roiUrl, index) => (
                                <tr key={index}>
                                    <td>
                                        <Form.Check
                                            type="checkbox"
                                            checked={selectedUrls.has(index)}
                                            onChange={(e) => handleUrlSelection(index, e.target.checked)}
                                        />
                                    </td>
                                    <td className="text-truncate" style={{maxWidth: '300px'}}>
                                        {roiUrl.url}
                                    </td>
                                    <td>
                                        <Badge bg="info" pill>{roiUrl.roi_score}</Badge>
                                    </td>
                                    <td>
                                        <Badge bg="secondary" pill>#{roiUrl.priority}</Badge>
                                    </td>
                                    <td>
                                        {roiUrl.metadata?.auth_endpoint && <Badge bg="warning" className="me-1">Auth</Badge>}
                                        {roiUrl.metadata?.api_endpoint && <Badge bg="primary" className="me-1">API</Badge>}
                                        {roiUrl.metadata?.admin_interface && <Badge bg="danger" className="me-1">Admin</Badge>}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </Table>
                </div>
                
                {/* Phase Configuration */}
                <Accordion className="mb-3">
                    <Accordion.Item eventKey="0">
                        <Accordion.Header>
                            <i className="bi bi-gear me-2"></i>
                            Advanced Configuration
                        </Accordion.Header>
                        <Accordion.Body>
                            <Form>
                                <h6>Testing Phases</h6>
                                <Form.Check
                                    type="checkbox"
                                    label="Phase 1: Attack Surface Mapping"
                                    checked={phaseConfig.phase1_enabled}
                                    onChange={(e) => setPhaseConfig(prev => ({ ...prev, phase1_enabled: e.target.checked }))}
                                    className="mb-2"
                                />
                                <Form.Check
                                    type="checkbox"
                                    label="Phase 2: DAST Scanning"
                                    checked={phaseConfig.phase2_enabled}
                                    onChange={(e) => setPhaseConfig(prev => ({ ...prev, phase2_enabled: e.target.checked }))}
                                    className="mb-2"
                                />
                                <Form.Check
                                    type="checkbox"
                                    label="Phase 3: Targeted Vulnerability Testing"
                                    checked={phaseConfig.phase3_enabled}
                                    onChange={(e) => setPhaseConfig(prev => ({ ...prev, phase3_enabled: e.target.checked }))}
                                    className="mb-3"
                                />
                                
                                <h6>Testing Options</h6>
                                <Form.Check
                                    type="checkbox"
                                    label="Multi-Identity Testing (Guest, User, Admin)"
                                    checked={phaseConfig.multi_identity_testing}
                                    onChange={(e) => setPhaseConfig(prev => ({ ...prev, multi_identity_testing: e.target.checked }))}
                                    className="mb-2"
                                />
                                <Form.Check
                                    type="checkbox"
                                    label="Out-of-Band (OOB) Testing"
                                    checked={phaseConfig.oob_testing}
                                    onChange={(e) => setPhaseConfig(prev => ({ ...prev, oob_testing: e.target.checked }))}
                                    className="mb-2"
                                />
                                <Form.Check
                                    type="checkbox"
                                    label="Browser-based Validation"
                                    checked={phaseConfig.browser_validation}
                                    onChange={(e) => setPhaseConfig(prev => ({ ...prev, browser_validation: e.target.checked }))}
                                    className="mb-2"
                                />
                            </Form>
                        </Accordion.Body>
                    </Accordion.Item>
                </Accordion>
                
                {/* Summary */}
                <Alert variant="info">
                    <strong>Selected:</strong> {selectedUrls.size} URLs will be tested across {
                        Object.values(phaseConfig).filter(Boolean).length
                    } enabled testing phases.
                </Alert>
            </Modal.Body>
            
            <Modal.Footer>
                <Button variant="secondary" onClick={onHide} disabled={loading}>
                    Cancel
                </Button>
                <Button variant="primary" onClick={handleStart} disabled={loading || selectedUrls.size === 0}>
                    {loading ? (
                        <>
                            <span className="spinner-border spinner-border-sm me-2" />
                            Starting...
                        </>
                    ) : (
                        <>
                            <i className="bi bi-play me-2"></i>
                            Start URL Workflow
                        </>
                    )}
                </Button>
            </Modal.Footer>
        </Modal>
    );
};

export default URLWorkflowConfigModal;
```

### 4. Findings Dashboard Component

```jsx
// client/src/components/FindingsDashboard.js (NEW)
import React, { useState, useEffect } from 'react';
import { Card, Table, Badge, Button, Modal, Tabs, Tab, Alert } from 'react-bootstrap';
import { fetchFindings } from '../utils/findingsUtils';

const FindingsDashboard = ({ scopeTargetId, workflowType = 'url' }) => {
    const [findings, setFindings] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedFinding, setSelectedFinding] = useState(null);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    
    useEffect(() => {
        const loadFindings = async () => {
            try {
                setLoading(true);
                const findingsData = await fetchFindings(scopeTargetId, { workflowType });
                setFindings(findingsData.findings || []);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };
        
        loadFindings();
        
        // Poll for updates every 5 seconds during active scans
        const interval = setInterval(loadFindings, 5000);
        return () => clearInterval(interval);
    }, [scopeTargetId, workflowType]);
    
    const getSeverityBadge = (severity) => {
        const variants = {
            critical: 'danger',
            high: 'warning',
            medium: 'primary',
            low: 'info',
            info: 'secondary'
        };
        return <Badge bg={variants[severity] || 'secondary'}>{severity}</Badge>;
    };
    
    const getCategoryIcon = (category) => {
        const icons = {
            xss: 'code-slash',
            sqli: 'database',
            idor: 'key',
            ssrf: 'arrow-up-right',
            auth_bypass: 'shield-slash',
            file_upload: 'upload',
            command_injection: 'terminal'
        };
        return icons[category] || 'bug';
    };
    
    const handleViewDetails = (finding) => {
        setSelectedFinding(finding);
        setShowDetailsModal(true);
    };
    
    if (loading) {
        return (
            <Card>
                <Card.Header>
                    <h5>Security Findings</h5>
                </Card.Header>
                <Card.Body className="text-center">
                    <div className="spinner-border" role="status">
                        <span className="visually-hidden">Loading...</span>
                    </div>
                    <p className="mt-2">Loading findings...</p>
                </Card.Body>
            </Card>
        );
    }
    
    return (
        <>
            <Card>
                <Card.Header className="d-flex justify-content-between align-items-center">
                    <h5>
                        <i className="bi bi-shield-exclamation me-2"></i>
                        Security Findings ({findings.length})
                    </h5>
                    <div>
                        <Badge bg="danger" className="me-2">
                            Critical: {findings.filter(f => f.severity === 'critical').length}
                        </Badge>
                        <Badge bg="warning" className="me-2">
                            High: {findings.filter(f => f.severity === 'high').length}
                        </Badge>
                        <Badge bg="primary">
                            Medium: {findings.filter(f => f.severity === 'medium').length}
                        </Badge>
                    </div>
                </Card.Header>
                
                <Card.Body>
                    {error && <Alert variant="danger">{error}</Alert>}
                    
                    {findings.length === 0 ? (
                        <div className="text-center text-muted py-4">
                            <i className="bi bi-shield-check display-4"></i>
                            <p>No security findings discovered yet.</p>
                            <small>Findings will appear here as the URL workflow progresses.</small>
                        </div>
                    ) : (
                        <Table striped hover responsive>
                            <thead>
                                <tr>
                                    <th>Category</th>
                                    <th>Title</th>
                                    <th>Severity</th>
                                    <th>Status</th>
                                    <th>Kill Chain</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {findings.map((finding) => (
                                    <tr key={finding.id}>
                                        <td>
                                            <i className={`bi bi-${getCategoryIcon(finding.category)} me-2`}></i>
                                            {finding.category.toUpperCase()}
                                        </td>
                                        <td>{finding.title}</td>
                                        <td>{getSeverityBadge(finding.severity)}</td>
                                        <td>
                                            <Badge bg={finding.status === 'confirmed' ? 'success' : 'secondary'}>
                                                {finding.status}
                                            </Badge>
                                        </td>
                                        <td>
                                            {finding.kill_chain_score > 0 && (
                                                <Badge bg="warning" pill>
                                                    {finding.kill_chain_score}/10
                                                </Badge>
                                            )}
                                        </td>
                                        <td>
                                            <Button
                                                size="sm"
                                                variant="outline-primary"
                                                onClick={() => handleViewDetails(finding)}
                                            >
                                                <i className="bi bi-eye"></i> Details
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </Table>
                    )}
                </Card.Body>
            </Card>
            
            {/* Finding Details Modal */}
            <FindingDetailsModal
                finding={selectedFinding}
                show={showDetailsModal}
                onHide={() => setShowDetailsModal(false)}
            />
        </>
    );
};

export default FindingsDashboard;
```

This frontend design maintains the existing Ars0n Framework patterns while seamlessly integrating the new URL workflow functionality, ensuring a consistent user experience and progressive workflow enablement.
