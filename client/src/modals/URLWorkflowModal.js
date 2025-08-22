import { Modal, Button, Form, Spinner, Alert, Table, ProgressBar, Badge, Card } from 'react-bootstrap';
import { useState, useEffect } from 'react';
import URLWorkflowHelpMeLearn from '../components/URLWorkflowHelpMeLearn';

function URLWorkflowModal({ show, handleClose, scopeTargetId, targetType }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [step, setStep] = useState('prerequisites'); // prerequisites, roi-selection, workflow-config, execution, results
  const [prerequisiteCheck, setPrerequisiteCheck] = useState(null);
  const [roiUrls, setRoiUrls] = useState([]);
  const [selectedUrls, setSelectedUrls] = useState([]);
  const [maxUrls, setMaxUrls] = useState(10);
  const [workflowSession, setWorkflowSession] = useState(null);
  const [workflowStatus, setWorkflowStatus] = useState(null);
  const [pollingInterval, setPollingInterval] = useState(null);

  // Server configuration
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  const baseURL = `${serverProtocol}://${serverIP}:${serverPort}`;

  useEffect(() => {
    if (show && step === 'prerequisites') {
      checkPrerequisites();
    }
    
    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, [show, scopeTargetId]);

  const checkPrerequisites = async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Check if Company and Wildcard workflows are completed
      const response = await fetch(`${baseURL}/api/url-workflow/roi-urls/${scopeTargetId}`);
      
      if (response.status === 412) {
        // Precondition failed - prerequisites not met
        setPrerequisiteCheck({
          passed: false,
          message: "Company and Wildcard workflows must be completed before URL workflow can be initiated."
        });
      } else if (response.ok) {
        const data = await response.json();
        setRoiUrls(data.urls || []);
        setPrerequisiteCheck({
          passed: true,
          message: `Prerequisites met. Found ${data.urls?.length || 0} ROI-scored URLs available for testing.`
        });
        
        if (data.urls?.length > 0) {
          setStep('roi-selection');
        }
      } else {
        throw new Error('Failed to check prerequisites');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleUrlSelection = (url, isSelected) => {
    if (isSelected) {
      setSelectedUrls([...selectedUrls, url]);
    } else {
      setSelectedUrls(selectedUrls.filter(u => u !== url));
    }
  };

  const selectAllUrls = () => {
    setSelectedUrls([...roiUrls]);
  };

  const selectTopUrls = () => {
    setSelectedUrls(roiUrls.slice(0, maxUrls));
  };

  const clearSelection = () => {
    setSelectedUrls([]);
  };

  const initiateWorkflow = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const requestBody = {
        selected_urls: selectedUrls.length > 0 ? selectedUrls : undefined,
        max_urls: selectedUrls.length === 0 ? maxUrls : undefined
      };

      const response = await fetch(`${baseURL}/api/url-workflow/initiate/${scopeTargetId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error('Failed to initiate URL workflow');
      }

      const data = await response.json();
      setWorkflowSession(data);
      setStep('execution');
      
      // Start polling for status
      startStatusPolling(data.session_id);
      
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const startStatusPolling = (sessionId) => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch(`${baseURL}/api/url-workflow/status/${sessionId}`);
        if (response.ok) {
          const status = await response.json();
          setWorkflowStatus(status);
          
          if (status.status === 'completed' || status.status === 'failed') {
            clearInterval(interval);
            setPollingInterval(null);
            setStep('results');
          }
        }
      } catch (err) {
        console.error('Status polling error:', err);
      }
    }, 2000);
    
    setPollingInterval(interval);
  };

  const resetModal = () => {
    setStep('prerequisites');
    setPrerequisiteCheck(null);
    setRoiUrls([]);
    setSelectedUrls([]);
    setWorkflowSession(null);
    setWorkflowStatus(null);
    setError(null);
    setMaxUrls(10);
    
    if (pollingInterval) {
      clearInterval(pollingInterval);
      setPollingInterval(null);
    }
  };

  const handleModalClose = () => {
    resetModal();
    handleClose();
  };

  const getPhaseProgress = () => {
    if (!workflowStatus) return 0;
    
    const phaseOrder = ['attack_surface_mapping', 'dast_scanning', 'targeted_testing', 'evidence_collection', 'completed'];
    const currentPhaseIndex = phaseOrder.indexOf(workflowStatus.current_phase);
    const totalPhases = phaseOrder.length - 1; // Don't count 'completed' as a phase
    
    if (workflowStatus.status === 'completed') return 100;
    if (workflowStatus.status === 'failed') return currentPhaseIndex * (100 / totalPhases);
    
    return (currentPhaseIndex / totalPhases) * 100;
  };

  const formatPhaseName = (phase) => {
    const phaseNames = {
      'attack_surface_mapping': 'Attack Surface Mapping',
      'dast_scanning': 'DAST Scanning',
      'targeted_testing': 'Targeted Testing',
      'evidence_collection': 'Evidence Collection',
      'completed': 'Completed'
    };
    return phaseNames[phase] || phase;
  };

  const renderPrerequisites = () => (
    <div>
      <URLWorkflowHelpMeLearn level="beginner" />
      
      <h5>URL Workflow Prerequisites</h5>
      <p>The URL workflow requires that Company and Wildcard workflows have been completed to discover and analyze web assets.</p>
      
      {loading && (
        <div className="text-center p-3">
          <Spinner animation="border" />
          <p>Checking prerequisites...</p>
        </div>
      )}
      
      {prerequisiteCheck && (
        <Alert variant={prerequisiteCheck.passed ? "success" : "warning"}>
          {prerequisiteCheck.message}
        </Alert>
      )}
      
      {prerequisiteCheck && !prerequisiteCheck.passed && (
        <div className="mt-3">
          <p><strong>Required Steps:</strong></p>
          <ol>
            <li>Complete Company workflow to discover organization assets</li>
            <li>Complete Wildcard workflow to enumerate subdomains and live web servers</li>
            <li>Ensure ROI algorithm has scored discovered URLs</li>
          </ol>
        </div>
      )}
    </div>
  );

  const renderRoiSelection = () => (
    <div>
      <h5>URL Selection for Automated Testing</h5>
      <p>Select URLs for comprehensive automated vulnerability testing. URLs are ranked by ROI (Return on Investment) score.</p>
      
      <div className="mb-3 d-flex gap-2 flex-wrap">
        <Button 
          variant="primary" 
          size="sm" 
          onClick={selectTopUrls}
          disabled={roiUrls.length === 0}
        >
          Select Top {maxUrls}
        </Button>
        <Button 
          variant="outline-primary" 
          size="sm" 
          onClick={selectAllUrls}
          disabled={roiUrls.length === 0}
        >
          Select All ({roiUrls.length})
        </Button>
        <Button 
          variant="outline-secondary" 
          size="sm" 
          onClick={clearSelection}
          disabled={selectedUrls.length === 0}
        >
          Clear Selection
        </Button>
        
        <Form.Group className="d-flex align-items-center ms-3">
          <Form.Label className="me-2 mb-0">Max URLs:</Form.Label>
          <Form.Control
            type="number"
            value={maxUrls}
            onChange={(e) => setMaxUrls(Math.max(1, Math.min(50, parseInt(e.target.value) || 10)))}
            style={{ width: '80px' }}
            min="1"
            max="50"
          />
        </Form.Group>
      </div>
      
      <div className="mb-3">
        <strong>Selected: {selectedUrls.length} URLs</strong>
      </div>
      
      {roiUrls.length > 0 ? (
        <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
          <Table striped bordered hover size="sm">
            <thead>
              <tr>
                <th style={{ width: '50px' }}>Select</th>
                <th>URL</th>
                <th style={{ width: '100px' }}>ROI Score</th>
                <th style={{ width: '120px' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {roiUrls.map((url, index) => (
                <tr key={index}>
                  <td>
                    <Form.Check
                      type="checkbox"
                      checked={selectedUrls.includes(url)}
                      onChange={(e) => handleUrlSelection(url, e.target.checked)}
                    />
                  </td>
                  <td>
                    <code style={{ fontSize: '0.85em' }}>{url}</code>
                  </td>
                  <td>
                    <Badge bg="info">High</Badge>
                  </td>
                  <td>
                    <Badge bg="success">Live</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      ) : (
        <Alert variant="warning">
          No ROI-scored URLs available. Please ensure Company and Wildcard workflows have discovered live web servers.
        </Alert>
      )}
    </div>
  );

  const renderExecution = () => (
    <div>
      <h5>URL Workflow Execution</h5>
      
      {workflowSession && (
        <Card className="mb-3">
          <Card.Body>
            <h6>Session Information</h6>
            <p><strong>Session ID:</strong> <code>{workflowSession.session_id}</code></p>
            <p><strong>URLs Selected:</strong> {workflowSession.selected_urls?.length || 0}</p>
            <p><strong>Estimated Time:</strong> {workflowSession.estimated_time}</p>
          </Card.Body>
        </Card>
      )}
      
      {workflowStatus && (
        <div>
          <h6>Progress</h6>
          <div className="mb-2">
            <strong>Current Phase:</strong> {formatPhaseName(workflowStatus.current_phase)}
          </div>
          <ProgressBar 
            now={getPhaseProgress()} 
            label={`${Math.round(getPhaseProgress())}%`}
            variant={workflowStatus.status === 'failed' ? 'danger' : 'primary'}
            className="mb-3"
          />
          
          <div className="row">
            <div className="col-md-6">
              <p><strong>Status:</strong> <Badge bg={
                workflowStatus.status === 'completed' ? 'success' : 
                workflowStatus.status === 'failed' ? 'danger' : 'primary'
              }>
                {workflowStatus.status}
              </Badge></p>
            </div>
            <div className="col-md-6">
              <p><strong>Findings:</strong> {workflowStatus.total_findings}</p>
            </div>
          </div>
          
          {workflowStatus.error_message && (
            <Alert variant="danger">
              <strong>Error:</strong> {workflowStatus.error_message}
            </Alert>
          )}
        </div>
      )}
    </div>
  );

  const renderResults = () => (
    <div>
      <h5>Workflow Results</h5>
      
      {workflowStatus && (
        <div>
          <Alert variant={workflowStatus.status === 'completed' ? 'success' : 'danger'}>
            <strong>Workflow {workflowStatus.status === 'completed' ? 'Completed' : 'Failed'}</strong>
            {workflowStatus.completed_at && (
              <div>Finished at: {new Date(workflowStatus.completed_at).toLocaleString()}</div>
            )}
          </Alert>
          
          <Card className="mb-3">
            <Card.Body>
              <h6>Summary</h6>
              <div className="row">
                <div className="col-md-6">
                  <p><strong>Total Findings:</strong> {workflowStatus.total_findings}</p>
                  <p><strong>Evidence Items:</strong> {workflowStatus.total_evidence_items}</p>
                </div>
                <div className="col-md-6">
                  <p><strong>Duration:</strong> {
                    workflowStatus.completed_at ? 
                    Math.round((new Date(workflowStatus.completed_at) - new Date(workflowStatus.started_at)) / 1000 / 60) + ' minutes' :
                    'In progress'
                  }</p>
                </div>
              </div>
            </Card.Body>
          </Card>
          
          <div className="d-flex gap-2">
            <Button 
              variant="primary" 
              onClick={() => {
                // Navigate to findings dashboard - implementation needed
                console.log('Navigate to findings for session:', workflowStatus.session_id);
              }}
            >
              View Findings
            </Button>
            <Button 
              variant="outline-primary"
              onClick={() => {
                // Export findings - implementation needed
                console.log('Export findings for session:', workflowStatus.session_id);
              }}
            >
              Export Results
            </Button>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <Modal show={show} onHide={handleModalClose} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>
          URL Workflow - Automated Vulnerability Testing
          {targetType && <Badge bg="secondary" className="ms-2">{targetType}</Badge>}
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError(null)}>
            {error}
          </Alert>
        )}
        
        {step === 'prerequisites' && renderPrerequisites()}
        {step === 'roi-selection' && renderRoiSelection()}
        {step === 'execution' && renderExecution()}
        {step === 'results' && renderResults()}
      </Modal.Body>
      
      <Modal.Footer>
        {step === 'prerequisites' && prerequisiteCheck?.passed && (
          <Button 
            variant="primary" 
            onClick={() => setStep('roi-selection')}
            disabled={loading}
          >
            Continue to URL Selection
          </Button>
        )}
        
        {step === 'roi-selection' && (
          <>
            <Button variant="secondary" onClick={() => setStep('prerequisites')}>
              Back
            </Button>
            <Button 
              variant="primary" 
              onClick={initiateWorkflow}
              disabled={loading || (selectedUrls.length === 0 && roiUrls.length === 0)}
            >
              {loading ? (
                <>
                  <Spinner size="sm" className="me-2" />
                  Starting Workflow...
                </>
              ) : (
                `Start URL Workflow (${selectedUrls.length || maxUrls} URLs)`
              )}
            </Button>
          </>
        )}
        
        {(step === 'execution' || step === 'results') && (
          <Button variant="secondary" onClick={handleModalClose}>
            Close
          </Button>
        )}
      </Modal.Footer>
    </Modal>
  );
}

export default URLWorkflowModal;
