import { useState, useEffect } from 'react';
import { Card, Table, Badge, Button, Form, InputGroup, Modal, Alert, Spinner, Pagination } from 'react-bootstrap';

function FindingsDashboard({ scopeTargetId, urlWorkflowSessionId }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    category: '',
    severity: [],
    status: [],
    search: ''
  });
  const [pagination, setPagination] = useState({
    limit: 20,
    offset: 0,
    total: 0,
    hasMore: false
  });
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [reproInstructions, setReproInstructions] = useState(null);
  const [loadingRepro, setLoadingRepro] = useState(false);

  // Server configuration
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  const baseURL = `${serverProtocol}://${serverIP}:${serverPort}`;

  const categories = [
    'xss', 'sqli', 'idor', 'ssrf', 'rce', 'lfi', 'rfi', 'csrf', 'xxe', 
    'nosqli', 'ldapi', 'ssti', 'auth_bypass', 'info_disclosure', 
    'misconfiguration', 'other'
  ];

  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const statuses = ['new', 'investigating', 'confirmed', 'false_positive', 'duplicate', 'resolved'];

  useEffect(() => {
    fetchFindings();
  }, [scopeTargetId, urlWorkflowSessionId, filters, pagination.offset]);

  const fetchFindings = async () => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams({
        limit: pagination.limit,
        offset: pagination.offset
      });

      if (scopeTargetId) params.append('scope_target_id', scopeTargetId);
      if (urlWorkflowSessionId) params.append('url_workflow_session_id', urlWorkflowSessionId);
      if (filters.category) params.append('category', filters.category);
      if (filters.search) params.append('search', filters.search);
      
      filters.severity.forEach(s => params.append('severity', s));
      filters.status.forEach(s => params.append('status', s));

      const response = await fetch(`${baseURL}/api/findings?${params}`);
      
      if (!response.ok) {
        throw new Error('Failed to fetch findings');
      }

      const data = await response.json();
      setFindings(data.findings || []);
      setPagination(prev => ({
        ...prev,
        total: data.total || 0,
        hasMore: data.has_more || false
      }));

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (filterType, value) => {
    if (filterType === 'severity' || filterType === 'status') {
      setFilters(prev => ({
        ...prev,
        [filterType]: prev[filterType].includes(value) 
          ? prev[filterType].filter(v => v !== value)
          : [...prev[filterType], value]
      }));
    } else {
      setFilters(prev => ({ ...prev, [filterType]: value }));
    }
    
    // Reset pagination when filters change
    setPagination(prev => ({ ...prev, offset: 0 }));
  };

  const clearFilters = () => {
    setFilters({
      category: '',
      severity: [],
      status: [],
      search: ''
    });
    setPagination(prev => ({ ...prev, offset: 0 }));
  };

  const handlePageChange = (newOffset) => {
    setPagination(prev => ({ ...prev, offset: newOffset }));
  };

  const updateFindingStatus = async (findingId, newStatus) => {
    try {
      const response = await fetch(`${baseURL}/api/findings/${findingId}/status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status: newStatus,
          verified_by: 'User', // TODO: Get from context
          notes: `Status changed to ${newStatus}`
        })
      });

      if (!response.ok) {
        throw new Error('Failed to update finding status');
      }

      // Refresh findings
      fetchFindings();
      
      // Update selected finding if it's open
      if (selectedFinding && selectedFinding.id === findingId) {
        setSelectedFinding(prev => ({ ...prev, status: newStatus }));
      }

    } catch (err) {
      setError(err.message);
    }
  };

  const viewFindingDetails = async (finding) => {
    setSelectedFinding(finding);
    setShowFindingModal(true);
    setReproInstructions(null);
    
    // Load reproduction instructions
    setLoadingRepro(true);
    try {
      const response = await fetch(`${baseURL}/api/findings/${finding.id}/reproduce`);
      if (response.ok) {
        const data = await response.json();
        setReproInstructions(data.recipes || []);
      }
    } catch (err) {
      console.error('Failed to load reproduction instructions:', err);
    } finally {
      setLoadingRepro(false);
    }
  };

  const exportFindings = async () => {
    try {
      const params = new URLSearchParams();
      if (scopeTargetId) params.append('scope_target_id', scopeTargetId);
      if (urlWorkflowSessionId) params.append('url_workflow_session_id', urlWorkflowSessionId);
      params.append('format', 'json');

      const response = await fetch(`${baseURL}/api/findings/export?${params}`);
      
      if (!response.ok) {
        throw new Error('Failed to export findings');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `findings-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

    } catch (err) {
      setError(err.message);
    }
  };

  const getSeverityVariant = (severity) => {
    const variants = {
      'critical': 'danger',
      'high': 'warning',
      'medium': 'info',
      'low': 'secondary',
      'info': 'light'
    };
    return variants[severity] || 'secondary';
  };

  const getStatusVariant = (status) => {
    const variants = {
      'new': 'primary',
      'investigating': 'warning',
      'confirmed': 'danger',
      'false_positive': 'secondary',
      'duplicate': 'secondary',
      'resolved': 'success'
    };
    return variants[status] || 'secondary';
  };

  const formatCategory = (category) => {
    return category.toUpperCase().replace('_', ' ');
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const renderPagination = () => {
    const totalPages = Math.ceil(pagination.total / pagination.limit);
    const currentPage = Math.floor(pagination.offset / pagination.limit) + 1;
    
    if (totalPages <= 1) return null;

    const items = [];
    const maxVisiblePages = 5;
    const startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
    const endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

    // Previous button
    items.push(
      <Pagination.Prev
        key="prev"
        disabled={currentPage === 1}
        onClick={() => handlePageChange((currentPage - 2) * pagination.limit)}
      />
    );

    // Page numbers
    for (let page = startPage; page <= endPage; page++) {
      items.push(
        <Pagination.Item
          key={page}
          active={page === currentPage}
          onClick={() => handlePageChange((page - 1) * pagination.limit)}
        >
          {page}
        </Pagination.Item>
      );
    }

    // Next button
    items.push(
      <Pagination.Next
        key="next"
        disabled={currentPage === totalPages}
        onClick={() => handlePageChange(currentPage * pagination.limit)}
      />
    );

    return <Pagination className="justify-content-center">{items}</Pagination>;
  };

  return (
    <Card>
      <Card.Header className="d-flex justify-content-between align-items-center">
        <h5 className="mb-0">Security Findings</h5>
        <div className="d-flex gap-2">
          <Button variant="outline-primary" size="sm" onClick={exportFindings}>
            Export
          </Button>
          <Button variant="outline-secondary" size="sm" onClick={fetchFindings}>
            Refresh
          </Button>
        </div>
      </Card.Header>

      <Card.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {/* Filters */}
        <div className="mb-3">
          <Form>
            <div className="row g-2">
              <div className="col-md-3">
                <InputGroup size="sm">
                  <InputGroup.Text>Search</InputGroup.Text>
                  <Form.Control
                    type="text"
                    placeholder="Search findings..."
                    value={filters.search}
                    onChange={(e) => handleFilterChange('search', e.target.value)}
                  />
                </InputGroup>
              </div>
              
              <div className="col-md-2">
                <Form.Select
                  size="sm"
                  value={filters.category}
                  onChange={(e) => handleFilterChange('category', e.target.value)}
                >
                  <option value="">All Categories</option>
                  {categories.map(cat => (
                    <option key={cat} value={cat}>{formatCategory(cat)}</option>
                  ))}
                </Form.Select>
              </div>
              
              <div className="col-md-3">
                <div className="d-flex flex-wrap gap-1">
                  {severities.map(severity => (
                    <Form.Check
                      key={severity}
                      type="checkbox"
                      id={`severity-${severity}`}
                      label={severity}
                      checked={filters.severity.includes(severity)}
                      onChange={() => handleFilterChange('severity', severity)}
                      style={{ fontSize: '0.85em' }}
                    />
                  ))}
                </div>
              </div>
              
              <div className="col-md-3">
                <div className="d-flex flex-wrap gap-1">
                  {statuses.map(status => (
                    <Form.Check
                      key={status}
                      type="checkbox"
                      id={`status-${status}`}
                      label={status}
                      checked={filters.status.includes(status)}
                      onChange={() => handleFilterChange('status', status)}
                      style={{ fontSize: '0.85em' }}
                    />
                  ))}
                </div>
              </div>
              
              <div className="col-md-1">
                <Button variant="outline-secondary" size="sm" onClick={clearFilters}>
                  Clear
                </Button>
              </div>
            </div>
          </Form>
        </div>

        {/* Results summary */}
        <div className="mb-3">
          <small className="text-muted">
            Showing {findings.length} of {pagination.total} findings
          </small>
        </div>

        {/* Findings table */}
        {loading ? (
          <div className="text-center p-4">
            <Spinner animation="border" />
            <p>Loading findings...</p>
          </div>
        ) : findings.length > 0 ? (
          <>
            <Table striped bordered hover responsive>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Title</th>
                  <th>URL</th>
                  <th>Status</th>
                  <th>Discovered</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(finding => (
                  <tr key={finding.id}>
                    <td>
                      <Badge bg={getSeverityVariant(finding.severity)}>
                        {finding.severity}
                      </Badge>
                    </td>
                    <td>
                      <Badge bg="secondary">
                        {formatCategory(finding.category)}
                      </Badge>
                    </td>
                    <td>
                      <div style={{ maxWidth: '200px' }}>
                        <div className="fw-bold">{finding.title}</div>
                        {finding.description && (
                          <small className="text-muted">
                            {finding.description.substring(0, 100)}...
                          </small>
                        )}
                      </div>
                    </td>
                    <td>
                      <code style={{ fontSize: '0.8em', wordBreak: 'break-all' }}>
                        {finding.url}
                      </code>
                    </td>
                    <td>
                      <Badge bg={getStatusVariant(finding.status)}>
                        {finding.status.replace('_', ' ')}
                      </Badge>
                    </td>
                    <td>
                      <small>{formatDate(finding.discovered_at)}</small>
                    </td>
                    <td>
                      <div className="d-flex gap-1">
                        <Button
                          variant="outline-primary"
                          size="sm"
                          onClick={() => viewFindingDetails(finding)}
                        >
                          View
                        </Button>
                        {finding.status === 'new' && (
                          <Button
                            variant="outline-warning"
                            size="sm"
                            onClick={() => updateFindingStatus(finding.id, 'confirmed')}
                          >
                            Confirm
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            {renderPagination()}
          </>
        ) : (
          <Alert variant="info">
            No findings found. Run the URL workflow to discover security vulnerabilities.
          </Alert>
        )}
      </Card.Body>

      {/* Finding Details Modal */}
      <Modal show={showFindingModal} onHide={() => setShowFindingModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Finding Details</Modal.Title>
        </Modal.Header>
        
        <Modal.Body>
          {selectedFinding && (
            <div>
              <div className="row mb-3">
                <div className="col-md-6">
                  <p><strong>Severity:</strong> <Badge bg={getSeverityVariant(selectedFinding.severity)}>{selectedFinding.severity}</Badge></p>
                  <p><strong>Category:</strong> <Badge bg="secondary">{formatCategory(selectedFinding.category)}</Badge></p>
                  <p><strong>Status:</strong> <Badge bg={getStatusVariant(selectedFinding.status)}>{selectedFinding.status.replace('_', ' ')}</Badge></p>
                </div>
                <div className="col-md-6">
                  <p><strong>Confidence:</strong> {selectedFinding.confidence}</p>
                  <p><strong>Method:</strong> {selectedFinding.method}</p>
                  <p><strong>Discovered:</strong> {formatDate(selectedFinding.discovered_at)}</p>
                </div>
              </div>
              
              <div className="mb-3">
                <h6>Title</h6>
                <p>{selectedFinding.title}</p>
              </div>
              
              {selectedFinding.description && (
                <div className="mb-3">
                  <h6>Description</h6>
                  <p>{selectedFinding.description}</p>
                </div>
              )}
              
              <div className="mb-3">
                <h6>URL</h6>
                <code>{selectedFinding.url}</code>
              </div>
              
              <div className="mb-3">
                <h6>Signal</h6>
                <pre style={{ backgroundColor: '#f8f9fa', padding: '10px', borderRadius: '4px', fontSize: '0.85em' }}>
                  {selectedFinding.signal}
                </pre>
              </div>
              
              {/* Reproduction Instructions */}
              <div className="mb-3">
                <h6>Reproduction Instructions</h6>
                {loadingRepro ? (
                  <div className="text-center p-2">
                    <Spinner size="sm" /> Loading reproduction instructions...
                  </div>
                ) : reproInstructions && reproInstructions.length > 0 ? (
                  <div>
                    {reproInstructions.map((recipe, index) => (
                      <Card key={index} className="mb-2">
                        <Card.Header>
                          <small>
                            <Badge bg="info">{recipe.recipe_type.replace('_', ' ')}</Badge>
                            {recipe.execution_environment && (
                              <span className="ms-2">Environment: {recipe.execution_environment}</span>
                            )}
                          </small>
                        </Card.Header>
                        <Card.Body>
                          <pre style={{ fontSize: '0.8em', whiteSpace: 'pre-wrap' }}>
                            {recipe.recipe_data}
                          </pre>
                        </Card.Body>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <Alert variant="info">No reproduction instructions available for this finding.</Alert>
                )}
              </div>
              
              {/* Status Update Actions */}
              <div className="mb-3">
                <h6>Actions</h6>
                <div className="d-flex gap-2 flex-wrap">
                  {selectedFinding.status !== 'confirmed' && (
                    <Button
                      variant="warning"
                      size="sm"
                      onClick={() => updateFindingStatus(selectedFinding.id, 'confirmed')}
                    >
                      Confirm
                    </Button>
                  )}
                  {selectedFinding.status !== 'false_positive' && (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => updateFindingStatus(selectedFinding.id, 'false_positive')}
                    >
                      False Positive
                    </Button>
                  )}
                  {selectedFinding.status !== 'resolved' && (
                    <Button
                      variant="success"
                      size="sm"
                      onClick={() => updateFindingStatus(selectedFinding.id, 'resolved')}
                    >
                      Resolve
                    </Button>
                  )}
                </div>
              </div>
            </div>
          )}
        </Modal.Body>
        
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowFindingModal(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>
    </Card>
  );
}

export default FindingsDashboard;
