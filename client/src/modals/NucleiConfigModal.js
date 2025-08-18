import { useState, useRef, useEffect } from 'react';
import { Modal, Button, Spinner, Alert, Row, Col, Form, Badge, Tab, Tabs, Table, InputGroup } from 'react-bootstrap';
import { FaSearch, FaUpload, FaTrash } from 'react-icons/fa';

const NucleiConfigModal = ({ 
  show, 
  handleClose, 
  activeTarget,
  onSaveConfig
}) => {
  const [activeTab, setActiveTab] = useState('targets');
  const [selectedCategory, setSelectedCategory] = useState('live_web_servers');
  const [selectedTargets, setSelectedTargets] = useState(new Set());
  const [selectedTemplates, setSelectedTemplates] = useState(new Set());
  const [selectedSeverities, setSelectedSeverities] = useState(new Set(['critical', 'high', 'medium', 'low', 'info']));
  const [attackSurfaceAssets, setAttackSurfaceAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [scannedTargets, setScannedTargets] = useState(new Set());
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStartIndex, setDragStartIndex] = useState(null);
  const [dragMode, setDragMode] = useState('select');
  const [uploadedTemplates, setUploadedTemplates] = useState([]);
  const [uploadingTemplates, setUploadingTemplates] = useState(false);
  const fileInputRef = useRef(null);
  const tableRef = useRef(null);

  // Attack Surface Categories
  const categories = [
    { key: 'asns', name: 'ASNs', icon: 'bi-diagram-3' },
    { key: 'network_ranges', name: 'Network Ranges', icon: 'bi-router' },
    { key: 'ip_addresses', name: 'IP Addresses', icon: 'bi-hdd-network' },
    { key: 'live_web_servers', name: 'Live Web Servers', icon: 'bi-server' },
    { key: 'cloud_assets', name: 'Cloud Assets', icon: 'bi-cloud' },
    { key: 'fqdns', name: 'Domain Names', icon: 'bi-globe' }
  ];

  // Nuclei Template Categories
  const templateCategories = [
    { key: 'cves', name: 'CVEs', description: 'Common Vulnerabilities and Exposures', icon: 'bi-shield-exclamation' },
    { key: 'vulnerabilities', name: 'Vulnerabilities', description: 'General vulnerability templates', icon: 'bi-bug' },
    { key: 'exposures', name: 'Exposures', description: 'Information disclosure templates', icon: 'bi-eye' },
    { key: 'technologies', name: 'Technologies', description: 'Technology detection templates', icon: 'bi-gear' },
    { key: 'misconfiguration', name: 'Misconfigurations', description: 'Common misconfigurations', icon: 'bi-exclamation-triangle' },
    { key: 'takeovers', name: 'Takeovers', description: 'Subdomain takeover templates', icon: 'bi-arrow-repeat' },
    { key: 'network', name: 'Network', description: 'Network-based templates', icon: 'bi-hdd-network' },
    { key: 'dns', name: 'DNS', description: 'DNS-related templates', icon: 'bi-globe' },
    { key: 'headless', name: 'Headless', description: 'Browser-based templates', icon: 'bi-window' },
    { key: 'custom', name: 'Custom Templates', description: `Upload your own Nuclei templates (${uploadedTemplates.length} uploaded)`, icon: 'bi-upload' }
  ];

  // Nuclei Template Severities
  const severityCategories = [
    { key: 'critical', name: 'Critical', description: 'Critical severity vulnerabilities', icon: 'bi-shield-exclamation', color: 'danger' },
    { key: 'high', name: 'High', description: 'High severity vulnerabilities', icon: 'bi-exclamation-triangle-fill', color: 'warning' },
    { key: 'medium', name: 'Medium', description: 'Medium severity vulnerabilities', icon: 'bi-exclamation-circle-fill', color: 'info' },
    { key: 'low', name: 'Low', description: 'Low severity vulnerabilities', icon: 'bi-info-circle-fill', color: 'success' },
    { key: 'info', name: 'Info', description: 'Informational findings', icon: 'bi-lightbulb', color: 'light' }
  ];

  useEffect(() => {
    if (show) {
      loadSavedConfig();
      fetchAttackSurfaceAssets();
    }
  }, [show, activeTarget]);

  useEffect(() => {
    fetchScannedTargets();
  }, [attackSurfaceAssets]);

  const fetchAttackSurfaceAssets = async () => {
    if (!activeTarget?.id) return;

    setLoadingAssets(true);
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/attack-surface-assets/${activeTarget.id}`
      );
      
      if (response.ok) {
        const data = await response.json();
        setAttackSurfaceAssets(data.assets || []);
      } else {
        setError('Failed to load attack surface assets. Please consolidate the attack surface first.');
      }
    } catch (error) {
      console.error('Error fetching attack surface assets:', error);
      setError('Failed to load attack surface assets. Please try again.');
    } finally {
      setLoadingAssets(false);
    }
  };

  const fetchScannedTargets = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/nuclei`
      );
      
      if (response.ok) {
        const scans = await response.json();
        const scannedSet = new Set();
        
        scans.forEach(scan => {
          if (scan.status === 'success' && scan.targets && Array.isArray(scan.targets)) {
            scan.targets.forEach(target => scannedSet.add(target));
          }
        });
        
        setScannedTargets(scannedSet);
      }
    } catch (error) {
      console.error('Error fetching scanned targets:', error);
    }
  };

  const loadSavedConfig = async () => {
    if (!activeTarget?.id) return;

    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/nuclei-config/${activeTarget.id}`
      );
      
      if (response.ok) {
        const config = await response.json();
        if (config.targets && Array.isArray(config.targets)) {
          setSelectedTargets(new Set(config.targets));
        }
        if (config.templates && Array.isArray(config.templates)) {
          setSelectedTemplates(new Set(config.templates));
        } else {
          // Set default templates if none exist
          const defaultTemplates = ['cves', 'vulnerabilities', 'exposures', 'technologies', 'misconfiguration', 'takeovers', 'network', 'dns', 'headless'];
          setSelectedTemplates(new Set(defaultTemplates));
        }
        if (config.severities && Array.isArray(config.severities)) {
          setSelectedSeverities(new Set(config.severities));
        } else {
          // Set default severities if none exist
          const defaultSeverities = ['critical', 'high', 'medium', 'low', 'info'];
          setSelectedSeverities(new Set(defaultSeverities));
        }
        if (config.uploaded_templates && Array.isArray(config.uploaded_templates)) {
          setUploadedTemplates(config.uploaded_templates);
        }
      }
    } catch (error) {
      console.error('Error loading Nuclei config:', error);
      // Set default templates on error as well
      const defaultTemplates = ['cves', 'vulnerabilities', 'exposures', 'technologies', 'misconfiguration', 'takeovers', 'network', 'dns', 'headless'];
      setSelectedTemplates(new Set(defaultTemplates));
    }
  };

  const handleSaveConfig = async () => {
    if (!activeTarget?.id) {
      setError('No active target selected');
      return;
    }

    setSaving(true);
    setError('');

    try {
      const config = {
        targets: Array.from(selectedTargets),
        templates: Array.from(selectedTemplates),
        severities: Array.from(selectedSeverities),
        uploaded_templates: uploadedTemplates,
        created_at: new Date().toISOString()
      };

      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/nuclei-config/${activeTarget.id}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(config),
        }
      );

      if (!response.ok) {
        throw new Error('Failed to save configuration');
      }

      if (onSaveConfig) {
        onSaveConfig(config);
      }

      handleClose();
    } catch (error) {
      console.error('Error saving Nuclei config:', error);
      setError('Failed to save configuration. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const getAssetsForCategory = (category) => {
    return attackSurfaceAssets.filter(asset => {
      switch (category) {
        case 'asns':
          return asset.asset_type === 'asn';
        case 'network_ranges':
          return asset.asset_type === 'network_range';
        case 'ip_addresses':
          return asset.asset_type === 'ip_address';
        case 'live_web_servers':
          return asset.asset_type === 'live_web_server';
        case 'cloud_assets':
          return asset.asset_type === 'cloud_asset';
        case 'fqdns':
          return asset.asset_type === 'fqdn';
        default:
          return false;
      }
    });
  };

  const getFilteredAssets = () => {
    const categoryAssets = getAssetsForCategory(selectedCategory);
    if (!searchFilter) return categoryAssets;
    
    return categoryAssets.filter(asset => {
      const searchText = searchFilter.toLowerCase();
      return (
        asset.asset_identifier.toLowerCase().includes(searchText) ||
        (asset.domain && asset.domain.toLowerCase().includes(searchText)) ||
        (asset.url && asset.url.toLowerCase().includes(searchText)) ||
        (asset.ip_address && asset.ip_address.toLowerCase().includes(searchText)) ||
        (asset.asn_number && asset.asn_number.toLowerCase().includes(searchText)) ||
        (asset.cidr_block && asset.cidr_block.toLowerCase().includes(searchText))
      );
    });
  };

  const handleTargetSelect = (targetId) => {
    const newSelected = new Set(selectedTargets);
    if (newSelected.has(targetId)) {
      newSelected.delete(targetId);
    } else {
      newSelected.add(targetId);
    }
    setSelectedTargets(newSelected);
  };

  const handleTemplateSelect = (templateKey) => {
    const newSelected = new Set(selectedTemplates);
    if (newSelected.has(templateKey)) {
      newSelected.delete(templateKey);
    } else {
      newSelected.add(templateKey);
    }
    setSelectedTemplates(newSelected);
  };

  const handleSeveritySelect = (severityKey) => {
    const newSelected = new Set(selectedSeverities);
    if (newSelected.has(severityKey)) {
      newSelected.delete(severityKey);
    } else {
      newSelected.add(severityKey);
    }
    setSelectedSeverities(newSelected);
  };

  const handleSelectAll = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => newSelected.add(asset.id));
    setSelectedTargets(newSelected);
  };

  const handleSelectNone = () => {
    setSelectedTargets(new Set());
  };

  const handleSelectNoneCurrentCategory = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => newSelected.delete(asset.id));
    setSelectedTargets(newSelected);
  };

  const handleSelectScanned = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => {
      if (scannedTargets.has(asset.id)) {
        newSelected.add(asset.id);
      }
    });
    setSelectedTargets(newSelected);
  };

  const handleSelectUnscanned = () => {
    const categoryAssets = getFilteredAssets();
    const newSelected = new Set(selectedTargets);
    categoryAssets.forEach(asset => {
      if (!scannedTargets.has(asset.id)) {
        newSelected.add(asset.id);
      }
    });
    setSelectedTargets(newSelected);
  };

  const handleSelectAllTemplates = () => {
    setSelectedTemplates(new Set(templateCategories.map(cat => cat.key)));
  };

  const handleSelectNoTemplates = () => {
    setSelectedTemplates(new Set());
  };

  const handleSelectAllSeverities = () => {
    setSelectedSeverities(new Set(severityCategories.map(sev => sev.key)));
  };

  const handleSelectNoSeverities = () => {
    setSelectedSeverities(new Set());
  };

  const handleFileUpload = async (event) => {
    const files = Array.from(event.target.files);
    if (files.length === 0) return;

    setUploadingTemplates(true);
    const newTemplates = [];

    for (const file of files) {
      if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
        try {
          const content = await file.text();
          newTemplates.push({
            id: Date.now() + Math.random(),
            name: file.name,
            size: file.size,
            content: content,
            uploaded_at: new Date().toISOString()
          });
        } catch (error) {
          console.error('Error reading file:', file.name, error);
        }
      }
    }

    setUploadedTemplates(prev => [...prev, ...newTemplates]);
    setUploadingTemplates(false);
    
    if (newTemplates.length > 0) {
      setSelectedTemplates(prev => new Set([...prev, 'custom']));
    }
    
    event.target.value = '';
  };

  const handleRemoveTemplate = (templateId) => {
    setUploadedTemplates(prev => prev.filter(template => template.id !== templateId));
  };

  const handleUploadClick = (event) => {
    event.stopPropagation();
    fileInputRef.current?.click();
  };

  const getAssetDisplayText = (asset) => {
    switch (asset.asset_type) {
      case 'asn':
        return `AS${asset.asn_number} - ${asset.asn_organization || 'Unknown'}`;
      case 'network_range':
        return `${asset.cidr_block} (${asset.subnet_size || 0} IPs)`;
      case 'ip_address':
        return `${asset.ip_address} ${asset.ip_type ? `(${asset.ip_type})` : ''}`;
      case 'live_web_server':
        return `${asset.url || asset.domain || asset.ip_address} ${asset.port ? `:${asset.port}` : ''}`;
      case 'cloud_asset':
        return `${asset.asset_identifier} (${asset.cloud_provider || 'Unknown'})`;
      case 'fqdn':
        return asset.fqdn || asset.domain || asset.asset_identifier;
      default:
        return asset.asset_identifier;
    }
  };

  const getAssetBadgeColor = (asset) => {
    switch (asset.asset_type) {
      case 'asn': return 'primary';
      case 'network_range': return 'info';
      case 'ip_address': return 'warning';
      case 'live_web_server': return 'success';
      case 'cloud_asset': return 'danger';
      case 'fqdn': return 'secondary';
      default: return 'dark';
    }
  };

  const handleCloseModal = () => {
    setError('');
    setSearchFilter('');
    setSelectedCategory('live_web_servers');
    setActiveTab('targets');
    handleClose();
  };

  const renderTargetSelection = () => (
    <Row>
      <Col md={3}>
        <h6 className="text-danger mb-3">Attack Surface Categories</h6>
        <div className="list-group">
          {categories.map(category => (
            <button
              key={category.key}
              className={`list-group-item list-group-item-action d-flex align-items-center ${
                selectedCategory === category.key ? 'active' : ''
              }`}
              onClick={() => setSelectedCategory(category.key)}
              style={{ backgroundColor: selectedCategory === category.key ? '#dc3545' : 'transparent' }}
            >
              <i className={`${category.icon} me-2`} />
              <span className="fw-bold">{category.name}</span>
              <Badge 
                bg={selectedCategory === category.key ? 'light' : 'secondary'}
                className="ms-auto"
                text={selectedCategory === category.key ? 'dark' : 'light'}
              >
                {getAssetsForCategory(category.key).length}
              </Badge>
            </button>
          ))}
        </div>
      </Col>
      <Col md={9}>
        <div className="d-flex justify-content-between align-items-center mb-3">
          <h6 className="text-danger mb-0">
            {categories.find(c => c.key === selectedCategory)?.name || 'Assets'}
          </h6>
          <div className="d-flex gap-2">
            <Button variant="outline-success" size="sm" onClick={handleSelectAll}>
              Select All
            </Button>
            <Button variant="outline-secondary" size="sm" onClick={handleSelectNoneCurrentCategory}>
              Select None (Category)
            </Button>
            <Button variant="outline-danger" size="sm" onClick={handleSelectNone}>
              Clear All Targets
            </Button>
            <Button variant="outline-info" size="sm" onClick={handleSelectScanned}>
              Select Scanned
            </Button>
            <Button variant="outline-warning" size="sm" onClick={handleSelectUnscanned}>
              Select Unscanned
            </Button>
          </div>
        </div>

        <InputGroup className="mb-3">
          <InputGroup.Text>
            <FaSearch />
          </InputGroup.Text>
          <Form.Control
            type="text"
            placeholder="Search assets..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            data-bs-theme="dark"
          />
        </InputGroup>

        {loadingAssets ? (
          <div className="text-center">
            <Spinner animation="border" variant="danger" />
            <div className="mt-2">Loading attack surface assets...</div>
          </div>
        ) : (
          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            <Table striped bordered hover variant="dark" size="sm" responsive>
              <thead>
                <tr>
                  <th width="40">
                    <Form.Check
                      type="checkbox"
                      checked={getFilteredAssets().length > 0 && 
                               getFilteredAssets().every(asset => selectedTargets.has(asset.id))}
                      onChange={(e) => {
                        if (e.target.checked) {
                          handleSelectAll();
                        } else {
                          handleSelectNoneCurrentCategory();
                        }
                      }}
                    />
                  </th>
                  <th>Asset</th>
                  <th>Type</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {getFilteredAssets().map(asset => (
                  <tr key={asset.id}>
                    <td>
                      <Form.Check
                        type="checkbox"
                        checked={selectedTargets.has(asset.id)}
                        onChange={() => handleTargetSelect(asset.id)}
                      />
                    </td>
                    <td>
                      <div style={{ wordBreak: 'break-all' }}>
                        {getAssetDisplayText(asset)}
                      </div>
                    </td>
                    <td>
                      <Badge bg={getAssetBadgeColor(asset)}>
                        {asset.asset_type.replace('_', ' ').toUpperCase()}
                      </Badge>
                    </td>
                    <td>
                      {scannedTargets.has(asset.id) ? (
                        <Badge bg="success">Scanned</Badge>
                      ) : (
                        <Badge bg="secondary">Unscanned</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            {getFilteredAssets().length === 0 && (
              <div className="text-center text-muted mt-3">
                No assets found for the selected category
              </div>
            )}
          </div>
        )}

        <div className="mt-3 text-info">
          <small>
            Selected: {selectedTargets.size} targets | 
            Category: {getAssetsForCategory(selectedCategory).length} assets | 
            Filtered: {getFilteredAssets().length} assets
          </small>
        </div>
      </Col>
    </Row>
  );

  const renderTemplateSelection = () => (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h6 className="text-danger mb-0">Nuclei Template Categories</h6>
        <div className="d-flex gap-2">
          <Button variant="outline-success" size="sm" onClick={handleSelectAllTemplates}>
            Select All
          </Button>
          <Button variant="outline-secondary" size="sm" onClick={handleSelectNoTemplates}>
            Select None
          </Button>
        </div>
      </div>

      <Row className="row-cols-1 row-cols-md-2 g-3 mb-4">
        {templateCategories.map(template => (
          <Col key={template.key}>
            <div 
              className={`card h-100 position-relative ${selectedTemplates.has(template.key) ? 'border-danger bg-danger bg-opacity-10' : 'border-secondary'}`}
              style={{ cursor: 'pointer' }}
              onClick={() => handleTemplateSelect(template.key)}
            >
              <div className="card-body p-2">
                <div className="d-flex align-items-stretch h-100">
                  <div className="d-flex align-items-center justify-content-center me-3" style={{ width: '60px', minWidth: '60px' }}>
                    <i className={`${template.icon} text-danger`} style={{ fontSize: '1.5rem' }}></i>
                  </div>
                  <div className="flex-grow-1 d-flex flex-column justify-content-center">
                    <h6 className="card-title mb-1">{template.name}</h6>
                    <p className="card-text text-muted small mb-0">
                      {template.description}
                    </p>
                  </div>
                </div>
                {template.key === 'custom' && (
                  <div className="position-absolute top-0 end-0 p-2 mr-2">
                    <Button 
                      variant="outline-danger" 
                      size="sm" 
                      onClick={handleUploadClick}
                      disabled={uploadingTemplates}
                      style={{ width: '50px', height: '100%', padding: '1px', marginRight: '1px' }}
                      className="d-flex flex-column justify-content-center align-items-center"
                    >
                      {uploadingTemplates ? (
                        <>
                          <Spinner animation="border" size="sm" className="mb-1 mt-1" />
                          <small>Uploading...</small>
                        </>
                      ) : (
                        <>
                          <FaUpload className="mb-1 mt-1" />
                          <small>Upload</small>
                        </>
                      )}
                    </Button>
                    <input
                      ref={fileInputRef}
                      type="file"
                      multiple
                      accept=".yaml,.yml"
                      onChange={handleFileUpload}
                      style={{ display: 'none' }}
                    />
                  </div>
                )}
              </div>
            </div>
          </Col>
        ))}
      </Row>

      <div className="d-flex justify-content-between align-items-center mb-3">
        <h6 className="text-danger mb-0">Template Severity Levels</h6>
        <div className="d-flex gap-2">
          <Button variant="outline-success" size="sm" onClick={handleSelectAllSeverities}>
            Select All
          </Button>
          <Button variant="outline-secondary" size="sm" onClick={handleSelectNoSeverities}>
            Select None
          </Button>
        </div>
      </div>

      <Row className="g-3 mb-4">
        {severityCategories.map(severity => (
          <Col key={severity.key} xs={12}>
            <div 
              className={`card h-100 position-relative ${selectedSeverities.has(severity.key) ? `border-${severity.color} bg-${severity.color} bg-opacity-10` : 'border-secondary'}`}
              style={{ cursor: 'pointer' }}
              onClick={() => handleSeveritySelect(severity.key)}
            >
              <div className="card-body p-3">
                <div className="d-flex align-items-center">
                  <div className="d-flex align-items-center justify-content-center me-3" style={{ width: '50px', minWidth: '50px' }}>
                    <i className={`${severity.icon} text-${severity.color}`} style={{ fontSize: '1.5rem' }}></i>
                  </div>
                  <div className="flex-grow-1">
                    <h6 className="card-title mb-1">{severity.name}</h6>
                    <p className="card-text text-muted small mb-0">
                      {severity.description}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </Col>
        ))}
      </Row>

      {uploadedTemplates.length > 0 && (
        <div className="mt-4">
          <h6 className="text-danger mb-3">Uploaded Custom Templates</h6>
          <div className="table-responsive">
            <Table striped bordered hover variant="dark" size="sm" responsive>
              <thead>
                <tr>
                  <th>Template Name</th>
                  <th>Size</th>
                  <th>Uploaded</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {uploadedTemplates.map(template => (
                  <tr key={template.id}>
                    <td>
                      <div style={{ wordBreak: 'break-all' }}>
                        {template.name}
                      </div>
                    </td>
                    <td>
                      <Badge bg="info">
                        {(template.size / 1024).toFixed(1)} KB
                      </Badge>
                    </td>
                    <td>
                      <small className="text-muted">
                        {new Date(template.uploaded_at).toLocaleDateString()}
                      </small>
                    </td>
                    <td>
                      <Button
                        variant="outline-danger"
                        size="sm"
                        onClick={() => handleRemoveTemplate(template.id)}
                      >
                        <FaTrash />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        </div>
      )}

      <div className="mt-3 text-info">
        <small>
          Selected: {selectedTemplates.size} template categories | 
          Severities: {selectedSeverities.size} levels | 
          Custom templates: {uploadedTemplates.length} uploaded
        </small>
      </div>
    </div>
  );

  return (
    <Modal 
      show={show} 
      onHide={handleCloseModal} 
      size="xl" 
      data-bs-theme="dark"
      className="modal-90w"
    >
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">
          <i className="bi bi-shield-shaded me-2" />
          Configure Nuclei Security Scan
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        <div className="mb-4">
          <div className="text-white">
            <div className="d-flex align-items-center">
              <i className="bi bi-shield-shaded me-2" />
              <div>
                <strong>Nuclei Security Scan:</strong> Configure targets and templates for comprehensive security scanning.
                Selected targets: <strong>{selectedTargets.size}</strong> | 
                Selected templates: <strong>{selectedTemplates.size}</strong> |
                Selected severities: <strong>{selectedSeverities.size}</strong>
              </div>
            </div>
          </div>
        </div>

        <Tabs
          activeKey={activeTab}
          onSelect={(k) => setActiveTab(k)}
          className="mb-3"
          variant="pills"
        >
          <Tab eventKey="targets" title="Select Targets">
            {renderTargetSelection()}
          </Tab>
          <Tab eventKey="templates" title="Select Templates">
            {renderTemplateSelection()}
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleCloseModal}>
          Cancel
        </Button>
        <Button 
          variant="danger" 
          onClick={handleSaveConfig}
          disabled={saving}
        >
          {saving ? (
            <>
              <Spinner animation="border" size="sm" className="me-2" />
              Saving...
            </>
          ) : (
            'Save Configuration'
          )}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default NucleiConfigModal; 