import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Card, Table, Toast, Button, Row, Col } from 'react-bootstrap';
import URLWorkflowModal from '../modals/URLWorkflowModal';
import FindingsDashboard from './FindingsDashboard';

const ScopeTargetDetails = () => {
    const [scopeTarget, setScopeTarget] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isSubfinderScanning, setIsSubfinderScanning] = useState(false);
    const [showToast, setShowToast] = useState(false);
    const [toastMessage, setToastMessage] = useState('');
    const [toastType, setToastType] = useState('success');
    const [showURLWorkflowModal, setShowURLWorkflowModal] = useState(false);
    const [activeTab, setActiveTab] = useState('overview');
    const { id } = useParams();

    useEffect(() => {
        fetchScopeTarget();
    }, []);

    useEffect(() => {
        if (scopeTarget) {
            fetchScopeTarget();
        }
    }, [scopeTarget]);

    const fetchScopeTarget = async () => {
        try {
            const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${id}`);
            if (!response.ok) throw new Error('Failed to fetch scope target');
            const data = await response.json();
            setScopeTarget(data);
            setIsLoading(false);
        } catch (error) {
            console.error('Error fetching scope target:', error);
            setIsLoading(false);
        }
    };

    const toast = (message, type = 'success') => {
        setToastMessage(message);
        setToastType(type);
        setShowToast(true);
        setTimeout(() => setShowToast(false), 3000);
    };

    const renderScanResults = (scans, toolName) => {
        if (!scans || scans.length === 0) return <p>No {toolName} scans found</p>;

        return (
            <div>
                <h5>{toolName} Scan Results</h5>
                <Table striped bordered hover>
                    <thead>
                        <tr>
                            <th>Scan ID</th>
                            <th>Status</th>
                            <th>Created At</th>
                        </tr>
                    </thead>
                    <tbody>
                        {scans.map(scan => (
                            <tr key={scan.id}>
                                <td>{scan.scan_id}</td>
                                <td>{scan.status}</td>
                                <td>{new Date(scan.created_at).toLocaleString()}</td>
                            </tr>
                        ))}
                    </tbody>
                </Table>
            </div>
        );
    };

    if (isLoading) {
        return <div>Loading...</div>;
    }

    if (!scopeTarget) {
        return <div>No active scope target found</div>;
    }

    return (
        <div>
            <div className="d-flex justify-content-between align-items-center mb-4">
                <h3>Scope Target Details</h3>
                <div className="d-flex gap-2">
                    <Button 
                        variant="primary" 
                        onClick={() => setShowURLWorkflowModal(true)}
                        disabled={scopeTarget?.type === 'URL'}
                    >
                        URL Workflow
                    </Button>
                </div>
            </div>

            <Card className="mb-4">
                <Card.Body>
                    <Row>
                        <Col md={8}>
                            <Card.Title>{scopeTarget.scope_target}</Card.Title>
                            <Card.Text>
                                <strong>Type:</strong> {scopeTarget.type}<br />
                                <strong>Mode:</strong> {scopeTarget.mode}<br />
                                <strong>Created:</strong> {new Date(scopeTarget.created_at).toLocaleString()}
                            </Card.Text>
                        </Col>
                        <Col md={4}>
                            <div className="d-flex flex-column gap-2">
                                <Button 
                                    variant={activeTab === 'overview' ? 'primary' : 'outline-primary'}
                                    size="sm"
                                    onClick={() => setActiveTab('overview')}
                                >
                                    Overview
                                </Button>
                                <Button 
                                    variant={activeTab === 'workflows' ? 'primary' : 'outline-primary'}
                                    size="sm"
                                    onClick={() => setActiveTab('workflows')}
                                >
                                    Workflows
                                </Button>
                                <Button 
                                    variant={activeTab === 'findings' ? 'primary' : 'outline-primary'}
                                    size="sm"
                                    onClick={() => setActiveTab('findings')}
                                >
                                    Security Findings
                                </Button>
                            </div>
                        </Col>
                    </Row>
                </Card.Body>
            </Card>

            {/* Tab Content */}
            {activeTab === 'overview' && (
                <Card>
                    <Card.Header>
                        <h5>Scope Target Overview</h5>
                    </Card.Header>
                    <Card.Body>
                        <p>This is the overview of your scope target. Here you can see basic information and quick actions.</p>
                        {scopeTarget.type !== 'URL' && (
                            <div className="alert alert-info">
                                <strong>Ready for URL Workflow:</strong> Once Company and Wildcard workflows are completed, 
                                you can run the automated URL workflow to discover and test web application vulnerabilities.
                            </div>
                        )}
                    </Card.Body>
                </Card>
            )}

            {activeTab === 'workflows' && (
                <Card>
                    <Card.Header>
                        <h5>Workflow Status</h5>
                    </Card.Header>
                    <Card.Body>
                        <div className="row">
                            <div className="col-md-4">
                                <Card className="mb-3">
                                    <Card.Body>
                                        <Card.Title>Company Workflow</Card.Title>
                                        <Card.Text>Asset discovery and enumeration</Card.Text>
                                        <Button variant="outline-primary" size="sm">View Results</Button>
                                    </Card.Body>
                                </Card>
                            </div>
                            <div className="col-md-4">
                                <Card className="mb-3">
                                    <Card.Body>
                                        <Card.Title>Wildcard Workflow</Card.Title>
                                        <Card.Text>Subdomain enumeration and validation</Card.Text>
                                        <Button variant="outline-primary" size="sm">View Results</Button>
                                    </Card.Body>
                                </Card>
                            </div>
                            <div className="col-md-4">
                                <Card className="mb-3">
                                    <Card.Body>
                                        <Card.Title>URL Workflow</Card.Title>
                                        <Card.Text>Automated vulnerability testing</Card.Text>
                                        <Button 
                                            variant="primary" 
                                            size="sm"
                                            onClick={() => setShowURLWorkflowModal(true)}
                                            disabled={scopeTarget?.type === 'URL'}
                                        >
                                            Start Workflow
                                        </Button>
                                    </Card.Body>
                                </Card>
                            </div>
                        </div>
                    </Card.Body>
                </Card>
            )}

            {activeTab === 'findings' && (
                <FindingsDashboard scopeTargetId={id} />
            )}

            {/* URL Workflow Modal */}
            <URLWorkflowModal 
                show={showURLWorkflowModal}
                handleClose={() => setShowURLWorkflowModal(false)}
                scopeTargetId={id}
                targetType={scopeTarget?.type}
            />

            <Toast
                show={showToast}
                onClose={() => setShowToast(false)}
                style={{
                    position: 'fixed',
                    bottom: 20,
                    right: 20,
                    minWidth: '250px'
                }}
                className={`bg-${toastType}`}
            >
                <Toast.Header>
                    <strong className="me-auto">Notification</strong>
                </Toast.Header>
                <Toast.Body>{toastMessage}</Toast.Body>
            </Toast>
        </div>
    );
};

export default ScopeTargetDetails; 