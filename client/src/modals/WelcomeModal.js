import { Modal, Button, Card, Row, Col } from 'react-bootstrap';
import { FaPlus, FaFileImport, FaRocket } from 'react-icons/fa';
import 'bootstrap-icons/font/bootstrap-icons.css';

function WelcomeModal({ show, handleClose, onAddScopeTarget, onImportData }) {
  return (
    <Modal
      show={show}
      onHide={handleClose}
      backdrop="static"
      keyboard={false}
      animation={true}
      size="lg"
      centered
      data-bs-theme="dark"
    >
      <Modal.Header className="flex-column align-items-center border-0 pb-0">
        <img
          src="/images/logo.avif"
          alt="Logo"
          style={{ width: '120px', height: '120px', marginBottom: '20px' }}
        />
        <Modal.Title className="w-100 text-center text-danger mb-3">
          Welcome to Ars0n Framework v2 <span style={{ fontSize: '0.8rem' }} className="text-muted">beta</span>
        </Modal.Title>
      </Modal.Header>
      
      <Modal.Body className="px-4 pb-4">
        <div className="text-center mb-4">
          <h5 className="text-white mb-3">
            <FaRocket className="me-2 text-danger" />
            Ready to Get Started?
          </h5>
          <p className="text-white-50 mb-4">
            No scope targets are currently configured. To begin your reconnaissance and security testing, 
            you can either create a new scope target or import existing scan data from a previous session.
          </p>
        </div>

        <Row className="g-4">
          <Col md={6}>
            <Card 
              className="h-100 border-2 border-danger hover-card"
              onClick={onAddScopeTarget}
              style={{ 
                cursor: 'pointer',
                transition: 'all 0.3s ease-in-out'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-5px)';
                e.currentTarget.style.boxShadow = '0 8px 25px rgba(220, 53, 69, 0.3)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <Card.Body className="text-center p-4">
                <div className="mb-3">
                  <FaPlus size={48} className="text-danger" />
                </div>
                <h5 className="text-white mb-3">Add Scope Target</h5>
                <p className="text-white-50 mb-3 small">
                  Create a new scope target to begin reconnaissance. Choose from Company, 
                  Wildcard domain, or specific URL targets.
                </p>
                <div className="d-flex justify-content-center flex-wrap gap-2 mb-3">
                  <img src="/images/Company.png" alt="Company" style={{ width: '30px', height: '30px' }} />
                  <img src="/images/Wildcard.png" alt="Wildcard" style={{ width: '30px', height: '30px' }} />
                  <img src="/images/URL.png" alt="URL" style={{ width: '30px', height: '30px' }} />
                </div>
                <Button 
                  variant="danger" 
                  size="sm"
                  className="w-100"
                  onClick={(e) => {
                    e.stopPropagation();
                    onAddScopeTarget();
                  }}
                >
                  <FaPlus className="me-2" />
                  Create New Target
                </Button>
              </Card.Body>
            </Card>
          </Col>

          <Col md={6}>
            <Card 
              className="h-100 border-2 border-danger hover-card"
              onClick={onImportData}
              style={{ 
                cursor: 'pointer',
                transition: 'all 0.3s ease-in-out'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-5px)';
                e.currentTarget.style.boxShadow = '0 8px 25px rgba(220, 53, 69, 0.3)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <Card.Body className="text-center p-4">
                <div className="mb-3">
                  <FaFileImport size={48} className="text-danger" />
                </div>
                <h5 className="text-white mb-3">Import Scan Data</h5>
                <p className="text-white-50 mb-3 small">
                  Restore a previous session by importing a .rs0n database file. 
                  This will load all scope targets and associated scan results.
                </p>
                <div className="mb-3">
                  <div className="d-inline-flex align-items-center bg-dark rounded px-3 py-2">
                    <FaFileImport className="text-white me-2" size={20} />
                    <span className="text-white-50 small">.rs0n file format</span>
                  </div>
                </div>
                <Button 
                  variant="danger" 
                  size="sm"
                  className="w-100"
                  onClick={(e) => {
                    e.stopPropagation();
                    onImportData();
                  }}
                >
                  <FaFileImport className="me-2" />
                  Import Database
                </Button>
              </Card.Body>
            </Card>
          </Col>
        </Row>


      </Modal.Body>
    </Modal>
  );
}

export default WelcomeModal; 