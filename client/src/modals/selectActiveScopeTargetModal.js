import { Modal, ListGroup, Button } from 'react-bootstrap';

function SelectActiveScopeTargetModal({
  showActiveModal,
  handleActiveModalClose,
  scopeTargets,
  activeTarget,
  handleActiveSelect,
  handleDelete,
}) {
  const sortedTargets = [...scopeTargets].sort((a, b) => 
    a.scope_target.localeCompare(b.scope_target)
  );

  return (
    <Modal data-bs-theme="dark" show={showActiveModal} onHide={handleActiveModalClose} centered>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Select Active Scope Target</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <ListGroup>
          {sortedTargets.map((target) => (
            <ListGroup.Item
              key={target.id}
              action
              onClick={() => handleActiveSelect(target)}
              className={activeTarget?.id === target.id ? 'bg-danger text-white' : ''}
            >
              <div className="d-flex align-items-center">
                <span>{target.scope_target}</span>
              </div>
            </ListGroup.Item>
          ))}
        </ListGroup>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="danger" onClick={handleDelete} className="me-auto">
          Delete
        </Button>
        <Button variant="danger" onClick={handleActiveModalClose}>
          Set Active
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

export default SelectActiveScopeTargetModal;
