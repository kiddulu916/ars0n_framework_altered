import { Modal, Table } from 'react-bootstrap';

export const HttpxResultsModal = ({ showHttpxResultsModal, handleCloseHttpxResultsModal, httpxResults }) => {
  const parseResults = (results) => {
    if (!results) {
      return [];
    }

    // Handle the new response format where result is nested in a String property
    const scanResults = results.result?.String;
    if (!scanResults) {
      return [];
    }

    try {
      const parsed = scanResults
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
          try {
            return JSON.parse(line);
          } catch (e) {
            console.error("[ERROR] Failed to parse line:", line, e);
            return null;
          }
        })
        .filter(result => result !== null);
      
      return parsed;
    } catch (error) {
      console.error("[ERROR] Error parsing httpx results:", error);
      return [];
    }
  };

  const getStatusStyle = (status) => {
    const styles = {
      backgroundColor: '#FFFFFF', // Default white
      color: '#000000',          // Default black text
      padding: '0.2em 0.5em',    // Smaller padding
      fontSize: '0.85em',        // Slightly smaller font
      fontWeight: '700',
      lineHeight: '1',
      textAlign: 'center',
      whiteSpace: 'nowrap',
      verticalAlign: 'baseline',
      borderRadius: '0.25rem',   // Slightly smaller border radius
      display: 'inline-block'
    };

    switch (status) {
      case 200:
        styles.backgroundColor = '#32CD32'; // Lime Green
        styles.color = '#000000';
        break;
      case 301:
        styles.backgroundColor = '#87CEEB'; // Sky Blue
        styles.color = '#000000';
        break;
      case 302:
        styles.backgroundColor = '#1E90FF'; // Dodger Blue
        styles.color = '#000000';
        break;
      case 304:
        styles.backgroundColor = '#E6E6FA'; // Light Purple
        styles.color = '#000000';
        break;
      case 400:
        styles.backgroundColor = '#FF0000'; // Bright Red
        styles.color = '#FFFFFF';
        break;
      case 401:
        styles.backgroundColor = '#FF7F50'; // Coral
        styles.color = '#FFFFFF';
        break;
      case 403:
        styles.backgroundColor = '#8B0000'; // Dark Red
        styles.color = '#FFFFFF';
        break;
      case 404:
        styles.backgroundColor = '#FFDAB9'; // Peach
        styles.color = '#000000';
        break;
      case 418:
        styles.backgroundColor = '#FF69B4'; // Hot Pink
        styles.color = '#FFFFFF';
        break;
      case 500:
        styles.backgroundColor = '#DAA520'; // Dark Yellow
        styles.color = '#FFFFFF';
        break;
      case 503:
        styles.backgroundColor = '#FF4500'; // Pumpkin Orange
        styles.color = '#FFFFFF';
        break;
      default:
        styles.backgroundColor = '#FFFFFF'; // White
        styles.color = '#000000';
        break;
    }

    return styles;
  };

  const parsedResults = parseResults(httpxResults);

  return (
    <Modal data-bs-theme="dark" show={showHttpxResultsModal} onHide={handleCloseHttpxResultsModal} fullscreen>
      <Modal.Header closeButton>
        <Modal.Title className="text-danger">Live Web Servers</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Table striped bordered hover responsive>
          <thead>
            <tr>
              <th>URL</th>
              <th>Status Code</th>
              <th>Title</th>
              <th>Web Server</th>
              <th>Technologies</th>
              <th>Content Length</th>
            </tr>
          </thead>
          <tbody>
            {parsedResults.map((result, index) => (
              <tr key={index}>
                <td>
                  <a 
                    href={result.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-danger text-decoration-none"
                  >
                    {result.url}
                  </a>
                </td>
                <td>
                  <span style={getStatusStyle(result.status_code)}>
                    {result.status_code}
                  </span>
                </td>
                <td>{result.title || '-'}</td>
                <td>{result.webserver || '-'}</td>
                <td>
                  {result.tech ? (
                    <div className="d-flex flex-wrap gap-1">
                      {result.tech.map((tech, i) => (
                        <span 
                          key={i} 
                          style={{
                            backgroundColor: '#6c757d',
                            color: '#fff',
                            padding: '0.2em 0.5em',
                            fontWeight: '700',
                            lineHeight: '1',
                            textAlign: 'center',
                            whiteSpace: 'nowrap',
                            verticalAlign: 'baseline',
                            borderRadius: '0.25rem',
                            display: 'inline-block'
                          }}
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  ) : '-'}
                </td>
                <td>{result.content_length || '-'}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Modal.Body>
    </Modal>
  );
}; 