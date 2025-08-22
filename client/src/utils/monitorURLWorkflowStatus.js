export const monitorURLWorkflowStatus = async (sessionId) => {
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  
  const response = await fetch(
    `${serverProtocol}://${serverIP}:${serverPort}/api/url-workflow/status/${sessionId}`
  );

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorData}`);
  }

  return await response.json();
};
