export const initiateURLWorkflow = async (scopeTargetId, options = {}) => {
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  
  const requestBody = {
    selected_urls: options.selectedUrls,
    max_urls: options.maxUrls || 10
  };

  const response = await fetch(
    `${serverProtocol}://${serverIP}:${serverPort}/api/url-workflow/initiate/${scopeTargetId}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody)
    }
  );

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorData}`);
  }

  return await response.json();
};
