export const fetchFindings = async (options = {}) => {
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  
  const params = new URLSearchParams({
    limit: (options.limit || 20).toString(),
    offset: (options.offset || 0).toString()
  });

  if (options.scopeTargetId) params.append('scope_target_id', options.scopeTargetId);
  if (options.urlWorkflowSessionId) params.append('url_workflow_session_id', options.urlWorkflowSessionId);
  if (options.category) params.append('category', options.category);
  if (options.search) params.append('search', options.search);
  
  if (options.severity && Array.isArray(options.severity)) {
    options.severity.forEach(s => params.append('severity', s));
  }
  
  if (options.status && Array.isArray(options.status)) {
    options.status.forEach(s => params.append('status', s));
  }

  const response = await fetch(
    `${serverProtocol}://${serverIP}:${serverPort}/api/findings?${params}`
  );

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorData}`);
  }

  return await response.json();
};

export const createFinding = async (findingData) => {
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  
  const response = await fetch(
    `${serverProtocol}://${serverIP}:${serverPort}/api/findings`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(findingData)
    }
  );

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorData}`);
  }

  return await response.json();
};

export const updateFindingStatus = async (findingId, status, verifiedBy = 'User', notes = '') => {
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  
  const response = await fetch(
    `${serverProtocol}://${serverIP}:${serverPort}/api/findings/${findingId}/status`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status,
        verified_by: verifiedBy,
        notes
      })
    }
  );

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorData}`);
  }

  return await response.json();
};

export const exportFindings = async (scopeTargetId, urlWorkflowSessionId = null, format = 'json') => {
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  
  const params = new URLSearchParams({
    format
  });

  if (scopeTargetId) params.append('scope_target_id', scopeTargetId);
  if (urlWorkflowSessionId) params.append('url_workflow_session_id', urlWorkflowSessionId);

  const response = await fetch(
    `${serverProtocol}://${serverIP}:${serverPort}/api/findings/export?${params}`
  );

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorData}`);
  }

  return response; // Return response for blob handling
};
