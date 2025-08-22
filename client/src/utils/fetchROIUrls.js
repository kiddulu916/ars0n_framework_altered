export const fetchROIUrls = async (scopeTargetId, maxUrls = 10) => {
  const serverProtocol = process.env.REACT_APP_SERVER_PROTOCOL || 'http';
  const serverIP = process.env.REACT_APP_SERVER_IP || '127.0.0.1';
  const serverPort = process.env.REACT_APP_SERVER_PORT || '8443';
  
  const params = new URLSearchParams({
    max_urls: maxUrls.toString()
  });

  const response = await fetch(
    `${serverProtocol}://${serverIP}:${serverPort}/api/url-workflow/roi-urls/${scopeTargetId}?${params}`
  );

  if (!response.ok) {
    const errorData = await response.text();
    throw new Error(`HTTP ${response.status}: ${response.statusText} - ${errorData}`);
  }

  return await response.json();
};
