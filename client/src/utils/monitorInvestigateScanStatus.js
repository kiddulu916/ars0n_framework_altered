const monitorInvestigateScanStatus = (
  activeTarget,
  setInvestigateScans,
  setMostRecentInvestigateScan,
  setIsInvestigateScanning,
  setMostRecentInvestigateScanStatus
) => {
  if (!activeTarget || !activeTarget.id) {
    console.warn('No active target or target ID available for investigate monitoring');
    return;
  }

  const targetId = activeTarget.id;

  const interval = setInterval(async () => {
    try {
      const response = await fetch(
        `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${targetId}/scans/investigate`
      );
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to fetch investigate scans: ${response.status} ${response.statusText} - ${errorText}`);
      }
      
      const scans = await response.json();
      setInvestigateScans(scans || []);
      
      if (scans && Array.isArray(scans) && scans.length > 0) {
        const mostRecent = scans[0];
        setMostRecentInvestigateScan(mostRecent);
        setMostRecentInvestigateScanStatus(mostRecent.status);
        
        if (mostRecent.status === 'success' || mostRecent.status === 'error') {
          setIsInvestigateScanning(false);
          clearInterval(interval);
        }
      }
    } catch (error) {
      console.error('Error monitoring investigate scan status:', error);
      console.error(`Failed URL: ${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${targetId}/scans/investigate`);
      setIsInvestigateScanning(false);
      clearInterval(interval);
    }
  }, 2000);

  return () => clearInterval(interval);
};

export default monitorInvestigateScanStatus; 