const fetchAttackSurfaceAssets = async (activeTarget) => {
  if (!activeTarget || !activeTarget.id) {
    throw new Error('Active target is required');
  }

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/attack-surface-assets/${activeTarget.id}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching attack surface assets:', error);
    throw error;
  }
};

export default fetchAttackSurfaceAssets; 