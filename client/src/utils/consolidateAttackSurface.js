const consolidateAttackSurface = async (activeTarget) => {
    if (!activeTarget || !activeTarget.id) {
        console.error('No active target available');
        return null;
    }

    try {
        const response = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/consolidate-attack-surface/${activeTarget.id}`,
            {
                method: 'POST',
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
        console.error('Error consolidating attack surface:', error);
        return null;
    }
};

export default consolidateAttackSurface; 