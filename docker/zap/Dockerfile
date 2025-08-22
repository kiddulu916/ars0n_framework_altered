FROM ghcr.io/zaproxy/zaproxy:stable

# Switch to root to install additional packages
USER root

# Install additional tools
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create scripts directory
RUN mkdir -p /zap/scripts

# Create ZAP automation script
RUN cat > /zap/scripts/scan.py << 'EOF'
#!/usr/bin/env python3
import sys
import json
import time
import requests
from zapv2 import ZAPv2

def run_zap_scan(target_url, scan_type='baseline'):
    # Start ZAP in daemon mode
    zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
    
    # Wait for ZAP to start
    time.sleep(2)
    
    # Spider the target
    print(f"Starting spider scan on {target_url}")
    scan_id = zap.spider.scan(target_url)
    
    # Wait for spider to complete
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(1)
    
    # Active scan
    if scan_type == 'active':
        print(f"Starting active scan on {target_url}")
        scan_id = zap.ascan.scan(target_url)
        
        while int(zap.ascan.status(scan_id)) < 100:
            print(f"Active scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(2)
    
    # Get alerts
    alerts = zap.core.alerts()
    
    # Generate report
    report = {
        'target': target_url,
        'scan_type': scan_type,
        'alerts': alerts,
        'summary': {
            'high': len([a for a in alerts if a['risk'] == 'High']),
            'medium': len([a for a in alerts if a['risk'] == 'Medium']),
            'low': len([a for a in alerts if a['risk'] == 'Low']),
            'informational': len([a for a in alerts if a['risk'] == 'Informational'])
        }
    }
    
    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: scan.py <target_url> [scan_type]")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else 'baseline'
    
    try:
        result = run_zap_scan(target_url, scan_type)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)
EOF

# Install Python ZAP API
RUN pip3 install python-owasp-zap-v2.4

# Make scripts executable
RUN chmod +x /zap/scripts/scan.py

# Switch back to zap user
USER zap

# Create custom ZAP policies directory
RUN mkdir -p /zap/policies

WORKDIR /zap

ENTRYPOINT ["python3", "/zap/scripts/scan.py"]
