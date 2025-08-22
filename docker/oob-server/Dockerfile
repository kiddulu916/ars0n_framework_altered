FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    dnsutils \
    netcat-openbsd \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    dnslib \
    scapy \
    asyncio-mqtt \
    requests

# Create OOB interaction server
RUN cat > /app/oob_server.py << 'EOF'
#!/usr/bin/env python3
import asyncio
import json
import time
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
import uvicorn
import socket
import threading
from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import DNSServer
import logging

app = FastAPI()

# Global storage for interactions
interactions = []

class OOBInteractionCollector:
    def __init__(self, domain="oob.ars0n.local", http_port=8888, dns_port=5353):
        self.domain = domain
        self.http_port = http_port
        self.dns_port = dns_port
        self.logger = logging.getLogger(__name__)
        
    def log_interaction(self, interaction_type, source_ip, data, protocol="HTTP"):
        interaction = {
            "id": f"{int(time.time())}-{len(interactions)}",
            "timestamp": datetime.utcnow().isoformat(),
            "type": interaction_type,
            "source_ip": source_ip,
            "protocol": protocol,
            "data": data,
            "domain": self.domain
        }
        interactions.append(interaction)
        self.logger.info(f"OOB Interaction: {interaction}")
        return interaction

collector = OOBInteractionCollector()

# HTTP endpoints for OOB interactions
@app.get("/")
async def root_handler(request: Request):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    interaction = collector.log_interaction(
        "http_request",
        client_ip,
        {
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "user_agent": user_agent
        },
        "HTTP"
    )
    
    return PlainTextResponse("OOB interaction received", status_code=200)

@app.get("/{path:path}")
async def catch_all_handler(request: Request, path: str):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    interaction = collector.log_interaction(
        "http_request",
        client_ip,
        {
            "method": request.method,
            "path": path,
            "url": str(request.url),
            "headers": dict(request.headers),
            "user_agent": user_agent,
            "query_params": dict(request.query_params)
        },
        "HTTP"
    )
    
    return PlainTextResponse(f"OOB interaction for path: {path}", status_code=200)

@app.post("/{path:path}")
async def post_handler(request: Request, path: str):
    client_ip = request.client.host
    body = await request.body()
    
    interaction = collector.log_interaction(
        "http_post",
        client_ip,
        {
            "method": request.method,
            "path": path,
            "url": str(request.url),
            "headers": dict(request.headers),
            "body": body.decode('utf-8', errors='ignore')[:1000]  # Limit body size
        },
        "HTTP"
    )
    
    return PlainTextResponse("POST received", status_code=200)

@app.get("/api/interactions")
async def get_interactions():
    """Retrieve all collected OOB interactions"""
    return {"interactions": interactions, "count": len(interactions)}

@app.delete("/api/interactions")
async def clear_interactions():
    """Clear all collected interactions"""
    global interactions
    interactions = []
    return {"message": "Interactions cleared", "count": 0}

# DNS Server for OOB interactions
class OOBDNSResolver:
    def __init__(self, collector):
        self.collector = collector
        
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        
        # Log DNS query
        client_ip = handler.client_address[0] if handler.client_address else "unknown"
        self.collector.log_interaction(
            "dns_query",
            client_ip,
            {
                "query": str(qname),
                "type": QTYPE[qtype],
                "question": str(request.q)
            },
            "DNS"
        )
        
        # Respond with A record pointing to ourselves
        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1")))
        
        return reply

def start_dns_server():
    """Start DNS server in a separate thread"""
    resolver = OOBDNSResolver(collector)
    dns_server = DNSServer(resolver, port=collector.dns_port, address="0.0.0.0")
    dns_server.start_thread()
    print(f"DNS server started on port {collector.dns_port}")

if __name__ == "__main__":
    # Start DNS server
    start_dns_server()
    
    # Start HTTP server
    print(f"Starting OOB interaction server on port {collector.http_port}")
    print(f"Domain: {collector.domain}")
    print(f"Access interactions: http://localhost:{collector.http_port}/api/interactions")
    
    uvicorn.run(app, host="0.0.0.0", port=collector.http_port)
EOF

# Create startup script
RUN cat > /app/start.sh << 'EOF'
#!/bin/bash
echo "Starting OOB Interaction Server..."
echo "HTTP Port: 8888"
echo "DNS Port: 5353"
python3 /app/oob_server.py
EOF

RUN chmod +x /app/start.sh

EXPOSE 8888 5353/udp

CMD ["/app/start.sh"]
