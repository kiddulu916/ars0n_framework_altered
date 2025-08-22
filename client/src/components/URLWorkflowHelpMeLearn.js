import { useState } from 'react';
import { Card, Collapse, Button, Badge, Alert } from 'react-bootstrap';

function URLWorkflowHelpMeLearn({ level = 'beginner' }) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [currentLevel, setCurrentLevel] = useState(level);

  const content = {
    beginner: {
      title: "What is the URL Workflow?",
      content: `
        The URL Workflow is an automated vulnerability testing system that takes the highest-value web applications 
        discovered during Company and Wildcard workflows and performs comprehensive security testing.

        Think of it as your personal security tester that:
        • Selects the most important URLs based on ROI (Return on Investment)
        • Maps the attack surface of web applications
        • Runs automated vulnerability scans
        • Tests for common security issues like XSS, SQL injection, and more
        • Collects evidence and generates reproduction instructions

        This workflow transforms manual security testing into an automated, systematic process.
      `,
      nextLevel: 'intermediate'
    },
    intermediate: {
      title: "How Does the URL Workflow Work?",
      content: `
        The URL Workflow operates in four distinct phases:

        **Phase 1: Attack Surface Mapping**
        • Web crawling to discover all endpoints
        • Directory brute-forcing to find hidden paths
        • JavaScript analysis to extract API endpoints
        • HTTP method enumeration

        **Phase 2: DAST (Dynamic Application Security Testing)**
        • Nuclei template scanning for known vulnerabilities
        • Custom vulnerability tests
        • Browser-based validation for complex issues

        **Phase 3: Targeted Vulnerability Testing**
        • SQL injection testing
        • Cross-site scripting (XSS) detection
        • IDOR (Insecure Direct Object Reference) testing
        • Server-side request forgery (SSRF) detection
        • Authentication bypass attempts

        **Phase 4: Evidence Collection**
        • Screenshot capture for visual proof
        • HAR file generation for network traffic
        • DOM snapshots for client-side evidence
        • Automated reproduction script generation

        Each phase builds upon the previous one to create a comprehensive security assessment.
      `,
      nextLevel: 'advanced'
    },
    advanced: {
      title: "Advanced URL Workflow Concepts",
      content: `
        **ROI Algorithm and URL Selection**
        The workflow uses a sophisticated ROI algorithm to prioritize URLs based on:
        • Technology stack complexity (higher score for dynamic applications)
        • Input parameters and forms (more attack vectors = higher priority)
        • Authentication requirements (protected resources are higher value)
        • Response characteristics (larger responses may indicate functionality)

        **Deduplication and Finding Management**
        • Uses SHA256 key hashing for intelligent deduplication
        • Groups similar findings across different URLs
        • Tracks findings across multiple testing contexts
        • Maintains finding lifecycle from discovery to resolution

        **Two-Stage Detection System**
        • Stage 1: Signal Detection - Fast identification of potential issues
        • Stage 2: Browser Validation - Confirms vulnerabilities in real browser environment
        • Reduces false positives while maintaining comprehensive coverage

        **Multi-Identity Testing**
        • Tests as unauthenticated user
        • Tests with low-privilege accounts
        • Tests for privilege escalation opportunities
        • Tests for cross-tenant data access

        **Out-of-Band (OOB) Interaction**
        • Detects blind vulnerabilities (SSRF, XXE, etc.)
        • Uses dedicated DNS and HTTP servers for interaction callbacks
        • Correlates OOB events with specific test payloads
        • Provides proof of exploitation for blind vulnerabilities

        **Kill Chain Analysis**
        • Identifies vulnerability chains for complex attacks
        • Maps attack paths from initial access to impact
        • Prioritizes findings based on exploitability
        • Generates comprehensive attack scenarios
      `,
      nextLevel: null
    }
  };

  const currentContent = content[currentLevel];

  const handleLevelChange = () => {
    if (currentContent.nextLevel) {
      setCurrentLevel(currentContent.nextLevel);
    }
  };

  const resetToBeginning = () => {
    setCurrentLevel('beginner');
  };

  return (
    <Card className="mb-3 border-primary">
      <Card.Header
        style={{ cursor: 'pointer' }}
        onClick={() => setIsExpanded(!isExpanded)}
        className="bg-light"
      >
        <div className="d-flex justify-content-between align-items-center">
          <div>
            <strong>🎓 Help Me Learn: URL Workflow</strong>
            <Badge bg="info" className="ms-2">{currentLevel}</Badge>
          </div>
          <i className={`bi bi-chevron-${isExpanded ? 'up' : 'down'}`}></i>
        </div>
      </Card.Header>
      
      <Collapse in={isExpanded}>
        <Card.Body>
          <h6>{currentContent.title}</h6>
          
          <div style={{ whiteSpace: 'pre-line', lineHeight: '1.6' }}>
            {currentContent.content}
          </div>
          
          {currentLevel === 'beginner' && (
            <Alert variant="info" className="mt-3">
              <strong>💡 Quick Start:</strong> The URL Workflow requires Company and Wildcard workflows 
              to be completed first. These workflows discover the web applications that the URL Workflow will test.
            </Alert>
          )}
          
          {currentLevel === 'intermediate' && (
            <Alert variant="warning" className="mt-3">
              <strong>⚠️ Important:</strong> Always ensure you have proper authorization before running 
              vulnerability tests. The URL Workflow should only be used on applications you own or have 
              explicit permission to test.
            </Alert>
          )}
          
          {currentLevel === 'advanced' && (
            <Alert variant="success" className="mt-3">
              <strong>🚀 Pro Tip:</strong> Use the findings dashboard to track your vulnerability management 
              process. Export findings to integrate with your security tools and create comprehensive reports.
            </Alert>
          )}
          
          <div className="mt-3 d-flex gap-2">
            {currentContent.nextLevel && (
              <Button
                variant="outline-primary"
                size="sm"
                onClick={handleLevelChange}
              >
                {currentContent.nextLevel === 'intermediate' && 'Show More Details'}
                {currentContent.nextLevel === 'advanced' && 'Show Advanced Info'}
              </Button>
            )}
            
            {currentLevel !== 'beginner' && (
              <Button
                variant="outline-secondary"
                size="sm"
                onClick={resetToBeginning}
              >
                Back to Basics
              </Button>
            )}
          </div>
          
          <hr />
          
          <div className="mt-3">
            <h6>Key Concepts to Remember:</h6>
            <ul style={{ fontSize: '0.9em' }}>
              {currentLevel === 'beginner' && (
                <>
                  <li><strong>ROI-driven:</strong> Tests the most valuable targets first</li>
                  <li><strong>Automated:</strong> Runs without manual intervention</li>
                  <li><strong>Educational:</strong> Provides learning opportunities at each step</li>
                </>
              )}
              {currentLevel === 'intermediate' && (
                <>
                  <li><strong>Four Phases:</strong> Surface mapping → DAST → Targeted testing → Evidence</li>
                  <li><strong>Progressive:</strong> Each phase builds on the previous one</li>
                  <li><strong>Comprehensive:</strong> Tests multiple vulnerability categories</li>
                </>
              )}
              {currentLevel === 'advanced' && (
                <>
                  <li><strong>Intelligent:</strong> Uses machine learning for prioritization</li>
                  <li><strong>Accurate:</strong> Two-stage detection reduces false positives</li>
                  <li><strong>Thorough:</strong> Multi-identity and OOB testing</li>
                  <li><strong>Actionable:</strong> Provides reproduction instructions and remediation guidance</li>
                </>
              )}
            </ul>
          </div>
        </Card.Body>
      </Collapse>
    </Card>
  );
}

export default URLWorkflowHelpMeLearn;
