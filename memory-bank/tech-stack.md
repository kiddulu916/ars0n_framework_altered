# Tech Stack: Ars0n Framework v2

This document outlines the technology stack used in the Ars0n Framework v2.

## Containerization and Orchestration

**Docker:** The entire application and all its dependencies are containerized using Docker. This ensures a consistent and reproducible environment across different operating systems.

**Docker Compose:** Used to define and run the multi-container application. The docker-compose.yml file manages the services, networks, and volumes for the frontend, backend, database, and all integrated tools.

## Backend

**Programming Language:** Go (Golang)
  **Why GoLang:** Chosen for its high performance, excellent concurrency support (ideal for running multiple security tools simultaneously), and ability to compile into a single, static binary. This simplifies the Docker container and reduces its size.

**API Framework:** RESTful API built using Gorilla Mux router for advanced routing capabilities
**Database Driver:** pgx/v5 for high-performance PostgreSQL connectivity
**UUID Generation:** Google UUID library for consistent identifier generation

## Frontend

**Framework:** React (Create React App)
  **Why React:** A widely-adopted and powerful library for building dynamic single-page applications (SPAs). Its component-based architecture makes the UI manageable and scalable.

**Styling:** Bootstrap CSS + Bootstrap Icons
  **Why Bootstrap:** Provides consistent, responsive UI components and grid system for rapid development.

**Additional Libraries:**
- React Bootstrap for component integration
- React Icons for consistent iconography
- React Force Graph for network visualization

## AI Service

**Framework:** FastAPI (Python)
**AI Models:** T5-small via Transformers library
**Additional Libraries:** PyTorch, Accelerate, NumPy
**Why FastAPI:** High-performance async API framework with automatic OpenAPI documentation

## Database

**Database:** PostgreSQL - A powerful, open-source object-relational database system used to store all scan results, target information, and application state. Its robustness and feature set make it ideal for handling complex data relationships.

## Integrated Security Tools

The framework integrates a wide array of best-in-class, open-source security tools.

## Subdomain & Asset Enumeration

**Tools:**

- Amass

- Subfinder

- Sublist3r

- Assetfinder

- ShuffleDNS

- GAU (Get All URLs)

- CTL (Certificate Transparency Log tool)

- DNSx

## Web Reconnaissance & Crawling

**Tools:**

- Httpx

- GoSpider

- Subdomainizer

- Katana

- FFuf

## Vulnerability Scanning

**Tools:**

- Nuclei

## OSINT & Infrastructure Analysis

**Tools:**

- Metabigor

- Cloud Enum

- GitHub Recon

- Naabu (Port Scanner)

- Reverse Whois (via Whoxy)

## Wordlist Generation

**Tools:**

- CeWL

## Third-Party APIs & Services

**Tools:**

- SecurityTrails

- Censys

- Shodan