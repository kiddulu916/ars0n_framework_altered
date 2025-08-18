# App Design Document: Ars0n Framework v2

## Introduction

- This document outlines the design and architecture of the Ars0n Framework v2, a tool designed to automate bug bounty hunting workflows and educate users on application security methodologies. The framework acts as a user-friendly wrapper around numerous open-source security tools, guiding users through a structured reconnaissance process.

## Goals and Objectives

**Primary Goal:** To lower the barrier of entry for bug bounty hunting by providing a guided, educational, and automated framework.

**Secondary Goal:** To provide experienced security professionals with a powerful and customizable tool for reconnaissance and attack surface mapping.

**Core Philosophy:** "Earn While You Learn." The tool should be practical for real-world hunting while simultaneously teaching the user the methodology behind each step.

## System Architecture

The system is built on a microservices architecture using Docker containers, orchestrated by Docker Compose.

### Frontend

A web-based user interface that provides the user with a visual representation of the workflows and results.

**Web Framework:** React (Create React App)
**JavaScript Components:** React with Bootstrap components
**UI Framework:** Bootstrap CSS with Bootstrap Icons
**Additional Libraries:** React Force Graph for network visualization

### Backend API

A central RESTful API that receives commands from the frontend, executes the appropriate security tools in their respective Docker containers, and manages data flow.

**API Framework:** Go with Gorilla Mux router
**Backend Language:** Go (Golang)
**Database:** A PostgreSQL database with 50+ tables storing all scan results, target information, user configurations, and consolidated attack surface data. This allows for data persistence, correlation, and advanced analytics.
**Tool Containers:** Each integrated security tool (Amass, Nuclei, etc.) runs in its own dedicated Docker container with sleep infinity entrypoint. This isolates dependencies and allows for easy updates and maintenance.
**Docker Integration:** The framework utilizes Docker socket mounting (/var/run/docker.sock) to execute commands in running tool containers via docker exec.

### AI Service

A FastAPI-based service that provides document question answering capabilities using local T5-small model.

**AI Framework:** FastAPI (Python)
**AI Models:** T5-small via Transformers library
**Dependencies:** PyTorch, Accelerate, NumPy for ML processing
**Purpose:** Local AI processing for educational content and query assistance

### UI/UX Design/Workflow

#### User Interface (UI) and User Experience (UX)

The UI is designed to be intuitive and to enforce the bug bounty hunting methodology.

**Welcome Screen:** Presents users with three clear options:

- Create a New Scope Target (Company, Wildcard, URL).

- Import Existing Scan Data (.rs0n file or from URL).

- Load Pre-Scanned Data for learning.

**Workflow View:** The main interface is organized by the three core workflows (Company, Wildcard, URL). Each workflow is a series of steps, visually laid out. The user is guided from one step to the next, preventing them from running tools out of sequence.

**"Help Me Learn!" Feature:** Each section includes an expandable "Help Me Learn!" dropdown that provides educational content about the current step, the tools being used, and the overall objective.

**Results Dashboard:** A centralized view to see all discovered assets (subdomains, IPs, URLs), vulnerabilities, and metadata. The results are sortable and filterable, with a key focus on the ROI Score.

**Settings:** A dedicated section for managing API keys for external services (SecurityTrails, Shodan, etc.).

#### Core Workflows

The framework's logic is built around three distinct, methodology-driven workflows.

#### Company Workflow

**Objective:** To map the entire digital footprint of an organization.

**Steps:**

- Discover ASNs and on-prem network ranges.

- Scan network ranges for live web servers.

- Discover root domains using passive techniques (Google Dorking, Certificate Transparency).

- Discover root domains using API-driven techniques (SecurityTrails, GitHub Recon).

- Consolidate all discovered domains.

- Enumerate cloud assets and subdomains for all root domains.

#### Wildcard Workflow

**Objective:** To enumerate all subdomains for a given root domain and prioritize them for manual testing.

**Steps:**

- Initial subdomain enumeration (Amass, Subfinder, etc.).

- Consolidate and find live web servers (Round 1).

- Brute-force subdomains using generated wordlists (ShuffleDNS, CeWL).

- Consolidate and find live web servers (Round 2).

- Discover more assets by crawling JavaScript files and links (GoSpider).

- Consolidate and find live web servers (Round 3).

**Decision Point:** Perform ROI Analysis by taking screenshots, analyzing metadata, and calculating an ROI score to guide manual testing.

#### URL Workflow (Educational)

**Objective:** To provide a hands-on, educational experience for learning manual testing techniques on a specific URL.

**Methodology:** Follows a "Discover → Understand → Test → Validate" approach.

**Modules (Planned):**

- Client-Side Injection (XSS).

- Server-Side Vulnerabilities (SQLi, Command Injection).

- Authentication and Authorization.

- Business Logic Flaws.

### Data Management

**Database Schema:** The PostgreSQL database has 50+ tables including scope_targets, consolidated_attack_surface_assets, tool-specific scan tables (amass_scans, nuclei_scans, etc.), configuration tables (user_settings, api_keys, auto_scan_config), and comprehensive asset management tables.

**Data Parsing:** Each integrated tool requires a dedicated parser to convert its raw output (text, JSON, etc.) into a structured format that can be inserted into the database.

**Import/Export:** The framework supports exporting all data related to a target into a single .rs0n file (a custom format, likely a compressed archive of JSON or CSV files) and importing these files to resume work or share results.
