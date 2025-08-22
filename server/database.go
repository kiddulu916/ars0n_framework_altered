package main

import (
	"context"
	"log"
	"strings"
)

func createTables() {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto;`,
		`DROP TABLE IF EXISTS requests CASCADE;`,

		`CREATE TABLE IF NOT EXISTS scope_targets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			type VARCHAR(50) NOT NULL CHECK (type IN ('Company', 'Wildcard', 'URL')),
			mode VARCHAR(50) NOT NULL CHECK (mode IN ('Passive', 'Active')),
			scope_target TEXT NOT NULL,
			active BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS auto_scan_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			config_snapshot JSONB NOT NULL,
			status VARCHAR(32) NOT NULL DEFAULT 'pending',
			started_at TIMESTAMP DEFAULT NOW(),
			ended_at TIMESTAMP,
			steps_run JSONB,
			error_message TEXT,
			final_consolidated_subdomains INTEGER,
			final_live_web_servers INTEGER
		);`,

		`CREATE TABLE IF NOT EXISTS user_settings (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			amass_rate_limit INTEGER DEFAULT 10,
			httpx_rate_limit INTEGER DEFAULT 150,
			subfinder_rate_limit INTEGER DEFAULT 20,
			gau_rate_limit INTEGER DEFAULT 10,
			sublist3r_rate_limit INTEGER DEFAULT 10,
			ctl_rate_limit INTEGER DEFAULT 10,
			shuffledns_rate_limit INTEGER DEFAULT 10000,
			cewl_rate_limit INTEGER DEFAULT 10,
			gospider_rate_limit INTEGER DEFAULT 5,
			subdomainizer_rate_limit INTEGER DEFAULT 5,
			nuclei_screenshot_rate_limit INTEGER DEFAULT 20,
			custom_user_agent TEXT,
			custom_header TEXT,
			burp_proxy_ip TEXT DEFAULT '127.0.0.1',
			burp_proxy_port INTEGER DEFAULT 8080,
			burp_api_ip TEXT DEFAULT '127.0.0.1',
			burp_api_port INTEGER DEFAULT 1337,
			burp_api_key TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`INSERT INTO user_settings (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM user_settings LIMIT 1);`,

		`CREATE TABLE IF NOT EXISTS api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tool_name VARCHAR(100) NOT NULL,
			api_key_name VARCHAR(200) NOT NULL,
			api_key_value TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tool_name, api_key_name)
		);`,

		`CREATE TABLE IF NOT EXISTS ai_api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			provider VARCHAR(100) NOT NULL,
			api_key_name VARCHAR(200) NOT NULL,
			key_values JSONB NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(provider, api_key_name)
		);`,

		`CREATE TABLE IF NOT EXISTS auto_scan_config (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			amass BOOLEAN DEFAULT TRUE,
			sublist3r BOOLEAN DEFAULT TRUE,
			assetfinder BOOLEAN DEFAULT TRUE,
			gau BOOLEAN DEFAULT TRUE,
			ctl BOOLEAN DEFAULT TRUE,
			subfinder BOOLEAN DEFAULT TRUE,
			consolidate_httpx_round1 BOOLEAN DEFAULT TRUE,
			shuffledns BOOLEAN DEFAULT TRUE,
			cewl BOOLEAN DEFAULT TRUE,
			consolidate_httpx_round2 BOOLEAN DEFAULT TRUE,
			gospider BOOLEAN DEFAULT TRUE,
			subdomainizer BOOLEAN DEFAULT TRUE,
			consolidate_httpx_round3 BOOLEAN DEFAULT TRUE,
			nuclei_screenshot BOOLEAN DEFAULT TRUE,
			metadata BOOLEAN DEFAULT TRUE,
			max_consolidated_subdomains INTEGER DEFAULT 2500,
			max_live_web_servers INTEGER DEFAULT 500,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`INSERT INTO auto_scan_config (id)
		SELECT gen_random_uuid()
		WHERE NOT EXISTS (SELECT 1 FROM auto_scan_config LIMIT 1);`,

		`CREATE TABLE IF NOT EXISTS auto_scan_state (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			current_step TEXT NOT NULL,
			is_paused BOOLEAN DEFAULT false,
			is_cancelled BOOLEAN DEFAULT false,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS amass_intel_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domains JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS httpx_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE, 
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS gau_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE, 
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS sublist3r_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS assetfinder_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS ctl_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS subfinder_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS shuffledns_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS cewl_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			url TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS shufflednscustom_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS gospider_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS subdomainizer_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS nuclei_screenshots (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS metadata_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			domain TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS company_metadata_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL,
			ip_port_scan_id UUID NOT NULL,
			status VARCHAR(50) NOT NULL,
			error_message TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS securitytrails_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS github_recon_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS shodan_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS censys_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS metabigor_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS cloud_enum_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS katana_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domains JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_company_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domains JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS nuclei_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			targets TEXT[] NOT NULL DEFAULT '{}',
			templates TEXT[] NOT NULL DEFAULT '{}',
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS investigate_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS ip_port_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			status VARCHAR(50) NOT NULL,
			total_network_ranges INT DEFAULT 0,
			processed_network_ranges INT DEFAULT 0,
			total_ips_discovered INT DEFAULT 0,
			total_ports_scanned INT DEFAULT 0,
			live_web_servers_found INT DEFAULT 0,
			error_message TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		`CREATE TABLE IF NOT EXISTS discovered_live_ips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID REFERENCES ip_port_scans(scan_id) ON DELETE CASCADE,
			ip_address INET NOT NULL,
			hostname TEXT,
			network_range TEXT NOT NULL,
			ping_time_ms FLOAT,
			discovered_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS live_web_servers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID REFERENCES ip_port_scans(scan_id) ON DELETE CASCADE,
			ip_address INET NOT NULL,
			hostname TEXT,
			port INT NOT NULL,
			protocol VARCHAR(10) NOT NULL,
			url TEXT NOT NULL,
			status_code INT,
			title TEXT,
			server_header TEXT,
			content_length BIGINT,
			technologies JSONB,
			response_time_ms FLOAT,
			screenshot_path TEXT,
			ssl_info JSONB,
			http_response_headers JSONB,
			findings_json JSONB,
			last_checked TIMESTAMP DEFAULT NOW(),
			UNIQUE(scan_id, ip_address, port, protocol)
		);`,

		`CREATE TABLE IF NOT EXISTS target_urls (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			url TEXT NOT NULL,
			screenshot TEXT,
			status_code INTEGER,
			title TEXT,
			web_server TEXT,
			technologies TEXT[],
			content_length INTEGER,
			newly_discovered BOOLEAN DEFAULT false,
			no_longer_live BOOLEAN DEFAULT false,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			has_deprecated_tls BOOLEAN DEFAULT false,
			has_expired_ssl BOOLEAN DEFAULT false,
			has_mismatched_ssl BOOLEAN DEFAULT false,
			has_revoked_ssl BOOLEAN DEFAULT false,
			has_self_signed_ssl BOOLEAN DEFAULT false,
			has_untrusted_root_ssl BOOLEAN DEFAULT false,
			has_wildcard_tls BOOLEAN DEFAULT false,
			findings_json JSONB,
			http_response TEXT,
			http_response_headers JSONB,
			dns_a_records TEXT[],
			dns_aaaa_records TEXT[],
			dns_cname_records TEXT[],
			dns_mx_records TEXT[],
			dns_txt_records TEXT[],
			dns_ns_records TEXT[],
			dns_ptr_records TEXT[],
			dns_srv_records TEXT[],
			katana_results JSONB,
			ffuf_results JSONB,
			roi_score INTEGER DEFAULT 50,
			ip_address TEXT,
			UNIQUE(url, scope_target_id)
		);`,

		`CREATE TABLE IF NOT EXISTS dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS ips (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			ip_address TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS subdomains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			subdomain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS cloud_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('aws', 'gcp', 'azu')),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS asns (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			number TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS subnets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS service_providers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			provider TEXT NOT NULL,
			raw_data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_subdomains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			subdomain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, subdomain)
		);`,

		`CREATE TABLE IF NOT EXISTS intel_network_ranges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr_block TEXT NOT NULL,
			asn TEXT,
			organization TEXT,
			description TEXT,
			country TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_intel_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS intel_asn_data (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			asn_number TEXT NOT NULL,
			organization TEXT,
			description TEXT,
			country TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_intel_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS google_dorking_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			domain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS reverse_whois_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			domain TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_company_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			domain TEXT NOT NULL,
			source TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_network_ranges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL,
			cidr_block TEXT NOT NULL,
			asn TEXT,
			organization TEXT,
			description TEXT,
			country TEXT,
			source TEXT NOT NULL,
			scan_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id) REFERENCES scope_targets(id) ON DELETE CASCADE,
			UNIQUE(scope_target_id, cidr_block, source)
		);`,

		`CREATE TABLE IF NOT EXISTS metabigor_network_ranges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr_block TEXT NOT NULL,
			asn TEXT,
			organization TEXT,
			country TEXT,
			scan_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES metabigor_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_cloud_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('aws', 'gcp', 'azure', 'unknown')),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_enum_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_enum_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_raw_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			raw_output TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES amass_enum_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
			include_wildcard_results BOOLEAN DEFAULT FALSE,
			wildcard_domains JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS amass_intel_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_network_ranges JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
			include_wildcard_results BOOLEAN DEFAULT FALSE,
			wildcard_domains JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES dnsx_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_raw_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			domain TEXT NOT NULL,
			raw_output TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES dnsx_company_scans(scan_id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_company_domain_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domain TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			last_scan_id UUID,
			raw_output TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS dnsx_company_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id, root_domain) REFERENCES dnsx_company_domain_results(scope_target_id, domain) ON DELETE CASCADE,
			UNIQUE(scope_target_id, root_domain, record, record_type)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_domain_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			domain TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			last_scan_id UUID,
			raw_output TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, domain)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_cloud_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			cloud_domain TEXT NOT NULL,
			type TEXT NOT NULL CHECK (type IN ('aws', 'gcp', 'azure', 'unknown')),
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id, root_domain) REFERENCES amass_enum_company_domain_results(scope_target_id, domain) ON DELETE CASCADE,
			UNIQUE(scope_target_id, root_domain, cloud_domain)
		);`,

		`CREATE TABLE IF NOT EXISTS amass_enum_company_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			record TEXT NOT NULL,
			record_type TEXT NOT NULL,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			FOREIGN KEY (scope_target_id, root_domain) REFERENCES amass_enum_company_domain_results(scope_target_id, domain) ON DELETE CASCADE,
			UNIQUE(scope_target_id, root_domain, record, record_type)
		);`,

		`CREATE TABLE IF NOT EXISTS katana_company_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_domains JSONB NOT NULL DEFAULT '[]',
			include_wildcard_results BOOLEAN DEFAULT FALSE,
			selected_wildcard_domains JSONB DEFAULT '[]',
			selected_live_web_servers JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS cloud_enum_configs (
			id SERIAL PRIMARY KEY,
			scope_target_id UUID NOT NULL UNIQUE REFERENCES scope_targets(id) ON DELETE CASCADE,
			keywords TEXT[],
			threads INTEGER DEFAULT 5,
			enabled_platforms JSONB DEFAULT '{"aws": true, "azure": true, "gcp": true}',
			custom_dns_server TEXT DEFAULT '',
			dns_resolver_mode TEXT DEFAULT 'multiple',
			resolver_config TEXT DEFAULT 'default',
			additional_resolvers TEXT DEFAULT '',
			mutations_file_path TEXT DEFAULT '',
			brute_file_path TEXT DEFAULT '',
			resolver_file_path TEXT DEFAULT '',
			selected_services JSONB DEFAULT '{"aws": ["s3"], "azure": ["storage-accounts"], "gcp": ["gcp-buckets"]}',
			selected_regions JSONB DEFAULT '{"aws": ["us-east-1"], "azure": ["eastus"], "gcp": ["us-central1"]}',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS katana_company_cloud_assets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			root_domain TEXT NOT NULL,
			asset_domain TEXT NOT NULL,
			asset_url TEXT NOT NULL,
			asset_type TEXT NOT NULL,
			service TEXT NOT NULL,
			description TEXT,
			source_url TEXT,
			region TEXT,
			last_scanned_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id, root_domain, asset_url, asset_type)
		);`,

		`CREATE TABLE IF NOT EXISTS nuclei_configs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			targets TEXT[] NOT NULL DEFAULT '{}',
			templates TEXT[] NOT NULL DEFAULT '{cves,vulnerabilities,exposures,technologies,misconfiguration,takeovers,network,dns,headless}',
			severities TEXT[] DEFAULT '{critical,high,medium,low,info}',
			uploaded_templates JSONB DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(scope_target_id)
		);`,

		// Migration: Drop unused Katana Company tables
		`DROP TABLE IF EXISTS katana_company_cloud_findings CASCADE;`,
		`DROP TABLE IF EXISTS katana_company_domain_results CASCADE;`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_assets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			asset_type VARCHAR(50) NOT NULL CHECK (asset_type IN ('asn', 'network_range', 'ip_address', 'live_web_server', 'cloud_asset', 'fqdn')),
			asset_identifier TEXT NOT NULL,
			asset_subtype VARCHAR(50),
			
			-- ASN specific fields
			asn_number TEXT,
			asn_organization TEXT,
			asn_description TEXT,
			asn_country TEXT,
			
			-- Network range specific fields
			cidr_block TEXT,
			subnet_size INTEGER,
			responsive_ip_count INTEGER,
			responsive_port_count INTEGER,
			
			-- IP address specific fields
			ip_address TEXT,
			ip_type TEXT,
			dnsx_a_records TEXT[],
			amass_a_records TEXT[],
			httpx_sources TEXT[],
			
			-- Live web server specific fields
			url TEXT,
			domain TEXT,
			port INTEGER,
			protocol TEXT,
			status_code INTEGER,
			title TEXT,
			web_server TEXT,
			technologies TEXT[],
			content_length INTEGER,
			response_time_ms FLOAT,
			screenshot_path TEXT,
			ssl_info JSONB,
			http_response_headers JSONB,
			findings_json JSONB,
			
			-- Cloud asset specific fields
			cloud_provider VARCHAR(50),
			cloud_service_type VARCHAR(100),
			cloud_region TEXT,
			
			-- FQDN specific fields
			fqdn TEXT,
			root_domain TEXT,
			subdomain TEXT,
			registrar TEXT,
			creation_date DATE,
			expiration_date DATE,
			updated_date DATE,
			name_servers TEXT[],
			status TEXT[],
			whois_info JSONB,
			ssl_certificate JSONB,
			ssl_expiry_date DATE,
			ssl_issuer TEXT,
			ssl_subject TEXT,
			ssl_version TEXT,
			ssl_cipher_suite TEXT,
			ssl_protocols TEXT[],
			resolved_ips TEXT[],
			mail_servers TEXT[],
			spf_record TEXT,
			dkim_record TEXT,
			dmarc_record TEXT,
			caa_records TEXT[],
			txt_records TEXT[],
			mx_records TEXT[],
			ns_records TEXT[],
			a_records TEXT[],
			aaaa_records TEXT[],
			cname_records TEXT[],
			ptr_records TEXT[],
			srv_records TEXT[],
			soa_record JSONB,
			last_dns_scan TIMESTAMP,
			last_ssl_scan TIMESTAMP,
			last_whois_scan TIMESTAMP,
			
			-- Common fields
			last_updated TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			
			UNIQUE(scope_target_id, asset_type, asset_identifier)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_relationships (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			parent_asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			child_asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			relationship_type VARCHAR(50) NOT NULL,
			relationship_data JSONB,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(parent_asset_id, child_asset_id, relationship_type)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_dns_records (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			record_type VARCHAR(10) NOT NULL,
			record_value TEXT NOT NULL,
			ttl INTEGER,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(asset_id, record_type, record_value)
		);`,

		`CREATE TABLE IF NOT EXISTS consolidated_attack_surface_metadata (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			asset_id UUID NOT NULL REFERENCES consolidated_attack_surface_assets(id) ON DELETE CASCADE,
			metadata_type VARCHAR(50) NOT NULL,
			metadata_key TEXT NOT NULL,
			metadata_value TEXT,
			metadata_json JSONB,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(asset_id, metadata_type, metadata_key)
		);`,

		// Add missing columns to user_settings table for existing installations
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_proxy_ip TEXT DEFAULT '127.0.0.1';`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_proxy_port INTEGER DEFAULT 8080;`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_api_ip TEXT DEFAULT '127.0.0.1';`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_api_port INTEGER DEFAULT 1337;`,
		`ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS burp_api_key TEXT DEFAULT '';`,

		// URL Workflow Session Management
		`CREATE TABLE IF NOT EXISTS url_workflow_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			session_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			selected_urls JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'attack_surface_mapping', 'dast_scanning', 'targeted_testing', 'evidence_collection', 'completed', 'failed')),
			current_phase VARCHAR(50) DEFAULT 'attack_surface_mapping',
			phase_progress JSONB DEFAULT '{}',
			results_summary JSONB DEFAULT '{}',
			error_message TEXT,
			started_at TIMESTAMP DEFAULT NOW(),
			completed_at TIMESTAMP,
			total_findings INTEGER DEFAULT 0,
			total_evidence_items INTEGER DEFAULT 0,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`,

		// Core Findings Pipeline Tables
		`CREATE TABLE IF NOT EXISTS findings (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			key_hash VARCHAR(64) NOT NULL UNIQUE,
			title TEXT NOT NULL,
			description TEXT,
			category VARCHAR(50) NOT NULL CHECK (category IN ('xss', 'sqli', 'idor', 'ssrf', 'rce', 'lfi', 'rfi', 'csrf', 'xxe', 'nosqli', 'ldapi', 'ssti', 'auth_bypass', 'info_disclosure', 'misconfiguration', 'broken_access_control', 'security_misconfiguration', 'cryptographic_failure', 'injection', 'insecure_design', 'vulnerable_components', 'identification_failures', 'software_data_integrity', 'logging_monitoring', 'other')),
			severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
			confidence VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (confidence IN ('high', 'medium', 'low')),
			signal TEXT NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'confirmed', 'false_positive', 'duplicate', 'resolved')),
			url TEXT NOT NULL,
			method VARCHAR(10) NOT NULL DEFAULT 'GET',
			parameters JSONB DEFAULT '{}',
			vulnerability_class VARCHAR(100),
			affected_component TEXT,
			impact_description TEXT,
			remediation_notes TEXT,
			references TEXT[],
			cvss_score DECIMAL(3,1),
			cvss_vector TEXT,
			cwe_id TEXT,
			owasp_category TEXT,
			manual_verification_required BOOLEAN DEFAULT false,
			automated_reproduction_available BOOLEAN DEFAULT false,
			url_workflow_session_id UUID REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
			scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
			discovered_at TIMESTAMP DEFAULT NOW(),
			last_updated TIMESTAMP DEFAULT NOW(),
			last_verified TIMESTAMP,
			verified_by TEXT,
			tags TEXT[] DEFAULT '{}',
			metadata JSONB DEFAULT '{}'
		);`,

		`CREATE TABLE IF NOT EXISTS vectors (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
			vector_type VARCHAR(50) NOT NULL CHECK (vector_type IN ('payload', 'request', 'response', 'parameter', 'header', 'cookie', 'path', 'query', 'body', 'file_upload', 'websocket', 'api_endpoint')),
			vector_data TEXT NOT NULL,
			vector_metadata JSONB DEFAULT '{}',
			execution_context TEXT,
			validation_status VARCHAR(20) DEFAULT 'pending' CHECK (validation_status IN ('pending', 'validated', 'failed', 'skipped')),
			validation_timestamp TIMESTAMP,
			validation_result TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS evidence_blobs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
			blob_type VARCHAR(50) NOT NULL CHECK (blob_type IN ('har_file', 'screenshot', 'dom_snapshot', 'pcap_file', 'request_response', 'video_recording', 'network_trace', 'console_logs', 'error_logs', 'source_code')),
			file_path TEXT,
			file_size_bytes BIGINT,
			mime_type TEXT,
			blob_data BYTEA,
			blob_metadata JSONB DEFAULT '{}',
			storage_type VARCHAR(20) DEFAULT 'filesystem' CHECK (storage_type IN ('filesystem', 'database', 's3', 'azure_blob')),
			compression_type VARCHAR(20),
			hash_sha256 TEXT,
			is_redacted BOOLEAN DEFAULT false,
			retention_expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS contexts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
			context_type VARCHAR(50) NOT NULL CHECK (context_type IN ('authentication', 'authorization', 'session', 'user_role', 'tenant', 'environment', 'browser', 'device', 'location', 'time_based')),
			context_name TEXT NOT NULL,
			context_value TEXT,
			context_metadata JSONB DEFAULT '{}',
			is_active BOOLEAN DEFAULT true,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(finding_id, context_type, context_name)
		);`,

		`CREATE TABLE IF NOT EXISTS repro_recipes (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
			recipe_type VARCHAR(50) NOT NULL CHECK (recipe_type IN ('curl_command', 'playwright_script', 'burp_request', 'postman_collection', 'har_slice', 'manual_steps', 'automated_script')),
			recipe_data TEXT NOT NULL,
			recipe_metadata JSONB DEFAULT '{}',
			execution_environment TEXT,
			prerequisites TEXT[],
			expected_outcome TEXT,
			execution_time_estimate INTEGER,
			success_criteria TEXT,
			troubleshooting_notes TEXT,
			is_validated BOOLEAN DEFAULT false,
			validation_timestamp TIMESTAMP,
			validation_notes TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS oob_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			event_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
			finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
			event_type VARCHAR(50) NOT NULL CHECK (event_type IN ('dns_query', 'http_request', 'tcp_connection', 'smtp_connection', 'ftp_connection', 'ldap_query', 'file_system_access', 'command_execution')),
			source_ip INET,
			destination_host TEXT,
			destination_port INTEGER,
			protocol VARCHAR(20),
			payload TEXT,
			event_data JSONB DEFAULT '{}',
			user_agent TEXT,
			referrer TEXT,
			timestamp TIMESTAMP DEFAULT NOW(),
			is_associated BOOLEAN DEFAULT false,
			association_confidence DECIMAL(3,2) DEFAULT 0.5,
			url_workflow_session_id UUID REFERENCES url_workflow_sessions(id) ON DELETE SET NULL,
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE
		);`,

		// Kill Chain Analysis Tables
		`CREATE TABLE IF NOT EXISTS kill_chain_analysis (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			session_id UUID NOT NULL REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
			chain_type VARCHAR(50) NOT NULL CHECK (chain_type IN ('privilege_escalation', 'lateral_movement', 'data_exfiltration', 'persistence', 'defense_evasion', 'credential_access', 'discovery', 'collection', 'command_control', 'impact')),
			chain_status VARCHAR(20) NOT NULL DEFAULT 'detected' CHECK (chain_status IN ('detected', 'validated', 'exploitable', 'mitigated')),
			risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
			attack_vector_summary TEXT,
			business_impact TEXT,
			technical_impact TEXT,
			exploitability_rating VARCHAR(20) CHECK (exploitability_rating IN ('trivial', 'easy', 'moderate', 'hard', 'expert')),
			attack_complexity VARCHAR(20) CHECK (attack_complexity IN ('low', 'medium', 'high')),
			required_privileges VARCHAR(20) CHECK (required_privileges IN ('none', 'low', 'high')),
			user_interaction VARCHAR(20) CHECK (user_interaction IN ('none', 'required')),
			attack_surface VARCHAR(50),
			potential_impact_areas TEXT[],
			mitigation_priority VARCHAR(20) CHECK (mitigation_priority IN ('critical', 'high', 'medium', 'low')),
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS kill_chain_steps (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			kill_chain_id UUID NOT NULL REFERENCES kill_chain_analysis(id) ON DELETE CASCADE,
			step_order INTEGER NOT NULL,
			step_type VARCHAR(50) NOT NULL,
			finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
			step_description TEXT NOT NULL,
			technical_details TEXT,
			prerequisites TEXT[],
			outcomes TEXT[],
			confidence_level DECIMAL(3,2) NOT NULL DEFAULT 0.5 CHECK (confidence_level >= 0 AND confidence_level <= 1),
			verification_status VARCHAR(20) DEFAULT 'pending' CHECK (verification_status IN ('pending', 'verified', 'failed', 'skipped')),
			automation_possible BOOLEAN DEFAULT false,
			manual_verification_required BOOLEAN DEFAULT true,
			estimated_execution_time INTEGER,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(kill_chain_id, step_order)
		);`,

		`CREATE TABLE IF NOT EXISTS kill_chain_patterns (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			pattern_name VARCHAR(100) NOT NULL UNIQUE,
			pattern_description TEXT,
			attack_category VARCHAR(50) NOT NULL,
			pattern_steps JSONB NOT NULL,
			required_findings TEXT[],
			optional_findings TEXT[],
			minimum_severity VARCHAR(20) NOT NULL,
			complexity_rating VARCHAR(20) NOT NULL,
			success_criteria TEXT,
			detection_logic TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);`,

		// Orchestrator-specific tables for robust worker pool and rate limiting
		`CREATE TABLE IF NOT EXISTS task_results (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			session_id UUID NOT NULL,
			task_type VARCHAR(50) NOT NULL,
			tool VARCHAR(50) NOT NULL,
			target TEXT NOT NULL,
			success BOOLEAN NOT NULL,
			error TEXT,
			duration BIGINT, -- Duration in milliseconds
			completed_at TIMESTAMP DEFAULT NOW(),
			findings_count INTEGER DEFAULT 0,
			evidence_count INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		`CREATE TABLE IF NOT EXISTS worker_health (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			worker_id INTEGER NOT NULL,
			is_alive BOOLEAN NOT NULL,
			last_heartbeat TIMESTAMP NOT NULL,
			tasks_completed BIGINT DEFAULT 0,
			tasks_failed BIGINT DEFAULT 0,
			memory_usage BIGINT DEFAULT 0, -- Memory usage in bytes
			cpu_usage FLOAT DEFAULT 0.0, -- CPU usage percentage
			active_task TEXT,
			start_time TIMESTAMP NOT NULL,
			total_execution_time BIGINT DEFAULT 0, -- Total execution time in milliseconds
			average_task_time BIGINT DEFAULT 0, -- Average task time in milliseconds
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(worker_id)
		);`,

		`CREATE TABLE IF NOT EXISTS rate_limiter_stats (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			host VARCHAR(255) NOT NULL,
			requests_allowed BIGINT DEFAULT 0,
			requests_blocked BIGINT DEFAULT 0,
			average_response BIGINT DEFAULT 0, -- Average response time in milliseconds
			error_rate FLOAT DEFAULT 0.0,
			circuit_state VARCHAR(20) DEFAULT 'closed',
			backoff_until TIMESTAMP,
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(host)
		);`,

		// Enhanced target_urls with ROI integration
		`ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS roi_score INTEGER DEFAULT 50;`,
		`ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS roi_factors JSONB DEFAULT '{}';`,
		`ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS roi_last_calculated TIMESTAMP;`,
		`ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS url_workflow_eligible BOOLEAN DEFAULT false;`,
		`ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS url_workflow_last_tested TIMESTAMP;`,
		`ALTER TABLE target_urls ADD COLUMN IF NOT EXISTS url_workflow_findings_count INTEGER DEFAULT 0;`,

		// Create logs table
		`CREATE TABLE IF NOT EXISTS logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			session_id UUID REFERENCES url_workflow_sessions(id) ON DELETE CASCADE,
			finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
			workflow_stage VARCHAR(100),
			log_level VARCHAR(20) NOT NULL CHECK (log_level IN ('debug', 'info', 'warn', 'error', 'fatal')),
			log_category VARCHAR(50) NOT NULL CHECK (log_category IN ('system', 'workflow', 'tool', 'finding', 'evidence', 'auth', 'api', 'database', 'orchestrator', 'kill_chain')),
			message TEXT NOT NULL,
			log_data JSONB DEFAULT '{}',
			error_details TEXT,
			stack_trace TEXT,
			execution_time_ms BIGINT,
			source_function VARCHAR(200),
			source_file VARCHAR(500),
			source_line INTEGER,
			user_agent TEXT,
			ip_address INET,
			created_at TIMESTAMP DEFAULT NOW()
		);`,

		// Create indexes for performance
		`CREATE INDEX IF NOT EXISTS target_urls_url_idx ON target_urls (url);`,
		`CREATE INDEX IF NOT EXISTS target_urls_scope_target_id_idx ON target_urls (scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS target_urls_roi_score_idx ON target_urls (roi_score DESC);`,
		`CREATE INDEX IF NOT EXISTS target_urls_url_workflow_eligible_idx ON target_urls (url_workflow_eligible);`,
		`CREATE INDEX IF NOT EXISTS idx_discovered_live_ips_scan_id ON discovered_live_ips(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_scan_id ON live_web_servers(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_live_web_servers_ip_port ON live_web_servers(ip_address, port);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_scope_target ON consolidated_attack_surface_assets(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_asset_type ON consolidated_attack_surface_assets(asset_type);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_asset_identifier ON consolidated_attack_surface_assets(asset_identifier);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_ip_address ON consolidated_attack_surface_assets(ip_address);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_domain ON consolidated_attack_surface_assets(domain);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_fqdn ON consolidated_attack_surface_assets(fqdn);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_root_domain ON consolidated_attack_surface_assets(root_domain);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_subdomain ON consolidated_attack_surface_assets(subdomain);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_registrar ON consolidated_attack_surface_assets(registrar);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_assets_ssl_expiry_date ON consolidated_attack_surface_assets(ssl_expiry_date);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_relationships_parent ON consolidated_attack_surface_relationships(parent_asset_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_relationships_child ON consolidated_attack_surface_relationships(child_asset_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_dns_records_asset_id ON consolidated_attack_surface_dns_records(asset_id);`,
		`CREATE INDEX IF NOT EXISTS idx_consolidated_attack_surface_metadata_asset_id ON consolidated_attack_surface_metadata(asset_id);`,

		// URL Workflow specific indexes
		`CREATE INDEX IF NOT EXISTS idx_url_workflow_sessions_scope_target_id ON url_workflow_sessions(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_url_workflow_sessions_status ON url_workflow_sessions(status);`,
		`CREATE INDEX IF NOT EXISTS idx_url_workflow_sessions_session_id ON url_workflow_sessions(session_id);`,

		// Findings pipeline indexes
		`CREATE INDEX IF NOT EXISTS idx_findings_key_hash ON findings(key_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_scope_target_id ON findings(scope_target_id);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_url_workflow_session_id ON findings(url_workflow_session_id);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_discovered_at ON findings(discovered_at);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url);`,

		`CREATE INDEX IF NOT EXISTS idx_vectors_finding_id ON vectors(finding_id);`,
		`CREATE INDEX IF NOT EXISTS idx_vectors_vector_type ON vectors(vector_type);`,
		`CREATE INDEX IF NOT EXISTS idx_vectors_validation_status ON vectors(validation_status);`,

		`CREATE INDEX IF NOT EXISTS idx_evidence_blobs_finding_id ON evidence_blobs(finding_id);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_blobs_blob_type ON evidence_blobs(blob_type);`,
		`CREATE INDEX IF NOT EXISTS idx_evidence_blobs_storage_type ON evidence_blobs(storage_type);`,

		`CREATE INDEX IF NOT EXISTS idx_contexts_finding_id ON contexts(finding_id);`,
		`CREATE INDEX IF NOT EXISTS idx_contexts_context_type ON contexts(context_type);`,
		`CREATE INDEX IF NOT EXISTS idx_contexts_is_active ON contexts(is_active);`,

		`CREATE INDEX IF NOT EXISTS idx_repro_recipes_finding_id ON repro_recipes(finding_id);`,
		`CREATE INDEX IF NOT EXISTS idx_repro_recipes_recipe_type ON repro_recipes(recipe_type);`,
		`CREATE INDEX IF NOT EXISTS idx_repro_recipes_is_validated ON repro_recipes(is_validated);`,

		`CREATE INDEX IF NOT EXISTS idx_oob_events_finding_id ON oob_events(finding_id);`,
		`CREATE INDEX IF NOT EXISTS idx_oob_events_event_type ON oob_events(event_type);`,
		`CREATE INDEX IF NOT EXISTS idx_oob_events_timestamp ON oob_events(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_oob_events_is_associated ON oob_events(is_associated);`,
		`CREATE INDEX IF NOT EXISTS idx_oob_events_scope_target_id ON oob_events(scope_target_id);`,

		// Kill chain indexes
		`CREATE INDEX IF NOT EXISTS idx_kill_chain_analysis_session_id ON kill_chain_analysis(session_id);`,
		`CREATE INDEX IF NOT EXISTS idx_kill_chain_analysis_chain_type ON kill_chain_analysis(chain_type);`,
		`CREATE INDEX IF NOT EXISTS idx_kill_chain_analysis_risk_score ON kill_chain_analysis(risk_score DESC);`,

		`CREATE INDEX IF NOT EXISTS idx_kill_chain_steps_kill_chain_id ON kill_chain_steps(kill_chain_id);`,
		`CREATE INDEX IF NOT EXISTS idx_kill_chain_steps_finding_id ON kill_chain_steps(finding_id);`,
		`CREATE INDEX IF NOT EXISTS idx_kill_chain_steps_step_order ON kill_chain_steps(step_order);`,

		`CREATE INDEX IF NOT EXISTS idx_kill_chain_patterns_pattern_name ON kill_chain_patterns(pattern_name);`,
		`CREATE INDEX IF NOT EXISTS idx_kill_chain_patterns_attack_category ON kill_chain_patterns(attack_category);`,

		// Orchestrator indexes for performance optimization
		`CREATE INDEX IF NOT EXISTS idx_task_results_session_id ON task_results(session_id);`,
		`CREATE INDEX IF NOT EXISTS idx_task_results_tool ON task_results(tool);`,
		`CREATE INDEX IF NOT EXISTS idx_task_results_success ON task_results(success);`,
		`CREATE INDEX IF NOT EXISTS idx_task_results_completed_at ON task_results(completed_at);`,
		`CREATE INDEX IF NOT EXISTS idx_task_results_duration ON task_results(duration);`,

		`CREATE INDEX IF NOT EXISTS idx_worker_health_worker_id ON worker_health(worker_id);`,
		`CREATE INDEX IF NOT EXISTS idx_worker_health_is_alive ON worker_health(is_alive);`,
		`CREATE INDEX IF NOT EXISTS idx_worker_health_last_heartbeat ON worker_health(last_heartbeat);`,
		`CREATE INDEX IF NOT EXISTS idx_worker_health_updated_at ON worker_health(updated_at);`,

		`CREATE INDEX IF NOT EXISTS idx_rate_limiter_stats_host ON rate_limiter_stats(host);`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limiter_stats_circuit_state ON rate_limiter_stats(circuit_state);`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limiter_stats_error_rate ON rate_limiter_stats(error_rate);`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limiter_stats_updated_at ON rate_limiter_stats(updated_at);`,

		// Logs indexes
		`CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs(session_id);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_finding_id ON logs(finding_id);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_log_level ON logs(log_level);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_log_category ON logs(log_category);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_workflow_stage ON logs(workflow_stage);`,
	}

	for _, query := range queries {
		_, err := dbPool.Exec(context.Background(), query)
		if err != nil {
			log.Printf("[ERROR] Failed to execute query: %s, error: %v", query, err)
			if !strings.Contains(err.Error(), "already exists") {
				log.Fatalf("[ERROR] Failed to create database schema: %v", err)
			}
		}
	}

	deletePendingScansQuery := `
		DELETE FROM amass_scans WHERE status = 'pending';
		DELETE FROM amass_intel_scans WHERE status = 'pending';
		DELETE FROM httpx_scans WHERE status = 'pending';
		DELETE FROM gau_scans WHERE status = 'pending';
		DELETE FROM sublist3r_scans WHERE status = 'pending';
		DELETE FROM assetfinder_scans WHERE status = 'pending';
		DELETE FROM ctl_scans WHERE status = 'pending';
		DELETE FROM subfinder_scans WHERE status = 'pending';
		DELETE FROM shuffledns_scans WHERE status = 'pending';
		DELETE FROM cewl_scans WHERE status = 'pending';
		DELETE FROM shufflednscustom_scans WHERE status = 'pending';
		DELETE FROM gospider_scans WHERE status = 'pending';
		DELETE FROM subdomainizer_scans WHERE status = 'pending';
		DELETE FROM nuclei_screenshots WHERE status = 'pending';
		DELETE FROM metadata_scans WHERE status = 'pending';
		DELETE FROM ip_port_scans WHERE status = 'pending';
		DELETE FROM katana_company_scans WHERE status = 'pending' OR status = 'running';
		DELETE FROM amass_enum_company_scans WHERE status = 'pending' OR status = 'running';
		DELETE FROM nuclei_scans WHERE status = 'pending' OR status = 'running';`

	_, err := dbPool.Exec(context.Background(), deletePendingScansQuery)
	if err != nil {
		log.Printf("[WARN] Failed to delete pending scans: %v", err)
	} else {
		log.Println("[INFO] Deleted any scans with status 'pending'")
	}

	log.Println("[INFO] Database schema created successfully")
}
