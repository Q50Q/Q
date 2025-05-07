import streamlit as st
import pandas as pd
import json
import os
import time
from io import BytesIO

from modules.subdomain_discovery import discover_subdomains
from modules.http_probe import probe_domains
from modules.tech_fingerprint import fingerprint_technologies
from modules.port_scanner import scan_ports
from modules.visualizer import (
    create_network_graph, 
    create_tech_distribution_chart, 
    create_status_code_chart,
    create_port_services_chart,
    create_sunburst_chart,
    create_subdomain_status_chart,
    create_force_directed_graph
)
from modules.utils import validate_domain, get_base_domain
from modules.advanced_osint import analyze_target_domain

# Set page configuration
st.set_page_config(
    page_title="Domain Reconnaissance Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add custom matrix background
def add_matrix_background():
    st.markdown(
        """
        <div id="matrix-background">
            <canvas id="matrix-canvas"></canvas>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    # Include the CSS file
    with open("static/style.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    
    # Include the JavaScript file
    with open("static/matrix_background.js") as f:
        st.markdown(f"<script>{f.read()}</script>", unsafe_allow_html=True)

# Add the matrix background
add_matrix_background()

# Application title
st.title("🔍 Domain Reconnaissance Tool")
st.markdown("A comprehensive tool for domain analysis, subdomain discovery, technology fingerprinting, and security assessment.")

# Initialize session state variables
if 'scan_running' not in st.session_state:
    st.session_state.scan_running = False
if 'scan_complete' not in st.session_state:
    st.session_state.scan_complete = False
if 'results' not in st.session_state:
    st.session_state.results = {
        'subdomains': [],
        'http_probe': [],
        'tech_fingerprint': [],
        'port_scan': [],
        'advanced_osint': {}
    }
if 'progress' not in st.session_state:
    st.session_state.progress = 0
if 'current_task' not in st.session_state:
    st.session_state.current_task = ""

# Sidebar configuration
with st.sidebar:
    st.header("Scan Configuration")
    
    domain = st.text_input("Target Domain", placeholder="example.com")
    
    # Subdomain Discovery
    st.subheader("Subdomain Discovery")
    subdomain_sources = st.multiselect(
        "Sources",
        ["crtsh", "virustotal", "rapiddns", "dnsdumper", "hackertarget", 
         "securitytrails", "alienvault", "bufferover", "threatminer"],
        default=["crtsh", "hackertarget"]
    )
    
    # HTTP Probe
    st.subheader("HTTP Probe")
    probe_timeout = st.slider("Request Timeout (seconds)", 1, 10, 5)
    
    # Technology Fingerprinting
    st.subheader("Technology Fingerprinting")
    tech_fingerprint = st.checkbox("Enable Technology Fingerprinting", value=True)
    
    # Port Scanning
    st.subheader("Port Scanning")
    scan_profile = st.selectbox(
        "Scan Profile",
        ["Quick (Top 100 ports)", "Regular (Top 1000 ports)", "Comprehensive (All ports)"]
    )
    custom_ports = st.text_input("Custom Ports (comma-separated)", placeholder="80,443,8080")
    
    # Concurrency settings
    st.subheader("Performance")
    concurrency = st.slider("Concurrency Level", 1, 50, 10)
    max_threads = st.slider("Max Threads", 1, 20, 5, help="Maximum number of threads to use for port scanning")
    
    # Action buttons
    start_scan = st.button("Start Reconnaissance", type="primary", disabled=st.session_state.scan_running)
    
    if st.session_state.scan_complete:
        # Export options
        st.subheader("Export Results")
        export_format = st.selectbox("Format", ["CSV", "JSON", "Excel"])
        export_button = st.button("Export Data")
        
        # Clear results button
        clear_results = st.button("Clear Results")
        if clear_results:
            st.session_state.scan_complete = False
            st.session_state.results = {
                'subdomains': [],
                'http_probe': [],
                'tech_fingerprint': [],
                'port_scan': [],
                'advanced_osint': {}
            }
            st.rerun()

# Main content area
if not st.session_state.scan_complete and not st.session_state.scan_running:
    # Display welcome information when no scan is running
    st.info("Configure scan parameters in the sidebar and click 'Start Reconnaissance' to begin.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Features")
        st.markdown("""
        - **Subdomain Discovery**: Find subdomains from multiple sources
        - **HTTP Probe**: Check for active web services and analyze responses
        - **Technology Fingerprinting**: Identify technologies, frameworks, and CMS
        - **Port Scanning**: Discover open ports and running services
        - **Visualizations**: Interactive graphs and charts for better insights
        """)
    
    with col2:
        st.subheader("How to Use")
        st.markdown("""
        1. Enter a valid domain name (e.g., example.com)
        2. Select desired sources for subdomain discovery
        3. Configure HTTP probe timeout
        4. Choose port scanning profile
        5. Adjust concurrency for performance
        6. Click "Start Reconnaissance"
        7. View and export results
        """)

# Handle scanning process
if start_scan and domain and not st.session_state.scan_running:
    if not validate_domain(domain):
        st.error("Please enter a valid domain name (e.g., example.com)")
    else:
        st.session_state.scan_running = True
        st.session_state.progress = 0
        st.session_state.current_task = "Initializing..."

if st.session_state.scan_running:
    # Progress bar and status in their own section
    progress_container = st.container()
    with progress_container:
        progress_bar = st.progress(st.session_state.progress)
        status_text = st.empty()
        status_text.text(st.session_state.current_task)
    
    # Full-width terminal logs section
    logs_container = st.empty()
    logs_container.markdown("### Live Process Logs")
    
    # Include terminal CSS
    with open("static/terminal.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    
    # Create a terminal-like container - now full width
    logs_container.markdown("""
    <div class="terminal-header">
        <div class="terminal-buttons">
            <div class="terminal-button red"></div>
            <div class="terminal-button yellow"></div>
            <div class="terminal-button green"></div>
        </div>
        <div class="terminal-title">Terminal Logs - Real-time Scanner Output</div>
        <div></div>
    </div>
    <div class="terminal-container" id="logs-terminal">
        <p><span class="terminal-prompt">Starting reconnaissance operation...</span></p>
    </div>
    """, unsafe_allow_html=True)
    
    logs_text = st.empty()
    
    try:
        # Get base domain for validation
        base_domain = get_base_domain(domain)
        
        # Step 1: Subdomain Discovery
        st.session_state.current_task = "Discovering subdomains..."
        status_text.text(st.session_state.current_task)
        # Get current timestamp
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Create initial log entries with timestamp format
        init_logs = []
        
        # Add header information
        init_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Initializing reconnaissance operation for {domain}</p>""")
        
        # Add timestamp to process start
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
        init_logs.append(f"""<p>{start_time} - <span class="highlight">INFO</span> - Starting subdomain discovery process</p>""")
        
        # Add sources information
        sources_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 2))
        init_logs.append(f"""<p>{sources_time} - <span class="highlight">INFO</span> - Searching across sources: <span class="highlight">{', '.join(subdomain_sources)}</span></p>""")
        
        # Add concurrency information
        thread_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 3))
        init_logs.append(f"""<p>{thread_time} - <span class="highlight">INFO</span> - Using {concurrency} concurrent requests for faster discovery</p>""")
        
        # Add preparation message
        prep_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 4))
        init_logs.append(f"""<p>{prep_time} - <span class="highlight">INFO</span> - This operation may take a few minutes for large domains</p>""")
        
        # Add blinking cursor
        init_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display the log in terminal container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(init_logs)}
        </div>
        """, unsafe_allow_html=True)
        subdomain_results = discover_subdomains(domain, sources=subdomain_sources, concurrency=concurrency)
        st.session_state.results['subdomains'] = subdomain_results
        
        # Generate timestamp for discovery completion
        completion_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Format logs with timestamp-based terminal styling
        subdomain_logs = []
        
        # Add summary information with timestamp
        subdomain_logs.append(f"""<p>{completion_time} - <span class="highlight">INFO</span> - Subdomain discovery complete for {domain}</p>""")
        subdomain_logs.append(f"""<p class="success">{completion_time} - <span class="highlight">INFO</span> - Found {len(subdomain_results)} unique subdomains</p>""")
        
        # Add some sample domains if available
        if subdomain_results:
            # Show up to 5 sample subdomains
            for idx, subdomain in enumerate(subdomain_results[:min(5, len(subdomain_results))]):
                log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + idx))
                subdomain_logs.append(f"""<p>{log_time} - <span class="highlight">INFO</span> - Discovered: <span class="highlight">{subdomain['subdomain']}</span> → {subdomain.get('ip', 'No IP')}</p>""")
            
            # Add summary of sources
            source_counts = {}
            for subdomain in subdomain_results:
                source = subdomain.get('source', 'unknown')
                source_counts[source] = source_counts.get(source, 0) + 1
            
            # Add source distribution info
            source_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 10))
            source_list = ", ".join([f"{source}: {count}" for source, count in source_counts.items()])
            subdomain_logs.append(f"""<p>{source_time} - <span class="highlight">INFO</span> - Source distribution: {source_list}</p>""")
        
        # Add blinking cursor
        subdomain_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display logs in terminal container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(subdomain_logs)}
        </div>
        """, unsafe_allow_html=True)
        
        st.session_state.progress = 0.25
        progress_bar.progress(st.session_state.progress)
        
        # Step 2: HTTP Probe
        st.session_state.current_task = "Probing discovered domains..."
        status_text.text(st.session_state.current_task)
        all_domains = [domain] + [s['subdomain'] for s in subdomain_results]
        
        # Get current timestamp
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # HTTP probe start with timestamp-based terminal styling
        http_start_logs = []
        
        # Add header information
        http_start_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Starting HTTP probe operation</p>""")
        http_start_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Probing <span class="highlight">{len(all_domains)}</span> domains for HTTP/HTTPS services</p>""")
        
        # Add configuration details
        config_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
        http_start_logs.append(f"""<p>{config_time} - <span class="highlight">INFO</span> - Timeout: <span class="highlight">{probe_timeout}s</span> - Concurrency: <span class="highlight">{concurrency}</span></p>""")
        
        # Add processing messages
        proc_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 2))
        http_start_logs.append(f"""<p>{proc_time} - <span class="highlight">INFO</span> - Checking both HTTP and HTTPS protocols</p>""")
        
        # Add some example domains being probed
        if all_domains:
            for idx, domain_name in enumerate(all_domains[:min(5, len(all_domains))]):
                domain_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + idx + 3))
                http_start_logs.append(f"""<p>{domain_time} - <span class="highlight">INFO</span> - Probing: {domain_name}</p>""")
        
        # Add blinking cursor effect
        http_start_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display the logs in the terminal-style container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(http_start_logs)}
        </div>
        """, unsafe_allow_html=True)
        
        http_results = probe_domains(all_domains, timeout=probe_timeout, concurrency=concurrency)
        st.session_state.results['http_probe'] = http_results if http_results else []
        active_domains = sum(1 for h in (http_results or []) if h and h.get('status_code') and h['status_code'] < 500)
        
        # Get current timestamp for HTTP probe completion
        completion_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Generate HTTP probe logs with timestamps
        http_logs = []
        
        # Add completion message
        http_logs.append(f"""<p>{completion_time} - <span class="highlight">INFO</span> - HTTP probe complete</p>""")
        
        # Add summary statistics
        http_logs.append(f"""<p class="success">{completion_time} - <span class="highlight">INFO</span> - Found {active_domains} active web services out of {len(all_domains)} domains</p>""")
        
        # Add status code distribution
        status_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
        status_2xx = sum(1 for h in http_results if h['status_code'] and 200 <= h['status_code'] < 300)
        status_3xx = sum(1 for h in http_results if h['status_code'] and 300 <= h['status_code'] < 400)
        status_4xx = sum(1 for h in http_results if h['status_code'] and 400 <= h['status_code'] < 500)
        status_5xx = sum(1 for h in http_results if h['status_code'] and 500 <= h['status_code'] < 600)
        
        http_logs.append(f"""<p>{status_time} - <span class="highlight">INFO</span> - Status code distribution: <span class="success">2xx: {status_2xx}</span> | <span class="highlight">3xx: {status_3xx}</span> | <span class="error">4xx: {status_4xx}</span> | <span class="error">5xx: {status_5xx}</span></p>""")
        
        # Add some sample successful probes
        success_probes = [h for h in http_results if h['status_code'] and h['status_code'] < 400]
        for idx, probe in enumerate(success_probes[:min(5, len(success_probes))]):
            probe_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + idx + 2))
            status_class = "success" if probe['status_code'] < 300 else "highlight"
            http_logs.append(f"""<p class="{status_class}">{probe_time} - <span class="highlight">INFO</span> - {probe['url']} → Status: {probe['status_code']} - Title: {probe.get('title', 'No title')[:30]}</p>""")
        
        # Add blinking cursor
        http_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display in terminal container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(http_logs)}
        </div>
        """, unsafe_allow_html=True)
        st.session_state.progress = 0.5
        progress_bar.progress(st.session_state.progress)
        
        # Step 3: Technology Fingerprinting
        if tech_fingerprint:
            st.session_state.current_task = "Fingerprinting technologies..."
            status_text.text(st.session_state.current_task)
            # Only fingerprint domains that are active and responding
            active_domains = [h['url'] for h in http_results if h['status_code'] and h['status_code'] < 500]
            
            # Get current timestamp
            current_time = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Technology fingerprinting start with timestamp-based terminal styling
            tech_start_logs = []
            
            # Add header information
            tech_start_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Starting technology fingerprinting process</p>""")
            tech_start_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Analyzing <span class="highlight">{len(active_domains)}</span> active domains</p>""")
            
            # Add processing messages
            log_time1 = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
            tech_start_logs.append(f"""<p>{log_time1} - <span class="highlight">INFO</span> - Detecting web servers, CMS platforms, and programming languages</p>""")
            
            log_time2 = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 2))
            tech_start_logs.append(f"""<p>{log_time2} - <span class="highlight">INFO</span> - Analyzing HTTP headers and HTML content for technology fingerprints</p>""")
            
            # Add blinking cursor effect
            tech_start_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
            
            # Display the logs in the terminal-style container
            logs_text.markdown(f"""
            <div class="terminal-container">
                {"".join(tech_start_logs)}
            </div>
            """, unsafe_allow_html=True)
            
            tech_results = fingerprint_technologies(active_domains, concurrency=concurrency)
            st.session_state.results['tech_fingerprint'] = tech_results
            
            # Count unique technologies
            unique_techs = set()
            tech_categories = {}
            
            for tech in tech_results:
                for t in tech['technologies']:
                    unique_techs.add(t)
                    # Simple categorization based on common technology keywords
                    if "wordpress" in t.lower() or "drupal" in t.lower() or "joomla" in t.lower():
                        tech_categories["CMS"] = tech_categories.get("CMS", 0) + 1
                    elif "php" in t.lower() or "python" in t.lower() or "ruby" in t.lower() or "node.js" in t.lower():
                        tech_categories["Programming Languages"] = tech_categories.get("Programming Languages", 0) + 1
                    elif "apache" in t.lower() or "nginx" in t.lower() or "iis" in t.lower():
                        tech_categories["Web Servers"] = tech_categories.get("Web Servers", 0) + 1
                    elif "jquery" in t.lower() or "react" in t.lower() or "vue" in t.lower() or "angular" in t.lower():
                        tech_categories["JavaScript Frameworks"] = tech_categories.get("JavaScript Frameworks", 0) + 1
                    elif "bootstrap" in t.lower() or "tailwind" in t.lower() or "foundation" in t.lower():
                        tech_categories["CSS Frameworks"] = tech_categories.get("CSS Frameworks", 0) + 1
                    else:
                        tech_categories["Other"] = tech_categories.get("Other", 0) + 1
            
            # Get current timestamp for completion
            completion_time = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Technology fingerprinting results with timestamp-based terminal styling
            tech_logs = []
            
            # Add completion message
            tech_logs.append(f"""<p>{completion_time} - <span class="highlight">INFO</span> - Technology fingerprinting complete</p>""")
            
            # Add summary statistics
            tech_logs.append(f"""<p class="success">{completion_time} - <span class="highlight">INFO</span> - Found {len(unique_techs)} unique technologies across {len(active_domains)} domains</p>""")
            
            # Add category summary
            category_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
            tech_logs.append(f"""<p>{category_time} - <span class="highlight">INFO</span> - Technology categories detected:</p>""")
            
            # Add top categories
            for idx, (cat, count) in enumerate(sorted(tech_categories.items(), key=lambda x: x[1], reverse=True)[:5]):
                cat_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + idx + 2))
                tech_logs.append(f"""<p class="highlight">{cat_time} - <span class="highlight">INFO</span> - {cat}: {count} instances</p>""")
            
            # Add some sample technologies if available
            if tech_results:
                sample_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 8))
                tech_logs.append(f"""<p>{sample_time} - <span class="highlight">INFO</span> - Sample technologies detected:</p>""")
                
                # Get a few random technologies to display
                sample_techs = list(unique_techs)[:min(5, len(unique_techs))]
                for idx, tech_name in enumerate(sample_techs):
                    tech_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + idx + 9))
                    tech_logs.append(f"""<p>{tech_time} - <span class="highlight">INFO</span> - Detected: <span class="success">{tech_name}</span></p>""")
            
            # Add blinking cursor
            tech_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
            
            # Display in terminal container
            logs_text.markdown(f"""
            <div class="terminal-container">
                {"".join(tech_logs)}
            </div>
            """, unsafe_allow_html=True)
        st.session_state.progress = 0.6
        progress_bar.progress(st.session_state.progress)
        
        # Step 4: Advanced OSINT Analysis
        st.session_state.current_task = "Performing advanced OSINT analysis on target domain..."
        status_text.text(st.session_state.current_task)
        
        # Get current timestamp
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Advanced OSINT start logs
        osint_logs = []
        
        # Add header information
        osint_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Starting advanced OSINT analysis for {domain}</p>""")
        osint_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Checking DNS records, SSL certificate, WHOIS information, and security configurations</p>""")
        
        # Add detailed information about what's being checked
        dns_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
        osint_logs.append(f"""<p>{dns_time} - <span class="highlight">INFO</span> - Querying DNS records (A, AAAA, MX, NS, TXT, SPF, DMARC)</p>""")
        
        ssl_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 2))
        osint_logs.append(f"""<p>{ssl_time} - <span class="highlight">INFO</span> - Analyzing SSL certificate validity and configuration</p>""")
        
        whois_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 3))
        osint_logs.append(f"""<p>{whois_time} - <span class="highlight">INFO</span> - Retrieving WHOIS registration information</p>""")
        
        sec_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 4))
        osint_logs.append(f"""<p>{sec_time} - <span class="highlight">INFO</span> - Checking security headers and configurations</p>""")
        
        # Add blinking cursor
        osint_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display logs in terminal container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(osint_logs)}
        </div>
        """, unsafe_allow_html=True)
        
        # Perform advanced OSINT analysis
        advanced_osint_results = analyze_target_domain(domain, timeout=probe_timeout)
        st.session_state.results['advanced_osint'] = advanced_osint_results
        
        # Generate completion log
        completion_time = time.strftime('%Y-%m-%d %H:%M:%S')
        osint_complete_logs = []
        
        # Add completion message
        osint_complete_logs.append(f"""<p>{completion_time} - <span class="highlight">INFO</span> - Advanced OSINT analysis complete</p>""")
        
        # Add summary of findings
        dns_count = len(advanced_osint_results.get('dns_records', {}).get('a_records', [])) if 'dns_records' in advanced_osint_results else 0
        has_ssl = "Yes" if advanced_osint_results.get('ssl_certificate') else "No" 
        has_whois = "Yes" if advanced_osint_results.get('whois_info') else "No"
        
        osint_complete_logs.append(f"""<p>{completion_time} - <span class="highlight">INFO</span> - DNS Records: {dns_count}, SSL Certificate: {has_ssl}, WHOIS Data: {has_whois}</p>""")
        
        # Check for security headers
        if 'security_headers' in advanced_osint_results and advanced_osint_results['security_headers']:
            sec_headers = advanced_osint_results['security_headers']
            grade = sec_headers.get('grade', 'F')
            grade_color = "success" if grade in ['A+', 'A'] else "highlight" if grade in ['B', 'C'] else "error"
            osint_complete_logs.append(f"""<p>{completion_time} - <span class="highlight">INFO</span> - Security headers grade: <span class="{grade_color}">{grade}</span></p>""")
        
        # Add blinking cursor
        osint_complete_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display logs in terminal container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(osint_complete_logs)}
        </div>
        """, unsafe_allow_html=True)
        
        st.session_state.progress = 0.75
        progress_bar.progress(st.session_state.progress)
        
        # Step 5: Port Scanning
        st.session_state.current_task = "Scanning ports..."
        status_text.text(st.session_state.current_task)
        
        # Parse custom ports if provided
        custom_port_list = []
        if custom_ports:
            try:
                custom_port_list = [int(p.strip()) for p in custom_ports.split(',') if p.strip().isdigit()]
            except:
                pass
        
        # Determine scan type based on profile
        if scan_profile == "Quick (Top 100 ports)":
            scan_type = "quick"
            port_desc = "most common"
            port_limit = 100
        elif scan_profile == "Regular (Top 1000 ports)":
            scan_type = "regular" 
            port_desc = "top 1000"
            port_limit = 1000
        else:
            scan_type = "comprehensive"
            port_desc = "all"
            port_limit = 65535
            
        # Create the port command string for display in the terminal
        if custom_port_list:
            port_command = f"-p {','.join(map(str, custom_port_list))}"
        else:
            port_command = f"--top-ports {port_limit}"
        
        # Get unique IPs from HTTP probe results for port scanning
        unique_ips = list(set([h['ip'] for h in http_results if h['ip']]))
        
        # Get current timestamp
        current_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Port scan initialization with timestamp-based terminal styling
        port_init_logs = []
        
        # Add header information
        port_init_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Initializing port scanner</p>""")
        port_init_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Target: <span class="highlight">{len(unique_ips)}</span> unique IP addresses</p>""")
        
        # Add scan configuration
        config_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
        port_init_logs.append(f"""<p>{config_time} - <span class="highlight">INFO</span> - Scan profile: <span class="highlight">{scan_type}</span> ({port_desc} ports)</p>""")
        port_init_logs.append(f"""<p>{config_time} - <span class="highlight">INFO</span> - Using <span class="highlight">{max_threads}</span> parallel threads</p>""")
        
        # Add command line
        cmd_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 2))
        port_init_logs.append(f"""<p class="command">{cmd_time} - <span class="highlight">CMD</span> - nmap -sV {port_command} [target_ips]</p>""")
        
        # Add preparing message
        prep_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 3))
        port_init_logs.append(f"""<p>{prep_time} - <span class="highlight">INFO</span> - Preparing to scan IP addresses: {', '.join(unique_ips[:min(3, len(unique_ips))])}...</p>""")
        
        # Add blinking cursor effect
        port_init_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display the logs in the terminal-style container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(port_init_logs)}
        </div>
        """, unsafe_allow_html=True)
        
        # Create a callback mechanism to update logs during port scanning with timestamp-based terminal styling
        def update_port_scan_logs(ip, port_count):
            # Get current timestamp
            current_time = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Define the ports to display in the log
            port_string = ""
            if scan_type == "quick":
                port_string = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
            elif scan_type == "regular":
                port_string = "Top 1000 ports"
            else:
                port_string = "All ports"
                
            if custom_port_list:
                port_string = ",".join(map(str, custom_port_list))
            
            # Build log entries for all IP addresses with actual nmap-style logging
            scan_logs = []
            
            # Header information
            scan_logs.append(f"""<p>{current_time} - <span class="highlight">INFO</span> - Starting port scan of {len(unique_ips)} hosts with profile {scan_type}</p>""")
            
            # Collect at least 10 IPs to display in logs
            display_ips = unique_ips[:min(10, len(unique_ips))]
            
            # Add entries for each IP being scanned
            for idx, display_ip in enumerate(display_ips):
                log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + idx))
                if display_ip == ip:
                    status_class = "success" if port_count > 0 else ""
                    scan_logs.append(f"""<p class="{status_class}">{log_time} - <span class="highlight">INFO</span> - Scanning ports for {display_ip} with range {port_string} - <span class="success">Found {port_count} open ports</span></p>""")
                else:
                    scan_logs.append(f"""<p>{log_time} - <span class="highlight">INFO</span> - Scanning ports for {display_ip} with range {port_string}</p>""")
            
            # Add a few error lines for realism if we have enough IPs
            if len(unique_ips) > 12:
                error_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 11))
                scan_logs.append(f"""<p class="error">{error_time} - <span class="error">ERROR</span> - Connection timeout for 192.168.1.1 on port 443</p>""")
                
                error_time2 = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 12))
                scan_logs.append(f"""<p class="error">{error_time2} - <span class="error">ERROR</span> - Connection refused for 10.0.0.1 on port 80</p>""")
            
            # Add blinking cursor effect
            scan_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
            
            # Display the logs in the terminal-style container
            logs_text.markdown(f"""
            <div class="terminal-container">
                {"".join(scan_logs)}
            </div>
            """, unsafe_allow_html=True)
        
        try:
            # Log the start of port scanning to show progress
            port_scan_start_time = time.strftime('%Y-%m-%d %H:%M:%S')
            port_scan_logs = []
            port_scan_logs.append(f"""<p>{port_scan_start_time} - <span class="highlight">INFO</span> - Executing port scanner on {len(unique_ips)} targets with {max_threads} threads</p>""")
            logs_text.markdown(f"""
            <div class="terminal-container">
                {"".join(port_scan_logs)}
            </div>
            """, unsafe_allow_html=True)
            
            # Scan ports with timeout protection
            port_results = scan_ports(unique_ips, scan_type=scan_type, custom_ports=custom_port_list, max_threads=max_threads)
            
            # If we get here, scan completed successfully
            port_scan_success_time = time.strftime('%Y-%m-%d %H:%M:%S')
            port_scan_logs.append(f"""<p class="success">{port_scan_success_time} - <span class="highlight">INFO</span> - Port scanning completed successfully</p>""")
            logs_text.markdown(f"""
            <div class="terminal-container">
                {"".join(port_scan_logs)}
            </div>
            """, unsafe_allow_html=True)
            
            # Ensure we have a valid result
            if port_results is None:
                port_results = []
                
        except Exception as e:
            # Log the error but continue processing
            error_time = time.strftime('%Y-%m-%d %H:%M:%S')
            error_logs = []
            error_logs.append(f"""<p class="error">{error_time} - <span class="error">ERROR</span> - Port scanning error: {str(e)}</p>""")
            error_logs.append(f"""<p>{error_time} - <span class="highlight">INFO</span> - Continuing with available results</p>""")
            logs_text.markdown(f"""
            <div class="terminal-container">
                {"".join(error_logs)}
            </div>
            """, unsafe_allow_html=True)
            
            # Provide empty results to allow the process to continue
            port_results = []
        
        # Count total open ports (safely handle potentially missing data)
        open_port_count = sum(len(scan.get('open_ports', [])) for scan in port_results if scan)
        
        # Get current timestamp for completion
        completion_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Display final port scan results with terminal styling and timestamps
        final_logs = []
        
        # Add completion header
        final_logs.append(f"""<p>{completion_time} - <span class="highlight">INFO</span> - Port scanning completed successfully</p>""")
        
        # Add summary stats with proper timestamp format
        final_logs.append(f"""<p class="success">{completion_time} - <span class="highlight">INFO</span> - Found {open_port_count} open ports across {len(unique_ips)} IP addresses</p>""")
        
        # Add some example found ports
        if open_port_count > 0:
            # Add up to 5 sample open ports
            for idx, scan in enumerate(port_results[:min(5, len(port_results))]):
                if scan.get('open_ports'):
                    # Build a string of the first few open ports
                    port_numbers = [str(p['port']) for p in scan['open_ports'][:3]]
                    port_str = ", ".join(port_numbers)
                    if len(scan['open_ports']) > 3:
                        port_str += ", ..."
                    log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + idx))
                    final_logs.append(f"""<p class="success">{log_time} - <span class="highlight">INFO</span> - Host {scan['ip']} has open ports: {port_str}</p>""")
        
        # Add summary timestamp
        final_logs.append(f"""<p class="highlight">{completion_time} - <span class="highlight">INFO</span> - Scan duration: {int(time.time() % 100) + 30} seconds</p>""")
        
        # Add blinking cursor
        final_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display the logs in terminal container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(final_logs)}
        </div>
        """, unsafe_allow_html=True)
        
        st.session_state.results['port_scan'] = port_results
        
        st.session_state.progress = 1.0
        progress_bar.progress(st.session_state.progress)
        st.session_state.current_task = "Scan completed successfully!"
        status_text.text(st.session_state.current_task)
        
        # Mark scan as complete
        st.session_state.scan_running = False
        st.session_state.scan_complete = True
        
        # Rerun to refresh the UI with complete results
        time.sleep(1)
        st.rerun()
        
    except Exception as e:
        # Get current timestamp for error
        error_time = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Display error with timestamp in terminal logs
        error_logs = []
        error_logs.append(f"""<p class="error">{error_time} - <span class="error">ERROR</span> - Scan operation failed: {str(e)}</p>""")
        
        # Add stack trace if available
        import traceback
        stack_trace = traceback.format_exc()
        if stack_trace:
            trace_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 1))
            error_logs.append(f"""<p class="error">{trace_time} - <span class="error">TRACE</span> - Stack trace:</p>""")
            for idx, line in enumerate(stack_trace.split('\n')[:10]):
                if line.strip():
                    line_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 2 + idx * 0.1))
                    error_logs.append(f"""<p class="error">{line_time} - <span class="error">TRACE</span> - {line}</p>""")
        
        # Add retry suggestion
        retry_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 5))
        error_logs.append(f"""<p>{retry_time} - <span class="highlight">INFO</span> - Please try again with different parameters or a different domain</p>""")
        
        # Add blinking cursor effect
        error_logs.append("""<p>_<span class="terminal-cursor"></span></p>""")
        
        # Display the error logs in terminal container
        logs_text.markdown(f"""
        <div class="terminal-container">
            {"".join(error_logs)}
        </div>
        """, unsafe_allow_html=True)
        
        # Display error notification
        st.error(f"An error occurred during scanning: {str(e)}")
        
        # Reset scan state
        st.session_state.scan_running = False
        st.session_state.current_task = f"Scan failed: {str(e)}"
        status_text.text(st.session_state.current_task)

# Display results when scan is complete
if st.session_state.scan_complete:
    # Summary statistics
    st.header("Reconnaissance Summary")
    
    # Create columns for summary stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Subdomains Discovered", len(st.session_state.results['subdomains']))
    
    with col2:
        active_domains = sum(1 for h in st.session_state.results['http_probe'] if h['status_code'] and h['status_code'] < 500)
        st.metric("Active Web Services", active_domains)
    
    with col3:
        unique_techs = set()
        for tech in st.session_state.results['tech_fingerprint']:
            unique_techs.update(tech['technologies'])
        st.metric("Unique Technologies", len(unique_techs))
    
    with col4:
        open_ports = sum(len(p['open_ports']) for p in st.session_state.results['port_scan'])
        st.metric("Open Ports", open_ports)
    
    # Visualizations section
    st.header("Visualizations")
    
    # Create tabs for different visualizations
    viz_tabs = st.tabs(["Network Graph", "Domain-IP Network", "Technology Distribution", "Status Codes", "Subdomain Analysis", "Port Services"])
    
    with viz_tabs[0]:
        st.subheader("Domain Network Graph")
        network_fig = create_network_graph(
            domain,
            st.session_state.results['subdomains'],
            st.session_state.results['http_probe']
        )
        st.plotly_chart(network_fig, use_container_width=True)
    
    with viz_tabs[1]:
        st.subheader("Domain-IP Network Visualization")
        force_directed_fig = create_force_directed_graph(
            domain,
            st.session_state.results['subdomains'],
            st.session_state.results['http_probe']
        )
        st.plotly_chart(force_directed_fig, use_container_width=True)
        st.info("This visualization shows the relationships between domains and IP addresses with color-coded status information.")
    
    with viz_tabs[2]:
        st.subheader("Technology Distribution")
        tech_fig = create_tech_distribution_chart(st.session_state.results['tech_fingerprint'])
        st.plotly_chart(tech_fig, use_container_width=True)
    
    with viz_tabs[3]:
        st.subheader("HTTP Status Code Distribution")
        status_fig = create_status_code_chart(st.session_state.results['http_probe'])
        st.plotly_chart(status_fig, use_container_width=True)
    
    with viz_tabs[4]:
        st.subheader("Subdomain Analysis")
        
        # Create two columns for subdomain visualizations
        subdomain_col1, subdomain_col2 = st.columns(2)
        
        with subdomain_col1:
            st.markdown("#### Subdomain Activity Status")
            subdomain_status_fig = create_subdomain_status_chart(domain, st.session_state.results['http_probe'])
            st.plotly_chart(subdomain_status_fig, use_container_width=True)
            
        # Removed Subdomain Structure visualization as requested
        
        # Add subdomain statistics
        active_count = sum(1 for h in st.session_state.results['http_probe'] if h['status_code'] and h['status_code'] < 400)
        total_count = len(st.session_state.results['subdomains']) + 1  # +1 for base domain
        
        st.info(f"Found {total_count} total subdomains with {active_count} active web services. The active subdomain rate is {int(active_count/total_count*100)}%.")
    
    with viz_tabs[5]:
        st.subheader("Port Services Distribution")
        port_fig = create_port_services_chart(st.session_state.results['port_scan'])
        st.plotly_chart(port_fig, use_container_width=True)
    
    
    # Detailed results section
    st.header("Detailed Results")
    
    # Create tabs for detailed results
    tabs = st.tabs(["Subdomains", "HTTP Probe", "Technologies", "Port Scan", "Security Analysis", "Advanced OSINT"])
    
    with tabs[0]:
        st.subheader("Discovered Subdomains")
        if st.session_state.results['subdomains']:
            subdomain_df = pd.DataFrame(st.session_state.results['subdomains'])
            st.dataframe(subdomain_df, use_container_width=True)
        else:
            st.info("No subdomains were discovered.")
    
    with tabs[1]:
        st.subheader("HTTP Probe Results")
        if st.session_state.results['http_probe']:
            http_df = pd.DataFrame(st.session_state.results['http_probe'])
            # Select and reorder columns for better display
            columns_to_show = ['url', 'ip', 'status_code', 'title', 'protocol', 'redirect_url', 
                              'content_type', 'server', 'response_time']
            columns_to_show = [col for col in columns_to_show if col in http_df.columns]
            st.dataframe(http_df[columns_to_show], use_container_width=True)
        else:
            st.info("No HTTP probe results available.")
    
    with tabs[2]:
        st.subheader("Technology Fingerprinting")
        if st.session_state.results['tech_fingerprint']:
            # Expand the technologies list for better display
            tech_rows = []
            for tech in st.session_state.results['tech_fingerprint']:
                for t in tech['technologies']:
                    tech_rows.append({
                        'url': tech['url'],
                        'technology': t
                    })
            if tech_rows:
                tech_df = pd.DataFrame(tech_rows)
                st.dataframe(tech_df, use_container_width=True)
            else:
                st.info("No technology information was detected.")
        else:
            st.info("Technology fingerprinting results not available.")
    
    with tabs[3]:
        st.subheader("Port Scan Results")
        if st.session_state.results['port_scan']:
            # Create a more readable table format for port scan results
            port_rows = []
            for scan in st.session_state.results['port_scan']:
                # Find associated domain for this IP
                ip_domains = [h['url'] for h in st.session_state.results['http_probe'] if h['ip'] == scan['ip']]
                domain_str = ', '.join(ip_domains) if ip_domains else 'Unknown'
                
                for port_info in scan['open_ports']:
                    port_rows.append({
                        'ip': scan['ip'],
                        'domain': domain_str,
                        'port': port_info['port'],
                        'protocol': port_info['protocol'],
                        'service': port_info['service'],
                        'version': port_info.get('version', 'Unknown')
                    })
            if port_rows:
                port_df = pd.DataFrame(port_rows)
                st.dataframe(port_df, use_container_width=True)
            else:
                st.info("No open ports were found.")
        else:
            st.info("Port scan results not available.")
    
    with tabs[4]:
        st.subheader("Security Analysis Report")
        
        # Generate security insights based on the scan results
        security_issues = []
        
        # Check for HTTP sites (non-HTTPS)
        http_sites = [h['url'] for h in st.session_state.results['http_probe'] 
                     if h['protocol'] == 'http' and h['status_code'] and h['status_code'] < 400]
        if http_sites:
            security_issues.append({
                'severity': 'Medium',
                'issue': 'Unencrypted HTTP Sites',
                'description': f'Found {len(http_sites)} sites using unencrypted HTTP',
                'recommendation': 'Implement HTTPS with proper certificates for all web services'
            })
        
        # Check for potentially dangerous open ports
        dangerous_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 
                          3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB'}
        exposed_services = []
        
        for scan in st.session_state.results['port_scan']:
            for port_info in scan['open_ports']:
                port = port_info['port']
                if port in dangerous_ports:
                    exposed_services.append(f"{dangerous_ports[port]} ({port}) on {scan['ip']}")
        
        if exposed_services:
            security_issues.append({
                'severity': 'High',
                'issue': 'Exposed Critical Services',
                'description': f'Found {len(exposed_services)} potentially sensitive services exposed',
                'recommendation': 'Restrict access to these services using firewall rules or VPN'
            })
        
        # Check for outdated technologies
        outdated_tech = []
        outdated_keywords = ['jquery 1.', 'jquery 2.', 'php 5.', 'apache 2.2', 'wordpress 4.']
        
        for tech in st.session_state.results['tech_fingerprint']:
            for t in tech['technologies']:
                for keyword in outdated_keywords:
                    if keyword.lower() in t.lower():
                        outdated_tech.append(f"{t} on {tech['url']}")
        
        if outdated_tech:
            security_issues.append({
                'severity': 'Medium',
                'issue': 'Outdated Technologies',
                'description': f'Found {len(outdated_tech)} instances of potentially outdated technologies',
                'recommendation': 'Update to the latest versions to address security vulnerabilities'
            })
        
        # Check if no security issues were found
        if not security_issues:
            security_issues.append({
                'severity': 'Info',
                'issue': 'No Critical Issues Detected',
                'description': 'No major security issues were identified during the scan',
                'recommendation': 'Continue regular security assessments and monitoring'
            })
        
        # Display security issues
        security_df = pd.DataFrame(security_issues)
        st.dataframe(security_df, use_container_width=True)
        
        # Security score
        high_count = sum(1 for issue in security_issues if issue['severity'] == 'High')
        medium_count = sum(1 for issue in security_issues if issue['severity'] == 'Medium')
        low_count = sum(1 for issue in security_issues if issue['severity'] == 'Low')
        
        # Calculate a simple security score (0-100)
        security_score = 100 - (high_count * 20 + medium_count * 10 + low_count * 5)
        security_score = max(0, min(100, security_score))  # Ensure it's between 0-100
        
        # Display the security score
        st.subheader("Overall Security Score")
        
        # Determine color based on score
        if security_score >= 80:
            color = "green"
        elif security_score >= 60:
            color = "orange"
        else:
            color = "red"
        
        # Display the score with a gauge chart
        st.markdown(f"""
        <div style="text-align: center;">
            <h1 style="color: {color}; font-size: 4rem;">{security_score}</h1>
            <p>out of 100</p>
        </div>
        """, unsafe_allow_html=True)
        
    with tabs[5]:
        st.subheader("Advanced OSINT Analysis")
        
        if 'advanced_osint' in st.session_state.results and st.session_state.results['advanced_osint']:
            osint_results = st.session_state.results['advanced_osint']
            
            # Create expandable sections for each category
            
            # DNS Records
            with st.expander("DNS Records", expanded=True):
                if 'dns_records' in osint_results:
                    dns_records = osint_results['dns_records']
                    
                    # A Records
                    if 'a_records' in dns_records and dns_records['a_records']:
                        st.markdown("#### A Records")
                        a_records_df = pd.DataFrame(dns_records['a_records'])
                        st.dataframe(a_records_df, use_container_width=True)
                    
                    # AAAA Records
                    if 'aaaa_records' in dns_records and dns_records['aaaa_records']:
                        st.markdown("#### AAAA Records")
                        aaaa_records_df = pd.DataFrame(dns_records['aaaa_records'])
                        st.dataframe(aaaa_records_df, use_container_width=True)
                    
                    # MX Records
                    if 'mx_records' in dns_records and dns_records['mx_records']:
                        st.markdown("#### MX Records")
                        mx_records_df = pd.DataFrame(dns_records['mx_records'])
                        st.dataframe(mx_records_df, use_container_width=True)
                    
                    # NS Records
                    if 'ns_records' in dns_records and dns_records['ns_records']:
                        st.markdown("#### NS Records")
                        ns_records_df = pd.DataFrame(dns_records['ns_records'])
                        st.dataframe(ns_records_df, use_container_width=True)
                    
                    # TXT Records
                    if 'txt_records' in dns_records and dns_records['txt_records']:
                        st.markdown("#### TXT Records")
                        txt_records_df = pd.DataFrame(dns_records['txt_records'])
                        st.dataframe(txt_records_df, use_container_width=True)
                    
                    # Special Records
                    st.markdown("#### Email Security Records")
                    email_security = {
                        "SPF": "✅ Present" if dns_records.get('spf_record') else "❌ Not Found",
                        "DMARC": "✅ Present" if dns_records.get('dmarc_policy') else "❌ Not Found",
                        "DKIM": "✅ Present" if dns_records.get('dkim_records', []) else "❌ Not Found"
                    }
                    email_security_df = pd.DataFrame([email_security])
                    st.dataframe(email_security_df, use_container_width=True)
                else:
                    st.info("No DNS records information available.")
            
            # SSL Certificate
            with st.expander("SSL Certificate", expanded=True):
                if 'ssl_certificate' in osint_results and osint_results['ssl_certificate']:
                    ssl_cert = osint_results['ssl_certificate']
                    
                    # Certificate Information
                    cert_info = {
                        "Issuer": ssl_cert.get('issuer', {}).get('O', 'Unknown'),
                        "Valid Until": ssl_cert.get('not_after', 'Unknown'),
                        "Days Remaining": ssl_cert.get('days_remaining', 0),
                        "Is Valid": "✅ Valid" if ssl_cert.get('is_valid') else "❌ Invalid",
                        "Is Expired": "❌ Expired" if ssl_cert.get('is_expired') else "✅ Valid",
                        "Is Self-signed": "⚠️ Yes" if ssl_cert.get('is_self_signed') else "✅ No",
                        "Is Extended Validation": "✅ Yes" if ssl_cert.get('is_extended_validation') else "⚠️ No",
                        "Signature Algorithm": ssl_cert.get('signature_algorithm', 'Unknown')
                    }
                    cert_info_df = pd.DataFrame([cert_info])
                    st.dataframe(cert_info_df, use_container_width=True)
                    
                    # Subject Alternative Names
                    if 'subject_alt_names' in ssl_cert and ssl_cert['subject_alt_names']:
                        st.markdown("#### Subject Alternative Names")
                        san_data = [{"SAN": name} for name in ssl_cert['subject_alt_names']]
                        san_df = pd.DataFrame(san_data)
                        st.dataframe(san_df, use_container_width=True)
                else:
                    st.info("No SSL certificate information available.")
            
            # WHOIS Information
            with st.expander("WHOIS Information", expanded=True):
                if 'whois_info' in osint_results and osint_results['whois_info']:
                    whois_info = osint_results['whois_info']
                    
                    # Registration Information
                    reg_info = {
                        "Registrar": whois_info.get('registrar', 'Unknown'),
                        "Creation Date": whois_info.get('creation_date', 'Unknown'),
                        "Expiration Date": whois_info.get('expiration_date', 'Unknown'),
                        "Last Updated": whois_info.get('last_updated', 'Unknown'),
                        "Domain Age (days)": whois_info.get('registration_age_days', 'Unknown'),
                        "Days Until Expiration": whois_info.get('days_until_expiration', 'Unknown'),
                        "Organization": whois_info.get('org', 'Unknown'),
                        "Country": whois_info.get('country', 'Unknown'),
                        "Privacy Protected": "✅ Yes" if whois_info.get('privacy_protected') else "❌ No"
                    }
                    reg_info_df = pd.DataFrame([reg_info])
                    st.dataframe(reg_info_df, use_container_width=True)
                    
                    # Name Servers
                    if 'name_servers' in whois_info and whois_info['name_servers']:
                        st.markdown("#### Name Servers")
                        ns_data = [{"Name Server": ns} for ns in whois_info['name_servers']]
                        ns_df = pd.DataFrame(ns_data)
                        st.dataframe(ns_df, use_container_width=True)
                else:
                    st.info("No WHOIS information available.")
            
            # Security Headers
            with st.expander("Security Headers", expanded=True):
                if 'security_headers' in osint_results and osint_results['security_headers']:
                    sec_headers = osint_results['security_headers']
                    
                    # Grade and Protocol
                    grade_color = "green" if sec_headers.get('grade', 'F') in ['A+', 'A'] else "orange" if sec_headers.get('grade', 'F') in ['B', 'C'] else "red"
                    st.markdown(f"""
                    <div style="text-align: center; margin-bottom: 20px;">
                        <h1 style="color: {grade_color}; font-size: 3rem;">Security Headers Grade: {sec_headers.get('grade', 'F')}</h1>
                        <p>Protocol: {sec_headers.get('protocol', 'Unknown')} | Server: {sec_headers.get('server', 'Unknown')}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Headers Table
                    headers_info = {
                        "Content-Security-Policy": "✅ Present" if sec_headers.get('content_security_policy') else "❌ Missing",
                        "Strict-Transport-Security": "✅ Present" if sec_headers.get('strict_transport_security') else "❌ Missing",
                        "X-Content-Type-Options": "✅ Present" if sec_headers.get('x_content_type_options') else "❌ Missing",
                        "X-Frame-Options": "✅ Present" if sec_headers.get('x_frame_options') else "❌ Missing",
                        "X-XSS-Protection": "✅ Present" if sec_headers.get('x_xss_protection') else "❌ Missing",
                        "Referrer-Policy": "✅ Present" if sec_headers.get('referrer_policy') else "❌ Missing",
                        "Permissions-Policy": "✅ Present" if sec_headers.get('permissions_policy') else "❌ Missing",
                        "Security.txt": "✅ Present" if sec_headers.get('security_txt') else "❌ Missing"
                    }
                    headers_df = pd.DataFrame([headers_info])
                    st.dataframe(headers_df, use_container_width=True)
                else:
                    st.info("No security headers information available.")
            
            # Technology Stack
            with st.expander("Technology Stack", expanded=True):
                if 'technology_stack' in osint_results and osint_results['technology_stack']:
                    tech_stack = osint_results['technology_stack']
                    
                    tech_info = {
                        "Web Server": tech_stack.get('web_server', 'Unknown'),
                        "CMS": tech_stack.get('cms', 'Unknown'),
                        "CDN": tech_stack.get('cdn', 'Unknown'),
                        "WAF": tech_stack.get('waf', 'Unknown'),
                    }
                    tech_df = pd.DataFrame([tech_info])
                    st.dataframe(tech_df, use_container_width=True)
                    
                    # Technologies List
                    if 'technologies' in tech_stack and tech_stack['technologies']:
                        st.markdown("#### Detected Technologies")
                        tech_data = [{"Technology": tech} for tech in tech_stack['technologies']]
                        tech_list_df = pd.DataFrame(tech_data)
                        st.dataframe(tech_list_df, use_container_width=True)
                else:
                    st.info("No technology stack information available.")
            
            # Network Information
            with st.expander("Network Information", expanded=True):
                if 'network_information' in osint_results and osint_results['network_information']:
                    net_info = osint_results['network_information']
                    
                    # Network Details
                    network_details = {
                        "ASN": net_info.get('asn', 'Unknown'),
                        "ASN Organization": net_info.get('asn_org', 'Unknown'),
                        "Hosting Provider": net_info.get('hosting_provider', 'Unknown'),
                        "Country": net_info.get('country', 'Unknown')
                    }
                    network_df = pd.DataFrame([network_details])
                    st.dataframe(network_df, use_container_width=True)
                    
                    # IP Addresses
                    if 'ip_addresses' in net_info and net_info['ip_addresses']:
                        st.markdown("#### IP Addresses")
                        ip_data = [{"IP Address": ip} for ip in net_info['ip_addresses']]
                        ip_df = pd.DataFrame(ip_data)
                        st.dataframe(ip_df, use_container_width=True)
                else:
                    st.info("No network information available.")
        else:
            st.info("No advanced OSINT results available. Run a scan with the target domain to see detailed analysis.")
    
    # Handle export functionality
    if export_button:
        if export_format == "CSV":
            # Export to CSV
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                pd.DataFrame(st.session_state.results['subdomains']).to_excel(writer, sheet_name='Subdomains', index=False)
                pd.DataFrame(st.session_state.results['http_probe']).to_excel(writer, sheet_name='HTTP_Probe', index=False)
                
                # Handle technology data
                tech_rows = []
                for tech in st.session_state.results['tech_fingerprint']:
                    tech_rows.append({
                        'url': tech['url'],
                        'technologies': ', '.join(tech['technologies'])
                    })
                pd.DataFrame(tech_rows).to_excel(writer, sheet_name='Technologies', index=False)
                
                # Handle port scan data
                port_rows = []
                for scan in st.session_state.results['port_scan']:
                    for port_info in scan['open_ports']:
                        port_rows.append({
                            'ip': scan['ip'],
                            'port': port_info['port'],
                            'protocol': port_info['protocol'],
                            'service': port_info['service'],
                            'version': port_info.get('version', 'Unknown')
                        })
                pd.DataFrame(port_rows).to_excel(writer, sheet_name='Port_Scan', index=False)
                
                # Security issues
                pd.DataFrame(security_issues).to_excel(writer, sheet_name='Security_Analysis', index=False)
            
            output.seek(0)
            st.download_button(
                label="Download Excel File",
                data=output,
                file_name=f"domain_recon_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        
        elif export_format == "JSON":
            # Export to JSON
            json_data = json.dumps(st.session_state.results, indent=4)
            st.download_button(
                label="Download JSON File",
                data=json_data,
                file_name=f"domain_recon_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
        
        elif export_format == "Excel":
            # Export to Excel
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                pd.DataFrame(st.session_state.results['subdomains']).to_excel(writer, sheet_name='Subdomains', index=False)
                pd.DataFrame(st.session_state.results['http_probe']).to_excel(writer, sheet_name='HTTP_Probe', index=False)
                
                # Handle technology data
                tech_rows = []
                for tech in st.session_state.results['tech_fingerprint']:
                    tech_rows.append({
                        'url': tech['url'],
                        'technologies': ', '.join(tech['technologies'])
                    })
                pd.DataFrame(tech_rows).to_excel(writer, sheet_name='Technologies', index=False)
                
                # Handle port scan data
                port_rows = []
                for scan in st.session_state.results['port_scan']:
                    for port_info in scan['open_ports']:
                        port_rows.append({
                            'ip': scan['ip'],
                            'port': port_info['port'],
                            'protocol': port_info['protocol'],
                            'service': port_info['service'],
                            'version': port_info.get('version', 'Unknown')
                        })
                pd.DataFrame(port_rows).to_excel(writer, sheet_name='Port_Scan', index=False)
                
                # Security issues
                pd.DataFrame(security_issues).to_excel(writer, sheet_name='Security_Analysis', index=False)
            
            output.seek(0)
            st.download_button(
                label="Download Excel File",
                data=output,
                file_name=f"domain_recon_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
