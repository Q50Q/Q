import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import networkx as nx
from collections import Counter, defaultdict
from typing import Dict, List, Any, Tuple
import tldextract
import re


def create_network_graph(domain: str, subdomains: List[Dict[str, Any]], http_results: List[Dict[str, Any]]) -> go.Figure:
    """
    Create a network visualization of domains and their relationships.
    
    Args:
        domain: The base domain
        subdomains: List of subdomain dictionaries
        http_results: List of HTTP probe result dictionaries
        
    Returns:
        Plotly figure object
    """
    # Create a directed graph
    G = nx.DiGraph()
    
    # Extract base domain
    base_extract = tldextract.extract(domain)
    base_domain = f"{base_extract.domain}.{base_extract.suffix}"
    
    # Add base domain as the central node
    G.add_node(base_domain, type='base', status='unknown')
    
    # Map of domains to status codes
    domain_status = {}
    for result in http_results:
        url = result['url']
        if url.startswith(('http://', 'https://')):
            url = url.split('://', 1)[1]
        domain_status[url.split('/', 1)[0]] = result.get('status_code', None)
    
    # Add subdomain nodes and edges
    for subdomain_info in subdomains:
        subdomain = subdomain_info['subdomain']
        
        # Skip if it's exactly the base domain
        if subdomain == base_domain:
            continue
        
        # Extract parts
        extract = tldextract.extract(subdomain)
        
        # Get domain parts
        parts = []
        if extract.subdomain:
            # Split the subdomain by dots
            subparts = extract.subdomain.split('.')
            for i in range(len(subparts)):
                part = '.'.join(subparts[-(i+1):])
                if part:
                    parts.append(f"{part}.{extract.domain}.{extract.suffix}")
        
        # Add the subdomain node
        status = domain_status.get(subdomain, 'unknown')
        if status and status < 400:
            status_color = 'active'
        elif status and status < 500:
            status_color = 'client_error'
        elif status:
            status_color = 'server_error'
        else:
            status_color = 'unknown'
        
        G.add_node(subdomain, type='subdomain', status=status_color)
        
        # Add edges between parts
        prev_part = None
        for part in parts:
            if part not in G:
                G.add_node(part, type='intermediate', status='unknown')
            if prev_part:
                G.add_edge(prev_part, part)
            prev_part = part
        
        # Connect to base domain if needed
        if parts:
            G.add_edge(base_domain, parts[0])
        else:
            G.add_edge(base_domain, subdomain)
    
    # Create positions using a spring layout
    pos = nx.spring_layout(G, k=0.5, iterations=50)
    
    # Create edge trace
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')
    
    # Create node trace
    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
    
    # Create a list of node types for coloring
    node_types = [G.nodes[node]['type'] for node in G.nodes()]
    
    # Create a list of node statuses for coloring
    node_statuses = [G.nodes[node]['status'] for node in G.nodes()]
    
    # Create a color mapping for status
    status_color_map = {
        'active': '#00CC96',  # Green for active
        'client_error': '#EF553B',  # Red for client errors
        'server_error': '#FFA15A',  # Orange for server errors
        'unknown': '#636EFA'  # Blue for unknown
    }
    
    node_colors = [status_color_map[status] for status in node_statuses]
    
    # Create size mapping for node types
    type_size_map = {
        'base': 20,
        'subdomain': 15,
        'intermediate': 10
    }
    
    node_sizes = [type_size_map[node_type] for node_type in node_types]
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        marker=dict(
            color=node_colors,
            size=node_sizes,
            line=dict(width=1, color='#000')
        )
    )
    
    # Set node hover text
    node_hover_text = []
    for node in G.nodes():
        if G.nodes[node]['type'] == 'subdomain':
            status_code = domain_status.get(node, 'Unknown')
            node_hover_text.append(f"{node}<br>Status: {status_code}")
        else:
            node_hover_text.append(node)
    
    node_trace.hovertext = node_hover_text
    
    # Create figure
    fig = go.Figure(data=[edge_trace, node_trace],
                  layout=go.Layout(
                      title=f"Domain Network for {domain}",
                      showlegend=False,
                      hovermode='closest',
                      margin=dict(b=20, l=5, r=5, t=40),
                      xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                      yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                  ))
    
    return fig

def create_tech_distribution_chart(tech_results: List[Dict[str, Any]]) -> go.Figure:
    """
    Create a technology distribution visualization.
    
    Args:
        tech_results: List of technology fingerprinting result dictionaries
        
    Returns:
        Plotly figure object
    """
    if not tech_results:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No technology data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Collect all technologies
    all_techs = []
    for result in tech_results:
        all_techs.extend(result.get('technologies', []))
    
    # Count occurrences
    tech_counts = Counter(all_techs)
    
    # Get the top technologies
    top_techs = tech_counts.most_common(20)  # Limit to top 20 for readability
    
    # Prepare data for bar chart
    techs, counts = zip(*top_techs) if top_techs else ([], [])
    
    # Create horizontal bar chart
    fig = go.Figure(go.Bar(
        x=counts,
        y=techs,
        orientation='h',
        marker=dict(
            color='rgba(50, 171, 96, 0.6)',
            line=dict(color='rgba(50, 171, 96, 1.0)', width=1)
        )
    ))
    
    # Update layout
    fig.update_layout(
        title='Technology Distribution',
        xaxis_title='Count',
        yaxis_title='Technology',
        yaxis=dict(
            categoryorder='total ascending'
        ),
        height=600
    )
    
    return fig

def create_subdomain_status_chart(domain: str, http_results: List[Dict[str, Any]]) -> go.Figure:
    """
    Create a visualization of active vs non-active subdomains.
    
    Args:
        domain: The base domain
        http_results: List of HTTP probe result dictionaries
        
    Returns:
        Plotly figure object
    """
    if not http_results:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No HTTP probe data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Count active and non-active domains
    active_domains = sum(1 for h in http_results if h['status_code'] and h['status_code'] < 500)
    non_active_domains = len(http_results) - active_domains
    
    # Prepare data for pie chart
    labels = ["Active", "Non-Active"]
    values = [active_domains, non_active_domains]
    
    # Define colors
    colors = {
        "Active": "#00CC96",
        "Non-Active": "#EF553B"
    }
    
    color_list = [colors[label] for label in labels]
    
    # Create pie chart
    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker=dict(colors=color_list),
        textinfo='label+percent',
        textposition='outside',
        pull=[0.1 if label == "Active" else 0 for label in labels]
    ))
    
    # Update layout
    fig.update_layout(
        title='Subdomain Activity Status',
        height=500
    )
    
    return fig

def create_status_code_chart(http_results: List[Dict[str, Any]]) -> go.Figure:
    """
    Create a visualization of HTTP status code distribution.
    
    Args:
        http_results: List of HTTP probe result dictionaries
        
    Returns:
        Plotly figure object
    """
    if not http_results:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No HTTP probe data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Count status codes
    status_counts = Counter()
    for result in (http_results or []):
        if not result:
            continue
        status = result.get('status_code')
        if status:
            # Group by status code class
            if status < 200:
                status_class = '1xx - Informational'
            elif status < 300:
                status_class = '2xx - Success'
            elif status < 400:
                status_class = '3xx - Redirection'
            elif status < 500:
                status_class = '4xx - Client Error'
            else:
                status_class = '5xx - Server Error'
            
            status_counts[status_class] += 1
        else:
            status_counts['No Response'] += 1
    
    # Prepare data for pie chart
    labels = list(status_counts.keys())
    values = list(status_counts.values())
    
    # Define colors for status classes
    colors = {
        '1xx - Informational': '#636EFA',
        '2xx - Success': '#00CC96',
        '3xx - Redirection': '#AB63FA',
        '4xx - Client Error': '#EF553B',
        '5xx - Server Error': '#FFA15A',
        'No Response': '#19D3F3'
    }
    
    color_list = [colors[label] for label in labels]
    
    # Create pie chart
    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker=dict(colors=color_list),
        textinfo='label+percent',
        textposition='outside',
        pull=[0.1 if label == 'No Response' else 0 for label in labels]
    ))
    
    # Update layout
    fig.update_layout(
        title='HTTP Status Code Distribution',
        height=500
    )
    
    return fig

# Geolocation function has been removed as requested


def create_port_services_chart(port_results: List[Dict[str, Any]]) -> go.Figure:
    """
    Create a visualization of open ports and services using a radial pie chart.
    
    Args:
        port_results: List of port scan result dictionaries
        
    Returns:
        Plotly figure object
    """
    if not port_results:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No port scan data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Collect all open ports and their services
    service_counts = Counter()
    for result in port_results:
        for port_info in result.get('open_ports', []):
            service = port_info.get('service', 'unknown')
            service_counts[service] += 1
    
    # Get the top services (limit to top 15 for readability)
    top_services = service_counts.most_common(15)
    
    # Generate distinct colors for each service
    import plotly.express as px
    color_scale = px.colors.qualitative.Plotly
    
    # Prepare data for pie chart
    labels, values = zip(*top_services) if top_services else ([], [])
    colors = [color_scale[i % len(color_scale)] for i in range(len(labels))]
    
    # Create a radial pie chart (sunburst-like)
    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.4,  # Donut-style chart
        marker=dict(colors=colors),
        textinfo='label+percent',
        textposition='auto',
        textfont=dict(size=12),
        insidetextorientation='radial',  # Radial text orientation
        hoverinfo='label+value+percent',
        sort=False  # Don't sort to keep it more visually interesting
    ))
    
    # Update layout
    fig.update_layout(
        title='Open Services Distribution',
        height=500,
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5
        )
    )
    
    return fig

def create_force_directed_graph(domain: str, subdomains: List[Dict[str, Any]], http_results: List[Dict[str, Any]]) -> go.Figure:
    """
    Create a force-directed network visualization with physics simulation.
    
    Args:
        domain: The base domain
        subdomains: List of subdomain dictionaries
        http_results: List of HTTP probe result dictionaries
        
    Returns:
        Plotly figure object
    """
    if not subdomains or not http_results:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="Not enough data for network visualization",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Create directed graph with networkx
    G = nx.DiGraph()
    
    # Extract base domain
    base_extract = tldextract.extract(domain)
    base_domain = f"{base_extract.domain}.{base_extract.suffix}"
    
    # Map domains to IPs
    domain_to_ip = {}
    ip_to_domains = defaultdict(list)
    
    for result in http_results:
        if result.get('ip') and result.get('url'):
            domain_to_ip[result['url']] = result['ip']
            ip_to_domains[result['ip']].append(result['url'])
    
    # Map of domains to status codes
    domain_status = {}
    for result in http_results:
        url = result['url']
        if url.startswith(('http://', 'https://')):
            url = url.split('://', 1)[1]
        domain_status[url.split('/', 1)[0]] = result.get('status_code', None)
    
    # Add base domain node
    G.add_node(base_domain, type='base_domain', active=True, level=0)
    
    # Add IP nodes
    for ip in ip_to_domains:
        G.add_node(ip, type='ip', active=True, level=1)
        G.add_edge(base_domain, ip)  # Connect base domain to all IPs
    
    # Add subdomain nodes and connect to IPs
    for subdomain_info in subdomains:
        subdomain = subdomain_info['subdomain']
        
        # Skip if it's exactly the base domain
        if subdomain == base_domain:
            continue
        
        G.add_node(subdomain, type='subdomain', active=True, level=2)
        
        # Connect to its IP if known
        if subdomain in domain_to_ip:
            G.add_edge(domain_to_ip[subdomain], subdomain)
        else:
            # Connect directly to base domain if IP unknown
            G.add_edge(base_domain, subdomain)
    
    # Use a force-directed layout algorithm
    pos = nx.spring_layout(G, k=0.6, iterations=100, seed=42)
    
    # Create edge traces
    edge_traces = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        
        edge_trace = go.Scatter(
            x=[x0, x1], 
            y=[y0, y1],
            mode='lines',
            line=dict(width=0.7, color='rgba(150, 150, 150, 0.7)'),
            hoverinfo='none'
        )
        edge_traces.append(edge_trace)
    
    # Create node traces for each type of node
    domain_trace = go.Scatter(
        x=[], y=[],
        mode='markers',
        hoverinfo='text',
        marker=dict(
            color='rgba(255, 0, 0, 0.8)',
            size=18,
            line=dict(width=1, color='rgb(0, 0, 0)')
        ),
        text=[],
        name='Domain'
    )
    
    ip_trace = go.Scatter(
        x=[], y=[],
        mode='markers',
        hoverinfo='text',
        marker=dict(
            color='rgba(31, 119, 180, 0.8)',
            size=14,
            symbol='diamond',
            line=dict(width=1, color='rgb(0, 0, 0)')
        ),
        text=[],
        name='IP Address'
    )
    
    subdomain_trace = go.Scatter(
        x=[], y=[],
        mode='markers',
        hoverinfo='text',
        marker=dict(
            size=10,
            color=[],
            colorscale='Viridis',
            line=dict(width=1, color='rgb(0, 0, 0)')
        ),
        text=[],
        name='Subdomain'
    )
    
    # Status to color mapping for subdomains
    status_colors = {
        '2xx': 'rgb(0, 204, 150)',  # Green
        '3xx': 'rgb(255, 193, 7)',  # Amber
        '4xx': 'rgb(255, 87, 34)',  # Red-Orange
        '5xx': 'rgb(244, 67, 54)',  # Red
        'unknown': 'rgb(158, 158, 158)'  # Gray
    }
    
    subdomain_colors = []
    
    # Populate node traces
    for node in G.nodes():
        node_type = G.nodes[node]['type']
        x, y = pos[node]
        
        if node_type == 'base_domain':
            domain_trace['x'] += (x,)
            domain_trace['y'] += (y,)
            domain_trace['text'] += (f"Base Domain: {node}",)
            
        elif node_type == 'ip':
            ip_trace['x'] += (x,)
            ip_trace['y'] += (y,)
            
            # Add connected domains to hover text
            domains_on_ip = ip_to_domains.get(node, [])
            hover_text = f"IP: {node}<br>Hosts {len(domains_on_ip)} domains"
            ip_trace['text'] += (hover_text,)
            
        elif node_type == 'subdomain':
            subdomain_trace['x'] += (x,)
            subdomain_trace['y'] += (y,)
            
            # Get status and determine color
            status = domain_status.get(node)
            if status is None:
                color_key = 'unknown'
                hover_text = f"Subdomain: {node}<br>Status: Unknown"
            else:
                if 200 <= status < 300:
                    color_key = '2xx'
                    hover_text = f"Subdomain: {node}<br>Status: {status} (OK)"
                elif 300 <= status < 400:
                    color_key = '3xx'
                    hover_text = f"Subdomain: {node}<br>Status: {status} (Redirect)"
                elif 400 <= status < 500:
                    color_key = '4xx'
                    hover_text = f"Subdomain: {node}<br>Status: {status} (Client Error)"
                else:
                    color_key = '5xx'
                    hover_text = f"Subdomain: {node}<br>Status: {status} (Server Error)"
            
            subdomain_colors.append(status_colors[color_key])
            subdomain_trace['text'] += (hover_text,)
    
    # Set subdomain colors
    subdomain_trace.marker.color = subdomain_colors
    
    # Create the figure
    fig = go.Figure(
        data=edge_traces + [domain_trace, ip_trace, subdomain_trace],
        layout=go.Layout(
            title=dict(
                text=f"Force-Directed Network for {domain}",
                font=dict(size=16)
            ),
            showlegend=True,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            legend=dict(
                x=0,
                y=1,
                traceorder="normal",
                font=dict(
                    family="sans-serif",
                    size=12,
                    color="black"
                ),
            ),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            annotations=[
                dict(
                    showarrow=False,
                    text="IP to Domain Network Map",
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002
                )
            ]
        )
    )
    
    # Update layout for dark theme compatibility
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=600
    )
    
    return fig


def create_sunburst_chart(domain: str, subdomains: List[Dict[str, Any]]) -> go.Figure:
    """
    Create a sunburst visualization of subdomain structure.
    
    Args:
        domain: The base domain
        subdomains: List of subdomain dictionaries
        
    Returns:
        Plotly figure object
    """
    if not subdomains:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No subdomain data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Extract base domain
    base_extract = tldextract.extract(domain)
    base_domain = f"{base_extract.domain}.{base_extract.suffix}"
    
    # Create a hierarchical structure for the sunburst chart
    hierarchy_data = []
    
    # Add the base domain as the root
    hierarchy_data.append({
        'id': base_domain,
        'parent': '',
        'label': base_domain,
        'value': 1
    })
    
    # Process each subdomain
    for subdomain_info in subdomains:
        subdomain = subdomain_info['subdomain']
        
        # Skip if it's exactly the base domain
        if subdomain == base_domain:
            continue
        
        # Extract subdomain parts
        extract = tldextract.extract(subdomain)
        
        # Skip if it doesn't have the same domain and suffix
        if extract.domain != base_extract.domain or extract.suffix != base_extract.suffix:
            continue
        
        if not extract.subdomain:
            continue
        
        # Split the subdomain into parts
        parts = extract.subdomain.split('.')
        parts.reverse()  # Start from the most specific to least specific
        
        # Build the chain of parents
        current_parent = base_domain
        current_path = []
        
        for part in parts:
            current_path.append(part)
            current_id = '.'.join(reversed(current_path)) + '.' + base_domain
            
            # Add this part to the hierarchy
            hierarchy_data.append({
                'id': current_id,
                'parent': current_parent,
                'label': part,
                'value': 1
            })
            
            current_parent = current_id
    
    # Convert to DataFrame for Plotly
    df = pd.DataFrame(hierarchy_data)
    
    # Create sunburst chart
    if df.empty:
        # Return an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No subdomain hierarchy data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
    else:
        fig = px.sunburst(
            df,
            ids='id',
            parents='parent',
            names='label',
            values='value',
            title=f"Subdomain Structure for {domain}"
        )
        
        # Update layout
        fig.update_layout(
            height=700,
            margin=dict(t=50, l=0, r=0, b=0)
        )
    
    return fig
