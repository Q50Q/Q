import asyncio
import logging
import socket
import time
from typing import Dict, List, Any, Optional, Set, Tuple
import nmap

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common port categories
COMMON_PORTS = {
    'web': [80, 443, 8080, 8443],
    'mail': [25, 587, 465, 110, 995, 143, 993],
    'database': [3306, 5432, 1521, 1433, 27017, 6379, 9200],
    'file_sharing': [21, 22, 445, 139],
    'remote_access': [22, 23, 3389, 5900],
    'dns': [53, 853],
    'monitoring': [161, 162, 199],
    'voip': [5060, 5061]
}

def scan_port_range(host: str, port_range: str) -> List[Dict[str, Any]]:
    """
    Scan a range of ports on a host using python-nmap.
    
    Args:
        host: The IP address to scan
        port_range: A string representing port range (e.g., "22-100" or "80,443,8080")
        
    Returns:
        List of dictionaries containing open port information
    """
    nm = nmap.PortScanner()
    
    try:
        # Run the scan with service detection
        nm.scan(host, port_range, arguments='-sV -T4')
        
        results = []
        
        # Check if host was scanned and is up
        if host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = sorted(nm[host][proto].keys())
                
                for port in ports:
                    port_info = nm[host][proto][port]
                    # Only include open ports
                    if port_info['state'] == 'open':
                        service_name = port_info['name'] if port_info['name'] != '' else 'unknown'
                        service_version = port_info['product']
                        if port_info['version']:
                            service_version += f" {port_info['version']}"
                        
                        results.append({
                            'port': port,
                            'protocol': proto,
                            'service': service_name,
                            'version': service_version if service_version else 'Unknown'
                        })
        
        return results
    
    except Exception as e:
        logger.error(f"Error scanning {host} port range {port_range}: {str(e)}")
        return []

def get_port_range_for_profile(profile: str, custom_ports: List[int] = None) -> str:
    """
    Get a port range string based on scan profile and custom ports.
    
    Args:
        profile: Scan profile ("quick", "regular", or "comprehensive")
        custom_ports: List of custom ports to include
        
    Returns:
        Port range string for nmap
    """
    if profile == "quick":
        # Top ~100 ports
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 
                3306, 3389, 5900, 8080, 8443]
    elif profile == "regular":
        # Use nmap's top 1000 ports by using a special syntax
        return "1-1000"
    else:  # comprehensive
        # Scan all ports (1-65535)
        return "1-65535"
    
    # Add custom ports if provided
    if custom_ports:
        ports.extend(custom_ports)
    
    # Remove duplicates and sort
    ports = sorted(list(set(ports)))
    
    # Convert to comma-separated string
    return ",".join(map(str, ports))

def scan_ports(ips: List[str], scan_type: str = "quick", custom_ports: List[int] = None, max_threads: int = 5) -> List[Dict[str, Any]]:
    """
    Scan ports on multiple IP addresses.
    
    Args:
        ips: List of IP addresses to scan
        scan_type: Type of scan ("quick", "regular", or "comprehensive")
        custom_ports: List of custom ports to include
        max_threads: Maximum number of threads to use for scanning
        
    Returns:
        List of dictionaries containing scan results
    """
    results = []
    
    # Get the port range to scan
    port_range = get_port_range_for_profile(scan_type, custom_ports)
    
    # Log scan start
    logger.info(f"Starting port scan of {len(ips)} hosts with profile {scan_type}")
    
    # If we have too many IPs, use threading to scan in parallel
    if len(ips) > 1 and max_threads > 1:
        from concurrent.futures import ThreadPoolExecutor
        from functools import partial
        
        # Define a function to scan a single IP
        def scan_single_ip(ip, port_range, scan_type):
            try:
                # Scan the ports
                logger.info(f"Scanning ports for {ip} with range {port_range}")
                open_ports = scan_port_range(ip, port_range)
                
                return {
                    'ip': ip,
                    'open_ports': open_ports,
                    'scan_type': scan_type
                }
            except Exception as e:
                logger.error(f"Error scanning {ip}: {str(e)}")
                # Return empty result on error
                return {
                    'ip': ip,
                    'open_ports': [],
                    'scan_type': scan_type,
                    'error': str(e)
                }
        
        # Create a partial function with fixed arguments
        scan_func = partial(scan_single_ip, port_range=port_range, scan_type=scan_type)
        
        # Use ThreadPoolExecutor to parallelize scans
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results = list(executor.map(scan_func, ips))
    else:
        # Original sequential scanning for single IP or when max_threads is 1
        for ip in ips:
            try:
                # Scan the ports
                logger.info(f"Scanning ports for {ip} with range {port_range}")
                open_ports = scan_port_range(ip, port_range)
                
                # Add result
                results.append({
                    'ip': ip,
                    'open_ports': open_ports,
                    'scan_type': scan_type
                })
            except Exception as e:
                logger.error(f"Error scanning {ip}: {str(e)}")
                # Add empty result
                results.append({
                    'ip': ip,
                    'open_ports': [],
                    'scan_type': scan_type,
                    'error': str(e)
                })
    
    return results
