import re
import os
import json
import tldextract
from typing import Dict, List, Any, Optional, Tuple
import ipaddress
import logging
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name.
    
    Args:
        domain: The domain to validate
        
    Returns:
        True if valid, False otherwise
    """
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://', 1)[1]
    
    # Remove path and query string if present
    domain = domain.split('/', 1)[0]
    
    # Use tldextract to validate domain
    extract = tldextract.extract(domain)
    
    # A valid domain must have both a domain name and a suffix
    if extract.domain and extract.suffix:
        return True
    
    return False

def get_base_domain(domain: str) -> str:
    """
    Get the base domain (without subdomain) from a domain string.
    
    Args:
        domain: The domain to process
        
    Returns:
        Base domain (e.g., example.com from sub.example.com)
    """
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://', 1)[1]
    
    # Remove path and query string if present
    domain = domain.split('/', 1)[0]
    
    # Extract the base domain
    extract = tldextract.extract(domain)
    
    return f"{extract.domain}.{extract.suffix}"

def is_ip_address(value: str) -> bool:
    """
    Check if a string is a valid IP address.
    
    Args:
        value: The string to check
        
    Returns:
        True if it's a valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def get_domain_parts(domain: str) -> Tuple[str, str, str]:
    """
    Split a domain into its parts: subdomain, domain, and suffix.
    
    Args:
        domain: The domain to split
        
    Returns:
        Tuple of (subdomain, domain, suffix)
    """
    extract = tldextract.extract(domain)
    return extract.subdomain, extract.domain, extract.suffix

def categorize_ports(port: int) -> str:
    """
    Categorize a port number into a service type.
    
    Args:
        port: Port number
        
    Returns:
        Category name
    """
    port_categories = {
        'web': [80, 443, 8080, 8443, 8000, 8888, 3000],
        'mail': [25, 465, 587, 110, 143, 993, 995],
        'dns': [53, 853],
        'ftp': [20, 21],
        'ssh': [22],
        'telnet': [23],
        'smb': [139, 445],
        'rdp': [3389],
        'database': [1433, 1521, 3306, 5432, 6379, 27017],
        'ldap': [389, 636],
        'monitoring': [161, 162, 199, 1098, 1099],
        'vpn': [1194, 1723, 500],
        'voip': [5060, 5061]
    }
    
    for category, ports in port_categories.items():
        if port in ports:
            return category
    
    return 'other'

def is_same_domain(domain1: str, domain2: str) -> bool:
    """
    Check if two domains have the same base domain.
    
    Args:
        domain1: First domain
        domain2: Second domain
        
    Returns:
        True if they have the same base domain, False otherwise
    """
    base1 = get_base_domain(domain1)
    base2 = get_base_domain(domain2)
    
    return base1 == base2

def extract_ip_from_url(url: str) -> Optional[str]:
    """
    Extract IP address from URL if present.
    
    Args:
        url: URL to parse
        
    Returns:
        IP address if found, None otherwise
    """
    # Check if URL contains an IP address
    ip_pattern = r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    match = re.search(ip_pattern, url)
    
    if match:
        ip = match.group(1)
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            pass
    
    return None



