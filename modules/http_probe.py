import asyncio
import httpx
import logging
import re
import socket
import ssl
from typing import Dict, List, Any, Optional, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable SSL warnings for insecure requests
ssl._create_default_https_context = ssl._create_unverified_context

async def probe_domain(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Probe a domain for HTTP/HTTPS service and analyze the response.
    
    Args:
        domain: The domain to probe
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing the probe results
    """
    result = {
        'url': domain,
        'ip': None,
        'status_code': None,
        'title': None,
        'protocol': None,
        'content_type': None,
        'server': None,
        'redirect_url': None,
        'headers': {},
        'response_time': None,
    }
    
    # Ensure domain has a scheme
    if not domain.startswith(('http://', 'https://')):
        # First try HTTPS
        urls_to_try = [f'https://{domain}', f'http://{domain}']
    else:
        urls_to_try = [domain]
    
    client = httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False  # Disable SSL verification for speed
    )
    
    try:
        # Try to resolve the domain to get IP
        try:
            ip = socket.gethostbyname(domain.split('://')[-1].split('/')[0])
            result['ip'] = ip
        except:
            pass
        
        # Try each URL (HTTPS first, then HTTP if needed)
        for url in urls_to_try:
            protocol = 'https' if url.startswith('https://') else 'http'
            
            try:
                start_time = asyncio.get_event_loop().time()
                response = await client.get(url)
                end_time = asyncio.get_event_loop().time()
                
                # Record the response time
                result['response_time'] = round((end_time - start_time) * 1000)  # in ms
                
                # Get the final URL after redirects
                final_url = str(response.url)
                if final_url != url:
                    result['redirect_url'] = final_url
                
                # Update the result with response data
                result['url'] = url
                result['status_code'] = response.status_code
                result['protocol'] = protocol
                result['headers'] = dict(response.headers)
                
                # Extract content type
                if 'content-type' in response.headers:
                    result['content_type'] = response.headers['content-type']
                
                # Extract server information
                if 'server' in response.headers:
                    result['server'] = response.headers['server']
                
                # Extract page title if HTML response
                if result['content_type'] and 'text/html' in result['content_type']:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        result['title'] = title_tag.string.strip()
                
                # Found a working URL, no need to try alternatives
                break
            
            except httpx.TimeoutException:
                logger.debug(f"Timeout connecting to {url}")
                # Continue to the next URL to try
            
            except Exception as e:
                logger.debug(f"Error connecting to {url}: {str(e)}")
                # Continue to the next URL to try
    
    except Exception as e:
        logger.error(f"Error probing {domain}: {str(e)}")
    
    finally:
        await client.aclose()
    
    return result

async def _probe_domains_async(domains: List[str], timeout: int = 5, concurrency: int = 10) -> List[Dict[str, Any]]:
    """
    Probe multiple domains asynchronously.
    
    Args:
        domains: List of domains to probe
        timeout: Request timeout in seconds
        concurrency: Maximum number of concurrent requests
        
    Returns:
        List of dictionaries containing probe results
    """
    # Use a semaphore to limit concurrency
    semaphore = asyncio.Semaphore(concurrency)
    
    async def probe_with_semaphore(domain):
        async with semaphore:
            return await probe_domain(domain, timeout)
    
    # Create tasks for all domains
    tasks = [probe_with_semaphore(domain) for domain in domains]
    
    # Run all tasks concurrently and gather results
    results = await asyncio.gather(*tasks)
    
    return results

def probe_domains(domains: List[str], timeout: int = 5, concurrency: int = 10) -> List[Dict[str, Any]]:
    """
    Probe multiple domains for HTTP/HTTPS services.
    
    Args:
        domains: List of domains to probe
        timeout: Request timeout in seconds
        concurrency: Maximum number of concurrent requests
        
    Returns:
        List of dictionaries containing probe results
    """
    # Run the async function in the default event loop
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # If we're not in an event loop, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(_probe_domains_async(domains, timeout, concurrency))
