import asyncio
import concurrent.futures
import dns.resolver
import json
import re
import httpx
import tldextract
import ssl
import socket
from typing import List, Dict, Any, Set
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable SSL warnings for insecure requests
ssl._create_default_https_context = ssl._create_unverified_context

class SubdomainSource:
    """Base class for subdomain discovery sources"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        """Get subdomains for a given domain"""
        raise NotImplementedError("Subclasses must implement this method")
    
    def clean_subdomain(self, subdomain: str, base_domain: str) -> str:
        """Clean and validate a subdomain"""
        # Remove leading wildcards and whitespace
        subdomain = re.sub(r'^[\s*\.]+', '', subdomain)
        # Remove trailing whitespace
        subdomain = subdomain.rstrip()
        # Ensure the subdomain ends with the base domain
        if not subdomain.endswith(base_domain) and '.' in subdomain:
            return subdomain
        
        ext = tldextract.extract(subdomain)
        # If this doesn't have the base domain's TLD, it might not be valid
        if not subdomain.endswith(f"{ext.domain}.{ext.suffix}"):
            return ""
        
        return subdomain

class CrtshSource(SubdomainSource):
    """Certificate Transparency subdomain discovery"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        # Improved crt.sh query to get more comprehensive results
        # The '%25' acts as an SQL wildcard to match anything before the domain
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                # Enhanced user agent to avoid being blocked
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        for item in data:
                            # Sometimes crt.sh returns subdomains with wildcards
                            name_value = item.get('name_value', '')
                            # Check if it contains wildcard subdomains
                            if '*.' in name_value:
                                # Wildcards might imply there are other subdomains
                                # Try additional queries with different patterns
                                await self._query_wildcard(domain, name_value.replace('*.', ''), subdomains, client)
                            
                            # Split on wildcards, new lines, spaces
                            subdomain_list = re.split(r'[*\n\s]', name_value)
                            for subdomain in subdomain_list:
                                clean_sub = self.clean_subdomain(subdomain, domain)
                                if clean_sub:
                                    subdomains.add(clean_sub)
                    except json.JSONDecodeError:
                        logger.error(f"JSON decode error from crt.sh for {domain}")
                else:
                    logger.warning(f"crt.sh returned status code {response.status_code} for {domain}")
                
                # Try a second query with identity wildcard to get even more results
                second_url = f"https://crt.sh/?q=%.{domain}&output=json&match=identity"
                try:
                    second_response = await client.get(second_url, headers=headers)
                    if second_response.status_code == 200:
                        try:
                            data = second_response.json()
                            for item in data:
                                subdomain_list = re.split(r'[*\n\s]', item.get('name_value', ''))
                                for subdomain in subdomain_list:
                                    clean_sub = self.clean_subdomain(subdomain, domain)
                                    if clean_sub:
                                        subdomains.add(clean_sub)
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error querying crt.sh for {domain}: {str(e)}")
        
        return subdomains
    
    async def _query_wildcard(self, domain: str, wildcard_base: str, subdomains: Set[str], client) -> None:
        """Query for specific wildcard subdomains to get more results"""
        if not wildcard_base or wildcard_base == domain:
            return
            
        try:
            url = f"https://crt.sh/?q=%.{wildcard_base}&output=json"
            response = await client.get(url)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for item in data:
                        subdomain_list = re.split(r'[*\n\s]', item.get('name_value', ''))
                        for subdomain in subdomain_list:
                            clean_sub = self.clean_subdomain(subdomain, domain)
                            if clean_sub:
                                subdomains.add(clean_sub)
                except Exception:
                    pass
        except Exception:
            pass

class HackertargetSource(SubdomainSource):
    """Hackertarget.com subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    results = response.text
                    if not results or "API count exceeded" in results:
                        logger.warning(f"API limit or no results from Hackertarget for {domain}")
                    else:
                        for line in results.split('\n'):
                            if line.strip():
                                subdomain = line.split(',')[0]
                                clean_sub = self.clean_subdomain(subdomain, domain)
                                if clean_sub:
                                    subdomains.add(clean_sub)
                else:
                    logger.warning(f"Hackertarget returned status code {response.status_code} for {domain}")
        except Exception as e:
            logger.error(f"Error querying Hackertarget for {domain}: {str(e)}")
        
        return subdomains

class RapidDnsSource(SubdomainSource):
    """RapidDNS subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    # RapidDNS returns HTML, need to extract the table rows
                    pattern = r'<td>([^<]+\.%s)</td>' % re.escape(domain)
                    matches = re.findall(pattern, response.text)
                    
                    for match in matches:
                        clean_sub = self.clean_subdomain(match, domain)
                        if clean_sub:
                            subdomains.add(clean_sub)
                else:
                    logger.warning(f"RapidDNS returned status code {response.status_code} for {domain}")
        except Exception as e:
            logger.error(f"Error querying RapidDNS for {domain}: {str(e)}")
        
        return subdomains

class DnsDumpsterSource(SubdomainSource):
    """DNSDumpster subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        url = "https://dnsdumpster.com/"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                # First get the CSRF token
                response = await client.get(url)
                if response.status_code != 200:
                    logger.warning(f"DNSDumpster returned status code {response.status_code} on initial request")
                    return subdomains
                
                # Extract the CSRF token
                csrf_token = ""
                csrf_regex = r'name=["\']csrfmiddlewaretoken["\'] value=["\'](.*?)["\']'
                csrf_match = re.search(csrf_regex, response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                else:
                    logger.warning("CSRF token not found in DNSDumpster response")
                    return subdomains
                
                # Now make the POST request
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': domain,
                    'user': 'free'
                }
                headers = {
                    'Referer': url,
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
                
                response = await client.post(url, data=data, headers=headers)
                if response.status_code == 200:
                    # Extract subdomains from the HTML response
                    pattern = r'[a-zA-Z0-9][a-zA-Z0-9-_.]*\.%s' % re.escape(domain)
                    matches = re.findall(pattern, response.text)
                    
                    for match in matches:
                        clean_sub = self.clean_subdomain(match, domain)
                        if clean_sub:
                            subdomains.add(clean_sub)
                else:
                    logger.warning(f"DNSDumpster returned status code {response.status_code} for {domain}")
        except Exception as e:
            logger.error(f"Error querying DNSDumpster for {domain}: {str(e)}")
        
        return subdomains

class VirusTotalSource(SubdomainSource):
    """VirusTotal subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        url = f"https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                # VirusTotal has pagination, so we may need multiple requests
                next_page = url
                while next_page:
                    response = await client.get(next_page, headers=headers)
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            for item in data.get('data', []):
                                if 'id' in item:
                                    subdomain = item['id']
                                    clean_sub = self.clean_subdomain(subdomain, domain)
                                    if clean_sub:
                                        subdomains.add(clean_sub)
                            
                            # Check if there's a next page
                            next_page = data.get('links', {}).get('next')
                            if not next_page:
                                break
                        except json.JSONDecodeError:
                            logger.error(f"JSON decode error from VirusTotal for {domain}")
                            break
                    else:
                        logger.warning(f"VirusTotal returned status code {response.status_code} for {domain}")
                        break
        except Exception as e:
            logger.error(f"Error querying VirusTotal for {domain}: {str(e)}")
        
        return subdomains

async def resolve_domain(domain: str) -> Dict[str, str]:
    """Resolve a domain to its IP address"""
    ip = None
    try:
        # Attempt to resolve the domain
        answers = dns.resolver.resolve(domain, 'A')
        if answers:
            ip = answers[0].address
    except Exception:
        pass
    
    return {
        'subdomain': domain,
        'ip': ip,
        'source': 'DNS Resolver'
    }

class SecurityTrailsSource(SubdomainSource):
    """SecurityTrails subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # First approach: Parse SecurityTrails web content
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Referer': 'https://securitytrails.com/'
                }
                
                url = f"https://securitytrails.com/domain/{domain}/dns"
                response = await client.get(url, headers=headers, follow_redirects=True)
                
                if response.status_code == 200:
                    # Extract subdomains from the HTML response
                    pattern = r'[a-zA-Z0-9][a-zA-Z0-9-_.]*\.%s' % re.escape(domain)
                    matches = re.findall(pattern, response.text)
                    
                    for match in matches:
                        clean_sub = self.clean_subdomain(match, domain)
                        if clean_sub:
                            subdomains.add(clean_sub)
        except Exception as e:
            logger.error(f"Error querying SecurityTrails for {domain}: {str(e)}")
        
        return subdomains

class AlienVaultSource(SubdomainSource):
    """AlienVault OTX subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        for record in data.get('passive_dns', []):
                            hostname = record.get('hostname', '')
                            if hostname and domain in hostname:
                                clean_sub = self.clean_subdomain(hostname, domain)
                                if clean_sub:
                                    subdomains.add(clean_sub)
                    except json.JSONDecodeError:
                        logger.error(f"JSON decode error from AlienVault for {domain}")
                else:
                    logger.warning(f"AlienVault returned status code {response.status_code} for {domain}")
        except Exception as e:
            logger.error(f"Error querying AlienVault for {domain}: {str(e)}")
        
        return subdomains

class BufferOverSource(SubdomainSource):
    """BufferOver.run subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        records = data.get('FDNS_A', []) + data.get('RDNS', [])
                        
                        for record in records:
                            parts = record.split(',')
                            if len(parts) == 2:
                                hostname = parts[1]
                                if domain in hostname:
                                    clean_sub = self.clean_subdomain(hostname, domain)
                                    if clean_sub:
                                        subdomains.add(clean_sub)
                    except json.JSONDecodeError:
                        logger.error(f"JSON decode error from BufferOver for {domain}")
                else:
                    logger.warning(f"BufferOver returned status code {response.status_code} for {domain}")
        except Exception as e:
            logger.error(f"Error querying BufferOver for {domain}: {str(e)}")
        
        return subdomains

class ThreatMinerSource(SubdomainSource):
    """ThreatMiner subdomain finder"""
    
    async def get_subdomains(self, domain: str) -> Set[str]:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                
                response = await client.get(url, headers=headers)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data.get('status_code') == 200:
                            for subdomain in data.get('results', []):
                                clean_sub = self.clean_subdomain(subdomain, domain)
                                if clean_sub:
                                    subdomains.add(clean_sub)
                    except json.JSONDecodeError:
                        logger.error(f"JSON decode error from ThreatMiner for {domain}")
                else:
                    logger.warning(f"ThreatMiner returned status code {response.status_code} for {domain}")
        except Exception as e:
            logger.error(f"Error querying ThreatMiner for {domain}: {str(e)}")
        
        return subdomains

async def discover_subdomains_for_source(domain: str, source_name: str) -> Set[str]:
    """Discover subdomains using a specific source"""
    sources = {
        'crtsh': CrtshSource(),
        'hackertarget': HackertargetSource(),
        'rapiddns': RapidDnsSource(),
        'dnsdumper': DnsDumpsterSource(),
        'virustotal': VirusTotalSource(),
        'securitytrails': SecurityTrailsSource(),
        'alienvault': AlienVaultSource(),
        'bufferover': BufferOverSource(),
        'threatminer': ThreatMinerSource()
    }
    
    if source_name not in sources:
        logger.warning(f"Unknown source: {source_name}")
        return set()
    
    logger.info(f"Discovering subdomains for {domain} using {source_name}")
    return await sources[source_name].get_subdomains(domain)

async def _discover_subdomains_async(domain: str, sources: List[str], concurrency: int) -> List[Dict[str, Any]]:
    """Discover subdomains asynchronously from multiple sources"""
    all_subdomains = set()
    
    # Gather subdomains from all sources
    tasks = [discover_subdomains_for_source(domain, source) for source in sources]
    results = await asyncio.gather(*tasks)
    
    # Combine results from all sources
    for subdomains in results:
        all_subdomains.update(subdomains)
    
    # Add the base domain itself to the list
    all_subdomains.add(domain)
    
    # Resolve all subdomains to get IPs
    semaphore = asyncio.Semaphore(concurrency)
    
    async def resolve_with_semaphore(subdomain):
        async with semaphore:
            return await resolve_domain(subdomain)
    
    resolve_tasks = [resolve_with_semaphore(subdomain) for subdomain in all_subdomains]
    subdomain_results = await asyncio.gather(*resolve_tasks)
    
    # Filter out None results (failed resolutions)
    return [result for result in subdomain_results if result is not None]

def discover_subdomains(domain: str, sources: List[str] = None, concurrency: int = 10) -> List[Dict[str, Any]]:
    """
    Discover subdomains for a given domain from multiple sources.
    
    Args:
        domain: The base domain to discover subdomains for
        sources: List of sources to use (crtsh, hackertarget, rapiddns, dnsdumper, virustotal)
        concurrency: Number of concurrent tasks
        
    Returns:
        List of dictionaries containing subdomain information
    """
    if sources is None:
        # Use all available sources for better subdomain coverage
        sources = ['crtsh', 'hackertarget', 'rapiddns', 'dnsdumper', 'virustotal', 
                   'securitytrails', 'alienvault', 'bufferover', 'threatminer']
    
    logger.info(f"Starting subdomain discovery for {domain} using sources: {', '.join(sources)}")
    
    # Run the async function in the default event loop
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # If we're not in an event loop, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(_discover_subdomains_async(domain, sources, concurrency))
