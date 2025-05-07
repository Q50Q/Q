import asyncio
import logging
import re
import httpx
from typing import Dict, List, Any, Set
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable SSL warnings for insecure requests
ssl._create_default_https_context = ssl._create_unverified_context

# Technology fingerprints - simple version, can be expanded
TECHNOLOGY_PATTERNS = {
    # Web servers
    'nginx': {
        'headers': [
            ('server', r'nginx', 'Nginx')
        ]
    },
    'apache': {
        'headers': [
            ('server', r'apache', 'Apache')
        ]
    },
    'iis': {
        'headers': [
            ('server', r'microsoft-iis', 'Microsoft IIS')
        ]
    },
    
    # Programming languages
    'php': {
        'headers': [
            ('x-powered-by', r'php/([0-9.]+)', 'PHP {0}')
        ],
        'cookies': [
            ('phpsessid', r'', 'PHP')
        ]
    },
    'asp.net': {
        'headers': [
            ('x-powered-by', r'asp\.net', 'ASP.NET'),
            ('x-aspnet-version', r'([0-9.]+)', 'ASP.NET {0}')
        ],
        'cookies': [
            ('asp.net_sessionid', r'', 'ASP.NET')
        ]
    },
    
    # Frameworks
    'laravel': {
        'cookies': [
            ('laravel_session', r'', 'Laravel')
        ]
    },
    'django': {
        'cookies': [
            ('csrftoken', r'', 'Django')
        ]
    },
    'ruby_on_rails': {
        'headers': [
            ('x-powered-by', r'rails', 'Ruby on Rails'),
            ('server', r'mod_rails|passenger', 'Ruby on Rails')
        ]
    },
    
    # CMS
    'wordpress': {
        'html': [
            (r'wp-content|wp-includes', 'WordPress'),
            (r'<meta name="generator" content="WordPress ([0-9.]+)"', 'WordPress {0}')
        ]
    },
    'joomla': {
        'html': [
            (r'<meta name="generator" content="Joomla', 'Joomla'),
            (r'/components/com_', 'Joomla')
        ]
    },
    'drupal': {
        'html': [
            (r'Drupal.settings', 'Drupal'),
            (r'jQuery.extend\(Drupal.settings', 'Drupal')
        ]
    },
    
    # JavaScript libraries
    'jquery': {
        'html': [
            (r'jquery[.-]([0-9.]+)(?:\.min)?\.js', 'jQuery {0}'),
            (r'/([0-9.]+)/jquery(?:\.min)?\.js', 'jQuery {0}'),
            (r'jquery-([0-9.]+)(?:\.min)?\.js', 'jQuery {0}')
        ]
    },
    'react': {
        'html': [
            (r'react(?:\.production|\.development)(?:\.min)?\.js', 'React'),
            (r'react-dom(?:\.production|\.development)(?:\.min)?\.js', 'React'),
            (r'__REACT_DEVTOOLS_GLOBAL_HOOK__', 'React')
        ]
    },
    'angular': {
        'html': [
            (r'angular[.-]([0-9.]+)(?:\.min)?\.js', 'Angular {0}'),
            (r'ng-app', 'Angular'),
            (r'ng-controller', 'Angular')
        ]
    },
    'vue': {
        'html': [
            (r'vue[.-]([0-9.]+)(?:\.min)?\.js', 'Vue.js {0}'),
            (r'__vue__', 'Vue.js')
        ]
    },
    
    # Analytics
    'google_analytics': {
        'html': [
            (r'gtag\(\'js\'', 'Google Analytics'),
            (r'google-analytics.com/analytics.js', 'Google Analytics')
        ]
    },
    
    # Hosting/CDN
    'cloudflare': {
        'headers': [
            ('cf-ray', r'', 'Cloudflare')
        ]
    },
    'cloudfront': {
        'headers': [
            ('x-amz-cf-id', r'', 'Amazon CloudFront')
        ]
    },
    'aws': {
        'headers': [
            ('x-amz-', r'', 'Amazon Web Services')
        ]
    },
    
    # Security
    'waf': {
        'headers': [
            ('x-waf-', r'', 'Web Application Firewall')
        ]
    }
}

async def fingerprint_technology(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Fingerprint technologies used by a website.
    
    Args:
        url: The URL to analyze
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing the detected technologies
    """
    result = {
        'url': url,
        'technologies': []
    }
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    try:
        # Make a request to the URL
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            response = await client.get(url)
            
            if response.status_code != 200:
                logger.warning(f"Received non-200 status code ({response.status_code}) for {url}")
                return result
            
            # Parse the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            html_content = response.text
            
            detected_technologies = set()
            
            # Check headers for technology clues
            for tech_name, tech_patterns in TECHNOLOGY_PATTERNS.items():
                # Check headers
                if 'headers' in tech_patterns:
                    for header_name, pattern, tech_label in tech_patterns['headers']:
                        if header_name in response.headers:
                            header_value = response.headers[header_name]
                            match = re.search(pattern, header_value, re.IGNORECASE)
                            if match:
                                if match.groups():
                                    # Format the label with the captured version
                                    tech = tech_label.format(*match.groups())
                                else:
                                    tech = tech_label
                                detected_technologies.add(tech)
                
                # Check cookies
                if 'cookies' in tech_patterns:
                    for cookie_name, pattern, tech_label in tech_patterns['cookies']:
                        for cookie in response.cookies:
                            if cookie_name.lower() == cookie.lower():
                                detected_technologies.add(tech_label)
                
                # Check HTML content
                if 'html' in tech_patterns:
                    for pattern, tech_label in tech_patterns['html']:
                        match = re.search(pattern, html_content, re.IGNORECASE)
                        if match:
                            if '{0}' in tech_label and match.groups():
                                # Format the label with the captured version
                                tech = tech_label.format(*match.groups())
                            else:
                                tech = tech_label
                            detected_technologies.add(tech)
            
            # Check for common JS frameworks by analyzing script tags
            script_tags = soup.find_all('script', src=True)
            for script in script_tags:
                src = script['src']
                
                # Additional framework detection from script sources
                if 'bootstrap' in src:
                    match = re.search(r'bootstrap[.-]?([0-9.]+)', src)
                    if match:
                        detected_technologies.add(f"Bootstrap {match.group(1)}")
                    else:
                        detected_technologies.add("Bootstrap")
                
                if 'tailwind' in src:
                    detected_technologies.add("Tailwind CSS")
                
                if 'materialize' in src:
                    detected_technologies.add("Materialize CSS")
            
            # Check meta tags for generator information
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                content = meta_generator.get('content')
                if 'wordpress' in content.lower():
                    match = re.search(r'WordPress ([0-9.]+)', content)
                    if match:
                        detected_technologies.add(f"WordPress {match.group(1)}")
                elif 'joomla' in content.lower():
                    detected_technologies.add("Joomla")
                elif 'drupal' in content.lower():
                    detected_technologies.add("Drupal")
                elif 'wix' in content.lower():
                    detected_technologies.add("Wix")
                elif 'shopify' in content.lower():
                    detected_technologies.add("Shopify")
                else:
                    # Add the generator content if it's not one of the known CMSes
                    detected_technologies.add(f"Generator: {content}")
            
            # Store the detected technologies
            result['technologies'] = sorted(list(detected_technologies))
            
    except Exception as e:
        logger.error(f"Error fingerprinting {url}: {str(e)}")
    
    return result

async def _fingerprint_technologies_async(urls: List[str], concurrency: int = 10) -> List[Dict[str, Any]]:
    """
    Fingerprint technologies used by multiple websites asynchronously.
    
    Args:
        urls: List of URLs to analyze
        concurrency: Maximum number of concurrent requests
        
    Returns:
        List of dictionaries containing detected technologies
    """
    # Use semaphore to limit concurrency
    semaphore = asyncio.Semaphore(concurrency)
    
    async def fingerprint_with_semaphore(url):
        async with semaphore:
            return await fingerprint_technology(url)
    
    # Create tasks for all URLs
    tasks = [fingerprint_with_semaphore(url) for url in urls]
    
    # Run all tasks concurrently and gather results
    results = await asyncio.gather(*tasks)
    
    return results

def fingerprint_technologies(urls: List[str], concurrency: int = 10) -> List[Dict[str, Any]]:
    """
    Fingerprint technologies used by multiple websites.
    
    Args:
        urls: List of URLs to analyze
        concurrency: Maximum number of concurrent requests
        
    Returns:
        List of dictionaries containing detected technologies
    """
    # Run the async function in the default event loop
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # If we're not in an event loop, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(_fingerprint_technologies_async(urls, concurrency))
