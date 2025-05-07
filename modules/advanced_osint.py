import dns.resolver
import dns.exception
import ssl
import socket
import whois
import json
import time
import requests
import re
import OpenSSL
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional, Tuple, Set

class AdvancedOSINT:
    """
    Advanced Open Source Intelligence (OSINT) module for comprehensive domain analysis.
    This module focuses only on the target domain and provides cutting-edge reconnaissance.
    """
    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        """
        Initialize the OSINT module with configuration options.
        
        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent for requests
        """
        self.timeout = timeout
        self.user_agent = user_agent or "DomainRecon/1.0"
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close"
        }
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a target domain.
        
        Args:
            domain: The domain to analyze
            
        Returns:
            Dictionary containing all gathered intelligence
        """
        result = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
        }
        
        # Perform DNS record analysis
        result["dns_records"] = self.analyze_dns_records(domain)
        
        # Perform SSL certificate analysis
        result["ssl_certificate"] = self.analyze_ssl_certificate(domain)
        
        # Analyze WHOIS information
        result["whois_info"] = self.analyze_whois_information(domain)
        
        # Analyze security headers
        result["security_headers"] = self.analyze_security_headers(domain)
        
        # Analyze website
        result["website_analysis"] = self.analyze_website_resources(domain)
        
        # Analyze technology stack
        result["technology_stack"] = self.analyze_technology_stack(domain)
        
        # Analyze email security
        result["email_security"] = self.analyze_email_security(domain)
        
        # Network information
        result["network_info"] = self.analyze_network_information(domain)
        
        return result
        
    def analyze_dns_records(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS record analysis."""
        results = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "dmarc_policy": None,
            "spf_record": None,
            "dkim_records": []
        }
        
        # Try to get A records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            results["a_records"] = [answer.address for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Try to get AAAA records (IPv6)
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            results["aaaa_records"] = [answer.address for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Try to get MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            results["mx_records"] = [{
                "preference": answer.preference,
                "exchange": str(answer.exchange)
            } for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Try to get NS records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            results["ns_records"] = [str(answer.target) for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Try to get TXT records and identify SPF
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for answer in answers:
                txt_string = str(answer).strip('"')
                results["txt_records"].append(txt_string)
                
                # Check if it's an SPF record
                if txt_string.startswith('v=spf1'):
                    results["spf_record"] = {
                        "record": txt_string,
                        "includes": re.findall(r'include:([^ ]+)', txt_string),
                        "ips": re.findall(r'ip4:([^ ]+)', txt_string) + re.findall(r'ip6:([^ ]+)', txt_string),
                        "all_policy": re.search(r'[~\-+?]all', txt_string).group(0) if re.search(r'[~\-+?]all', txt_string) else None
                    }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Try to get CNAME records
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            results["cname_records"] = [str(answer.target) for answer in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Try to get DMARC record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for answer in answers:
                txt_string = str(answer).strip('"')
                if txt_string.startswith('v=DMARC1'):
                    policy_match = re.search(r'p=([^;]+)', txt_string)
                    sub_policy_match = re.search(r'sp=([^;]+)', txt_string)
                    pct_match = re.search(r'pct=([^;]+)', txt_string)
                    rua_match = re.search(r'rua=([^;]+)', txt_string)
                    ruf_match = re.search(r'ruf=([^;]+)', txt_string)
                    
                    results["dmarc_policy"] = {
                        "record": txt_string,
                        "policy": policy_match.group(1) if policy_match else None,
                        "subdomain_policy": sub_policy_match.group(1) if sub_policy_match else None,
                        "percent": pct_match.group(1) if pct_match else "100",
                        "aggregate_reports": rua_match.group(1) if rua_match else None,
                        "forensic_reports": ruf_match.group(1) if ruf_match else None
                    }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Try to find DKIM records for common selectors
        common_selectors = ["default", "dkim", "k1", "selector1", "selector2", "google", "mail"]
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for answer in answers:
                    txt_string = str(answer).strip('"')
                    if "v=DKIM1" in txt_string:
                        results["dkim_records"].append({
                            "selector": selector,
                            "record": txt_string
                        })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
        
        return results
    
    def analyze_ssl_certificate(self, domain: str) -> Optional[Dict[str, Any]]:
        """Analyze the SSL certificate for the domain."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_binary = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)
                    
                    # Extract cipher information
                    cipher = ssock.cipher()
                    
                    # Extract certificate information with proper error handling
                    try:
                        not_before = datetime.strptime(cert.get('notBefore', ''), "%b %d %H:%M:%S %Y %Z") if cert.get('notBefore') else datetime.now()
                        not_after = datetime.strptime(cert.get('notAfter', ''), "%b %d %H:%M:%S %Y %Z") if cert.get('notAfter') else datetime.now()
                    except (ValueError, TypeError):
                        # Handle date parsing errors
                        not_before = datetime.now()
                        not_after = datetime.now()
                    
                    # Get Subject Alternative Names
                    san = []
                    if cert and 'subjectAltName' in cert:
                        for item in cert.get('subjectAltName', []):
                            if item and len(item) > 1 and item[0].lower() == 'dns':
                                san.append(item[1])
                    
                    # Get subject components with proper error handling
                    subject = {}
                    issuer = {}
                    
                    if cert and 'subject' in cert and cert['subject']:
                        try:
                            subject = dict(item[0] for item in cert.get('subject', []) if item and len(item) > 0)
                        except (ValueError, TypeError, AttributeError, IndexError):
                            subject = {}
                            
                    if cert and 'issuer' in cert and cert['issuer']:
                        try:
                            issuer = dict(item[0] for item in cert.get('issuer', []) if item and len(item) > 0)
                        except (ValueError, TypeError, AttributeError, IndexError):
                            issuer = {}
                    
                    # Get certificate fingerprints with proper error handling
                    try:
                        fingerprint_sha1 = x509.digest('sha1').decode('ascii')
                        fingerprint_sha256 = x509.digest('sha256').decode('ascii')
                        signature_algorithm = x509.get_signature_algorithm().decode('ascii')
                        version = x509.get_version()
                        serial_number = f"{x509.get_serial_number():x}"
                    except (AttributeError, ValueError, TypeError, Exception):
                        # Handle errors with certificate attributes
                        fingerprint_sha1 = "unknown"
                        fingerprint_sha256 = "unknown"
                        signature_algorithm = "unknown"
                        version = 0
                        serial_number = "unknown"
                    
                    # Verify certificate chain
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = True
                        context.verify_mode = ssl.CERT_REQUIRED
                        with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                is_valid = True
                    except (ssl.SSLError, socket.error, socket.timeout, ConnectionRefusedError, ValueError, TypeError):
                        is_valid = False
                    
                    # Validate cipher information
                    if cipher and len(cipher) >= 3:
                        cipher_name = cipher[0]
                        cipher_version = cipher[1]
                        cipher_bits = cipher[2]
                    else:
                        cipher_name = "unknown"
                        cipher_version = "unknown"
                        cipher_bits = 0
                    
                    # Calculate days remaining with error handling
                    try:
                        days_remaining = (not_after - datetime.now()).days
                        is_expired = datetime.now() > not_after
                    except (TypeError, ValueError):
                        days_remaining = 0
                        is_expired = True
                    
                    return {
                        "is_valid": is_valid,
                        "subject": subject,
                        "issuer": issuer,
                        "version": version,
                        "serial_number": serial_number,
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_remaining": days_remaining,
                        "subject_alt_names": san,
                        "cipher_suite": {
                            "name": cipher_name,
                            "version": cipher_version,
                            "bits": cipher_bits
                        },
                        "fingerprints": {
                            "sha1": fingerprint_sha1,
                            "sha256": fingerprint_sha256
                        },
                        "signature_algorithm": signature_algorithm,
                        "is_extended_validation": "jurisdictionC" in subject or "businessCategory" in subject,
                        "is_expired": is_expired,
                        "is_self_signed": subject == issuer
                    }
            
        except (socket.gaierror, socket.timeout, ConnectionRefusedError, ssl.SSLError, ValueError, TypeError):
            # SSL is not available or other error occurred
            return None
    
    def analyze_whois_information(self, domain: str) -> Dict[str, Any]:
        """Analyze WHOIS information for the domain."""
        try:
            whois_info = whois.whois(domain)
            result = {
                "registrar": whois_info.registrar,
                "creation_date": self._format_whois_date(whois_info.creation_date),
                "expiration_date": self._format_whois_date(whois_info.expiration_date),
                "last_updated": self._format_whois_date(whois_info.updated_date),
                "name_servers": whois_info.name_servers if isinstance(whois_info.name_servers, list) else [whois_info.name_servers] if whois_info.name_servers else [],
                "status": whois_info.status if isinstance(whois_info.status, list) else [whois_info.status] if whois_info.status else [],
                "emails": whois_info.emails if isinstance(whois_info.emails, list) else [whois_info.emails] if whois_info.emails else [],
                "org": whois_info.org,
                "country": whois_info.country,
                "privacy_protected": self._is_privacy_protected(whois_info),
                "days_until_expiration": self._calculate_days_until_expiration(whois_info.expiration_date),
                "registration_age_days": self._calculate_registration_age(whois_info.creation_date)
            }
            
            return result
        except Exception:
            return {
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
                "last_updated": None,
                "name_servers": [],
                "status": [],
                "emails": [],
                "org": None,
                "country": None,
                "privacy_protected": None,
                "days_until_expiration": None,
                "registration_age_days": None,
                "error": "Failed to retrieve WHOIS information"
            }
    
    def analyze_security_headers(self, domain: str) -> Dict[str, Any]:
        """Analyze security headers for the domain."""
        try:
            urls = [f"https://{domain}", f"http://{domain}"]
            for url in urls:
                try:
                    response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
                    if 200 <= response.status_code < 400:
                        headers = response.headers
                        
                        # Extract security headers
                        return {
                            "content_security_policy": headers.get("Content-Security-Policy"),
                            "strict_transport_security": headers.get("Strict-Transport-Security"),
                            "x_content_type_options": headers.get("X-Content-Type-Options"),
                            "x_frame_options": headers.get("X-Frame-Options"),
                            "x_xss_protection": headers.get("X-XSS-Protection"),
                            "referrer_policy": headers.get("Referrer-Policy"),
                            "permissions_policy": headers.get("Permissions-Policy") or headers.get("Feature-Policy"),
                            "server": headers.get("Server"),
                            "status_code": response.status_code,
                            "protocol": url.split("://")[0],
                            "security_txt": self._check_security_txt(domain),
                            "grade": self._grade_security_headers({
                                "Content-Security-Policy": headers.get("Content-Security-Policy"),
                                "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
                                "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
                                "X-Frame-Options": headers.get("X-Frame-Options"),
                                "X-XSS-Protection": headers.get("X-XSS-Protection"),
                                "Referrer-Policy": headers.get("Referrer-Policy"),
                                "Permissions-Policy": headers.get("Permissions-Policy") or headers.get("Feature-Policy")
                            })
                        }
                except (requests.RequestException, ConnectionError):
                    continue
        except Exception:
            pass
        
        return {
            "content_security_policy": None,
            "strict_transport_security": None,
            "x_content_type_options": None,
            "x_frame_options": None,
            "x_xss_protection": None,
            "referrer_policy": None,
            "permissions_policy": None,
            "server": None,
            "status_code": None,
            "protocol": None,
            "security_txt": None,
            "grade": "F"
        }
    
    def analyze_website_resources(self, domain: str) -> Dict[str, Any]:
        """Analyze website resources like robots.txt and sitemap.xml."""
        result = {
            "robots_txt": None,
            "sitemap_xml": None,
            "disallowed_paths": [],
            "allowed_paths": [],
            "sitemaps_in_robots": []
        }
        
        # Check robots.txt
        try:
            robots_url = f"https://{domain}/robots.txt"
            response = requests.get(robots_url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                result["robots_txt"] = robots_url
                
                # Parse robots.txt
                for line in response.text.split('\n'):
                    line = line.strip()
                    
                    # Look for Disallow directives
                    if line.startswith('Disallow:'):
                        path = line[len('Disallow:'):].strip()
                        if path:
                            result["disallowed_paths"].append(path)
                    
                    # Look for Allow directives
                    elif line.startswith('Allow:'):
                        path = line[len('Allow:'):].strip()
                        if path:
                            result["allowed_paths"].append(path)
                    
                    # Look for Sitemap directives
                    elif line.startswith('Sitemap:'):
                        sitemap_url = line[len('Sitemap:'):].strip()
                        if sitemap_url:
                            result["sitemaps_in_robots"].append(sitemap_url)
        except (requests.RequestException, ConnectionError):
            # Try HTTP if HTTPS fails
            try:
                robots_url = f"http://{domain}/robots.txt"
                response = requests.get(robots_url, headers=self.headers, timeout=self.timeout)
                if response.status_code == 200:
                    result["robots_txt"] = robots_url
                    
                    # Parse robots.txt
                    for line in response.text.split('\n'):
                        line = line.strip()
                        
                        # Look for Disallow directives
                        if line.startswith('Disallow:'):
                            path = line[len('Disallow:'):].strip()
                            if path:
                                result["disallowed_paths"].append(path)
                        
                        # Look for Allow directives
                        elif line.startswith('Allow:'):
                            path = line[len('Allow:'):].strip()
                            if path:
                                result["allowed_paths"].append(path)
                        
                        # Look for Sitemap directives
                        elif line.startswith('Sitemap:'):
                            sitemap_url = line[len('Sitemap:'):].strip()
                            if sitemap_url:
                                result["sitemaps_in_robots"].append(sitemap_url)
            except (requests.RequestException, ConnectionError):
                pass
        
        # Check sitemap.xml
        try:
            sitemap_url = f"https://{domain}/sitemap.xml"
            response = requests.get(sitemap_url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                result["sitemap_xml"] = sitemap_url
        except (requests.RequestException, ConnectionError):
            # Try HTTP if HTTPS fails
            try:
                sitemap_url = f"http://{domain}/sitemap.xml"
                response = requests.get(sitemap_url, headers=self.headers, timeout=self.timeout)
                if response.status_code == 200:
                    result["sitemap_xml"] = sitemap_url
            except (requests.RequestException, ConnectionError):
                pass
        
        return result
    
    def analyze_technology_stack(self, domain: str) -> Dict[str, Any]:
        """Analyze technology stack of the domain."""
        result = {
            "web_server": None,
            "cloud_provider": None,
            "cdn": None,
            "cms": None,
            "waf": None,
            "javascript_frameworks": [],
            "analytics": [],
            "advertising": [],
            "technologies": [],
        }
        
        try:
            # Try HTTPS first
            url = f"https://{domain}"
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            # If HTTPS fails, try HTTP
            if response.status_code >= 400:
                url = f"http://{domain}"
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            # Extract server header
            server_header = response.headers.get('Server')
            if server_header:
                result["web_server"] = server_header
            
            # Check for CDN headers
            cdn_headers = {
                'Cloudflare': ['cf-ray', 'cf-cache-status'],
                'Akamai': ['x-akamai-transformed'],
                'Fastly': ['fastly-io-info'],
                'CloudFront': ['x-amz-cf-id'],
                'Sucuri': ['x-sucuri-id'],
                'Incapsula': ['x-iinfo'],
                'KeyCDN': ['x-cdn'],
                'StackPath': ['x-sp-edge']
            }
            
            for cdn, headers in cdn_headers.items():
                for header in headers:
                    if header.lower() in [h.lower() for h in response.headers.keys()]:
                        result["cdn"] = cdn
                        break
                if result["cdn"]:
                    break
            
            # Check for WAF headers and signatures
            waf_signatures = {
                'Cloudflare': ['cf-ray'],
                'ModSecurity': ['mod_security'],
                'AWS WAF': ['x-amzn-waf-'],
                'Sucuri': ['x-sucuri-id'],
                'Incapsula': ['x-iinfo', '_incap_'],
                'F5 ASM': ['x-wa-info'],
                'Akamai': ['akamai']
            }
            
            for waf, signatures in waf_signatures.items():
                for signature in signatures:
                    header_match = any(signature.lower() in h.lower() for h in response.headers.keys())
                    content_match = signature.lower() in response.text.lower()
                    if header_match or content_match:
                        result["waf"] = waf
                        break
                if result["waf"]:
                    break
            
            # Check for cloud provider signatures
            cloud_signatures = {
                'AWS': ['amazonaws.com', 'aws.amazon.com', 'x-amz-'],
                'Google Cloud': ['googleusercontent.com', 'storage.googleapis.com'],
                'Microsoft Azure': ['azure.com', 'windowsazure.com', 'msecnd.net'],
                'DigitalOcean': ['digitalocean.com'],
                'Heroku': ['herokuapp.com'],
                'Oracle Cloud': ['oraclecloud.com']
            }
            
            for provider, signatures in cloud_signatures.items():
                for signature in signatures:
                    header_match = any(signature.lower() in str(v).lower() for k, v in response.headers.items())
                    content_match = signature.lower() in response.text.lower()
                    url_match = signature.lower() in url.lower()
                    
                    if header_match or content_match or url_match:
                        result["cloud_provider"] = provider
                        break
                if result["cloud_provider"]:
                    break
            
            # Check for CMS signatures
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', '/wp-', 'wordpress'],
                'Joomla': ['joomla', '/administrator'],
                'Drupal': ['drupal', 'sites/default/files', 'sites/all/themes'],
                'Magento': ['magento', 'skin/frontend'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'Wix': ['wix.com', '_wix'],
                'Squarespace': ['squarespace.com', 'static.squarespace.com']
            }
            
            for cms, signatures in cms_signatures.items():
                for signature in signatures:
                    if signature.lower() in response.text.lower():
                        result["cms"] = cms
                        break
                if result["cms"]:
                    break
            
            # Check for JavaScript frameworks
            js_frameworks = {
                'React': ['react.js', 'react-dom'],
                'Angular': ['angular.js', 'ng-app', 'ng-controller'],
                'Vue.js': ['vue.js', 'data-v-'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap.min.js', 'bootstrap.css'],
                'Modernizr': ['modernizr'],
                'Ember.js': ['ember.js']
            }
            
            for framework, signatures in js_frameworks.items():
                for signature in signatures:
                    if signature.lower() in response.text.lower():
                        result["javascript_frameworks"].append(framework)
                        break
            
            # Check for analytics tools
            analytics_tools = {
                'Google Analytics': ['google-analytics.com', 'ga.js', 'analytics.js', 'gtag'],
                'Hotjar': ['hotjar.com', 'static.hotjar.com'],
                'Mixpanel': ['mixpanel.com', 'mixpanel.init'],
                'New Relic': ['newrelic.com', 'nr-data.net'],
                'Adobe Analytics': ['sc.omtrdc.net', 's_code.js'],
                'Matomo': ['matomo.js', 'piwik.js']
            }
            
            for tool, signatures in analytics_tools.items():
                for signature in signatures:
                    if signature.lower() in response.text.lower():
                        result["analytics"].append(tool)
                        break
            
            # Check for advertising platforms
            ad_platforms = {
                'Google AdSense': ['adsbygoogle.js', 'googlesyndication.com'],
                'Google Ad Manager': ['doubleclick.net', 'googletagservices.com'],
                'Facebook Ads': ['connect.facebook.net/en_US/fbevents.js'],
                'Amazon Associates': ['amazon-adsystem.com'],
                'Taboola': ['taboola.com'],
                'Outbrain': ['outbrain.com']
            }
            
            for platform, signatures in ad_platforms.items():
                for signature in signatures:
                    if signature.lower() in response.text.lower():
                        result["advertising"].append(platform)
                        break
            
            # Additional technologies
            tech_signatures = {
                'Font Awesome': ['font-awesome'],
                'Google Fonts': ['fonts.googleapis.com'],
                'Cloudflare': ['cloudflare.com'],
                'reCAPTCHA': ['recaptcha'],
                'Stripe': ['js.stripe.com'],
                'PayPal': ['paypal.com'],
                'Google Maps': ['maps.googleapis.com'],
                'Vimeo': ['vimeo.com'],
                'YouTube': ['youtube.com']
            }
            
            for tech, signatures in tech_signatures.items():
                for signature in signatures:
                    if signature.lower() in response.text.lower():
                        result["technologies"].append(tech)
                        break
            
        except (requests.RequestException, ConnectionError):
            pass
        
        return result
    
    def analyze_email_security(self, domain: str) -> Dict[str, Any]:
        """Analyze email security configurations."""
        result = {
            "has_spf": False,
            "has_dmarc": False,
            "has_dkim": False,
            "spf_policy": None,
            "dmarc_policy": None,
            "dkim_selectors": [],
            "mx_records": [],
            "email_provider": None
        }
        
        # Check SPF record
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for answer in answers:
                txt_string = str(answer).strip('"')
                if txt_string.startswith('v=spf1'):
                    result["has_spf"] = True
                    
                    # Determine SPF policy
                    if ' -all' in txt_string:
                        result["spf_policy"] = "strict"
                    elif ' ~all' in txt_string:
                        result["spf_policy"] = "soft fail"
                    elif ' ?all' in txt_string:
                        result["spf_policy"] = "neutral"
                    elif ' +all' in txt_string:
                        result["spf_policy"] = "allow all (insecure)"
                    else:
                        result["spf_policy"] = "unknown"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Check DMARC record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for answer in answers:
                txt_string = str(answer).strip('"')
                if txt_string.startswith('v=DMARC1'):
                    result["has_dmarc"] = True
                    
                    # Determine DMARC policy
                    policy_match = re.search(r'p=([^;]+)', txt_string)
                    if policy_match:
                        result["dmarc_policy"] = policy_match.group(1)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        # Check DKIM records
        common_selectors = ["default", "dkim", "k1", "selector1", "selector2", "google", "mail"]
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for answer in answers:
                    txt_string = str(answer).strip('"')
                    if "v=DKIM1" in txt_string:
                        result["has_dkim"] = True
                        result["dkim_selectors"].append(selector)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
        
        # Check MX records to determine email provider
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for answer in answers:
                exchange = str(answer.exchange).lower()
                result["mx_records"].append({
                    "preference": answer.preference,
                    "exchange": exchange
                })
                
                # Identify popular email providers
                if "google" in exchange or "gmail" in exchange or "googlemail" in exchange:
                    result["email_provider"] = "Google Workspace"
                elif "microsoft" in exchange or "outlook" in exchange or "hotmail" in exchange:
                    result["email_provider"] = "Microsoft 365"
                elif "protonmail" in exchange:
                    result["email_provider"] = "ProtonMail"
                elif "zoho" in exchange:
                    result["email_provider"] = "Zoho Mail"
                elif "mail.protection.outlook.com" in exchange:
                    result["email_provider"] = "Microsoft Exchange Online"
                elif "amazonses" in exchange or "aws" in exchange:
                    result["email_provider"] = "Amazon SES"
                elif "mailgun" in exchange:
                    result["email_provider"] = "Mailgun"
                elif "sendgrid" in exchange:
                    result["email_provider"] = "SendGrid"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        
        return result
    
    def analyze_network_information(self, domain: str) -> Dict[str, Any]:
        """Analyze network information for the domain."""
        result = {
            "ip_addresses": [],
            "asn": None,
            "asn_org": None,
            "country": None,
            "hosting_provider": None
        }
        
        # First get IP addresses
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            result["ip_addresses"] = ip_addresses
            
            if ip_addresses:
                main_ip = ip_addresses[0]
                
                # Try to get ASN information
                try:
                    # Use ipinfo.io API
                    response = requests.get(f"https://ipinfo.io/{main_ip}/json", timeout=self.timeout)
                    if response.status_code == 200:
                        data = response.json()
                        result["asn"] = data.get("org", "").split()[0].replace("AS", "") if "org" in data else None
                        result["asn_org"] = " ".join(data.get("org", "").split()[1:]) if "org" in data else None
                        result["country"] = data.get("country")
                        result["hosting_provider"] = result["asn_org"]
                except (requests.RequestException, ValueError):
                    pass
        except (socket.gaierror, socket.herror):
            pass
        
        return result
    
    def _format_whois_date(self, date_value) -> Optional[str]:
        """Format WHOIS date values consistently."""
        if not date_value:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value.isoformat()
        
        return str(date_value)
    
    def _is_privacy_protected(self, whois_info) -> bool:
        """Determine if WHOIS privacy protection is enabled."""
        privacy_keywords = [
            "privacy", "private", "redacted", "protected", "withheld",
            "proxy", "whoisguard", "guard", "privacy.link"
        ]
        
        fields_to_check = [
            whois_info.registrant,
            whois_info.admin,
            whois_info.tech,
            str(whois_info.emails).lower() if whois_info.emails else "",
            str(whois_info.name).lower() if whois_info.name else "",
            str(whois_info.org).lower() if whois_info.org else ""
        ]
        
        for field in fields_to_check:
            if field:
                field_str = str(field).lower()
                if any(keyword in field_str for keyword in privacy_keywords):
                    return True
        
        return False
    
    def _calculate_days_until_expiration(self, expiration_date) -> Optional[int]:
        """Calculate days until domain expiration."""
        if not expiration_date:
            return None
        
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        if isinstance(expiration_date, datetime):
            return (expiration_date - datetime.now()).days
        
        return None
    
    def _calculate_registration_age(self, creation_date) -> Optional[int]:
        """Calculate domain registration age in days."""
        if not creation_date:
            return None
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if isinstance(creation_date, datetime):
            return (datetime.now() - creation_date).days
        
        return None
    
    def _check_security_txt(self, domain: str) -> Optional[str]:
        """Check if the domain has a security.txt file."""
        security_txt_locations = [
            f"https://{domain}/.well-known/security.txt",
            f"https://{domain}/security.txt",
            f"http://{domain}/.well-known/security.txt",
            f"http://{domain}/security.txt"
        ]
        
        for location in security_txt_locations:
            try:
                response = requests.get(location, headers=self.headers, timeout=self.timeout)
                if response.status_code == 200:
                    return location
            except (requests.RequestException, ConnectionError):
                continue
        
        return None
    
    def _grade_security_headers(self, headers: Dict[str, Any]) -> str:
        """Grade security headers implementation."""
        grade_points = 0
        max_points = 7  # One point for each important security header
        
        # Content-Security-Policy
        if headers.get("Content-Security-Policy"):
            grade_points += 1
        
        # Strict-Transport-Security
        if headers.get("Strict-Transport-Security"):
            grade_points += 1
        
        # X-Content-Type-Options
        if headers.get("X-Content-Type-Options") == "nosniff":
            grade_points += 1
        
        # X-Frame-Options
        if headers.get("X-Frame-Options"):
            grade_points += 1
        
        # X-XSS-Protection
        if headers.get("X-XSS-Protection"):
            grade_points += 1
        
        # Referrer-Policy
        if headers.get("Referrer-Policy"):
            grade_points += 1
        
        # Permissions-Policy or Feature-Policy
        if headers.get("Permissions-Policy") or headers.get("Feature-Policy"):
            grade_points += 1
        
        # Calculate grade
        percentage = (grade_points / max_points) * 100
        
        if percentage >= 90:
            return "A+"
        elif percentage >= 80:
            return "A"
        elif percentage >= 70:
            return "B"
        elif percentage >= 60:
            return "C"
        elif percentage >= 50:
            return "D"
        else:
            return "F"


def analyze_target_domain(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Analyze a single domain with advanced OSINT techniques.
    
    Args:
        domain: The domain to analyze
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing comprehensive domain analysis
    """
    osint = AdvancedOSINT(timeout=timeout)
    return osint.analyze_domain(domain)