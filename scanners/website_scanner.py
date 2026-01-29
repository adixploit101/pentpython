"""
Website Vulnerability Scanner
Comprehensive security assessment for web applications
"""
import requests
import socket
import ssl
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any
import subprocess
from bs4 import BeautifulSoup

class WebsiteScanner:
    def __init__(self, url: str):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.domain = urlparse(self.url).netloc
        self.vulnerabilities = []
        self.info = []
        
    def scan(self) -> Dict[str, Any]:
        """Run comprehensive website security scan"""
        results = {
            'url': self.url,
            'vulnerabilities': [],
            'security_headers': {},
            'ssl_info': {},
            'open_ports': [],
            'findings': []
        }
        
        try:
            # 1. Security Headers Check
            headers_result = self._check_security_headers()
            results['security_headers'] = headers_result
            
            # 2. SSL/TLS Analysis
            ssl_result = self._check_ssl()
            results['ssl_info'] = ssl_result
            
            # 3. SQL Injection Test
            sqli_vulns = self._test_sql_injection()
            results['vulnerabilities'].extend(sqli_vulns)
            
            # 4. XSS Test
            xss_vulns = self._test_xss()
            results['vulnerabilities'].extend(xss_vulns)
            
            # 5. CSRF Check
            csrf_vulns = self._check_csrf()
            results['vulnerabilities'].extend(csrf_vulns)
            
            # 6. Directory Traversal
            dir_vulns = self._test_directory_traversal()
            results['vulnerabilities'].extend(dir_vulns)
            
            # 7. Information Disclosure
            info_vulns = self._check_information_disclosure()
            results['vulnerabilities'].extend(info_vulns)
            
            # 8. Port Scan
            open_ports = self._scan_ports()
            results['open_ports'] = open_ports
            
            # 9. Authentication Issues
            auth_vulns = self._check_authentication()
            results['vulnerabilities'].extend(auth_vulns)
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _check_security_headers(self) -> Dict[str, Any]:
        """Check for security headers"""
        try:
            response = requests.get(self.url, timeout=10, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy')
            }
            
            # Check for missing headers
            missing = [k for k, v in security_headers.items() if v is None]
            if missing:
                self.vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'severity': 'Medium',
                    'description': f'Missing headers: {", ".join(missing)}',
                    'remediation': 'Add security headers to prevent common attacks'
                })
            
            return security_headers
        except Exception as e:
            return {'error': str(e)}
    
    def _check_ssl(self) -> Dict[str, Any]:
        """Check SSL/TLS configuration"""
        try:
            if not self.url.startswith('https'):
                self.vulnerabilities.append({
                    'type': 'No HTTPS',
                    'severity': 'High',
                    'description': 'Website does not use HTTPS encryption',
                    'remediation': 'Implement SSL/TLS certificate'
                })
                return {'https_enabled': False}
            
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    ssl_info = {
                        'https_enabled': True,
                        'tls_version': version,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject'])
                    }
                    
                    # Check for weak TLS
                    if version in ['TLSv1', 'TLSv1.1']:
                        self.vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'severity': 'High',
                            'description': f'Using outdated {version}',
                            'remediation': 'Upgrade to TLS 1.2 or 1.3'
                        })
                    
                    return ssl_info
        except Exception as e:
            return {'error': str(e)}
    
    def _test_sql_injection(self) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        vulns = []
        payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users--", "1' UNION SELECT NULL--"]
        
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:3]:  # Test first 3 forms
                inputs = form.find_all('input')
                for payload in payloads[:2]:  # Test 2 payloads per form
                    data = {inp.get('name', 'test'): payload for inp in inputs if inp.get('name')}
                    
                    try:
                        action = form.get('action', '')
                        target_url = urljoin(self.url, action)
                        test_response = requests.post(target_url, data=data, timeout=5)
                        
                        # Check for SQL errors
                        sql_errors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'oracle', 'odbc']
                        if any(err in test_response.text.lower() for err in sql_errors):
                            vulns.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'description': f'Possible SQL injection in form at {target_url}',
                                'remediation': 'Use parameterized queries and input validation'
                            })
                            break
                    except:
                        continue
        except Exception as e:
            pass
        
        return vulns
    
    def _test_xss(self) -> List[Dict]:
        """Test for XSS vulnerabilities"""
        vulns = []
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
        
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:2]:
                inputs = form.find_all('input')
                for payload in xss_payloads[:1]:
                    data = {inp.get('name', 'test'): payload for inp in inputs if inp.get('name')}
                    
                    try:
                        action = form.get('action', '')
                        target_url = urljoin(self.url, action)
                        test_response = requests.post(target_url, data=data, timeout=5)
                        
                        if payload in test_response.text:
                            vulns.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'High',
                                'description': f'Reflected XSS found in form at {target_url}',
                                'remediation': 'Sanitize and encode all user inputs'
                            })
                            break
                    except:
                        continue
        except Exception as e:
            pass
        
        return vulns
    
    def _check_csrf(self) -> List[Dict]:
        """Check for CSRF protection"""
        vulns = []
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                # Check for CSRF tokens
                csrf_token_found = False
                inputs = form.find_all('input')
                for inp in inputs:
                    name = inp.get('name', '').lower()
                    if 'csrf' in name or 'token' in name:
                        csrf_token_found = True
                        break
                
                if not csrf_token_found and form.get('method', '').upper() == 'POST':
                    vulns.append({
                        'type': 'Missing CSRF Protection',
                        'severity': 'Medium',
                        'description': 'POST form without CSRF token detected',
                        'remediation': 'Implement CSRF tokens for all state-changing operations'
                    })
                    break
        except Exception as e:
            pass
        
        return vulns
    
    def _test_directory_traversal(self) -> List[Dict]:
        """Test for directory traversal vulnerabilities"""
        vulns = []
        payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam']
        
        try:
            for payload in payloads:
                test_url = f"{self.url}?file={payload}"
                response = requests.get(test_url, timeout=5)
                
                if 'root:' in response.text or 'Administrator' in response.text:
                    vulns.append({
                        'type': 'Directory Traversal',
                        'severity': 'Critical',
                        'description': 'Possible directory traversal vulnerability detected',
                        'remediation': 'Validate and sanitize file path inputs'
                    })
                    break
        except Exception as e:
            pass
        
        return vulns
    
    def _check_information_disclosure(self) -> List[Dict]:
        """Check for information disclosure"""
        vulns = []
        try:
            response = requests.get(self.url, timeout=10)
            
            # Check for exposed server info
            server = response.headers.get('Server', '')
            if server:
                vulns.append({
                    'type': 'Server Information Disclosure',
                    'severity': 'Low',
                    'description': f'Server header reveals: {server}',
                    'remediation': 'Remove or obfuscate server version information'
                })
            
            # Check for error messages
            error_patterns = ['error', 'exception', 'stack trace', 'debug', 'warning']
            if any(pattern in response.text.lower() for pattern in error_patterns):
                vulns.append({
                    'type': 'Error Message Disclosure',
                    'severity': 'Low',
                    'description': 'Detailed error messages may leak sensitive information',
                    'remediation': 'Implement custom error pages'
                })
        except Exception as e:
            pass
        
        return vulns
    
    def _scan_ports(self) -> List[int]:
        """Scan common ports"""
        common_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        try:
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.domain, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
        except Exception as e:
            pass
        
        return open_ports
    
    def _check_authentication(self) -> List[Dict]:
        """Check for authentication issues"""
        vulns = []
        try:
            # Check for basic auth
            response = requests.get(self.url, timeout=10)
            if response.status_code == 401:
                auth_header = response.headers.get('WWW-Authenticate', '')
                if 'Basic' in auth_header:
                    vulns.append({
                        'type': 'Weak Authentication',
                        'severity': 'Medium',
                        'description': 'Using Basic Authentication without HTTPS',
                        'remediation': 'Use stronger authentication methods (OAuth, JWT)'
                    })
        except Exception as e:
            pass
        
        return vulns
