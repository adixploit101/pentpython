"""
Code Project Security Scanner
Static analysis for source code projects - Top 10 Vibe Code Vulnerabilities
"""
import os
import re
import zipfile
import json
from typing import Dict, List, Any
from pathlib import Path

class CodeScanner:
    def __init__(self, project_path: str):
        self.project_path = project_path
        self.vulnerabilities = []
        self.files_scanned = 0
        self.languages_detected = set()
        
    def scan(self) -> Dict[str, Any]:
        """Run comprehensive code security scan"""
        results = {
            'project_name': os.path.basename(self.project_path),
            'vulnerabilities': [],
            'files_scanned': 0,
            'languages': [],
            'security_score': 0
        }
        
        try:
            # Extract if ZIP
            extract_path = self._extract_project()
            
            # Scan for vulnerabilities
            vulns = []
            
            # 1. Rate Limit Bypassing / No Rate Limit
            vulns.extend(self._check_rate_limiting(extract_path))
            
            # 2. API Key Exposure in Client Code
            vulns.extend(self._check_api_key_exposure(extract_path))
            
            # 3. No Authentication on Internal Endpoints
            vulns.extend(self._check_authentication(extract_path))
            
            # 4. Over Permissions and CORS
            vulns.extend(self._check_cors_permissions(extract_path))
            
            # 5. No Input Validation
            vulns.extend(self._check_input_validation(extract_path))
            
            # 6. Typosquatting
            vulns.extend(self._check_typosquatting(extract_path))
            
            # 7. Missing Input Sanitization
            vulns.extend(self._check_input_sanitization(extract_path))
            
            # 8. Outdated Dependencies
            vulns.extend(self._check_outdated_dependencies(extract_path))
            
            # 9. Business Logic Flaws
            vulns.extend(self._check_business_logic(extract_path))
            
            # 10. No Error Handling
            vulns.extend(self._check_error_handling(extract_path))
            
            results['vulnerabilities'] = vulns
            results['files_scanned'] = self.files_scanned
            results['languages'] = list(self.languages_detected)
            results['security_score'] = self._calculate_security_score(vulns)
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _extract_project(self) -> str:
        """Extract ZIP project to temp directory"""
        if self.project_path.endswith('.zip'):
            extract_path = self.project_path.replace('.zip', '_extracted')
            with zipfile.ZipFile(self.project_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
            return extract_path
        return self.project_path
    
    def _scan_files(self, directory: str, extensions: List[str]) -> List[str]:
        """Scan directory for files with specific extensions"""
        files = []
        try:
            for root, dirs, filenames in os.walk(directory):
                # Skip common directories
                dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'venv', '__pycache__', 'dist', 'build']]
                
                for filename in filenames:
                    if any(filename.endswith(ext) for ext in extensions):
                        files.append(os.path.join(root, filename))
                        self.files_scanned += 1
                        
                        # Detect language
                        if filename.endswith(('.py', '.pyw')):
                            self.languages_detected.add('Python')
                        elif filename.endswith(('.js', '.jsx', '.ts', '.tsx')):
                            self.languages_detected.add('JavaScript/TypeScript')
                        elif filename.endswith(('.java',)):
                            self.languages_detected.add('Java')
                        elif filename.endswith(('.go',)):
                            self.languages_detected.add('Go')
                        elif filename.endswith(('.php',)):
                            self.languages_detected.add('PHP')
        except Exception as e:
            pass
        
        return files
    
    def _check_rate_limiting(self, directory: str) -> List[Dict]:
        """Check for missing rate limiting on API endpoints"""
        vulns = []
        
        # Patterns for API endpoints without rate limiting
        patterns = {
            'Python/Flask': r'@app\.route\(["\'].*["\'].*\)[\s\S]{0,200}def\s+\w+',
            'Python/FastAPI': r'@app\.(get|post|put|delete)\(["\'].*["\'].*\)',
            'JavaScript/Express': r'app\.(get|post|put|delete)\(["\'].*["\']',
            'JavaScript/Next.js': r'export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE)',
        }
        
        rate_limit_indicators = ['rate_limit', 'ratelimit', 'throttle', 'limiter']
        
        files = self._scan_files(directory, ['.py', '.js', '.ts', '.tsx'])
        
        for file_path in files[:100]:  # Limit to first 100 files
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for API endpoints
                    for lang, pattern in patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            # Check if rate limiting is present
                            has_rate_limit = any(indicator in content.lower() for indicator in rate_limit_indicators)
                            
                            if not has_rate_limit:
                                vulns.append({
                                    'type': 'No Rate Limiting',
                                    'severity': 'High',
                                    'description': f'API endpoints in {os.path.basename(file_path)} lack rate limiting',
                                    'file': os.path.basename(file_path),
                                    'remediation': 'Implement rate limiting middleware (e.g., Flask-Limiter, express-rate-limit)'
                                })
                                break
            except:
                continue
        
        return vulns[:5]  # Return max 5 instances
    
    def _check_api_key_exposure(self, directory: str) -> List[Dict]:
        """Check for hardcoded API keys and secrets"""
        vulns = []
        
        # Patterns for API keys and secrets
        patterns = {
            'API Key': r'(?i)(api[_-]?key|apikey)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Secret Key': r'(?i)(secret[_-]?key|secretkey)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
            'Password': r'(?i)(password|passwd)[\s]*[:=][\s]*["\']([^"\']{8,})["\']',
            'Token': r'(?i)(token|auth[_-]?token)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            'Private Key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        }
        
        files = self._scan_files(directory, ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.env', '.config', '.json'])
        
        for file_path in files[:200]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for secret_type, pattern in patterns.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            vulns.append({
                                'type': 'API Key Exposure',
                                'severity': 'Critical',
                                'description': f'Hardcoded {secret_type} found in {os.path.basename(file_path)}',
                                'file': os.path.basename(file_path),
                                'remediation': 'Move secrets to environment variables or secure vault'
                            })
                            break
            except:
                continue
        
        return vulns[:10]
    
    def _check_authentication(self, directory: str) -> List[Dict]:
        """Check for missing authentication on internal endpoints"""
        vulns = []
        
        # Patterns for endpoints without auth
        endpoint_patterns = [
            r'@app\.route\(["\']/(admin|internal|api/internal)',
            r'app\.(get|post|put|delete)\(["\']/(admin|internal|api/internal)',
            r'export\s+async\s+function\s+(GET|POST|PUT|DELETE).*/(admin|internal)',
        ]
        
        auth_indicators = ['@login_required', '@auth', 'authenticate', 'requireAuth', 'isAuthenticated', 'checkAuth']
        
        files = self._scan_files(directory, ['.py', '.js', '.ts', '.tsx'])
        
        for file_path in files[:100]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for pattern in endpoint_patterns:
                        if re.search(pattern, content):
                            # Check for auth decorators/middleware
                            has_auth = any(indicator in content for indicator in auth_indicators)
                            
                            if not has_auth:
                                vulns.append({
                                    'type': 'No Authentication on Internal Endpoints',
                                    'severity': 'Critical',
                                    'description': f'Internal endpoint in {os.path.basename(file_path)} lacks authentication',
                                    'file': os.path.basename(file_path),
                                    'remediation': 'Add authentication middleware/decorators to all internal endpoints'
                                })
                                break
            except:
                continue
        
        return vulns[:5]
    
    def _check_cors_permissions(self, directory: str) -> List[Dict]:
        """Check for overly permissive CORS configuration"""
        vulns = []
        
        # Patterns for permissive CORS
        cors_patterns = [
            r'Access-Control-Allow-Origin.*\*',
            r'cors\(\{.*origin:\s*["\']?\*["\']?',
            r'CORS\(.*origins=\["\*"\]',
            r'allow_origins=\["\*"\]',
        ]
        
        files = self._scan_files(directory, ['.py', '.js', '.ts', '.java', '.go', '.php'])
        
        for file_path in files[:100]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for pattern in cors_patterns:
                        if re.search(pattern, content):
                            vulns.append({
                                'type': 'Overly Permissive CORS',
                                'severity': 'High',
                                'description': f'Wildcard CORS policy in {os.path.basename(file_path)}',
                                'file': os.path.basename(file_path),
                                'remediation': 'Restrict CORS to specific trusted domains'
                            })
                            break
            except:
                continue
        
        return vulns[:5]
    
    def _check_input_validation(self, directory: str) -> List[Dict]:
        """Check for missing input validation"""
        vulns = []
        
        # Patterns for user input without validation
        input_patterns = [
            r'request\.(args|form|json|data)\[',
            r'req\.(body|query|params)\.',
            r'@RequestParam',
            r'c\.Query\(',
        ]
        
        validation_indicators = ['validate', 'validator', 'schema', 'pydantic', 'joi', 'yup', 'zod']
        
        files = self._scan_files(directory, ['.py', '.js', '.ts', '.java', '.go'])
        
        for file_path in files[:100]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    has_input = any(re.search(pattern, content) for pattern in input_patterns)
                    has_validation = any(indicator in content.lower() for indicator in validation_indicators)
                    
                    if has_input and not has_validation:
                        vulns.append({
                            'type': 'No Input Validation',
                            'severity': 'High',
                            'description': f'User input in {os.path.basename(file_path)} lacks validation',
                            'file': os.path.basename(file_path),
                            'remediation': 'Implement input validation using schemas (Pydantic, Joi, etc.)'
                        })
                        break
            except:
                continue
        
        return vulns[:5]
    
    def _check_typosquatting(self, directory: str) -> List[Dict]:
        """Check for suspicious package dependencies (typosquatting)"""
        vulns = []
        
        # Common typosquatting targets
        legitimate_packages = {
            'requests', 'numpy', 'pandas', 'flask', 'django', 'express', 'react', 'vue', 'angular',
            'lodash', 'axios', 'moment', 'webpack', 'babel', 'typescript'
        }
        
        suspicious_patterns = [
            (r'reqeusts', 'requests'),
            (r'numppy', 'numpy'),
            (r'pandsa', 'pandas'),
            (r'flsk', 'flask'),
            (r'djnago', 'django'),
            (r'expres', 'express'),
            (r'raect', 'react'),
        ]
        
        # Check package.json
        package_files = self._scan_files(directory, ['package.json', 'requirements.txt', 'go.mod', 'pom.xml'])
        
        for file_path in package_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for suspicious, legitimate in suspicious_patterns:
                        if re.search(suspicious, content, re.IGNORECASE):
                            vulns.append({
                                'type': 'Potential Typosquatting',
                                'severity': 'Critical',
                                'description': f'Suspicious package "{suspicious}" (did you mean "{legitimate}"?) in {os.path.basename(file_path)}',
                                'file': os.path.basename(file_path),
                                'remediation': 'Verify package names and remove suspicious dependencies'
                            })
            except:
                continue
        
        return vulns
    
    def _check_input_sanitization(self, directory: str) -> List[Dict]:
        """Check for missing input sanitization (SQL injection, XSS)"""
        vulns = []
        
        # SQL injection patterns
        sql_patterns = [
            r'execute\(["\'].*\+.*["\']',
            r'query\(["\'].*\+.*["\']',
            r'SELECT.*\+.*FROM',
            r'f"SELECT.*{.*}.*FROM',
        ]
        
        # XSS patterns
        xss_patterns = [
            r'innerHTML\s*=',
            r'dangerouslySetInnerHTML',
            r'document\.write\(',
        ]
        
        files = self._scan_files(directory, ['.py', '.js', '.ts', '.jsx', '.tsx', '.php'])
        
        for file_path in files[:100]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check SQL injection
                    for pattern in sql_patterns:
                        if re.search(pattern, content):
                            vulns.append({
                                'type': 'SQL Injection Risk',
                                'severity': 'Critical',
                                'description': f'Potential SQL injection in {os.path.basename(file_path)}',
                                'file': os.path.basename(file_path),
                                'remediation': 'Use parameterized queries or ORM'
                            })
                            break
                    
                    # Check XSS
                    for pattern in xss_patterns:
                        if re.search(pattern, content):
                            vulns.append({
                                'type': 'XSS Risk',
                                'severity': 'High',
                                'description': f'Potential XSS vulnerability in {os.path.basename(file_path)}',
                                'file': os.path.basename(file_path),
                                'remediation': 'Sanitize and encode all user inputs before rendering'
                            })
                            break
            except:
                continue
        
        return vulns[:10]
    
    def _check_outdated_dependencies(self, directory: str) -> List[Dict]:
        """Check for outdated or vulnerable dependencies"""
        vulns = []
        
        # Known vulnerable package versions (simplified)
        vulnerable_packages = {
            'lodash': ['4.17.15', '4.17.19'],
            'axios': ['0.18.0', '0.19.0'],
            'express': ['4.16.0', '4.17.0'],
        }
        
        package_files = self._scan_files(directory, ['package.json', 'requirements.txt'])
        
        for file_path in package_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    if 'package.json' in file_path:
                        # Check for old package versions
                        for pkg, versions in vulnerable_packages.items():
                            for version in versions:
                                if f'"{pkg}": "{version}"' in content:
                                    vulns.append({
                                        'type': 'Outdated Dependency',
                                        'severity': 'Medium',
                                        'description': f'Vulnerable version of {pkg} ({version}) in {os.path.basename(file_path)}',
                                        'file': os.path.basename(file_path),
                                        'remediation': f'Update {pkg} to latest version'
                                    })
            except:
                continue
        
        return vulns
    
    def _check_business_logic(self, directory: str) -> List[Dict]:
        """Check for common business logic flaws"""
        vulns = []
        
        # Patterns for business logic issues
        patterns = [
            (r'if\s+price\s*<\s*0', 'Negative price check missing'),
            (r'if\s+quantity\s*<\s*0', 'Negative quantity check missing'),
            (r'transfer\(.*\).*without.*balance.*check', 'Missing balance verification'),
        ]
        
        files = self._scan_files(directory, ['.py', '.js', '.ts', '.java'])
        
        for file_path in files[:50]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for missing business logic validations
                    if 'price' in content.lower() and 'if' not in content.lower():
                        vulns.append({
                            'type': 'Business Logic Flaw',
                            'severity': 'Medium',
                            'description': f'Potential missing validation in {os.path.basename(file_path)}',
                            'file': os.path.basename(file_path),
                            'remediation': 'Add comprehensive business logic validation'
                        })
                        break
            except:
                continue
        
        return vulns[:3]
    
    def _check_error_handling(self, directory: str) -> List[Dict]:
        """Check for missing error handling"""
        vulns = []
        
        # Patterns for functions without try-catch
        function_patterns = {
            'Python': r'def\s+\w+\([^)]*\):',
            'JavaScript': r'(function\s+\w+\([^)]*\)|const\s+\w+\s*=\s*\([^)]*\)\s*=>)',
        }
        
        error_handling = ['try', 'except', 'catch', 'finally']
        
        files = self._scan_files(directory, ['.py', '.js', '.ts'])
        
        for file_path in files[:50]:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Count functions
                    function_count = 0
                    for lang, pattern in function_patterns.items():
                        function_count += len(re.findall(pattern, content))
                    
                    # Count error handling
                    error_count = sum(content.count(keyword) for keyword in error_handling)
                    
                    # If many functions but little error handling
                    if function_count > 3 and error_count < 2:
                        vulns.append({
                            'type': 'Missing Error Handling',
                            'severity': 'Medium',
                            'description': f'Insufficient error handling in {os.path.basename(file_path)} ({function_count} functions, {error_count} error handlers)',
                            'file': os.path.basename(file_path),
                            'remediation': 'Add try-catch blocks and proper error handling'
                        })
            except:
                continue
        
        return vulns[:5]
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate security score (0-100)"""
        score = 100
        
        severity_weights = {
            'Critical': 20,
            'High': 12,
            'Medium': 7,
            'Low': 3
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            score -= severity_weights.get(severity, 3)
        
        return max(0, score)
