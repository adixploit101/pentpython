"""
APK Security Scanner
Android application security analysis
"""
import os
import zipfile
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any
import hashlib

class ApkScanner:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.vulnerabilities = []
        self.permissions = []
        self.manifest_data = {}
        
    def scan(self) -> Dict[str, Any]:
        """Run comprehensive APK security scan"""
        results = {
            'filename': os.path.basename(self.apk_path),
            'file_hash': self._calculate_hash(),
            'vulnerabilities': [],
            'permissions': [],
            'manifest_info': {},
            'security_score': 0
        }
        
        try:
            # 1. Extract and analyze manifest
            manifest_info = self._analyze_manifest()
            results['manifest_info'] = manifest_info
            results['permissions'] = self.permissions
            
            # 2. Check for hardcoded secrets
            secret_vulns = self._find_hardcoded_secrets()
            results['vulnerabilities'].extend(secret_vulns)
            
            # 3. Check permissions
            perm_vulns = self._analyze_permissions()
            results['vulnerabilities'].extend(perm_vulns)
            
            # 4. Check for insecure storage
            storage_vulns = self._check_insecure_storage()
            results['vulnerabilities'].extend(storage_vulns)
            
            # 5. Check network security
            network_vulns = self._check_network_security()
            results['vulnerabilities'].extend(network_vulns)
            
            # 6. Check exported components
            export_vulns = self._check_exported_components()
            results['vulnerabilities'].extend(export_vulns)
            
            # 7. Check for weak crypto
            crypto_vulns = self._check_weak_crypto()
            results['vulnerabilities'].extend(crypto_vulns)
            
            # 8. Check debuggable flag
            debug_vulns = self._check_debuggable()
            results['vulnerabilities'].extend(debug_vulns)
            
            # Calculate security score
            results['security_score'] = self._calculate_security_score(results['vulnerabilities'])
            
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _calculate_hash(self) -> str:
        """Calculate SHA256 hash of APK"""
        try:
            sha256_hash = hashlib.sha256()
            with open(self.apk_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return "Error calculating hash"
    
    def _analyze_manifest(self) -> Dict[str, Any]:
        """Extract and analyze AndroidManifest.xml"""
        manifest_info = {}
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Try to read manifest
                if 'AndroidManifest.xml' in apk.namelist():
                    manifest_data = apk.read('AndroidManifest.xml')
                    
                    # Note: Real APK manifest is binary XML, needs special parsing
                    # For demo, we'll extract basic info from file list
                    manifest_info['has_manifest'] = True
                    
                    # Get file list
                    files = apk.namelist()
                    manifest_info['total_files'] = len(files)
                    manifest_info['has_native_libs'] = any('lib/' in f for f in files)
                    manifest_info['has_assets'] = any('assets/' in f for f in files)
                    
                    # Check for common files
                    manifest_info['has_resources'] = any('res/' in f for f in files)
                    manifest_info['has_classes'] = any('.dex' in f for f in files)
                    
        except Exception as e:
            manifest_info['error'] = str(e)
        
        return manifest_info
    
    def _find_hardcoded_secrets(self) -> List[Dict]:
        """Find hardcoded API keys, passwords, tokens"""
        vulns = []
        
        # Patterns for common secrets
        patterns = {
            'API Key': r'(?i)(api[_-]?key|apikey)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Private Key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            'Password': r'(?i)(password|passwd|pwd)[\s]*[:=][\s]*["\']([^"\']{6,})["\']',
            'Token': r'(?i)(token|auth)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            'Secret': r'(?i)(secret|client_secret)[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']'
        }
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Check common config files
                config_files = [f for f in apk.namelist() if f.endswith(('.xml', '.json', '.properties', '.txt'))]
                
                for file_path in config_files[:50]:  # Limit to first 50 files
                    try:
                        content = apk.read(file_path).decode('utf-8', errors='ignore')
                        
                        for secret_type, pattern in patterns.items():
                            matches = re.findall(pattern, content)
                            if matches:
                                vulns.append({
                                    'type': f'Hardcoded {secret_type}',
                                    'severity': 'Critical',
                                    'description': f'Found hardcoded {secret_type.lower()} in {file_path}',
                                    'remediation': 'Remove hardcoded secrets, use secure storage or environment variables'
                                })
                                break  # One vuln per file
                    except:
                        continue
        except Exception as e:
            pass
        
        return vulns
    
    def _analyze_permissions(self) -> List[Dict]:
        """Analyze app permissions for over-permissions"""
        vulns = []
        
        # Dangerous permissions
        dangerous_perms = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_SMS', 'SEND_SMS',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'CAMERA',
            'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
            'READ_PHONE_STATE', 'CALL_PHONE'
        ]
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                if 'AndroidManifest.xml' in apk.namelist():
                    # Simulated permission check (real implementation needs binary XML parser)
                    manifest_data = apk.read('AndroidManifest.xml')
                    
                    # Check for dangerous permissions in binary data
                    for perm in dangerous_perms:
                        if perm.encode() in manifest_data:
                            self.permissions.append(perm)
                    
                    if len(self.permissions) > 5:
                        vulns.append({
                            'type': 'Over-Permissions',
                            'severity': 'Medium',
                            'description': f'App requests {len(self.permissions)} dangerous permissions',
                            'remediation': 'Review and minimize requested permissions'
                        })
        except Exception as e:
            pass
        
        return vulns
    
    def _check_insecure_storage(self) -> List[Dict]:
        """Check for insecure data storage patterns"""
        vulns = []
        
        insecure_patterns = [
            (r'SharedPreferences.*MODE_WORLD_READABLE', 'World-readable SharedPreferences'),
            (r'openFileOutput.*MODE_WORLD_READABLE', 'World-readable files'),
            (r'SQLiteDatabase.*execSQL', 'Potential SQL injection in SQLite'),
        ]
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Check .dex files (Dalvik bytecode)
                dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
                
                for dex_file in dex_files[:3]:  # Check first 3 dex files
                    try:
                        content = apk.read(dex_file)
                        
                        for pattern, desc in insecure_patterns:
                            if re.search(pattern.encode(), content):
                                vulns.append({
                                    'type': 'Insecure Data Storage',
                                    'severity': 'High',
                                    'description': desc,
                                    'remediation': 'Use Android Keystore and encrypted storage'
                                })
                                break
                    except:
                        continue
        except Exception as e:
            pass
        
        return vulns
    
    def _check_network_security(self) -> List[Dict]:
        """Check network security configuration"""
        vulns = []
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Check for network security config
                has_network_config = any('network_security_config' in f for f in apk.namelist())
                
                if not has_network_config:
                    vulns.append({
                        'type': 'Missing Network Security Config',
                        'severity': 'Medium',
                        'description': 'No network security configuration found',
                        'remediation': 'Implement network security config with certificate pinning'
                    })
                
                # Check for cleartext traffic
                manifest_data = apk.read('AndroidManifest.xml')
                if b'usesCleartextTraffic' in manifest_data and b'true' in manifest_data:
                    vulns.append({
                        'type': 'Cleartext Traffic Allowed',
                        'severity': 'High',
                        'description': 'App allows unencrypted HTTP traffic',
                        'remediation': 'Disable cleartext traffic and use HTTPS only'
                    })
        except Exception as e:
            pass
        
        return vulns
    
    def _check_exported_components(self) -> List[Dict]:
        """Check for insecurely exported components"""
        vulns = []
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                manifest_data = apk.read('AndroidManifest.xml')
                
                # Check for exported components
                if b'android:exported="true"' in manifest_data:
                    vulns.append({
                        'type': 'Exported Components',
                        'severity': 'Medium',
                        'description': 'App has exported components that may be accessible to other apps',
                        'remediation': 'Review exported components and add permission checks'
                    })
        except Exception as e:
            pass
        
        return vulns
    
    def _check_weak_crypto(self) -> List[Dict]:
        """Check for weak cryptography"""
        vulns = []
        
        weak_crypto_patterns = [
            (b'DES', 'Weak DES encryption'),
            (b'MD5', 'Weak MD5 hashing'),
            (b'SHA1', 'Weak SHA1 hashing'),
            (b'ECB', 'Insecure ECB mode'),
        ]
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
                
                for dex_file in dex_files[:2]:
                    try:
                        content = apk.read(dex_file)
                        
                        for pattern, desc in weak_crypto_patterns:
                            if pattern in content:
                                vulns.append({
                                    'type': 'Weak Cryptography',
                                    'severity': 'High',
                                    'description': desc,
                                    'remediation': 'Use AES-256, SHA-256, or modern crypto libraries'
                                })
                                break
                    except:
                        continue
        except Exception as e:
            pass
        
        return vulns
    
    def _check_debuggable(self) -> List[Dict]:
        """Check if app is debuggable"""
        vulns = []
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                manifest_data = apk.read('AndroidManifest.xml')
                
                if b'android:debuggable="true"' in manifest_data:
                    vulns.append({
                        'type': 'Debuggable Application',
                        'severity': 'High',
                        'description': 'App is debuggable in production',
                        'remediation': 'Disable debuggable flag for production builds'
                    })
        except Exception as e:
            pass
        
        return vulns
    
    def _calculate_security_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate security score (0-100)"""
        score = 100
        
        severity_weights = {
            'Critical': 25,
            'High': 15,
            'Medium': 10,
            'Low': 5
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            score -= severity_weights.get(severity, 5)
        
        return max(0, score)
