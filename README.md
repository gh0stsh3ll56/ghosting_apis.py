# API Vulnerability Scanner - Ghost Ops Security

## Overview
Comprehensive API security testing tool that performs attack surface mapping, parameter fuzzing, and OWASP Top 10 vulnerability testing with detailed reporting.

## Features

### 🎯 Attack Surface Mapping
- Automatic endpoint discovery and enumeration
- HTTP method fuzzing (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
- Content-type detection
- Response analysis

### 🔍 Parameter Fuzzing
- Intelligent parameter discovery
- Common parameter wordlist
- Response difference analysis

### 🛡️ OWASP Top 10 Testing

1. **SQL Injection**
   - Error-based detection
   - Time-based blind SQLi
   - Union-based attacks
   - Multiple DBMS signatures

2. **Cross-Site Scripting (XSS)**
   - Reflected XSS
   - Multiple payload variations
   - Context-aware detection

3. **Command Injection**
   - OS command execution
   - Time-based detection
   - Output pattern matching

4. **Path Traversal**
   - Directory traversal
   - File inclusion
   - Multiple encoding variants

5. **Server-Side Request Forgery (SSRF)**
   - Internal network access
   - Cloud metadata exploitation
   - Localhost bypass techniques

6. **Insecure Direct Object Reference (IDOR)**
   - Object enumeration
   - Authorization bypass
   - Multiple ID testing

7. **XML External Entity (XXE)**
   - File disclosure
   - SSRF via XXE
   - XML parser exploitation

8. **Security Misconfiguration**
   - Missing security headers
   - Information disclosure
   - Default configurations

### 📊 Reporting
- **Console Output**: Real-time colored output
- **JSON Report**: Machine-readable format
- **HTML Report**: Professional formatted report
- **Table Format**: Severity-sorted findings
- **Detailed Evidence**: Payloads, responses, and remediation

## Installation

```bash
# Clone or download the script
chmod +x api_vuln_scanner.py

# Install dependencies
pip3 install requests --break-system-packages
```

## Usage

### Basic Scan
```bash
python3 api_vuln_scanner.py -u https://api.example.com
```

### With Authentication Header
```bash
python3 api_vuln_scanner.py -u https://api.example.com \
  -H "Authorization: Bearer eyJhbGc..."
```

### Multiple Headers
```bash
python3 api_vuln_scanner.py -u https://api.example.com \
  -H "Authorization: Bearer TOKEN" \
  -H "X-API-Key: your-api-key" \
  -H "User-Agent: GhostOps/1.0"
```

### Custom Endpoint Wordlist
```bash
python3 api_vuln_scanner.py -u https://api.example.com \
  -w custom_endpoints.txt
```

### With Proxy (Burp Suite)
```bash
python3 api_vuln_scanner.py -u https://api.example.com \
  --proxy http://127.0.0.1:8080
```

### Threaded Scanning
```bash
python3 api_vuln_scanner.py -u https://api.example.com \
  -t 20  # 20 threads for faster scanning
```

### Full Example
```bash
python3 api_vuln_scanner.py \
  -u https://api.target.com \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -w api_endpoints.txt \
  -t 15 \
  --proxy http://127.0.0.1:8080
```

## Command Line Arguments

```
-u, --url          Target API base URL (required)
-H, --header       Custom headers (can be used multiple times)
-w, --wordlist     Custom endpoint wordlist file
-t, --threads      Number of threads (default: 10)
--proxy            Proxy URL (e.g., http://127.0.0.1:8080)
```

## Custom Wordlist Format

Create a text file with one endpoint per line:

```
/api/v1/users
/api/v1/admin
/api/v1/login
/api/v2/authenticate
/api/products
/api/orders
/graphql
```

## Output Files

The scanner generates two report files in `/mnt/user-data/outputs/`:

1. **JSON Report**: `api_scan_YYYYMMDD_HHMMSS.json`
   - Machine-readable format
   - Complete finding details
   - Easy integration with other tools

2. **HTML Report**: `api_scan_YYYYMMDD_HHMMSS.html`
   - Professional formatted report
   - Color-coded severity levels
   - Executive summary
   - Detailed findings with remediation

## Report Structure

### Console Output
```
╔═══════════════════════════════════════════════════════════╗
║       API Vulnerability Scanner - Ghost Ops Security      ║
║            Advanced OWASP Top 10 Testing Suite            ║
╚═══════════════════════════════════════════════════════════╝

[+] Phase 1: Attack Surface Mapping
[✓] Found: GET /api/v1/users (HTTP 200)
[✓] Found: POST /api/v1/users (HTTP 401)

[+] Phase 2: Parameter Fuzzing
[✓] Found parameter: id
[✓] Found parameter: email

[+] Phase 3: OWASP Top 10 Vulnerability Testing
[*] Testing SQL Injection...
[!] SQL Injection found in parameter: id

VULNERABILITY ASSESSMENT REPORT
════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
Target: https://api.example.com
Total Vulnerabilities: 5
Critical: 2 | High: 2 | Medium: 1 | Low: 0

DETAILED FINDINGS
#    SEVERITY    TYPE                           ENDPOINT
────────────────────────────────────────────────────────────
1    CRITICAL    SQL Injection                  /api/v1/users
2    CRITICAL    Command Injection              /api/v1/search
```

### JSON Report Structure
```json
{
  "scan_info": {
    "target": "https://api.example.com",
    "timestamp": "2025-10-09 15:30:45",
    "total_vulnerabilities": 5
  },
  "summary": {
    "CRITICAL": 2,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0
  },
  "findings": [
    {
      "endpoint": "/api/v1/users",
      "method": "GET",
      "vulnerability_type": "SQL Injection",
      "severity": "CRITICAL",
      "description": "SQL injection vulnerability detected in parameter 'id'",
      "payload": "' OR '1'='1",
      "response_code": 200,
      "evidence": "SQL error pattern detected: mysql",
      "remediation": "Use parameterized queries/prepared statements...",
      "timestamp": "2025-10-09 15:31:02"
    }
  ]
}
```

## Vulnerability Detection Methods

### SQL Injection
- Error message pattern matching (MySQL, PostgreSQL, Oracle, SQL Server)
- Time-based blind detection (WAITFOR, SLEEP)
- Boolean-based blind detection
- Union-based injection

### XSS Detection
- Payload reflection in response
- HTML context analysis
- Script tag detection
- Event handler detection

### Command Injection
- Command output patterns (/etc/passwd, uid=, gid=)
- Time-based detection (sleep commands)
- OS-specific signatures

### Path Traversal
- File content patterns (system files)
- Encoding bypass detection
- NULL byte injection

### SSRF Detection
- Cloud metadata access (AWS, GCP, Azure)
- Internal service response patterns
- Localhost access verification

### IDOR Detection
- Multiple object access comparison
- Authorization bypass testing
- Content-length analysis

## Severity Levels

| Severity | Description | Example |
|----------|-------------|---------|
| **CRITICAL** | Immediate risk, remote code execution possible | SQL Injection, Command Injection, XXE |
| **HIGH** | Significant risk, data exposure or unauthorized access | XSS, Path Traversal, IDOR, SSRF |
| **MEDIUM** | Moderate risk, security controls missing | Missing Security Headers |
| **LOW** | Minor risk, information disclosure | Verbose Error Messages |

## Best Practices

### Pre-Engagement
1. **Get Authorization**: Always obtain written permission before testing
2. **Scope Definition**: Clearly define which endpoints are in scope
3. **Backup Communication**: Have alternate contact methods
4. **Testing Window**: Agree on testing timeframes

### During Testing
1. **Rate Limiting**: Use appropriate thread count to avoid DoS
2. **Proxy Configuration**: Route through Burp Suite for detailed analysis
3. **Authentication**: Use valid credentials to test authenticated endpoints
4. **Documentation**: Keep detailed notes of findings

### Post-Testing
1. **Report Generation**: Review both JSON and HTML reports
2. **Validation**: Manually verify critical findings
3. **Impact Assessment**: Evaluate business impact of findings
4. **Remediation**: Provide clear, actionable remediation steps

## Integration with Burp Suite

Route traffic through Burp Suite for advanced analysis:

```bash
# Start Burp Suite and configure proxy listener on 127.0.0.1:8080

python3 api_vuln_scanner.py \
  -u https://api.example.com \
  --proxy http://127.0.0.1:8080
```

Benefits:
- HTTP history review
- Manual payload modification
- Active Scanner integration
- Request/response manipulation

## Remediation Guidance

### SQL Injection
```python
# Vulnerable
query = f"SELECT * FROM users WHERE id = '{user_id}'"

# Secure
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

### XSS
```python
# Vulnerable
return f"<div>Welcome {username}</div>"

# Secure
from html import escape
return f"<div>Welcome {escape(username)}</div>"
```

### Command Injection
```python
# Vulnerable
os.system(f"ping {user_input}")

# Secure - Use safe alternatives
import subprocess
subprocess.run(['ping', '-c', '4', user_input], 
               capture_output=True, timeout=5)
```

### Path Traversal
```python
# Vulnerable
open(f"files/{filename}", 'r')

# Secure
import os
safe_path = os.path.join(BASE_DIR, filename)
if not safe_path.startswith(BASE_DIR):
    raise ValueError("Invalid path")
```

## Limitations

- **Authentication**: Limited to provided credentials
- **Rate Limiting**: May trigger rate limits on target
- **False Positives**: Manual verification recommended
- **Complex Workflows**: May not detect multi-step vulnerabilities
- **Custom Frameworks**: May not recognize all framework-specific patterns

## Legal Disclaimer

This tool is provided for legal security testing and educational purposes only. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Understanding the scope and limitations of testing
- Ensuring no damage is caused to target systems

Unauthorized access to computer systems is illegal. Ghost Ops Security and the tool authors are not responsible for misuse of this tool.

## Support

For Ghost Ops Security clients:
- Technical support: support@ghostopssecurity.com
- Emergency response: +1-XXX-XXX-XXXX

## Version History

**v1.0** - Initial Release
- Complete OWASP Top 10 coverage
- HTML and JSON reporting
- Multi-threaded scanning
- Proxy support
- Custom wordlist support

## Credits

Developed by Ghost Ops Security
Penetration Testing & Security Research

---

**Remember**: Always obtain proper authorization before performing security assessments.
