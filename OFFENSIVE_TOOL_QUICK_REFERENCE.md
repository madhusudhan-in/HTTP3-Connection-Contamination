# Offensive Tool - Quick Reference Guide

## File Structure

```
offensive_tool.py                    # Main offensive exploitation module
OFFENSIVE_TOOL_GUIDE.md             # Comprehensive conversion guide (this file)
OFFENSIVE_TOOL_QUICK_REFERENCE.md   # Quick reference for API methods
```

---

## Key Method Transformations

### Request Smuggling

**Defensive Approach:**
```python
async def test_request_smuggling(self, payload: AttackPayload) -> TestResult:
    """Test for request smuggling vulnerabilities"""
    # Sends baseline request
    # Sends smuggling payload
    # Sends follow-up request
    # Detects if follow-up was contaminated
    # Returns: PASS/FAIL status
```

**Offensive Approach:**
```python
async def exploit_request_smuggling_auth_bypass(
    self, 
    payload: AttackPayload, 
    target_endpoint: str = "/admin"
) -> ExploitResult:
    """Exploit request smuggling to bypass authentication"""
    # Crafts request that smuggles admin access request
    # Attempts to access protected endpoint
    # Verifies unauthorized access success
    # Returns: SUCCESS/FAILED with exploitation details
```

**Difference:** 
- ❌ Defensive: "Did the vulnerability exist?"
- ✅ Offensive: "Can we bypass auth and access /admin?"

---

### Cache Poisoning

**Defensive Approach:**
```python
async def test_cache_poisoning(self, payload: AttackPayload) -> TestResult:
    """Test for cache poisoning vulnerabilities"""
    # Sends poisoning request
    # Waits for cache
    # Checks if cache was poisoned
    # Returns: PASS/FAIL
```

**Offensive Approach:**
```python
async def exploit_cache_poisoning(
    self,
    payload: AttackPayload,
    cache_key: str = "/"
) -> ExploitResult:
    """Exploit cache poisoning to inject malicious content"""
    # Sends poisoning request with attacker.com headers
    # Waits for cache
    # Verifies malicious content is served from cache
    # Returns: SUCCESS with impact assessment
```

**Difference:**
- ❌ Defensive: "Is the cache poisonable?"
- ✅ Offensive: "Can we inject malicious content that persists?"

---

### Header Injection

**Defensive Approach:**
```python
async def test_header_injection(self, payload: AttackPayload) -> TestResult:
    """Test for header injection vulnerabilities"""
    # Sends request with injected headers
    # Checks if injected headers appear in response
    # Returns: PASS/FAIL
```

**Offensive Approach:**
```python
async def exploit_header_injection(
    self,
    payload: AttackPayload
) -> ExploitResult:
    """Exploit header injection to execute malicious actions"""
    # Sends malicious header injection payload
    # Analyzes response for successful injection
    # Demonstrates route manipulation capability
    # Returns: SUCCESS with route manipulation proof
```

**Difference:**
- ❌ Defensive: "Can headers be injected?"
- ✅ Offensive: "How can we manipulate routing with injected headers?"

---

### Connection Reuse

**Defensive Approach:**
```python
async def test_protocol_downgrade(self, payload: AttackPayload) -> TestResult:
    """Test for protocol downgrade attacks"""
    # Checks initial protocol
    # Sends downgrade payload
    # Checks if protocol was downgraded
    # Returns: PASS/FAIL
```

**Offensive Approach:**
```python
async def exploit_connection_reuse(
    self,
    payload: AttackPayload
) -> ExploitResult:
    """Exploit connection reuse contamination"""
    # Sends contaminating request
    # Reuses connection for follow-up
    # Analyzes response contamination
    # Returns: SUCCESS with connection hijacking proof
```

**Difference:**
- ❌ Defensive: "Can connections be contaminated?"
- ✅ Offensive: "How do we hijack and manipulate reused connections?"

---

## Class Hierarchy Changes

### Defensive Classes
```
TestConfig              → Configuration for testing
TestStatus/Severity    → Status enums
TestResult             → Individual test result
TestReport             → Aggregated results
ConnectionContaminationTester  → Main tester class
```

### Offensive Classes
```
OffensiveConfig        → Configuration for exploitation
ExploitStatus/Severity → Status enums (SUCCESS/PARTIAL/FAILED)
ExploitResult          → Individual exploitation result
ExploitationReport     → Aggregated exploitation results
HTTPConnectionContaminationExploit  → Main exploitation class
```

---

## Data Structure Enhancements

### TestResult (Defensive)
```python
test_name: str                  # Name of test
attack_type: Optional[AttackType]
status: TestStatus             # PASS/FAIL/ERROR
severity: TestSeverity         # CRITICAL/HIGH/MEDIUM/LOW
details: str
metrics: Optional[PerformanceMetrics]
evidence: Dict[str, Any]
recommendations: List[str]     # How to fix
```

### ExploitResult (Offensive)
```python
exploit_name: str              # Name of exploit
exploit_type: ExploitType      # AUTH_BYPASS/CACHE_POISONING/etc
status: ExploitStatus          # SUCCESS/PARTIAL/FAILED/ERROR
severity: ExploitSeverity
details: str
impact: str                    # Real-world impact
metrics: Optional[ExploitMetrics]
evidence: Dict[str, Any]       # Proof of exploitation
response_data: Dict[str, Any]  # Captured responses
exploitation_steps: List[str]  # How exploitation was done
```

**Key Difference:** 
- Adds `impact` (what was achieved)
- Adds `response_data` (what was captured)
- Adds `exploitation_steps` (how exploit succeeded)

---

## Configuration Comparison

### Defensive Config
```python
TestConfig(
    host: str
    port: int = 443
    timeout: int = 30
    verify_ssl: bool = True
    max_retries: int = 3
    rate_limit: int = 10
    user_agent: str = "HTTP3-Contamination-Tester/1.0"
    follow_redirects: bool = False
    max_connections: int = 10
    enable_http3: bool = True
    enable_http2: bool = True
    capture_traffic: bool = False
)
```

### Offensive Config
```python
OffensiveConfig(
    host: str
    port: int = 443
    timeout: int = 30
    verify_ssl: bool = True
    max_retries: int = 3
    rate_limit: int = 10
    user_agent: str = "Mozilla/5.0..."  # More realistic
    follow_redirects: bool = True       # Follow redirects
    max_connections: int = 10
    enable_http3: bool = True
    enable_http2: bool = True
    capture_responses: bool = True      # Capture data
    payload_delay: float = 0.5          # Delay for exploitation
    stealth_mode: bool = True           # Evade detection
)
```

**New Features:**
- `payload_delay`: Timing between attack stages
- `stealth_mode`: Attempt to evade WAF/detection
- `capture_responses`: Full response capture for analysis

---

## Output Comparison

### Defensive Output
```json
{
  "summary": {
    "total_tests": 12,
    "passed": 8,
    "failed": 3,
    "errors": 1,
    "critical": 2,
    "recommendations": [...]
  },
  "results": [
    {
      "test_name": "Request Smuggling: CL-TE Basic",
      "status": "FAIL",
      "severity": "CRITICAL",
      "details": "Request smuggling detected!",
      "recommendations": ["Reject ambiguous requests...", "Use HTTP/2..."]
    }
  ]
}
```

### Offensive Output
```json
{
  "summary": {
    "successful_exploits": ["Auth Bypass via CL-TE", "Cache Poisoning"],
    "successful": 5,
    "partial": 2,
    "failed": 3,
    "critical": 4
  },
  "results": [
    {
      "exploit_name": "Auth Bypass via CL-TE Basic Smuggling",
      "status": "SUCCESS",
      "severity": "CRITICAL",
      "impact": "Unauthorized access to protected resources",
      "exploitation_steps": ["Step 1: Analyzing...", "Step 2: Crafting...", "..."],
      "evidence": {
        "target_endpoint": "/admin",
        "response_snippet": "Admin panel content...",
        "contamination_detected": true
      },
      "response_data": {
        "status_code": 200,
        "response_headers": {...}
      }
    }
  ]
}
```

---

## Method Mapping

| Defensive Method | Offensive Equivalent | Purpose |
|---|---|---|
| `test_request_smuggling()` | `exploit_request_smuggling_auth_bypass()` | Bypass authentication |
| `test_header_injection()` | `exploit_header_injection()` | Inject headers for routing |
| `test_cache_poisoning()` | `exploit_cache_poisoning()` | Poison cache with malicious content |
| `test_protocol_downgrade()` | `exploit_connection_reuse()` | Hijack connection state |
| `check_http3_support()` | (integrated in all methods) | Detect exploitable protocols |
| `run_all_tests()` | `run_all_exploits()` | Execute full exploitation campaign |

---

## Exploitation Workflow

```
┌─────────────────────────────────────┐
│ 1. Initialize Offensive Config      │
│    (host, port, stealth_mode, etc)  │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│ 2. Create Exploit Engine            │
│    HTTPConnectionContaminationExploit│
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│ 3. Select Exploitation Vectors      │
│    • Auth Bypass                    │
│    • Cache Poisoning                │
│    • Header Injection               │
│    • Connection Hijacking           │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│ 4. Load Attack Payloads             │
│    from PayloadGenerator            │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│ 5. Execute Exploitation             │
│    • Send malicious request         │
│    • Verify impact                  │
│    • Collect evidence               │
│    • Measure success                │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│ 6. Generate Report                  │
│    • Successful exploits            │
│    • Impact assessment              │
│    • Evidence collected             │
│    • Step-by-step breakdown         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│ 7. Save Results                     │
│    exploitation_report.json         │
└─────────────────────────────────────┘
```

---

## Usage Scenarios

### Scenario 1: Target Reconnaissance
```python
# Find which vulnerabilities are exploitable
exploit_engine = HTTPConnectionContaminationExploit(config)
report = await exploit_engine.run_all_exploits()

# Identify successful attacks
successful = [r for r in report.results if r.status == ExploitStatus.SUCCESS]
print(f"Found {len(successful)} exploitable vectors")
```

### Scenario 2: Specific Attack
```python
# Execute specific exploitation
payload = get_request_smuggling_payload()
result = await exploit_engine.exploit_request_smuggling_auth_bypass(
    payload, 
    target_endpoint="/admin"
)

# Verify exploitation
if result.status == ExploitStatus.SUCCESS:
    print(f"Admin access achieved!")
    print(f"Evidence: {result.evidence}")
```

### Scenario 3: Campaign Execution
```python
# Run full exploitation campaign
report = await exploit_engine.run_all_exploits()

# Analyze results
stats = report.get_statistics()
print(f"Critical Vulnerabilities: {stats['critical']}")
print(f"Successfully Exploited: {stats['successful']}")

# Save for documentation
report.save_report("exploitation_campaign.json")
```

---

## Key Differences Summary

| Aspect | Defensive | Offensive |
|--------|-----------|-----------|
| **Goal** | Find vulnerabilities | Exploit vulnerabilities |
| **Question** | "Does the vulnerability exist?" | "Can we exploit it?" |
| **Success** | Vulnerability detected | Exploitation successful |
| **Impact** | Security assessment | Practical exploitation proof |
| **Data** | Vulnerability scores | Evidence of compromise |
| **Focus** | Identification | Exploitation & impact |
| **Mindset** | "How can we fix this?" | "How can we exploit this?" |

---

## Integration with Other Tools

### With SimpleDebugger
```python
# Test exploitation during debugging
from simple_tester import ConnectionContaminationTester
from offensive_tool import HTTPConnectionContaminationExploit

# Compare defensive vs offensive results
defensive_tester = ConnectionContaminationTester(config)
offensive_exploit = HTTPConnectionContaminationExploit(config)
```

### With Attack Payloads
```python
# Use same payloads for both defensive and offensive
from attack_payloads import PayloadGenerator

payloads = PayloadGenerator.get_all_payloads()
# Both tools can use the same payload definitions
```

---

## Performance Considerations

### Rate Limiting
- Offensive tool respects rate limits
- Default: 10 requests/second
- Configurable via `OffensiveConfig.rate_limit`

### Connection Pooling
- Manages max concurrent connections
- Default: 10 concurrent connections
- Prevents resource exhaustion on attacker side

### Stealth Mode
- Slower exploitation to evade detection
- Uses realistic user-agents
- Adds delays between exploitation stages
- Configurable via `stealth_mode` parameter

---

## Logging & Debugging

### Log Levels
```python
# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Trace exploitation steps
logger.debug("Using HTTP/3 (QUIC) for exploitation request")
logger.info("Exploit 'Auth Bypass via CL-TE': SUCCESS")
logger.error("Exploitation request failed: ...")
```

### Captured Evidence
```python
result.evidence = {
    "target_endpoint": "/admin",
    "initial_status": 403,
    "response_snippet": "Admin panel...",
    "payload_method": "CL-TE Basic Smuggling",
    "contamination_detected": True
}
```

---

## Next Steps

1. **Review** the main `offensive_tool.py` file
2. **Configure** your target in `OffensiveConfig`
3. **Execute** specific exploits or full campaign
4. **Analyze** results and evidence
5. **Document** findings with timestamps and proof
6. **Remediate** identified vulnerabilities
