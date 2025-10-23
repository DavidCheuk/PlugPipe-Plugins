# Salesforce CRM Plugin - Security Guidelines

## Security Overview

The Salesforce CRM Plugin implements comprehensive security hardening following the FTHAD methodology. This document provides security guidelines, threat model analysis, and compliance requirements for enterprise deployment.

## Threat Model

### Attack Vectors Mitigated

#### 1. SOQL Injection Attacks
**Threat**: Malicious SOQL queries through parameter manipulation
**Mitigation**: Multi-layer SOQL parameter validation and Universal Input Sanitizer integration

```python
# Protected against
dangerous_queries = [
    "Account WHERE Name = 'Test'; DROP TABLE Users--",
    "Contact WHERE Email = '' OR '1'='1'",
    "Lead WHERE Company = 'x' UNION SELECT Password FROM User"
]
```

#### 2. Instance URL Injection (SSRF)
**Threat**: Server-Side Request Forgery through malicious instance URLs
**Mitigation**: Comprehensive URL validation with domain restrictions

```python
# Protected against
dangerous_urls = [
    "http://localhost:8080/salesforce",      # Localhost access
    "https://192.168.1.1/salesforce",       # Private networks
    "file:///etc/passwd",                    # File system access
    "ftp://internal.company.com/data",      # Non-HTTPS protocols
    "javascript:alert('xss')"               # JavaScript injection
]
```

#### 3. Authentication Bypass Attacks
**Threat**: Unauthorized access through weak or bypassed authentication
**Mitigation**: Multi-method authentication with credential validation

```python
# Protected against
weak_credentials = [
    {"username": "", "password": ""},           # Empty credentials
    {"username": "admin", "password": "123"},   # Weak passwords
    {"token": "expired_token_12345"},           # Invalid/expired tokens
    {"auth_method": "custom_bypass"}            # Unsupported methods
]
```

#### 4. Data Payload Injection
**Threat**: Malicious content in record data leading to downstream attacks
**Mitigation**: Comprehensive payload validation and content sanitization

```python
# Protected against
malicious_payloads = [
    {"Name": "<script>alert('xss')</script>"},
    {"Description": "javascript:alert('xss')"},
    {"CustomField__c": "eval('malicious code')"},
    {"Comments": "<?php system('rm -rf /'); ?>"}
]
```

#### 5. API Request Manipulation
**Threat**: Unauthorized operations through manipulated API requests
**Mitigation**: Operation validation and request sanitization

```python
# Protected against
malicious_requests = [
    {"operation": "custom_delete_all"},         # Unsupported operations
    {"sobject": "User; DROP TABLE Account"},    # Object injection
    {"record_id": "../admin/config"},           # Path traversal
    {"fields": ["Password", "SecretKey"]}       # Sensitive field access
]
```

## Security Validation Methods

### 1. Instance URL Validation
```python
def _validate_salesforce_instance_url(self, url: str) -> Dict[str, Any]:
    """Comprehensive Salesforce instance URL security validation."""

    # Protocol validation
    if not url.startswith('https://'):
        # Enforces HTTPS for security

    # Domain validation
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.netloc.endswith('.salesforce.com'):
        # Validates legitimate Salesforce domains

    # Private network protection
    dangerous_patterns = [
        r'localhost',           # Localhost access
        r'127\.0\.0\.1',       # Loopback IP
        r'192\.168\.',         # Private network Class C
        r'10\.',               # Private network Class A
        r'172\.1[6-9]\.',      # Private network Class B
        r'169\.254\.',         # Link-local addresses
    ]
```

### 2. Credential Security Validation
```python
def _validate_salesforce_credentials(self, creds: Dict[str, Any]) -> Dict[str, Any]:
    """Comprehensive credential security validation."""

    # Password strength validation
    password = creds.get('password', '')
    if len(password) < 8:
        # Enforces minimum password length

    # Username format validation
    username = creds.get('username', '')
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', username):
        # Validates email format for Salesforce usernames

    # Token validation
    token = creds.get('access_token', '')
    if token and not self.authenticator.is_token_valid(token):
        # Validates token format and expiration
```

### 3. SOQL Injection Prevention
```python
def _validate_salesforce_identifier(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
    """Validate Salesforce identifiers for injection prevention."""

    # Universal Input Sanitizer integration
    if self.universal_sanitizer:
        sanitizer_result = self.universal_sanitizer.process({}, {
            'input_data': identifier,
            'sanitization_types': ['sql_injection', 'code_injection']
        })

    # Format validation
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', identifier):
        # Enforces Salesforce naming conventions

    # SQL keyword prevention
    sql_keywords = ['SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
    if identifier.upper() in sql_keywords:
        # Blocks SQL reserved words
```

### 4. API Request Security
```python
def _validate_salesforce_api_request(self, operation: str, sobject: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Validate API request parameters for security issues."""

    # Operation validation
    valid_operations = ['list', 'get', 'create', 'update', 'delete', 'search']
    if operation not in valid_operations:
        # Restricts to supported operations only

    # Object name validation
    sobject_validation = self._validate_salesforce_identifier(sobject, 'sobject')

    # Data payload validation for write operations
    if data and operation in ['create', 'update']:
        data_validation = self._validate_salesforce_data_payload(data)
```

### 5. Data Payload Security
```python
def _validate_salesforce_data_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate data payload for malicious content."""

    # Size limit enforcement
    payload_str = json.dumps(data)
    if len(payload_str) > 1048576:  # 1MB limit
        # Prevents resource exhaustion attacks

    # Field-by-field validation
    for field_name, field_value in data.items():
        field_validation = self._validate_salesforce_identifier(field_name, 'field')

        if isinstance(field_value, str):
            value_validation = self._validate_field_value(field_value)
```

### 6. Field Value Security
```python
def _validate_field_value(self, value: str) -> Dict[str, Any]:
    """Validate field values for dangerous content."""

    # Dangerous pattern detection
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',  # Script injection
        r'javascript:',               # JavaScript protocol
        r'data:text/html',           # Data URLs
        r'eval\s*\(',               # Code evaluation
        r'exec\s*\(',               # Code execution
    ]

    # Length validation
    if len(value) > 32768:  # 32KB limit
        # Prevents oversized field values
```

## Security Configuration

### Production Security Template
```json
{
  "instance_url": "https://yourcompany.salesforce.com",
  "auth_method": "oauth2",
  "client_id": "3MVG9YDQS5WtC11...",
  "client_secret": "secure_client_secret_min_32_chars",
  "username": "integration.user@yourcompany.com",
  "password": "SecurePassword123!@#",
  "security_validation": {
    "enable_url_validation": true,
    "enable_soql_injection_prevention": true,
    "enable_payload_validation": true,
    "max_payload_size": 1048576,
    "enforce_https": true
  }
}
```

### Network Security Configuration
```json
{
  "instance_url": "https://yourcompany.salesforce.com",
  "network_security": {
    "allowed_domains": ["*.salesforce.com", "*.force.com"],
    "blocked_networks": ["localhost", "127.0.0.1", "192.168.*", "10.*"],
    "require_https": true,
    "validate_certificates": true
  }
}
```

### Authentication Security Configuration
```json
{
  "auth_method": "oauth2",
  "authentication_security": {
    "min_password_length": 8,
    "require_strong_passwords": true,
    "token_validation_enabled": true,
    "credential_redaction_enabled": true,
    "supported_methods": ["oauth2", "jwt"]
  }
}
```

## Compliance Standards

### OWASP Integration Security

#### A01: Injection
- ✅ SOQL injection prevention through parameter validation
- ✅ Command injection prevention in API requests
- ✅ Universal Input Sanitizer integration
- ✅ Multi-layer validation approach

#### A02: Broken Authentication
- ✅ Multi-method authentication support (OAuth2, JWT)
- ✅ Credential validation and strength requirements
- ✅ Token validation and lifecycle management
- ✅ Authentication plugin architecture

#### A03: Sensitive Data Exposure
- ✅ Credential redaction in logs and errors
- ✅ HTTPS enforcement for data transmission
- ✅ Secure credential storage validation
- ✅ No sensitive data in debug outputs

#### A04: XML External Entities (XXE)
- ✅ Content validation prevents XXE in payloads
- ✅ Safe JSON parsing and content handling
- ✅ No external entity processing

#### A05: Broken Access Control
- ✅ Instance URL validation prevents unauthorized access
- ✅ API operation validation and authorization
- ✅ Record-level access control through Salesforce APIs

### Enterprise Security Standards

#### 1. Defense in Depth
- **Perimeter Security**: Instance URL validation blocks external threats
- **Network Security**: HTTPS enforcement and domain validation
- **Application Security**: Input validation and sanitization
- **Data Security**: Payload validation and credential protection

#### 2. Zero Trust Architecture
- **Never Trust, Always Verify**: All inputs validated regardless of source
- **Least Privilege**: Minimal required permissions and operations
- **Assume Breach**: Comprehensive logging and error handling
- **Verify Explicitly**: Multi-layer authentication and authorization

## Security Monitoring

### Security Events to Monitor
```python
security_events = {
    "soql_injection_attempt": "Malicious SOQL detected in parameters",
    "url_injection_attempt": "Suspicious instance URL detected",
    "authentication_failure": "Authentication validation failed",
    "payload_validation_failure": "Dangerous content detected in payload",
    "api_request_violation": "Invalid API operation attempted",
    "credential_validation_failure": "Weak or invalid credentials detected"
}
```

### Integration with Security Plugins
```bash
# Enable security monitoring
{
  "plugin_dependencies": {
    "required": [
      "universal_input_sanitizer",
      "monitoring_prometheus"
    ],
    "optional": [
      "security_incident_response",
      "audit_elk_stack"
    ]
  }
}
```

### Security Metrics
```python
security_metrics = {
    "salesforce_security_validations_total": "Total security validations performed",
    "salesforce_security_violations_total": "Total security violations detected",
    "salesforce_blocked_requests_total": "Total malicious requests blocked",
    "salesforce_credential_validations_total": "Total credential validations",
    "salesforce_soql_injection_blocks_total": "Total SOQL injection attempts blocked"
}
```

## Incident Response

### Security Incident Classification

#### Severity 1: Critical
- SOQL injection attempts with successful bypass
- Instance URL injection leading to SSRF
- Authentication bypass attempts
- Mass data extraction attempts

#### Severity 2: High
- SOQL injection attempts (blocked)
- Malicious payload injection
- Credential brute force attempts
- Unauthorized API operations

#### Severity 3: Medium
- Invalid authentication attempts
- Weak credential usage
- Input validation warnings
- Configuration security issues

#### Severity 4: Low
- General validation warnings
- Performance security concerns
- Documentation violations
- Non-critical configuration issues

### Response Procedures

#### Immediate Response (0-15 minutes)
1. **Block malicious requests** - Security validation prevents execution
2. **Log security event** - Comprehensive logging with context
3. **Alert security team** - Integration with monitoring systems
4. **Preserve evidence** - Request details and validation results

#### Short-term Response (15 minutes - 1 hour)
1. **Investigate attack pattern** - Analyze related requests
2. **Check for data compromise** - Verify Salesforce data integrity
3. **Review access logs** - Identify potential account compromise
4. **Update security rules** - Enhance validation if needed

#### Long-term Response (1 hour - 1 week)
1. **Conduct security review** - Comprehensive security assessment
2. **Update security documentation** - Lessons learned integration
3. **Enhance monitoring** - Improve detection capabilities
4. **Security training** - Team education on new threats

## Security Testing

### Security Test Cases
```python
security_test_cases = [
    # SOQL injection security
    ("Account WHERE Name = 'Test'; DROP TABLE Users", False, "Should block SOQL injection"),
    ("Contact WHERE Email = '' OR '1'='1'", False, "Should block boolean injection"),
    ("Account WHERE Name = 'Test'", True, "Should allow valid SOQL"),

    # URL injection security
    ("http://localhost:8080/salesforce", False, "Should block localhost access"),
    ("https://192.168.1.1/salesforce", False, "Should block private network"),
    ("https://yourcompany.salesforce.com", True, "Should allow valid Salesforce URL"),

    # Payload injection security
    ({"Name": "<script>alert('xss')</script>"}, False, "Should block script injection"),
    ({"Description": "javascript:alert('xss')"}, False, "Should block JavaScript protocol"),
    ({"Name": "Test Account"}, True, "Should allow safe content"),

    # Authentication security
    ({"username": "", "password": ""}, False, "Should reject empty credentials"),
    ({"username": "admin", "password": "123"}, False, "Should reject weak password"),
    ({"username": "user@company.com", "password": "SecurePass123!"}, True, "Should accept strong credentials")
]
```

### Penetration Testing Guidelines

#### SOQL Injection Testing
```bash
# Test SOQL injection prevention
curl -X POST "http://localhost:8080/salesforce-crm" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "list",
    "sobject": "Account WHERE Name = '\''Test'\''; DROP TABLE Users--",
    "fields": ["Id", "Name"]
  }'
# Expected: Security validation should block this
```

#### Instance URL Testing
```bash
# Test URL injection prevention
curl -X POST "http://localhost:8080/salesforce-crm" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_url": "http://localhost:8080/salesforce",
    "operation": "list",
    "sobject": "Account"
  }'
# Expected: Security validation should block this
```

#### Payload Injection Testing
```bash
# Test content injection prevention
curl -X POST "http://localhost:8080/salesforce-crm" \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "create",
    "sobject": "Account",
    "data": {
      "Name": "<script>alert(\"xss\")</script>",
      "Description": "javascript:alert(\"xss\")"
    }
  }'
# Expected: Security validation should detect and block this
```

## Security Deployment Checklist

### Pre-Deployment Security Review
- [ ] All security validation methods implemented and tested
- [ ] FTHAD audit report reviewed and approved
- [ ] Security configuration templates validated
- [ ] Compliance requirements verified
- [ ] Incident response procedures documented
- [ ] Security monitoring configured
- [ ] Penetration testing completed
- [ ] Security team training conducted

### Production Deployment Security
- [ ] HTTPS enforcement enabled
- [ ] Strong authentication credentials configured
- [ ] Instance URL validation enabled
- [ ] SOQL injection prevention active
- [ ] Payload validation configured
- [ ] Security monitoring enabled
- [ ] Incident response procedures activated
- [ ] Regular security assessments scheduled

### Post-Deployment Security Monitoring
- [ ] Security metrics collection enabled
- [ ] Alert thresholds configured
- [ ] Log aggregation and analysis active
- [ ] Regular security assessments scheduled
- [ ] Vulnerability management process active
- [ ] Security training program ongoing
- [ ] Compliance reporting automated
- [ ] Continuous improvement process established

This security documentation provides comprehensive guidelines for secure deployment and operation of the Salesforce CRM Plugin in enterprise environments, ensuring robust protection against identified threats while maintaining operational efficiency.