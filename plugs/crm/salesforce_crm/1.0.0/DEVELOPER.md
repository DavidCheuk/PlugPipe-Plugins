# Salesforce CRM Plugin - Developer Documentation

## Architecture Overview

The Salesforce CRM Plugin implements a security-hardened, enterprise-grade Salesforce integration using the FTHAD (Fix-Test-Harden-Audit-Doc) methodology.

### Core Components

#### 1. SalesforceAuthenticationInterface (ABC Pattern)
```python
class SalesforceAuthenticationInterface(ABC):
    """Abstract interface for Salesforce authentication methods."""

    @abstractmethod
    def get_supported_methods(self) -> List[str]:
        """Return list of supported authentication methods."""
        pass

    @abstractmethod
    async def authenticate(self, config: Dict[str, Any], session: requests.Session) -> Dict[str, Any]:
        """Authenticate with Salesforce using specified method."""
        pass

    @abstractmethod
    def is_token_valid(self, token: str) -> bool:
        """Validate if a token is valid and not expired."""
        pass
```

#### 2. DefaultSalesforceAuthenticator
Default implementation supporting OAuth2 authentication:

```python
class DefaultSalesforceAuthenticator(SalesforceAuthenticationInterface):
    """Default Salesforce authenticator supporting OAuth2."""

    def get_supported_methods(self) -> List[str]:
        return ["oauth2"]

    async def authenticate(self, config: Dict[str, Any], session: requests.Session) -> Dict[str, Any]:
        """Perform OAuth2 authentication with Salesforce."""
        # Implementation details...
```

#### 3. SalesforceClient
Main client class with comprehensive security validation:

```python
class SalesforceClient:
    """Enterprise Salesforce client with comprehensive security hardening."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = requests.Session()
        self.authenticator = self._load_authenticator()
        self.universal_sanitizer = self._load_universal_sanitizer()
        self.logger = self._setup_logging()
```

### Security Architecture

#### Input Validation Pipeline
1. **Instance URL Validation** → SSRF prevention
2. **Credential Validation** → Authentication security
3. **API Request Validation** → Operation authorization
4. **Data Payload Validation** → Content security
5. **SOQL Parameter Validation** → Injection prevention
6. **Universal Sanitizer Integration** → Comprehensive threat detection

#### Security Methods Implementation
```python
# Network security validation
def _validate_salesforce_instance_url(self, url: str) -> Dict[str, Any]

# Authentication security
def _validate_salesforce_credentials(self, creds: Dict[str, Any]) -> Dict[str, Any]

# API request security
def _validate_salesforce_api_request(self, operation: str, sobject: str, data: Dict[str, Any] = None) -> Dict[str, Any]

# Data payload security
def _validate_salesforce_data_payload(self, data: Dict[str, Any]) -> Dict[str, Any]

# SOQL injection prevention
def _validate_salesforce_identifier(self, identifier: str, identifier_type: str) -> Dict[str, Any]
def _validate_soql_filter(self, filter_clause: str) -> Dict[str, Any]

# Field value security
def _validate_field_value(self, value: str) -> Dict[str, Any]
def _validate_record_id(self, record_id: str) -> Dict[str, Any]

# Universal input sanitization
async def _validate_and_sanitize_input(self, data: Any, context: str) -> Dict[str, Any]
```

## Development Patterns

### 1. Adding New Authentication Methods

#### Step 1: Create Authentication Plugin
```python
# plugs/authentication/salesforce_jwt/1.0.0/main.py
class JWTSalesforceAuthenticator(SalesforceAuthenticationInterface):
    """JWT-based Salesforce authenticator."""

    def get_supported_methods(self) -> List[str]:
        return ["jwt"]

    async def authenticate(self, config: Dict[str, Any], session: requests.Session) -> Dict[str, Any]:
        # JWT authentication implementation
        private_key = config.get('private_key')
        client_id = config.get('client_id')
        username = config.get('username')

        # Create JWT token
        jwt_token = self._create_jwt_token(private_key, client_id, username)

        # Exchange JWT for access token
        return await self._exchange_jwt_for_token(jwt_token, session)

    def is_token_valid(self, token: str) -> bool:
        # JWT token validation logic
        return self._validate_jwt_token(token)
```

#### Step 2: Register Authentication Plugin
The authentication plugin loader will automatically discover plugins:
```python
def load_authentication_plugin(auth_method: str) -> Optional[SalesforceAuthenticationInterface]:
    """Load authentication plugin dynamically."""
    try:
        plugin_name = f"salesforce_{auth_method}_authenticator"
        plugin_wrapper = pp(plugin_name)

        if plugin_wrapper:
            # Plugin found, instantiate authenticator
            return plugin_wrapper.get_authenticator_instance()
        return None
    except Exception as e:
        logger.warning(f"Failed to load authentication plugin {auth_method}: {e}")
        return None
```

### 2. Adding Security Validation

#### Pattern for New Validation Methods
```python
def _validate_new_feature(self, data: Any) -> Dict[str, Any]:
    """Validate new feature for security vulnerabilities."""
    validation_result = {
        'is_safe': True,
        'security_issues': [],
        'sanitized_data': data
    }

    # Universal Input Sanitizer integration
    if self.universal_sanitizer:
        try:
            sanitizer_result = self.universal_sanitizer.process({}, {
                'input_data': str(data),
                'sanitization_types': ['relevant_injection_types']
            })

            if not sanitizer_result.get('is_safe', False):
                validation_result['is_safe'] = False
                validation_result['security_issues'].extend(
                    sanitizer_result.get('threats_detected', ['Security threat detected'])
                )
        except Exception as e:
            logger.warning(f"Universal Input Sanitizer error: {e}")

    # Custom validation logic
    if dangerous_condition:
        validation_result['security_issues'].append("Description of issue")
        validation_result['is_safe'] = False

    # Sanitize data
    validation_result['sanitized_data'] = sanitize_data(data)

    return validation_result
```

#### Integration with Universal Sanitizer
```python
async def _validate_and_sanitize_input(self, data: Any, context: str) -> Dict[str, Any]:
    # Add new context handling
    elif context == 'new_feature' and isinstance(data, ExpectedType):
        feature_validation = self._validate_new_feature(data)
        validation_result.update(feature_validation)
```

### 3. CRUD Operations Implementation

#### Create Record with Security Validation
```python
async def create_record(self, sobject: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new record with comprehensive security validation."""
    try:
        # Security validation
        api_validation = self._validate_salesforce_api_request('create', sobject, data)
        if not api_validation['is_valid']:
            return create_error_response('security_validation_failed',
                                       f"Security validation failed: {api_validation['security_issues']}")

        # Authentication
        await self._authenticate()

        # Prepare sanitized data
        sanitized_data = api_validation['sanitized_data']

        # API request
        url = f"{self.instance_url}/services/data/v57.0/sobjects/{sobject}"
        response = self.session.post(url, json=sanitized_data)
        response.raise_for_status()

        return {
            "success": True,
            "data": response.json()
        }

    except requests.RequestException as e:
        logger.error(f"Create record failed: {e}")
        return create_error_response('api_request_failed', str(e))
```

#### List Records with SOQL Security
```python
async def list_records(self, sobject: str, fields: List[str] = None,
                      filters: str = None, limit: int = 100) -> Dict[str, Any]:
    """List records with SOQL injection prevention."""
    try:
        # Security validation
        soql_validation = self._validate_soql_parameters(sobject, fields, filters, limit)
        if not soql_validation['is_safe']:
            return create_error_response('soql_injection_prevented',
                                       f"SOQL injection detected: {soql_validation['threats_detected']}")

        # Build safe SOQL query
        safe_fields = soql_validation['sanitized_fields']
        safe_sobject = soql_validation['sanitized_sobject']
        safe_filters = soql_validation['sanitized_filters']
        safe_limit = soql_validation['sanitized_limit']

        query = f"SELECT {', '.join(safe_fields)} FROM {safe_sobject}"
        if safe_filters:
            query += f" WHERE {safe_filters}"
        query += f" LIMIT {safe_limit}"

        # Execute query
        return await self._execute_soql(query)

    except Exception as e:
        logger.error(f"List records failed: {e}")
        return create_error_response('list_operation_failed', str(e))
```

## Testing Patterns

### 1. FTHAD Test Structure
```python
class TestSalesforceCRMFTHAD:
    def setup_method(self):
        self.client = salesforce_crm_main.SalesforceClient(self.test_config)

    # FIX phase tests
    def test_fix_phase_abc_pattern_implementation(self):
        # Test ABC pattern implementation
        assert salesforce_crm_main.SalesforceAuthenticationInterface.__abstractmethods__

    # TEST phase tests
    def test_test_phase_no_notimplementederror_instances(self):
        # Verify NotImplementedError elimination
        with open('./plugs/salesforce_crm/1.0.0/main.py', 'r') as f:
            source_code = f.read()
        assert 'NotImplementedError' not in source_code

    # HARDEN phase tests
    def test_harden_phase_salesforce_security_validation(self):
        # Test security validation methods
        dangerous_url = 'http://localhost:8080/salesforce'
        result = self.client._validate_salesforce_instance_url(dangerous_url)
        assert result['is_valid'] is False

    # AUDIT phase tests
    def test_audit_phase_code_quality_metrics(self):
        # Test code quality and compliance
        import inspect
        source = inspect.getsource(salesforce_crm_main)
        assert 'from abc import ABC, abstractmethod' in source

    # DOC phase tests
    def test_doc_phase_comprehensive_functionality(self):
        # Test documentation coverage
        assert hasattr(salesforce_crm_main, 'SalesforceClient')
```

### 2. Security Testing Patterns
```python
def test_security_validation_method(self):
    """Test pattern for security validation methods."""

    # Test valid inputs
    valid_input = create_valid_input()
    result = self.client._validate_method(valid_input)
    assert result['is_safe'] is True

    # Test dangerous inputs
    dangerous_inputs = [
        create_dangerous_input_1(),
        create_dangerous_input_2(),
        create_dangerous_input_3()
    ]

    for dangerous_input in dangerous_inputs:
        result = self.client._validate_method(dangerous_input)
        assert (result['is_safe'] is False or len(result['security_issues']) > 0)
```

### 3. Authentication Testing
```python
async def test_authentication_functionality(self):
    """Test comprehensive authentication functionality."""

    # Test OAuth2 method support
    default_auth = salesforce_crm_main.DefaultSalesforceAuthenticator()
    methods = default_auth.get_supported_methods()
    assert 'oauth2' in methods

    # Test authentication result structure
    auth_result = await default_auth.authenticate(self.test_config, self.session)
    assert 'success' in auth_result
    assert 'access_token' in auth_result

    # Test token validation
    assert default_auth.is_token_valid('valid_token_format')
    assert not default_auth.is_token_valid('invalid_token')
```

## Configuration Patterns

### 1. Environment-Specific Configuration
```python
# Development
development_config = {
    "instance_url": "https://dev-yourcompany.salesforce.com",
    "auth_method": "oauth2",
    "client_id": "dev_client_id",
    "client_secret": "dev_client_secret",
    "username": "dev.user@yourcompany.com",
    "password": "DevPassword123!",
    "security_validation": {
        "enable_all_validations": True,
        "strict_mode": False
    }
}

# Staging
staging_config = {
    "instance_url": "https://staging-yourcompany.salesforce.com",
    "auth_method": "oauth2",
    "security_validation": {
        "enable_all_validations": True,
        "strict_mode": True,
        "log_security_events": True
    }
}

# Production
production_config = {
    "instance_url": "https://yourcompany.salesforce.com",
    "auth_method": "oauth2",
    "security_validation": {
        "enable_all_validations": True,
        "strict_mode": True,
        "log_security_events": True,
        "monitor_security_metrics": True
    }
}
```

### 2. Security Configuration Templates
```python
# High Security Template
high_security_config = {
    "security_validation": {
        "enable_url_validation": True,
        "enable_soql_injection_prevention": True,
        "enable_payload_validation": True,
        "enable_credential_validation": True,
        "max_payload_size": 1048576,  # 1MB
        "max_field_length": 32768,    # 32KB
        "enforce_https": True,
        "validate_certificates": True
    }
}

# Performance Optimized Template
performance_config = {
    "security_validation": {
        "enable_essential_validations_only": True,
        "cache_validation_results": True,
        "async_validation": True,
        "batch_validation": True
    }
}
```

## Error Handling Patterns

### 1. Comprehensive Error Classification
```python
class SalesforceSecurityError(Exception):
    """Base exception for Salesforce security errors."""
    pass

class SOQLInjectionError(SalesforceSecurityError):
    """Raised when SOQL injection is detected."""
    pass

class InstanceURLError(SalesforceSecurityError):
    """Raised when instance URL validation fails."""
    pass

class AuthenticationSecurityError(SalesforceSecurityError):
    """Raised when authentication security validation fails."""
    pass

class PayloadValidationError(SalesforceSecurityError):
    """Raised when payload validation fails."""
    pass
```

### 2. Error Response Patterns
```python
def create_error_response(error_type: str, error_message: str, details: Dict = None) -> Dict[str, Any]:
    """Create standardized error response."""
    return {
        'salesforce_status': 'error',
        'salesforce_error': error_message,
        'salesforce_result': {
            'status': 'error',
            'error': error_message,
            'error_type': error_type,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
    }

def create_security_error_response(security_issues: List[str], context: str) -> Dict[str, Any]:
    """Create security-specific error response."""
    return create_error_response(
        'security_validation_failed',
        f"Security validation failed in {context}",
        {
            'security_issues': security_issues,
            'blocked_for_security': True,
            'contact_security_team': True
        }
    )
```

### 3. Graceful Degradation Pattern
```python
async def with_graceful_degradation(self, operation: Callable, fallback: Callable = None):
    """Execute operation with graceful degradation."""
    try:
        return await operation()
    except SalesforceSecurityError as e:
        # Security errors should not be gracefully degraded
        logger.error(f"Security error: {e}")
        raise e
    except Exception as e:
        logger.warning(f"Operation failed: {e}")
        if fallback:
            return await fallback()
        return create_error_response('operation_failed', str(e))
```

## Performance Optimization

### 1. Async/Await Implementation
```python
class AsyncSalesforceClient:
    """Async-optimized Salesforce client."""

    async def batch_operations(self, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple operations concurrently."""
        tasks = []
        for op in operations:
            if op['type'] == 'create':
                tasks.append(self.create_record(op['sobject'], op['data']))
            elif op['type'] == 'update':
                tasks.append(self.update_record(op['sobject'], op['record_id'], op['data']))
            elif op['type'] == 'delete':
                tasks.append(self.delete_record(op['sobject'], op['record_id']))

        # Execute all operations concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._process_batch_results(results)
```

### 2. Connection Management
```python
class ConnectionManager:
    """Manage Salesforce connections efficiently."""

    def __init__(self):
        self.session_pool = {}
        self.connection_lock = asyncio.Lock()

    async def get_session(self, config_hash: str, config: Dict[str, Any]) -> requests.Session:
        """Get or create session with connection pooling."""
        async with self.connection_lock:
            if config_hash not in self.session_pool:
                session = requests.Session()
                session.headers.update({
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                })
                self.session_pool[config_hash] = session
            return self.session_pool[config_hash]
```

### 3. Caching Strategy
```python
class ValidationCache:
    """Cache validation results for performance."""

    def __init__(self, ttl: int = 300):  # 5 minutes TTL
        self.cache = {}
        self.ttl = ttl

    def get_validation_result(self, input_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached validation result."""
        if input_hash in self.cache:
            result, timestamp = self.cache[input_hash]
            if time.time() - timestamp < self.ttl:
                return result
            else:
                del self.cache[input_hash]
        return None

    def store_validation_result(self, input_hash: str, result: Dict[str, Any]):
        """Store validation result in cache."""
        self.cache[input_hash] = (result, time.time())
```

## Integration Guidelines

### 1. PlugPipe Signal Integration
```python
async def enrich_with_plugpipe_signals(self, data: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich Salesforce data with PlugPipe signal metadata."""
    if ctx.get('signal_metadata', False):
        enriched = dict(data)
        enriched.update({
            '_plugpipe_metadata': {
                'source_plugin': ctx.get('source_plugin'),
                'signal_type': ctx.get('signal_type'),
                'timestamp': ctx.get('timestamp'),
                'trace_id': ctx.get('trace_id'),
                'plugin_version': '1.0.0',
                'security_validated': True
            }
        })
        return enriched
    return data
```

### 2. Monitoring Integration
```python
async def integrate_monitoring(self, config: Dict[str, Any]):
    """Integrate with monitoring plugins."""
    try:
        from shares.loader import pp
        monitoring_plugin = pp('monitoring_prometheus')

        if monitoring_plugin:
            await monitoring_plugin.process({
                'metric_name': 'salesforce_crm_health',
                'metric_value': 1,
                'labels': {
                    'plugin': 'salesforce_crm',
                    'version': '1.0.0',
                    'security_enabled': True
                }
            }, {})
    except Exception as e:
        logger.warning(f"Monitoring integration failed: {e}")
```

### 3. Security Plugin Integration
```python
async def integrate_security_plugins(self, config: Dict[str, Any]):
    """Integrate with additional security plugins."""
    try:
        # Audit logging integration
        audit_plugin = pp('audit_elk_stack')
        if audit_plugin:
            await audit_plugin.process({
                'event_type': 'salesforce_operation',
                'plugin': 'salesforce_crm',
                'security_validated': True,
                'timestamp': datetime.utcnow().isoformat()
            }, {})

        # Incident response integration
        incident_plugin = pp('security_incident_response')
        if incident_plugin:
            # Register for security event notifications
            await incident_plugin.register_security_handler('salesforce_crm', self.handle_security_incident)

    except Exception as e:
        logger.warning(f"Security plugin integration failed: {e}")
```

This developer documentation provides comprehensive guidance for extending, modifying, and integrating the Salesforce CRM Plugin within the PlugPipe ecosystem while maintaining security and performance standards.