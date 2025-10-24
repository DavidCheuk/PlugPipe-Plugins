# Keycloak Identity Management Plug

## Overview

The Keycloak Identity Management Plug demonstrates PlugPipe's core principle **"reuse, never reinvent"** by leveraging Keycloak's proven enterprise identity and access management platform instead of implementing custom authentication, authorization, and user management systems.

## Philosophy: Enterprise Identity Management

This plugin exemplifies the PlugPipe approach to identity and access management:

✅ **Reuse Proven Identity**: Keycloak provides enterprise-grade identity and access management  
✅ **Never Reinvent Authentication**: Instead of custom auth, we integrate with Keycloak's standards-based platform  
✅ **Ecosystem Integration**: Works with existing enterprise identity infrastructure (LDAP, AD, SAML, OIDC)  
✅ **Battle-Tested Security**: Leverages Keycloak's security hardening and compliance features  

## Features

### 🔐 **Enterprise Identity and Access Management**
- **Standards-Based Authentication**: OAuth2, OpenID Connect, SAML 2.0 support
- **Centralized User Management**: Self-service capabilities with admin oversight
- **Multi-Factor Authentication**: TOTP, WebAuthn, SMS, and custom MFA flows
- **Identity Federation**: LDAP, Active Directory, and social provider integration

### 🛡️ **Advanced Security Features**
- **Role-Based Access Control**: Fine-grained RBAC with hierarchical roles
- **Single Sign-On (SSO)**: Seamless authentication across applications
- **Session Management**: Configurable session policies and timeout controls
- **Brute Force Protection**: Account lockout and progressive delays

### 🏢 **Enterprise Integration**
- **LDAP/AD Integration**: Seamless integration with existing directory services
- **SAML Federation**: Enterprise SAML identity provider integration
- **API-First Architecture**: REST APIs for programmatic management
- **Multi-Tenant Support**: Realm isolation for organizational separation

### ⚙️ **Operational Excellence**
- **High Availability**: Clustering and failover support
- **Audit Trails**: Comprehensive logging for compliance and security
- **Custom Themes**: Branded login pages and user interfaces  
- **Event Monitoring**: Real-time identity event processing

## Configuration

### Basic Usage

```yaml
# Pipe step using Keycloak identity management
steps:
  - plugin: identity_keycloak
    config:
      operation: "authenticate_user"
      auth_config:
        username: "john.doe"
        password: "secure_password"
        realm: "production"
```

### Advanced Configuration

```yaml
# Production Keycloak configuration
keycloak_config:
  server_url: "https://auth.company.com"
  admin_username: "${KEYCLOAK_ADMIN_USER}"
  admin_password: "${KEYCLOAK_ADMIN_PASSWORD}"
  admin_realm: "master"
  verify_ssl: true

# User creation configuration
user_config:
  username: "new.user"
  email: "new.user@company.com"
  first_name: "New"
  last_name: "User"
  enabled: true
  attributes:
    department: "engineering"
    role: "developer"
```

### Environment-Specific Templates

#### Development
```yaml
keycloak_config:
  server_url: "http://localhost:8080"
  admin_username: "admin"
  admin_password: "admin"
  verify_ssl: false
default_realm: "development"
```

#### Production
```yaml
keycloak_config:
  server_url: "${KEYCLOAK_URL}"
  admin_username: "${KEYCLOAK_ADMIN_USER}"
  admin_password: "${KEYCLOAK_ADMIN_PASSWORD}"
  verify_ssl: true
default_realm: "production"
```

## Supported Operations

### User Authentication

```python
# Authenticate user with Keycloak
auth_result = await keycloak.process({
    "operation": "authenticate_user",
    "auth_config": {
        "username": "john.doe",
        "password": "secure_password",
        "realm": "production"
    }
}, config)

# Result: {
#   "success": True, 
#   "result": {
#     "authenticated": True,
#     "access_token": "eyJhbGciOiJSUzI1NiIs...",
#     "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
#     "token_type": "Bearer",
#     "expires_in": 300
#   }
# }
```

### User Management

```python
# Create new user
create_result = await keycloak.process({
    "operation": "create_user",
    "user_config": {
        "username": "new.employee",
        "email": "new.employee@company.com",
        "password": "temporary_password",
        "first_name": "New",
        "last_name": "Employee",
        "attributes": {
            "department": "sales",
            "hire_date": "2024-01-15"
        }
    }
}, config)

# Update user profile
update_result = await keycloak.process({
    "operation": "update_user",
    "user_config": {
        "user_id": "user-123",
        "email": "updated.email@company.com",
        "attributes": {
            "department": "marketing"
        }
    }
}, config)
```

### Access Authorization

```python
# Check user permissions
authz_result = await keycloak.process({
    "operation": "authorize_access",
    "authz_config": {
        "user_id": "user-123",
        "resource": "financial_data",
        "action": "read",
        "context": {
            "ip_address": "192.168.1.100",
            "user_agent": "PlugPipe/1.0"
        }
    }
}, config)

# Result: {
#   "success": True,
#   "result": {
#     "authorized": True,
#     "permissions": ["read", "write"]
#   }
# }
```

### Role Management

```python
# Create new role
role_result = await keycloak.process({
    "operation": "create_role",
    "role_config": {
        "role_name": "data_analyst",
        "description": "Access to analytics and reporting tools",
        "attributes": {
            "permissions": ["analytics:read", "reports:generate"]
        }
    }
}, config)

# Assign role to user
assign_result = await keycloak.process({
    "operation": "assign_role", 
    "role_config": {
        "user_id": "user-123",
        "role_name": "data_analyst"
    }
}, config)
```

## Keycloak Integration

### Server Configuration

```yaml
# keycloak.conf - Keycloak server configuration
hostname: auth.company.com
http-enabled: true
http-port: 8080
https-port: 8443

# Database configuration
db: postgresql
db-url: jdbc:postgresql://db.company.com:5432/keycloak
db-username: keycloak
db-password: ${DB_PASSWORD}

# Features
features: account3,admin-fine-grained-authz,authorization,web-authn

# Clustering
cache: ispn
cache-stack: kubernetes
```

### Realm Configuration

```json
{
  "realm": "production",
  "enabled": true,
  "registrationAllowed": false,
  "resetPasswordAllowed": true,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "passwordPolicy": "length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1)",
  "sslRequired": "external",
  "loginTheme": "company-theme",
  "emailTheme": "company-theme"
}
```

### Client Configuration

```json
{
  "clientId": "plugpipe-api",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "protocol": "openid-connect",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "authorizationServicesEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "redirectUris": ["https://api.company.com/*"],
  "webOrigins": ["https://api.company.com"]
}
```

## Installation

### Prerequisites

```bash
# Install Keycloak server
docker run -d --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:20.0.0 start-dev

# Or using Docker Compose
version: '3.8'
services:
  keycloak:
    image: quay.io/keycloak/keycloak:20.0.0
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_DB: postgresql
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: password
    ports:
      - "8080:8080"
    command: start-dev
```

### Plug Installation

```bash
# Install Python dependencies
pip install python-keycloak>=3.0.0 requests>=2.25.0

# Install via PlugPipe CLI
plugpipe install identity_keycloak

# Or clone manually
git clone https://github.com/plugpipe/plugs/identity_keycloak
```

## Usage Examples

### Enterprise SSO Integration

```yaml
# pipeline.yaml - Pipe with enterprise SSO
name: enterprise_data_pipeline
steps:
  - name: authenticate_via_sso
    plugin: identity_keycloak
    config:
      operation: authenticate_user
      auth_config:
        username: "{{ pipeline.user }}"
        password: "{{ pipeline.token }}"
        realm: "enterprise"
  
  - name: authorize_data_access
    plugin: identity_keycloak
    config:
      operation: authorize_access
      authz_config:
        user_id: "{{ previous_step.result.user_id }}"
        resource: "customer_data"
        action: "read"
  
  - name: process_data
    plugin: data_processor
    config:
      data_source: "{{ authorized_data_source }}"
    conditions:
      - "{{ steps.authorize_data_access.result.authorized }}"
```

### Identity Federation with LDAP

```python
# Configure LDAP identity federation
import asyncio
from plugpipe import load_plugin

async def setup_ldap_federation():
    keycloak = await load_plugin("identity_keycloak")
    
    # Configure LDAP provider
    await keycloak.process({
        "operation": "configure_ldap",
        "sso_config": {
            "provider_type": "ldap",
            "provider_config": {
                "connection_url": "ldap://ad.company.com:389",
                "bind_dn": "CN=service,OU=Services,DC=company,DC=com",
                "bind_credential": "${LDAP_PASSWORD}",
                "user_dn": "OU=Users,DC=company,DC=com",
                "username_attribute": "sAMAccountName",
                "rdn_attribute": "cn",
                "uuid_attribute": "objectGUID"
            },
            "auto_create_user": True,
            "default_roles": ["employee"]
        }
    }, config)
```

### Role-Based Data Access

```python
# Implement role-based data access control
async def secure_data_access(user_token: str, dataset: str):
    keycloak = await load_plugin("identity_keycloak")
    
    # Validate token and get user info
    token_result = await keycloak.process({
        "operation": "manage_tokens",
        "token_config": {
            "token": user_token,
            "token_type": "access_token",
            "validate_only": True
        }
    }, config)
    
    if not token_result["success"]:
        return {"error": "Invalid token"}
    
    # Check authorization for dataset
    authz_result = await keycloak.process({
        "operation": "authorize_access",
        "authz_config": {
            "user_id": token_result["result"]["user_id"],
            "resource": f"dataset:{dataset}",
            "action": "read"
        }
    }, config)
    
    if authz_result["result"]["authorized"]:
        return {"access_granted": True, "dataset": dataset}
    else:
        return {"access_denied": True, "reason": "Insufficient permissions"}
```

## Realm and Client Templates

### Multi-Tenant Realm Setup

```json
{
  "realm": "tenant-{{tenant_id}}",
  "enabled": true,
  "displayName": "{{tenant_name}} Organization",
  "registrationAllowed": true,
  "resetPasswordAllowed": true,
  "rememberMe": true,
  "verifyEmail": true,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "sslRequired": "external",
  "passwordPolicy": "length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername",
  "attributes": {
    "tenant_id": "{{tenant_id}}",
    "billing_tier": "{{billing_tier}}"
  }
}
```

### API Client Template

```json
{
  "clientId": "{{service_name}}-api",
  "name": "{{service_display_name}} API Client",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "protocol": "openid-connect",
  "publicClient": false,
  "serviceAccountsEnabled": true,
  "authorizationServicesEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "attributes": {
    "access.token.lifespan": "300",
    "client.session.idle.timeout": "1800",
    "client.session.max.lifespan": "7200"
  }
}
```

## Monitoring and Alerting

### Health Checks

```python
# Check identity infrastructure health
health = await keycloak.health_check()
print(f"Keycloak: {health['result']['keycloak_status']}")
print(f"Realm: {health['result']['realm_status']}")
```

### Identity Event Monitoring

```python
# Monitor authentication events
async def monitor_auth_events():
    keycloak = await load_plugin("identity_keycloak")
    
    # This would integrate with Keycloak's event system
    events = await keycloak.process({
        "operation": "get_events",
        "event_config": {
            "event_types": ["LOGIN", "LOGIN_ERROR", "LOGOUT"],
            "time_range": "last_hour"
        }
    }, config)
    
    # Process security events
    for event in events["result"]["events"]:
        if event["type"] == "LOGIN_ERROR":
            print(f"Failed login attempt: {event['userId']} from {event['ipAddress']}")
```

## Troubleshooting

### Common Issues

**Keycloak Server Not Reachable**
```
Error: Identity operation failed: HTTPConnectionPool(host='localhost', port=8080)
Solution: Ensure Keycloak server is running and accessible
```

**Authentication Failed**
```
Error: Authentication failed: 401 Unauthorized
Solution: Verify username/password and realm configuration
```

**SSL Certificate Issues**
```
Error: SSL certificate verification failed
Solution: Set verify_ssl: false for development or configure proper certificates
```

### Debug Mode

```yaml
# Enable debug logging
keycloak_config:
  debug: true
mock_mode: true  # Use mock for development
```

### Keycloak Logs

```bash
# Check Keycloak server logs
docker logs keycloak

# Check specific realm events
curl -X GET "http://localhost:8080/admin/realms/production/events" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Test realm connectivity
curl -X GET "http://localhost:8080/realms/production/.well-known/openid_configuration"
```

## Architecture

This plugin follows PlugPipe's plugin-first identity architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PlugPipe      │    │ Keycloak         │    │ Identity        │
│   Pipe      │───▶│ Plug           │───▶│ Providers       │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Authentication   │    │ LDAP/AD         │
                       │ Services         │    │ Integration     │
                       │                  │    │                 │
                       └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Authorization    │    │ SAML/OIDC       │
                       │ Engine           │    │ Federation      │
                       └──────────────────┘    └─────────────────┘
```

## Security Considerations

### Production Deployment

- **Use HTTPS**: Always deploy Keycloak with SSL/TLS in production
- **Database Security**: Use encrypted connections to the database
- **Network Isolation**: Deploy in a secure network with firewall rules
- **Regular Updates**: Keep Keycloak updated with security patches

### Authentication Best Practices

- **Strong Password Policies**: Enforce complex passwords with rotation
- **Multi-Factor Authentication**: Enable MFA for administrative accounts
- **Session Management**: Configure appropriate session timeouts
- **Brute Force Protection**: Enable account lockout policies

### Compliance and Auditing

- **Audit Logging**: Enable comprehensive event logging
- **Data Retention**: Configure appropriate log retention policies
- **Compliance Reporting**: Generate reports for regulatory compliance
- **Privacy Controls**: Implement GDPR/CCPA data handling procedures

## Contributing

This plugin demonstrates the PlugPipe principle of leveraging proven enterprise technology. When contributing:

1. **Maintain Keycloak Integration**: All enhancements should leverage Keycloak capabilities
2. **Follow Security Best Practices**: Use Keycloak's security features appropriately
3. **Enterprise Compatibility**: Ensure compatibility with enterprise Keycloak deployments
4. **Performance Optimization**: Monitor and optimize identity operation performance

## License

MIT License - see LICENSE file for details.

---

**PlugPipe Philosophy**: This plugin exemplifies "reuse, never reinvent" by leveraging Keycloak's proven enterprise identity and access management platform instead of implementing custom authentication and authorization systems. By integrating with existing enterprise identity infrastructure, we provide standards-based identity management with battle-tested security and rich ecosystem support.