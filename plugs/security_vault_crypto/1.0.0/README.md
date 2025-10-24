# HashiCorp Vault Crypto Plug

## Overview

The HashiCorp Vault Crypto Plug demonstrates PlugPipe's core principle **"reuse, never reinvent"** by leveraging HashiCorp Vault's proven cryptographic engine for all cryptographic operations, instead of implementing custom crypto code.

## Philosophy: Enterprise Cryptography Done Right

This plugin exemplifies the PlugPipe approach to cryptographic security:

✅ **Reuse Proven Cryptography**: HashiCorp Vault provides enterprise-grade, FIPS-compliant cryptographic operations  
✅ **Never Reinvent Crypto**: Instead of custom implementations, we integrate with Vault's battle-tested crypto engine  
✅ **Enterprise Integration**: Works with existing Vault infrastructure, policies, and HSM backends  
✅ **Community Validated**: Leverages Vault's massive community and security validation  

## Features

### 🔐 **Enterprise Cryptographic Operations**
- **Encryption/Decryption**: AES-GCM, ChaCha20-Poly1305 via Vault Transit engine
- **Digital Signing**: RSA-PSS, ECDSA, Ed25519 signatures with automatic key management
- **Key Management**: Automatic key generation, rotation, and lifecycle management
- **Certificate Operations**: X.509 certificate generation and signing via Vault PKI

### 🛡️ **Enterprise Security Features**
- **FIPS 140-2 Compliance**: FIPS-validated cryptographic operations when using appropriate Vault configuration
- **HSM Integration**: Hardware Security Module support through Vault Enterprise
- **Audit Logging**: Comprehensive audit trails for all cryptographic operations
- **Role-Based Access**: Integration with Vault's RBAC and policy systems

### ⚙️ **Production Features**
- **High Availability**: Vault clustering and auto-unseal support
- **Cloud Integration**: Auto-unseal with AWS KMS, Azure Key Vault, Google Cloud KMS
- **Namespace Support**: Multi-tenant isolation via Vault namespaces
- **Policy Enforcement**: Vault policies control crypto operation permissions

## Configuration

### Basic Usage

```yaml
# Pipe step using Vault crypto
steps:
  - plugin: security_vault_crypto
    config:
      operation: "encrypt"
      data: "sensitive data to encrypt"
      key_name: "my-encryption-key"
      vault_config:
        url: "${VAULT_ADDR}"
        token: "${VAULT_TOKEN}"
        mount_path: "transit"
```

### Advanced Configuration

```yaml
# Production Vault crypto configuration
vault_config:
  url: "https://vault.company.com:8200"
  token: "${VAULT_TOKEN}"
  namespace: "production"
  ca_cert: "/etc/ssl/certs/vault-ca.pem"
  mount_path: "crypto"
  pki_path: "pki"
  role_name: "web-server"

# Security settings
security_level: "strict"
audit_all_operations: true
```

### Environment-Specific Templates

#### Development
```yaml
vault_config:
  url: "http://127.0.0.1:8200"
  token: "${VAULT_DEV_TOKEN}"
  mount_path: "transit"
security_level: "standard"
```

#### Production
```yaml
vault_config:
  url: "${VAULT_ADDR}"
  token: "${VAULT_TOKEN}"
  namespace: "${VAULT_NAMESPACE}"
  ca_cert: "${VAULT_CACERT}"
  mount_path: "transit"
  pki_path: "pki"
security_level: "strict"
audit_all_operations: true
```

## Supported Operations

### Encryption/Decryption

```python
# Encrypt data
encrypt_result = await vault_crypto.process({
    "operation": "encrypt",
    "data": "sensitive information",
    "key_name": "app-encryption-key"
}, config)

# Decrypt data
decrypt_result = await vault_crypto.process({
    "operation": "decrypt",
    "data": encrypt_result["result"]["ciphertext"],
    "key_name": "app-encryption-key"
}, config)
```

### Digital Signing

```python
# Sign message
sign_result = await vault_crypto.process({
    "operation": "sign",
    "message": "document to sign",
    "key_name": "signing-key",
    "algorithm": "rsa-pss"
}, config)

# Verify signature
verify_result = await vault_crypto.process({
    "operation": "verify",
    "message": "document to sign",
    "signature": sign_result["result"]["signature"],
    "key_name": "signing-key",
    "algorithm": "rsa-pss"
}, config)
```

### Key Management

```python
# Generate new key
key_result = await vault_crypto.process({
    "operation": "generate_key",
    "key_name": "new-crypto-key",
    "key_type": "aes256-gcm96",
    "exportable": False
}, config)

# Rotate existing key
rotate_result = await vault_crypto.process({
    "operation": "rotate_key",
    "key_name": "existing-key"
}, config)
```

### Certificate Operations

```python
# Create certificate
cert_result = await vault_crypto.process({
    "operation": "create_certificate",
    "certificate_config": {
        "common_name": "api.company.com",
        "alt_names": ["api-internal.company.com"],
        "ttl": "8760h"  # 1 year
    },
    "vault_config": {
        "role_name": "web-server"
    }
}, config)
```

## Vault Engine Integration

### Transit Engine (Encryption & Signing)

```bash
# Enable Transit engine in Vault
vault auth -method=userpass username=admin
vault secrets enable transit

# Create encryption key
vault write -f transit/keys/my-key

# Create signing key  
vault write transit/keys/signing-key type=rsa-2048
```

### PKI Engine (Certificates)

```bash
# Enable PKI engine
vault secrets enable pki

# Configure PKI
vault write pki/root/generate/internal \
    common_name="Company CA" \
    ttl=8760h

# Create role
vault write pki/roles/web-server \
    allowed_domains="company.com" \
    allow_subdomains=true \
    max_ttl=8760h
```

## Installation

### Prerequisites

```bash
# Install HashiCorp Vault server
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault

# Install Python dependencies
pip install hvac>=1.0.0 cryptography>=36.0.0
```

### Plug Installation

```bash
# Install via PlugPipe CLI
plugpipe install security_vault_crypto

# Or clone manually
git clone https://github.com/plugpipe/plugs/security_vault_crypto
```

### Vault Configuration

```hcl
# vault.hcl - Basic Vault configuration
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
ui = true
```

## Usage Examples

### Basic Encryption Pipe

```yaml
# pipeline.yaml - Secure data processing
name: secure_data_pipeline
steps:
  - name: validate_input
    plugin: data_validator
    config:
      schema: input_schema.json
  
  - name: encrypt_sensitive_data
    plugin: security_vault_crypto
    config:
      operation: encrypt
      data: "{{ previous_step.sensitive_field }}"
      key_name: "data-encryption-key"
      vault_config:
        url: "${VAULT_ADDR}"
        token: "${VAULT_TOKEN}"
  
  - name: store_encrypted_data
    plugin: database_writer
    config:
      table: encrypted_data
      data:
        ciphertext: "{{ previous_step.result.ciphertext }}"
        key_name: "{{ previous_step.result.key_name }}"
```

### Certificate Generation Pipe

```yaml
# cert-pipeline.yaml - Automated certificate generation
name: certificate_generation
steps:
  - name: generate_server_cert
    plugin: security_vault_crypto
    config:
      operation: create_certificate
      certificate_config:
        common_name: "{{ input.hostname }}"
        alt_names: 
          - "{{ input.hostname }}.internal"
          - "{{ input.ip_address }}"
        ttl: "8760h"
      vault_config:
        pki_path: "pki"
        role_name: "server-cert"
  
  - name: deploy_certificate
    plugin: deployment_manager
    config:
      certificate: "{{ previous_step.result.certificate }}"
      private_key: "{{ previous_step.result.private_key }}"
      target_servers: "{{ input.target_servers }}"
```

### Integration with Monitoring

```python
# Monitor crypto operations
import asyncio
from plugpipe import load_plugin

async def monitored_crypto_operation():
    vault_crypto = await load_plugin("security_vault_crypto")
    monitor = await load_plugin("prometheus_monitor")
    
    # Perform crypto operation
    start_time = time.time()
    result = await vault_crypto.process({
        "operation": "encrypt",
        "data": "sensitive data",
        "key_name": "monitoring-key"
    }, vault_config)
    
    # Record metrics
    await monitor.process({
        "metric_name": "vault_crypto_operation_duration",
        "value": time.time() - start_time,
        "labels": {
            "operation": "encrypt",
            "success": str(result["success"]).lower()
        }
    }, monitor_config)
    
    return result
```

## Security Considerations

### Vault Security Best Practices

#### 1. **Authentication & Authorization**
```bash
# Use appropriate auth methods (not root token in production)
vault auth enable userpass
vault auth enable ldap
vault auth enable oidc
```

#### 2. **Policy-Based Access Control**
```hcl
# crypto-policy.hcl - Restrict crypto operations
path "transit/encrypt/app-*" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/app-*" {
  capabilities = ["create", "update"]
}

path "transit/keys/app-*" {
  capabilities = ["read"]
}
```

#### 3. **Audit Logging**
```hcl
# Enable audit logging
audit "file" {
  file_path = "/opt/vault/logs/audit.log"
}
```

### Production Security Checklist

- [ ] Vault sealed with auto-unseal (cloud KMS)
- [ ] TLS encryption enabled for all Vault communication
- [ ] Appropriate authentication method configured (not dev tokens)
- [ ] Vault policies restrict crypto operations by role
- [ ] Audit logging enabled and monitored
- [ ] Regular key rotation policies in place
- [ ] Vault infrastructure properly secured and monitored

## Monitoring and Observability

### Health Checks

```python
# Check Vault crypto plugin health
health = await vault_crypto.health_check()
print(f"Vault status: {health['vault_status']}")
print(f"Transit enabled: {health['transit_enabled']}")
print(f"PKI enabled: {health['pki_enabled']}")
```

### Integration with Prometheus

```yaml
# Monitor crypto operations
steps:
  - plugin: security_vault_crypto
    config: {...}
    
  - plugin: prometheus_monitor
    config:
      metrics:
        - name: vault_crypto_operations_total
          type: counter
          value: 1
          labels:
            operation: "{{ vault_crypto.operation }}"
            success: "{{ vault_crypto.success }}"
            key_name: "{{ vault_crypto.key_name }}"
```

### Audit Trail Integration

```yaml
# Log all crypto operations
steps:
  - plugin: security_vault_crypto
    config: {...}
    
  - plugin: security_audit_logger
    config:
      event_type: cryptographic_operation
      details:
        operation: "{{ vault_crypto.operation }}"
        key_name: "{{ vault_crypto.key_name }}"
        vault_path: "{{ vault_crypto.vault_metadata.vault_path }}"
        success: "{{ vault_crypto.success }}"
```

## Troubleshooting

### Common Issues

**Vault Authentication Failed**
```
Error: Vault authentication failed. Check token and connectivity.
Solution: Verify VAULT_TOKEN and VAULT_ADDR environment variables
```

**Transit Engine Not Enabled**
```
Error: secrets engine "transit" is not enabled
Solution: Enable transit engine: vault secrets enable transit
```

**Key Not Found**
```
Error: key "my-key" not found
Solution: Create key: vault write -f transit/keys/my-key
```

**Permission Denied**
```
Error: 1 error occurred: permission denied
Solution: Check Vault policies allow the requested operation
```

### Debug Mode

```yaml
# Enable debug logging
vault_config:
  debug: true
  log_level: "trace"
mock_vault: true  # Use mock for development
```

### Vault Server Logs

```bash
# Check Vault server logs
sudo journalctl -u vault -f

# Check audit logs
tail -f /opt/vault/logs/audit.log
```

## Architecture

This plugin follows PlugPipe's plugin-first security architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PlugPipe      │    │ Vault Crypto     │    │ HashiCorp       │
│   Pipe      │───▶│ Plug           │───▶│ Vault Server    │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Crypto Operation │    │ Vault Engines   │
                       │ (Encrypted)      │    │ • Transit       │
                       │                  │    │ • PKI          │
                       └──────────────────┘    │ • KV           │
                                               └─────────────────┘
```

## Contributing

This plugin demonstrates the PlugPipe principle of leveraging proven technology. When contributing:

1. **Maintain Vault Integration**: All enhancements should leverage Vault capabilities
2. **Security First**: Any changes must maintain or improve security posture  
3. **Enterprise Compatibility**: Consider Vault Enterprise features and HSM integration
4. **Performance Optimization**: Monitor and optimize Vault API call patterns

## License

MIT License - see LICENSE file for details.

---

**PlugPipe Philosophy**: This plugin exemplifies "reuse, never reinvent" by leveraging HashiCorp Vault's proven cryptographic engine instead of implementing custom crypto operations. By integrating with existing Vault infrastructure, we provide enterprise-grade cryptographic operations with battle-tested reliability and FIPS compliance.