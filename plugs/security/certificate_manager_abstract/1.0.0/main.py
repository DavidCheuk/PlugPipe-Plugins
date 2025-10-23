#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Certificate Manager Abstract Plugin

Abstract base plugin for certificate management operations following PlugPipe's
"reuse everything, reinvent nothing" principle. This plugin defines the universal
certificate management interface that all certificate plugins must implement.

Market Research Foundation:
- HashiCorp Vault PKI (dynamic X.509 certificates)
- AWS Certificate Manager (public/private CA integration)
- Let's Encrypt ACME (automated certificate provisioning)
- DigiCert Trust Lifecycle Manager (enterprise certificate lifecycle)
- Kubernetes cert-manager (cloud-native certificate automation)
- Venafi/CyberArk (machine identity security)

Architecture Principles:
- Abstract interface for certificate operations
- Vendor-neutral certificate management
- Standardized certificate lifecycle operations
- Enterprise security compliance
- Cloud-native and on-premise support
"""

import asyncio
import logging
import re
import base64
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
import json
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class CertificateRequest:
    """Standard certificate request format"""
    common_name: str
    subject_alternative_names: List[str] = None
    organization: str = None
    organizational_unit: str = None
    country: str = None
    state: str = None
    locality: str = None
    key_type: str = "RSA"  # RSA, ECDSA
    key_size: int = 2048
    validity_days: int = 90
    certificate_format: str = "PEM"  # PEM, DER, PKCS12
    use_case: str = "tls_server"  # tls_server, tls_client, code_signing, email

@dataclass
class Certificate:
    """Standard certificate representation"""
    certificate_id: str
    certificate_pem: str
    private_key_pem: str
    certificate_chain: List[str] = None
    serial_number: str = None
    issuer: str = None
    subject: str = None
    not_before: datetime = None
    not_after: datetime = None
    fingerprint_sha256: str = None
    key_type: str = None
    key_size: int = None
    extensions: Dict[str, Any] = None

@dataclass
class CertificateStatus:
    """Certificate status information"""
    certificate_id: str
    status: str  # active, expired, revoked, pending
    validity_status: str  # valid, expiring_soon, expired
    days_until_expiry: int
    last_validation: datetime
    validation_errors: List[str] = None

class AbstractCertificateManager(ABC):
    """
    Abstract base class for certificate management operations
    
    All certificate management plugins must inherit from this class and implement
    the required methods. This ensures consistent interface across all certificate
    providers while maintaining PlugPipe's plugin-based architecture.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.provider_name = self._validate_provider_name(config.get('provider', 'unknown'))
        self.logger = logger.getChild(self.provider_name)

        # Security hardening setup
        self._setup_security_defaults()

    def _validate_provider_name(self, provider: str) -> str:
        """Validate and sanitize certificate provider name."""
        # Certificate provider name validation
        if not re.match(r'^[a-z][a-z0-9_-]{1,32}$', provider.lower()):
            logger.warning(f"Invalid provider name '{provider}', using 'unknown'")
            return 'unknown'

        # Whitelist trusted certificate providers
        trusted_providers = {
            'hashicorp_vault', 'lets_encrypt', 'aws_certificate_manager',
            'digicert', 'venafi', 'microsoft_ca', 'kubernetes_cert_manager',
            'openssl', 'cfssl', 'step_ca', 'vault', 'acme', 'unknown'
        }

        clean_provider = provider.lower().replace('-', '_')
        if clean_provider not in trusted_providers:
            logger.warning(f"Untrusted provider '{provider}', using 'unknown'")
            return 'unknown'

        return clean_provider

    def _setup_security_defaults(self):
        """Setup security hardening defaults for certificate management."""
        # Certificate security defaults
        self.security_config = {
            'min_key_size_rsa': 2048,
            'min_key_size_ecdsa': 256,
            'max_validity_days': 365,
            'require_strong_key': True,
            'block_weak_algorithms': True,
            'enforce_san_validation': True,
            'require_secure_storage': True,
            'enable_audit_logging': True,
            'certificate_transparency_required': True
        }

        # Blocked weak algorithms
        self.blocked_algorithms = {
            'md5', 'sha1', 'des', '3des', 'rc4', 'md2'
        }

        # Allowed key types and minimum sizes
        self.allowed_key_types = {
            'RSA': {'min_size': 2048, 'max_size': 4096},
            'ECDSA': {'min_size': 256, 'max_size': 521},
            'Ed25519': {'min_size': 256, 'max_size': 256}
        }

    def _validate_certificate_request(self, request: CertificateRequest) -> Dict[str, Any]:
        """Validate and sanitize certificate request for security."""
        validation_result = {
            'is_valid': True,
            'sanitized_request': request,
            'errors': [],
            'security_issues': []
        }

        try:
            # Validate common name
            if not self._validate_domain_name(request.common_name):
                validation_result['errors'].append(f"Invalid common name: {request.common_name}")
                validation_result['is_valid'] = False

            # Validate Subject Alternative Names (SANs)
            if request.subject_alternative_names:
                valid_sans = []
                for san in request.subject_alternative_names:
                    if self._validate_domain_name(san):
                        valid_sans.append(san)
                    else:
                        validation_result['security_issues'].append(f"Blocked invalid SAN: {san}")
                request.subject_alternative_names = valid_sans

            # Validate key type and size
            if request.key_type not in self.allowed_key_types:
                validation_result['errors'].append(f"Unsupported key type: {request.key_type}")
                validation_result['is_valid'] = False
            else:
                key_config = self.allowed_key_types[request.key_type]
                if request.key_size < key_config['min_size']:
                    validation_result['errors'].append(
                        f"Key size {request.key_size} below minimum {key_config['min_size']} for {request.key_type}"
                    )
                    validation_result['is_valid'] = False
                elif request.key_size > key_config['max_size']:
                    validation_result['security_issues'].append(
                        f"Key size {request.key_size} exceeds maximum {key_config['max_size']}, using maximum"
                    )
                    request.key_size = key_config['max_size']

            # Validate validity period
            if request.validity_days > self.security_config['max_validity_days']:
                validation_result['security_issues'].append(
                    f"Validity period {request.validity_days} exceeds maximum {self.security_config['max_validity_days']}, using maximum"
                )
                request.validity_days = self.security_config['max_validity_days']

            # Validate organization fields
            if request.organization:
                request.organization = self._sanitize_certificate_field(request.organization)
            if request.organizational_unit:
                request.organizational_unit = self._sanitize_certificate_field(request.organizational_unit)
            if request.country:
                request.country = self._validate_country_code(request.country)
            if request.state:
                request.state = self._sanitize_certificate_field(request.state)
            if request.locality:
                request.locality = self._sanitize_certificate_field(request.locality)

            # Validate use case
            allowed_use_cases = {'tls_server', 'tls_client', 'code_signing', 'email', 'timestamping'}
            if request.use_case not in allowed_use_cases:
                validation_result['security_issues'].append(
                    f"Invalid use case '{request.use_case}', using 'tls_server'"
                )
                request.use_case = 'tls_server'

            validation_result['sanitized_request'] = request

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['errors'].append(f"Validation error: {str(e)}")

        return validation_result

    def _validate_domain_name(self, domain: str) -> bool:
        """Validate domain name for certificate security."""
        if not domain or len(domain) > 253:
            return False

        # Basic domain name regex (RFC compliant)
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, domain):
            return False

        # Block dangerous domains
        blocked_domains = {
            'localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'example.org',
            'test.com', 'invalid', 'local'
        }

        if domain.lower() in blocked_domains:
            return False

        # Block wildcard abuse
        if domain.count('*') > 1 or (domain.startswith('*') and not domain.startswith('*.')):
            return False

        return True

    def _sanitize_certificate_field(self, field: str) -> str:
        """Sanitize certificate field values."""
        if not field:
            return ''

        # Remove dangerous characters
        sanitized = re.sub(r'[<>"\';\\\x00-\x1f\x7f-\x9f]', '', field)

        # Limit length
        return sanitized[:64]

    def _validate_country_code(self, country: str) -> str:
        """Validate ISO 3166-1 alpha-2 country code."""
        if not country or len(country) != 2:
            return 'US'  # Default to US

        # Common ISO 3166-1 alpha-2 codes
        valid_countries = {
            'US', 'CA', 'GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'AU', 'JP',
            'KR', 'CN', 'IN', 'BR', 'MX', 'CH', 'SE', 'NO', 'DK', 'FI'
        }

        country_upper = country.upper()
        if country_upper in valid_countries:
            return country_upper

        return 'US'  # Default to US for invalid codes

    def _validate_certificate_id(self, certificate_id: str) -> str:
        """Validate and sanitize certificate identifier."""
        if not certificate_id:
            return ''

        # Certificate ID should be alphanumeric with allowed separators
        if not re.match(r'^[a-zA-Z0-9_-]{1,64}$', certificate_id):
            logger.error(f"Invalid certificate ID format: {certificate_id}")
            return ''

        return certificate_id

    def _validate_certificate_data(self, certificate_pem: str) -> Dict[str, Any]:
        """Validate certificate PEM data for security issues."""
        validation_result = {
            'is_valid': True,
            'errors': [],
            'security_issues': []
        }

        try:
            # Basic PEM format validation
            if not certificate_pem or not isinstance(certificate_pem, str):
                validation_result['is_valid'] = False
                validation_result['errors'].append("Missing or invalid certificate PEM data")
                return validation_result

            # Check for PEM headers
            if '-----BEGIN CERTIFICATE-----' not in certificate_pem:
                validation_result['is_valid'] = False
                validation_result['errors'].append("Invalid PEM format: missing BEGIN header")

            if '-----END CERTIFICATE-----' not in certificate_pem:
                validation_result['is_valid'] = False
                validation_result['errors'].append("Invalid PEM format: missing END header")

            # Check for suspicious content
            suspicious_patterns = [
                r'<script', r'javascript:', r'data:',
                r'\x00', r'\xff', r'eval\('
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, certificate_pem, re.IGNORECASE):
                    validation_result['security_issues'].append(f"Suspicious content detected: {pattern}")

            # Validate base64 content (basic check)
            try:
                # Extract base64 content between headers
                lines = certificate_pem.split('\n')
                b64_content = ''.join(line.strip() for line in lines
                                    if line.strip() and not line.startswith('-----'))
                if b64_content:
                    base64.b64decode(b64_content)
            except Exception:
                validation_result['security_issues'].append("Invalid base64 encoding in certificate")

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['errors'].append(f"Certificate validation error: {str(e)}")

        return validation_result

    async def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Universal input validation and sanitization for certificate operations."""
        validation_result = {
            'is_valid': True,
            'sanitized_value': data,
            'errors': [],
            'security_issues': []
        }

        try:
            if context == 'certificate_request' and isinstance(data, dict):
                # Convert dict to CertificateRequest for validation
                request = CertificateRequest(**data)
                cert_validation = self._validate_certificate_request(request)
                validation_result.update(cert_validation)
                validation_result['sanitized_value'] = cert_validation['sanitized_request']

            elif context == 'certificate_id':
                validated_id = self._validate_certificate_id(str(data))
                if not validated_id:
                    validation_result['is_valid'] = False
                    validation_result['errors'].append("Invalid certificate ID")
                validation_result['sanitized_value'] = validated_id

            elif context == 'certificate_pem':
                cert_validation = self._validate_certificate_data(str(data))
                validation_result.update(cert_validation)

            elif isinstance(data, str):
                # Generic string sanitization
                sanitized = re.sub(r'[<>"\';\\\x00-\x1f\x7f-\x9f]', '', data)
                validation_result['sanitized_value'] = sanitized[:1024]  # Limit length

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['errors'].append(f"Input validation error: {str(e)}")
            validation_result['security_issues'].append("Input validation failed")

        return validation_result
        
    @abstractmethod
    async def issue_certificate(self, request: CertificateRequest) -> Certificate:
        """Issue a new certificate based on the request parameters"""
        pass
    
    @abstractmethod
    async def renew_certificate(self, certificate_id: str, request: CertificateRequest = None) -> Certificate:
        """Renew an existing certificate"""
        pass
    
    @abstractmethod
    async def revoke_certificate(self, certificate_id: str, reason: str = "unspecified") -> Dict[str, Any]:
        """Revoke a certificate"""
        pass
    
    @abstractmethod
    async def get_certificate(self, certificate_id: str) -> Certificate:
        """Retrieve certificate details"""
        pass
    
    @abstractmethod
    async def list_certificates(self, filters: Dict[str, Any] = None) -> List[Certificate]:
        """List certificates with optional filtering"""
        pass
    
    @abstractmethod
    async def validate_certificate(self, certificate_id: str) -> CertificateStatus:
        """Validate certificate status and expiry"""
        pass
    
    @abstractmethod
    async def get_certificate_chain(self, certificate_id: str) -> List[str]:
        """Get full certificate chain"""
        pass
    
    # Optional methods with default implementations
    async def bulk_issue_certificates(self, requests: List[CertificateRequest]) -> List[Certificate]:
        """Bulk issue certificates (default implementation)"""
        results = []
        for request in requests:
            try:
                cert = await self.issue_certificate(request)
                results.append(cert)
            except Exception as e:
                self.logger.error(f"Failed to issue certificate for {request.common_name}: {e}")
                continue
        return results
    
    async def get_expiring_certificates(self, days_ahead: int = 30) -> List[CertificateStatus]:
        """Get certificates expiring within specified days"""
        all_certificates = await self.list_certificates()
        expiring = []
        
        for cert in all_certificates:
            status = await self.validate_certificate(cert.certificate_id)
            if status.days_until_expiry <= days_ahead and status.days_until_expiry >= 0:
                expiring.append(status)
        
        return expiring
    
    async def auto_renew_expiring_certificates(self, days_ahead: int = 30) -> Dict[str, Any]:
        """Automatically renew certificates expiring soon"""
        expiring = await self.get_expiring_certificates(days_ahead)
        results = {"renewed": 0, "failed": 0, "errors": []}
        
        for cert_status in expiring:
            try:
                await self.renew_certificate(cert_status.certificate_id)
                results["renewed"] += 1
            except Exception as e:
                results["failed"] += 1
                results["errors"].append({
                    "certificate_id": cert_status.certificate_id,
                    "error": str(e)
                })
        
        return results

class CertificateManagerPlugin:
    """
    PlugPipe Certificate Manager Abstract Plugin
    
    This plugin provides the abstract interface and standard operations for
    certificate management across all certificate providers in the PlugPipe ecosystem.
    """
    
    def __init__(self):
        self.logger = logger
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process certificate management operations
        
        Supported operations:
        - issue_certificate: Issue new certificate
        - renew_certificate: Renew existing certificate
        - revoke_certificate: Revoke certificate
        - get_certificate: Retrieve certificate details
        - list_certificates: List all certificates
        - validate_certificate: Validate certificate status
        - get_expiring_certificates: Get certificates expiring soon
        - auto_renew_certificates: Automatically renew expiring certificates
        """
        operation = cfg.get('operation', 'get_status')
        
        try:
            if operation == 'get_status':
                return await self._get_abstract_status(ctx, cfg)
            elif operation == 'validate_interface':
                return await self._validate_interface(ctx, cfg)
            elif operation == 'list_supported_providers':
                return await self._list_supported_providers(ctx, cfg)
            else:
                return {
                    "success": False,
                    "error": f"Abstract plugin does not implement operation: {operation}",
                    "supported_operations": [
                        "get_status", "validate_interface", "list_supported_providers"
                    ],
                    "note": "Use concrete certificate provider plugins for actual certificate operations"
                }
                
        except Exception as e:
            self.logger.error(f"Certificate manager abstract plugin error: {e}")
            return {
                "success": False,
                "error": str(e),
                "plugin": "certificate_manager_abstract"
            }
    
    async def _get_abstract_status(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get abstract plugin status and interface information"""
        return {
            "success": True,
            "plugin": "certificate_manager_abstract",
            "version": "1.0.0",
            "description": "Abstract base plugin for certificate management operations",
            "interface_methods": [
                "issue_certificate", "renew_certificate", "revoke_certificate",
                "get_certificate", "list_certificates", "validate_certificate",
                "get_certificate_chain", "bulk_issue_certificates",
                "get_expiring_certificates", "auto_renew_expiring_certificates"
            ],
            "supported_providers": [
                "hashicorp_vault", "lets_encrypt_acme", "aws_certificate_manager",
                "digicert", "venafi", "microsoft_ca", "kubernetes_cert_manager"
            ],
            "certificate_formats": ["PEM", "DER", "PKCS12"],
            "key_types": ["RSA", "ECDSA"],
            "use_cases": ["tls_server", "tls_client", "code_signing", "email"],
            "enterprise_features": [
                "bulk_operations", "auto_renewal", "expiry_monitoring",
                "certificate_validation", "chain_verification"
            ]
        }
    
    async def _validate_interface(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that concrete implementations follow the abstract interface"""
        provider = cfg.get('provider')
        if not provider:
            return {
                "success": False,
                "error": "Provider name required for interface validation"
            }
        
        # This would be used by concrete plugins to validate their implementation
        required_methods = [
            'issue_certificate', 'renew_certificate', 'revoke_certificate',
            'get_certificate', 'list_certificates', 'validate_certificate',
            'get_certificate_chain'
        ]
        
        return {
            "success": True,
            "provider": provider,
            "required_methods": required_methods,
            "validation_status": "Interface validation framework ready",
            "note": "Concrete plugins should implement all required abstract methods"
        }
    
    async def _list_supported_providers(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """List certificate providers supported by PlugPipe ecosystem"""
        providers = {
            "hashicorp_vault": {
                "name": "HashiCorp Vault PKI",
                "type": "private_ca",
                "features": ["dynamic_certificates", "short_lived_certs", "policy_based_access"],
                "use_cases": ["internal_services", "microservices", "kubernetes"]
            },
            "lets_encrypt_acme": {
                "name": "Let's Encrypt ACME",
                "type": "public_ca",
                "features": ["free_certificates", "automated_renewal", "domain_validation"],
                "use_cases": ["web_servers", "public_apis", "cdn"]
            },
            "aws_certificate_manager": {
                "name": "AWS Certificate Manager",
                "type": "cloud_ca",
                "features": ["aws_integration", "automatic_renewal", "load_balancer_integration"],
                "use_cases": ["aws_workloads", "elastic_load_balancer", "cloudfront"]
            },
            "digicert": {
                "name": "DigiCert Trust Lifecycle Manager",
                "type": "enterprise_ca",
                "features": ["enterprise_support", "quantum_safe", "multi_cloud"],
                "use_cases": ["enterprise_pki", "compliance", "global_deployments"]
            },
            "venafi": {
                "name": "Venafi/CyberArk Certificate Manager",
                "type": "enterprise_platform",
                "features": ["machine_identity", "policy_enforcement", "compliance_reporting"],
                "use_cases": ["enterprise_security", "compliance", "audit_trails"]
            },
            "kubernetes_cert_manager": {
                "name": "cert-manager for Kubernetes",
                "type": "cloud_native",
                "features": ["kubernetes_native", "automatic_renewal", "multiple_issuers"],
                "use_cases": ["kubernetes_workloads", "ingress_certificates", "service_mesh"]
            }
        }
        
        return {
            "success": True,
            "providers": providers,
            "total_providers": len(providers),
            "enterprise_ready": True
        }

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "certificate_manager_abstract",
    "version": "1.0.0",
    "description": "Abstract base plugin for certificate management operations across all certificate providers",
    "author": "PlugPipe Security Team",
    "category": "security",
    "tags": ["certificates", "pki", "security", "abstract", "base"],
    "requirements": [],
    "interface_version": "1.0.0",
    "supported_operations": [
        "get_status", "validate_interface", "list_supported_providers"
    ]
}

# Create plugin instance for PlugPipe
plugin_instance = CertificateManagerPlugin()

# Main process function for PlugPipe
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for PlugPipe"""
    return await plugin_instance.process(ctx, cfg)