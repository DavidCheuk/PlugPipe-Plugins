#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe HashiCorp Vault Certificate Manager Plugin

Production-ready plugin for HashiCorp Vault PKI certificate management following
PlugPipe's "reuse everything, reinvent nothing" principle by integrating with
battle-tested HashiCorp Vault PKI secrets engine.

Key Features (from market research):
- Dynamic X.509 certificate generation on-demand
- Automatic certificate lifecycle management with short TTLs
- Policy-based access control and certificate restrictions
- Private CA operations for internal/microservice certificates
- Kubernetes integration for container workloads
- Enterprise security with audit trails and compliance

Based on HashiCorp Vault PKI Documentation:
- https://www.hashicorp.com/products/vault/use-cases/certificate-management
- https://developer.hashicorp.com/vault/tutorials/archive/kubernetes-cert-manager
"""

import asyncio
import base64
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
import aiohttp
from pathlib import Path
import sys

# Add project root for abstract class import
PROJECT_ROOT = Path(__file__).parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    # Import abstract base classes
    import importlib.util
    abstract_path = PROJECT_ROOT / "plugs/security/certificate_manager_abstract/1.0.0/main.py"
    spec = importlib.util.spec_from_file_location("abstract_cert_manager", str(abstract_path))
    abstract_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(abstract_module)
    
    AbstractCertificateManager = abstract_module.AbstractCertificateManager
    CertificateRequest = abstract_module.CertificateRequest
    Certificate = abstract_module.Certificate
    CertificateStatus = abstract_module.CertificateStatus
    
except Exception as e:
    logging.warning(f"Could not import abstract certificate manager: {e}")
    # Fallback minimal implementation
    class AbstractCertificateManager:
        def __init__(self, config): 
            self.config = config
    
    class CertificateRequest:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class Certificate:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class CertificateStatus:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

logger = logging.getLogger(__name__)

class VaultCertificateManager(AbstractCertificateManager):
    """
    HashiCorp Vault PKI certificate manager implementation
    
    Integrates with Vault's PKI secrets engine to provide dynamic certificate
    generation and management following enterprise security best practices.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Vault connection configuration
        self.vault_url = config.get('vault_url', os.getenv('VAULT_ADDR', 'http://localhost:8200'))
        self.vault_token = config.get('vault_token', os.getenv('VAULT_TOKEN'))
        self.vault_namespace = config.get('vault_namespace', os.getenv('VAULT_NAMESPACE'))
        
        # PKI mount path configuration
        self.pki_mount = config.get('pki_mount', 'pki')
        self.intermediate_pki_mount = config.get('intermediate_pki_mount', 'pki_int')
        
        # Certificate defaults
        self.default_ttl = config.get('default_ttl', '24h')
        self.max_ttl = config.get('max_ttl', '8760h')  # 1 year
        
        # Role configuration
        self.default_role = config.get('default_role', 'default-role')
        
        # Enterprise features
        self.enable_audit_logging = config.get('enable_audit_logging', True)
        self.enable_policy_enforcement = config.get('enable_policy_enforcement', True)
        
        self.logger = logger.getChild('vault')
        
        # Certificate storage for tracking
        self.issued_certificates = {}
    
    async def _make_vault_request(self, method: str, endpoint: str, data: Dict = None, headers: Dict = None) -> Dict[str, Any]:
        """Make authenticated request to Vault API"""
        url = f"{self.vault_url.rstrip('/')}/v1/{endpoint}"
        
        request_headers = {
            'X-Vault-Token': self.vault_token,
            'Content-Type': 'application/json'
        }
        
        if self.vault_namespace:
            request_headers['X-Vault-Namespace'] = self.vault_namespace
            
        if headers:
            request_headers.update(headers)
        
        async with aiohttp.ClientSession() as session:
            if method.upper() == 'GET':
                async with session.get(url, headers=request_headers) as response:
                    if response.status == 404:
                        return {"data": None}
                    response.raise_for_status()
                    return await response.json()
            elif method.upper() == 'POST':
                async with session.post(url, headers=request_headers, json=data or {}) as response:
                    response.raise_for_status()
                    return await response.json()
            elif method.upper() == 'PUT':
                async with session.put(url, headers=request_headers, json=data or {}) as response:
                    response.raise_for_status()
                    return await response.json()
            elif method.upper() == 'DELETE':
                async with session.delete(url, headers=request_headers) as response:
                    response.raise_for_status()
                    return await response.json() if response.content_length else {}
    
    async def issue_certificate(self, request: CertificateRequest) -> Certificate:
        """Issue new certificate using Vault PKI"""
        try:
            # Prepare certificate request for Vault
            vault_request = {
                'common_name': request.common_name,
                'ttl': f"{request.validity_days * 24}h",  # Convert days to hours
                'format': 'pem'
            }
            
            # Add subject alternative names if provided
            if request.subject_alternative_names:
                vault_request['alt_names'] = ','.join(request.subject_alternative_names)
            
            # Add IP SANs if any IP addresses in SANs
            ip_sans = [san for san in (request.subject_alternative_names or []) 
                      if self._is_ip_address(san)]
            if ip_sans:
                vault_request['ip_sans'] = ','.join(ip_sans)
                # Remove IP addresses from alt_names
                dns_sans = [san for san in (request.subject_alternative_names or []) 
                          if not self._is_ip_address(san)]
                if dns_sans:
                    vault_request['alt_names'] = ','.join(dns_sans)
                else:
                    vault_request.pop('alt_names', None)
            
            # Add additional subject information
            if request.organization:
                vault_request['organization'] = request.organization
            if request.organizational_unit:
                vault_request['ou'] = request.organizational_unit
            if request.country:
                vault_request['country'] = request.country
            if request.state:
                vault_request['province'] = request.state
            if request.locality:
                vault_request['locality'] = request.locality
            
            # Issue certificate via Vault PKI
            endpoint = f"{self.intermediate_pki_mount}/issue/{self.default_role}"
            response = await self._make_vault_request('POST', endpoint, vault_request)
            
            if not response.get('data'):
                raise Exception("Vault returned empty response for certificate issuance")
            
            cert_data = response['data']
            
            # Generate certificate ID
            cert_id = f"vault-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{hash(request.common_name) % 10000:04d}"
            
            # Create certificate object
            certificate = Certificate(
                certificate_id=cert_id,
                certificate_pem=cert_data.get('certificate', ''),
                private_key_pem=cert_data.get('private_key', ''),
                certificate_chain=[cert_data.get('issuing_ca', '')] if cert_data.get('issuing_ca') else [],
                serial_number=cert_data.get('serial_number', ''),
                issuer=f"Vault PKI - {self.intermediate_pki_mount}",
                subject=request.common_name,
                not_before=datetime.now(),
                not_after=datetime.now() + timedelta(days=request.validity_days),
                key_type=request.key_type,
                key_size=request.key_size
            )
            
            # Store certificate for tracking
            self.issued_certificates[cert_id] = {
                'certificate': certificate,
                'vault_serial': cert_data.get('serial_number', ''),
                'issued_at': datetime.now(),
                'request': request
            }
            
            if self.enable_audit_logging:
                self.logger.info(f"Certificate issued successfully: {cert_id} for {request.common_name}")
            
            return certificate
            
        except Exception as e:
            self.logger.error(f"Failed to issue certificate for {request.common_name}: {e}")
            raise Exception(f"Vault certificate issuance failed: {e}")
    
    async def renew_certificate(self, certificate_id: str, request: CertificateRequest = None) -> Certificate:
        """Renew certificate (Vault doesn't support renewal, so we reissue)"""
        try:
            if certificate_id not in self.issued_certificates:
                raise Exception(f"Certificate {certificate_id} not found in local tracking")
            
            # Get original request if not provided
            if not request:
                request = self.issued_certificates[certificate_id]['request']
            
            # Issue new certificate (Vault model is reissuance, not renewal)
            new_certificate = await self.issue_certificate(request)
            
            # Revoke old certificate if possible
            try:
                await self.revoke_certificate(certificate_id, "superseded")
            except Exception as e:
                self.logger.warning(f"Could not revoke old certificate during renewal: {e}")
            
            if self.enable_audit_logging:
                self.logger.info(f"Certificate renewed (reissued): {certificate_id} -> {new_certificate.certificate_id}")
            
            return new_certificate
            
        except Exception as e:
            self.logger.error(f"Failed to renew certificate {certificate_id}: {e}")
            raise Exception(f"Certificate renewal failed: {e}")
    
    async def revoke_certificate(self, certificate_id: str, reason: str = "unspecified") -> Dict[str, Any]:
        """Revoke certificate in Vault"""
        try:
            if certificate_id not in self.issued_certificates:
                raise Exception(f"Certificate {certificate_id} not found in local tracking")
            
            cert_info = self.issued_certificates[certificate_id]
            vault_serial = cert_info['vault_serial']
            
            # Revoke in Vault PKI
            revoke_data = {
                'serial_number': vault_serial
            }
            
            endpoint = f"{self.intermediate_pki_mount}/revoke"
            await self._make_vault_request('POST', endpoint, revoke_data)
            
            # Update local tracking
            cert_info['revoked'] = True
            cert_info['revoked_at'] = datetime.now()
            cert_info['revoke_reason'] = reason
            
            if self.enable_audit_logging:
                self.logger.info(f"Certificate revoked: {certificate_id} (serial: {vault_serial})")
            
            return {
                "success": True,
                "certificate_id": certificate_id,
                "serial_number": vault_serial,
                "revoked_at": cert_info['revoked_at'].isoformat(),
                "reason": reason
            }
            
        except Exception as e:
            self.logger.error(f"Failed to revoke certificate {certificate_id}: {e}")
            raise Exception(f"Certificate revocation failed: {e}")
    
    async def get_certificate(self, certificate_id: str) -> Certificate:
        """Retrieve certificate details"""
        if certificate_id not in self.issued_certificates:
            raise Exception(f"Certificate {certificate_id} not found")
        
        return self.issued_certificates[certificate_id]['certificate']
    
    async def list_certificates(self, filters: Dict[str, Any] = None) -> List[Certificate]:
        """List certificates with optional filtering"""
        certificates = []
        
        for cert_id, cert_info in self.issued_certificates.items():
            certificate = cert_info['certificate']
            
            # Apply filters if provided
            if filters:
                if filters.get('status') == 'active' and cert_info.get('revoked'):
                    continue
                if filters.get('status') == 'revoked' and not cert_info.get('revoked'):
                    continue
                if filters.get('common_name') and filters['common_name'] not in certificate.subject:
                    continue
            
            certificates.append(certificate)
        
        return certificates
    
    async def validate_certificate(self, certificate_id: str) -> CertificateStatus:
        """Validate certificate status and expiry"""
        if certificate_id not in self.issued_certificates:
            raise Exception(f"Certificate {certificate_id} not found")
        
        cert_info = self.issued_certificates[certificate_id]
        certificate = cert_info['certificate']
        
        now = datetime.now()
        days_until_expiry = (certificate.not_after - now).days
        
        # Determine validity status
        if cert_info.get('revoked'):
            status = "revoked"
            validity_status = "revoked"
        elif certificate.not_after < now:
            status = "expired"
            validity_status = "expired"
        elif days_until_expiry <= 7:
            status = "active"
            validity_status = "expiring_soon"
        else:
            status = "active"
            validity_status = "valid"
        
        return CertificateStatus(
            certificate_id=certificate_id,
            status=status,
            validity_status=validity_status,
            days_until_expiry=days_until_expiry,
            last_validation=now
        )
    
    async def get_certificate_chain(self, certificate_id: str) -> List[str]:
        """Get full certificate chain"""
        certificate = await self.get_certificate(certificate_id)
        return certificate.certificate_chain or []
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    async def get_vault_status(self) -> Dict[str, Any]:
        """Get Vault PKI engine status"""
        try:
            # Check PKI mount status
            mounts_response = await self._make_vault_request('GET', 'sys/mounts')
            mounts = mounts_response.get('data', {})
            
            pki_mounted = f"{self.intermediate_pki_mount}/" in mounts
            
            status = {
                "vault_url": self.vault_url,
                "pki_mount": self.intermediate_pki_mount,
                "pki_mounted": pki_mounted,
                "certificates_tracked": len(self.issued_certificates),
                "vault_connection": "healthy"
            }
            
            if pki_mounted:
                # Get PKI configuration
                try:
                    config_response = await self._make_vault_request('GET', f"{self.intermediate_pki_mount}/config/ca")
                    status["ca_configured"] = bool(config_response.get('data'))
                except:
                    status["ca_configured"] = False
            
            return status
            
        except Exception as e:
            return {
                "vault_url": self.vault_url,
                "vault_connection": "unhealthy",
                "error": str(e)
            }

class VaultCertificateManagerPlugin:
    """
    PlugPipe HashiCorp Vault Certificate Manager Plugin
    
    Production-ready plugin integrating with HashiCorp Vault PKI for dynamic
    certificate generation and enterprise certificate lifecycle management.
    """
    
    def __init__(self):
        self.logger = logger
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process Vault certificate management operations
        
        Supported operations:
        - issue_certificate: Issue new certificate via Vault PKI
        - renew_certificate: Renew (reissue) existing certificate
        - revoke_certificate: Revoke certificate in Vault
        - get_certificate: Retrieve certificate details
        - list_certificates: List all issued certificates
        - validate_certificate: Validate certificate status
        - get_vault_status: Get Vault PKI engine status
        """
        operation = cfg.get('operation', 'get_status')
        
        try:
            # Initialize Vault certificate manager
            vault_manager = VaultCertificateManager(cfg)
            
            if operation == 'get_status':
                return await self._get_plugin_status(vault_manager, ctx, cfg)
            elif operation == 'issue_certificate':
                return await self._issue_certificate(vault_manager, ctx, cfg)
            elif operation == 'renew_certificate':
                return await self._renew_certificate(vault_manager, ctx, cfg)
            elif operation == 'revoke_certificate':
                return await self._revoke_certificate(vault_manager, ctx, cfg)
            elif operation == 'get_certificate':
                return await self._get_certificate(vault_manager, ctx, cfg)
            elif operation == 'list_certificates':
                return await self._list_certificates(vault_manager, ctx, cfg)
            elif operation == 'validate_certificate':
                return await self._validate_certificate(vault_manager, ctx, cfg)
            elif operation == 'get_vault_status':
                return await self._get_vault_status(vault_manager, ctx, cfg)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operation: {operation}",
                    "supported_operations": [
                        "get_status", "issue_certificate", "renew_certificate", 
                        "revoke_certificate", "get_certificate", "list_certificates",
                        "validate_certificate", "get_vault_status"
                    ]
                }
                
        except Exception as e:
            self.logger.error(f"Vault certificate manager plugin error: {e}")
            return {
                "success": False,
                "error": str(e),
                "plugin": "vault_certificate_manager"
            }
    
    async def _get_plugin_status(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get plugin status and Vault connection info"""
        vault_status = await vault_manager.get_vault_status()
        
        return {
            "success": True,
            "plugin": "vault_certificate_manager",
            "version": "1.0.0",
            "description": "HashiCorp Vault PKI certificate management plugin",
            "vault_status": vault_status,
            "features": [
                "Dynamic certificate generation",
                "Automatic certificate lifecycle management",
                "Policy-based access control",
                "Short-lived certificates",
                "Enterprise audit trails",
                "Private CA operations"
            ],
            "enterprise_ready": True
        }
    
    async def _issue_certificate(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Issue new certificate"""
        # Create certificate request
        request = CertificateRequest(
            common_name=cfg.get('common_name', ''),
            subject_alternative_names=cfg.get('subject_alternative_names', []),
            organization=cfg.get('organization'),
            organizational_unit=cfg.get('organizational_unit'),
            country=cfg.get('country'),
            state=cfg.get('state'),
            locality=cfg.get('locality'),
            key_type=cfg.get('key_type', 'RSA'),
            key_size=cfg.get('key_size', 2048),
            validity_days=cfg.get('validity_days', 90),
            certificate_format=cfg.get('certificate_format', 'PEM'),
            use_case=cfg.get('use_case', 'tls_server')
        )
        
        certificate = await vault_manager.issue_certificate(request)
        
        return {
            "success": True,
            "operation": "issue_certificate",
            "certificate_id": certificate.certificate_id,
            "certificate": {
                "certificate_pem": certificate.certificate_pem,
                "private_key_pem": certificate.private_key_pem,
                "certificate_chain": certificate.certificate_chain,
                "serial_number": certificate.serial_number,
                "subject": certificate.subject,
                "issuer": certificate.issuer,
                "not_before": certificate.not_before.isoformat(),
                "not_after": certificate.not_after.isoformat()
            },
            "provider": "hashicorp_vault"
        }
    
    async def _renew_certificate(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Renew certificate"""
        certificate_id = cfg.get('certificate_id')
        if not certificate_id:
            return {"success": False, "error": "certificate_id required"}
        
        # Prepare renewal request if provided
        request = None
        if cfg.get('common_name'):
            request = CertificateRequest(
                common_name=cfg.get('common_name'),
                subject_alternative_names=cfg.get('subject_alternative_names', []),
                validity_days=cfg.get('validity_days', 90)
            )
        
        certificate = await vault_manager.renew_certificate(certificate_id, request)
        
        return {
            "success": True,
            "operation": "renew_certificate",
            "old_certificate_id": certificate_id,
            "new_certificate_id": certificate.certificate_id,
            "certificate": {
                "certificate_pem": certificate.certificate_pem,
                "private_key_pem": certificate.private_key_pem,
                "not_before": certificate.not_before.isoformat(),
                "not_after": certificate.not_after.isoformat()
            },
            "provider": "hashicorp_vault"
        }
    
    async def _revoke_certificate(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Revoke certificate"""
        certificate_id = cfg.get('certificate_id')
        reason = cfg.get('reason', 'unspecified')
        
        if not certificate_id:
            return {"success": False, "error": "certificate_id required"}
        
        result = await vault_manager.revoke_certificate(certificate_id, reason)
        result["operation"] = "revoke_certificate"
        result["provider"] = "hashicorp_vault"
        
        return result
    
    async def _get_certificate(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get certificate details"""
        certificate_id = cfg.get('certificate_id')
        
        if not certificate_id:
            return {"success": False, "error": "certificate_id required"}
        
        certificate = await vault_manager.get_certificate(certificate_id)
        
        return {
            "success": True,
            "operation": "get_certificate",
            "certificate_id": certificate_id,
            "certificate": {
                "certificate_pem": certificate.certificate_pem,
                "serial_number": certificate.serial_number,
                "subject": certificate.subject,
                "issuer": certificate.issuer,
                "not_before": certificate.not_before.isoformat(),
                "not_after": certificate.not_after.isoformat(),
                "key_type": certificate.key_type,
                "key_size": certificate.key_size
            },
            "provider": "hashicorp_vault"
        }
    
    async def _list_certificates(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """List certificates"""
        filters = cfg.get('filters', {})
        certificates = await vault_manager.list_certificates(filters)
        
        cert_list = []
        for cert in certificates:
            cert_list.append({
                "certificate_id": cert.certificate_id,
                "subject": cert.subject,
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat()
            })
        
        return {
            "success": True,
            "operation": "list_certificates",
            "certificates": cert_list,
            "total_count": len(cert_list),
            "filters_applied": filters,
            "provider": "hashicorp_vault"
        }
    
    async def _validate_certificate(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Validate certificate"""
        certificate_id = cfg.get('certificate_id')
        
        if not certificate_id:
            return {"success": False, "error": "certificate_id required"}
        
        status = await vault_manager.validate_certificate(certificate_id)
        
        return {
            "success": True,
            "operation": "validate_certificate",
            "certificate_id": certificate_id,
            "status": status.status,
            "validity_status": status.validity_status,
            "days_until_expiry": status.days_until_expiry,
            "last_validation": status.last_validation.isoformat(),
            "provider": "hashicorp_vault"
        }
    
    async def _get_vault_status(self, vault_manager, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get Vault PKI status"""
        vault_status = await vault_manager.get_vault_status()
        
        return {
            "success": True,
            "operation": "get_vault_status",
            "vault_status": vault_status,
            "provider": "hashicorp_vault"
        }

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "vault_certificate_manager",
    "version": "1.0.0",
    "description": "HashiCorp Vault PKI certificate management plugin with dynamic certificate generation",
    "author": "PlugPipe Security Team",
    "category": "security",
    "tags": ["vault", "certificates", "pki", "hashicorp", "dynamic_certificates"],
    "requirements": ["aiohttp", "requests"],
    "supported_operations": [
        "get_status", "issue_certificate", "renew_certificate", "revoke_certificate",
        "get_certificate", "list_certificates", "validate_certificate", "get_vault_status"
    ]
}

# Create plugin instance for PlugPipe
plugin_instance = VaultCertificateManagerPlugin()

# Main process function for PlugPipe
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for PlugPipe"""
    return await plugin_instance.process(ctx, cfg)