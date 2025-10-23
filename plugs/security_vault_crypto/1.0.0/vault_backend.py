# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Real HashiCorp Vault backend for security operations.

This module provides concrete implementations for Vault cryptographic operations,
replacing mock implementations with production-ready Vault integrations.
"""

import os
import json
import base64
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
import asyncio

try:
    import hvac
    from hvac.exceptions import VaultError, InvalidPath, Forbidden
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)


class VaultBackend:
    """Production-ready HashiCorp Vault backend for cryptographic operations."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Vault backend."""
        if not VAULT_AVAILABLE:
            raise ImportError("HashiCorp Vault client not available. Install with: pip install hvac")
        
        self.config = config or {}
        self.vault_config = self.config.get("vault_config", {})
        
        # Connection settings
        self.vault_url = self.vault_config.get("url", os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"))
        self.vault_token = self.vault_config.get("token", os.getenv("VAULT_TOKEN"))
        self.vault_namespace = self.vault_config.get("namespace", os.getenv("VAULT_NAMESPACE"))
        self.ca_cert = self.vault_config.get("ca_cert", os.getenv("VAULT_CACERT"))
        self.client_cert = self.vault_config.get("client_cert", os.getenv("VAULT_CLIENT_CERT"))
        self.client_key = self.vault_config.get("client_key", os.getenv("VAULT_CLIENT_KEY"))
        
        # Engine paths
        self.transit_path = self.vault_config.get("transit_path", "transit")
        self.pki_path = self.vault_config.get("pki_path", "pki")
        self.kv_path = self.vault_config.get("kv_path", "secret")
        
        # Initialize client
        self.client = None
        self.initialized = False
        
    async def initialize(self):
        """Initialize Vault client and verify connectivity."""
        if self.initialized:
            return
        
        try:
            # Create Vault client
            self.client = hvac.Client(
                url=self.vault_url,
                token=self.vault_token,
                namespace=self.vault_namespace,
                cert=(self.client_cert, self.client_key) if self.client_cert and self.client_key else None,
                ca_cert=self.ca_cert,
                timeout=30,
                retries=3
            )
            
            # Test authentication
            if not self.client.is_authenticated():
                raise ValueError("Vault authentication failed. Check token and connectivity.")
            
            # Verify required engines are enabled
            await self._verify_engines()
            
            self.initialized = True
            logger.info(f"Connected to Vault at {self.vault_url}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Vault backend: {str(e)}")
            raise
    
    async def _verify_engines(self):
        """Verify required Vault engines are enabled."""
        try:
            auth_mounts = self.client.sys.list_auth_methods()
            secret_mounts = self.client.sys.list_mounted_secrets_engines()
            
            # Check if required engines are mounted
            required_engines = {
                f"{self.transit_path}/": "transit",
                f"{self.pki_path}/": "pki",
                f"{self.kv_path}/": "kv"
            }
            
            for mount_path, engine_type in required_engines.items():
                if mount_path not in secret_mounts["data"]:
                    logger.warning(f"Engine {engine_type} not mounted at {mount_path}")
                    # Optionally enable engines automatically
                    # await self._enable_engine(mount_path, engine_type)
            
        except Exception as e:
            logger.warning(f"Could not verify Vault engines: {str(e)}")
    
    async def encrypt_data(self, key_name: str, plaintext: str, context: Optional[Dict[str, str]] = None) -> str:
        """Encrypt data using Vault Transit engine."""
        await self.initialize()
        
        try:
            # Prepare request
            encrypt_data = {
                'plaintext': base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')
            }
            
            if context:
                encrypt_data['context'] = base64.b64encode(json.dumps(context).encode('utf-8')).decode('utf-8')
            
            # Encrypt using Vault Transit
            response = self.client.secrets.transit.encrypt_data(
                name=key_name,
                mount_point=self.transit_path,
                **encrypt_data
            )
            
            ciphertext = response['data']['ciphertext']
            logger.debug(f"Encrypted data with key {key_name}")
            
            return ciphertext
            
        except VaultError as e:
            logger.error(f"Vault encryption error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    async def decrypt_data(self, key_name: str, ciphertext: str, context: Optional[Dict[str, str]] = None) -> str:
        """Decrypt data using Vault Transit engine."""
        await self.initialize()
        
        try:
            # Prepare request
            decrypt_data = {
                'ciphertext': ciphertext
            }
            
            if context:
                decrypt_data['context'] = base64.b64encode(json.dumps(context).encode('utf-8')).decode('utf-8')
            
            # Decrypt using Vault Transit
            response = self.client.secrets.transit.decrypt_data(
                name=key_name,
                mount_point=self.transit_path,
                **decrypt_data
            )
            
            plaintext_b64 = response['data']['plaintext']
            plaintext = base64.b64decode(plaintext_b64).decode('utf-8')
            
            logger.debug(f"Decrypted data with key {key_name}")
            
            return plaintext
            
        except VaultError as e:
            logger.error(f"Vault decryption error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise
    
    async def sign_data(self, key_name: str, message: str, signature_algorithm: str = "pss") -> str:
        """Sign data using Vault Transit engine."""
        await self.initialize()
        
        try:
            # Prepare message for signing
            message_b64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
            
            # Sign using Vault Transit
            response = self.client.secrets.transit.sign_data(
                name=key_name,
                hash_input=message_b64,
                signature_algorithm=signature_algorithm,
                mount_point=self.transit_path
            )
            
            signature = response['data']['signature']
            logger.debug(f"Signed data with key {key_name}")
            
            return signature
            
        except VaultError as e:
            logger.error(f"Vault signing error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Signing error: {str(e)}")
            raise
    
    async def verify_signature(self, key_name: str, message: str, signature: str, 
                              signature_algorithm: str = "pss") -> bool:
        """Verify signature using Vault Transit engine."""
        await self.initialize()
        
        try:
            # Prepare message for verification
            message_b64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
            
            # Verify using Vault Transit
            response = self.client.secrets.transit.verify_signed_data(
                name=key_name,
                hash_input=message_b64,
                signature=signature,
                signature_algorithm=signature_algorithm,
                mount_point=self.transit_path
            )
            
            valid = response['data']['valid']
            logger.debug(f"Verified signature with key {key_name}: {valid}")
            
            return valid
            
        except VaultError as e:
            logger.error(f"Vault verification error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Verification error: {str(e)}")
            raise
    
    async def create_key(self, key_name: str, key_type: str = "aes256-gcm96", 
                        exportable: bool = False, allow_plaintext_backup: bool = False) -> Dict[str, Any]:
        """Create a new cryptographic key in Vault Transit engine."""
        await self.initialize()
        
        try:
            # Create key in Vault Transit
            self.client.secrets.transit.create_key(
                name=key_name,
                key_type=key_type,
                exportable=exportable,
                allow_plaintext_backup=allow_plaintext_backup,
                mount_point=self.transit_path
            )
            
            # Get key info
            key_info = await self.get_key_info(key_name)
            
            logger.info(f"Created key {key_name} of type {key_type}")
            
            return {
                "key_name": key_name,
                "key_type": key_type,
                "key_version": key_info.get("latest_version", 1),
                "creation_time": key_info.get("creation_time"),
                "exportable": exportable
            }
            
        except VaultError as e:
            logger.error(f"Vault key creation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Key creation error: {str(e)}")
            raise
    
    async def rotate_key(self, key_name: str) -> Dict[str, Any]:
        """Rotate cryptographic key in Vault Transit engine."""
        await self.initialize()
        
        try:
            # Rotate key in Vault
            response = self.client.secrets.transit.rotate_key(
                name=key_name,
                mount_point=self.transit_path
            )
            
            # Get updated key info
            key_info = await self.get_key_info(key_name)
            
            logger.info(f"Rotated key {key_name} to version {key_info.get('latest_version')}")
            
            return {
                "key_name": key_name,
                "new_version": key_info.get("latest_version"),
                "rotation_time": datetime.now(timezone.utc).isoformat()
            }
            
        except VaultError as e:
            logger.error(f"Vault key rotation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Key rotation error: {str(e)}")
            raise
    
    async def get_key_info(self, key_name: str) -> Dict[str, Any]:
        """Get information about a key from Vault Transit engine."""
        await self.initialize()
        
        try:
            response = self.client.secrets.transit.read_key(
                name=key_name,
                mount_point=self.transit_path
            )
            
            return response['data']
            
        except VaultError as e:
            logger.error(f"Vault key info error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Key info error: {str(e)}")
            raise
    
    async def create_certificate(self, common_name: str, ttl: str = "8760h", 
                                alt_names: Optional[List[str]] = None,
                                ip_sans: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create certificate using Vault PKI engine."""
        await self.initialize()
        
        try:
            # Prepare certificate request
            cert_data = {
                'common_name': common_name,
                'ttl': ttl
            }
            
            if alt_names:
                cert_data['alt_names'] = ','.join(alt_names)
            
            if ip_sans:
                cert_data['ip_sans'] = ','.join(ip_sans)
            
            # Create certificate using Vault PKI
            response = self.client.secrets.pki.generate_certificate(
                name='default',  # Role name - would be configurable
                mount_point=self.pki_path,
                **cert_data
            )
            
            cert_data = response['data']
            
            logger.info(f"Created certificate for {common_name}")
            
            return {
                "certificate": cert_data['certificate'],
                "private_key": cert_data['private_key'],
                "serial_number": cert_data['serial_number'],
                "issuing_ca": cert_data.get('issuing_ca'),
                "ca_chain": cert_data.get('ca_chain', [])
            }
            
        except VaultError as e:
            logger.error(f"Vault certificate creation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Certificate creation error: {str(e)}")
            raise
    
    async def revoke_certificate(self, serial_number: str) -> Dict[str, Any]:
        """Revoke certificate using Vault PKI engine."""
        await self.initialize()
        
        try:
            response = self.client.secrets.pki.revoke_certificate(
                serial_number=serial_number,
                mount_point=self.pki_path
            )
            
            logger.info(f"Revoked certificate {serial_number}")
            
            return {
                "serial_number": serial_number,
                "revocation_time": response['data']['revocation_time']
            }
            
        except VaultError as e:
            logger.error(f"Vault certificate revocation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Certificate revocation error: {str(e)}")
            raise
    
    async def store_secret(self, path: str, secret_data: Dict[str, Any], 
                          version: Optional[int] = None) -> Dict[str, Any]:
        """Store secret using Vault KV engine."""
        await self.initialize()
        
        try:
            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data,
                mount_point=self.kv_path,
                cas=version
            )
            
            logger.debug(f"Stored secret at {path}")
            
            return {
                "path": path,
                "version": response['data']['version'],
                "created_time": response['data']['created_time']
            }
            
        except VaultError as e:
            logger.error(f"Vault secret storage error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Secret storage error: {str(e)}")
            raise
    
    async def retrieve_secret(self, path: str, version: Optional[int] = None) -> Dict[str, Any]:
        """Retrieve secret using Vault KV engine."""
        await self.initialize()
        
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
                mount_point=self.kv_path
            )
            
            logger.debug(f"Retrieved secret from {path}")
            
            return {
                "data": response['data']['data'],
                "metadata": response['data']['metadata']
            }
            
        except VaultError as e:
            logger.error(f"Vault secret retrieval error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Secret retrieval error: {str(e)}")
            raise
    
    async def delete_secret(self, path: str, versions: Optional[List[int]] = None) -> Dict[str, Any]:
        """Delete secret versions using Vault KV engine."""
        await self.initialize()
        
        try:
            if versions:
                # Delete specific versions
                response = self.client.secrets.kv.v2.delete_secret_versions(
                    path=path,
                    versions=versions,
                    mount_point=self.kv_path
                )
            else:
                # Soft delete latest version
                response = self.client.secrets.kv.v2.delete_latest_version_of_secret(
                    path=path,
                    mount_point=self.kv_path
                )
            
            logger.debug(f"Deleted secret versions at {path}")
            
            return {
                "path": path,
                "deleted_versions": versions or ["latest"]
            }
            
        except VaultError as e:
            logger.error(f"Vault secret deletion error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Secret deletion error: {str(e)}")
            raise
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get Vault health status."""
        try:
            if not self.initialized:
                await self.initialize()
            
            # Get Vault health
            health = self.client.sys.read_health_status(standby_ok=True)
            
            # Get secret engines status
            engines = self.client.sys.list_mounted_secrets_engines()
            
            return {
                "healthy": True,
                "vault_status": "connected",
                "vault_version": health.get("version"),
                "cluster_name": health.get("cluster_name"),
                "sealed": health.get("sealed", False),
                "standby": health.get("standby", False),
                "engines": list(engines["data"].keys()) if engines else []
            }
            
        except Exception as e:
            logger.error(f"Vault health check error: {str(e)}")
            return {
                "healthy": False,
                "vault_status": "error",
                "error": str(e)
            }
    
    async def close(self):
        """Close Vault connection."""
        if self.client:
            # hvac client doesn't require explicit closing
            pass
        
        self.initialized = False
        logger.info("Closed Vault backend connection")