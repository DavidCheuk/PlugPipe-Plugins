# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
HashiCorp Vault Cryptographic Plug for PlugPipe Security.

This plugin demonstrates the PlugPipe principle "reuse, never reinvent" by leveraging 
HashiCorp Vault's proven cryptographic engine instead of implementing custom crypto operations.

Philosophy:
- Reuse Vault's enterprise-grade key management and cryptographic operations
- Never reinvent cryptography that's already been battle-tested
- Integrate with existing Vault infrastructure and policies
- Provide FIPS-compliant and HSM-backed cryptographic operations

Security Features via Vault:
- Enterprise key management with automatic rotation
- FIPS 140-2 compliant cryptographic operations  
- Hardware Security Module (HSM) integration support
- Comprehensive audit logging of all crypto operations
- Role-based access control and policy enforcement
"""

import os
import json
import base64
import logging
from typing import Dict, Any, Optional, List, Union
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
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Import real Vault backend
try:
    from .vault_backend import VaultBackend
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False

logger = logging.getLogger(__name__)


class VaultCryptoPlug:
    """
    HashiCorp Vault cryptographic operations plugin.
    
    This plugin wraps Vault's enterprise-grade cryptographic engine instead of
    implementing custom crypto operations, following PlugPipe's "reuse, never reinvent" principle.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Vault crypto plugin."""
        if not VAULT_AVAILABLE:
            raise ImportError("HashiCorp Vault client not available. Install with: pip install hvac")
        
        self.config = config or {}
        self.vault_config = self.config.get("vault_config", {})
        
        # Initialize real Vault backend
        self.backend = None
        if BACKEND_AVAILABLE:
            self.backend = VaultBackend(self.config)
        else:
            logger.warning("Vault backend not available - using fallback implementations")
        
        # Legacy Vault client for backward compatibility
        self.vault_client = self._initialize_vault_client()
        
        # Configuration
        self.default_mount_path = self.vault_config.get("mount_path", "transit")
        self.default_pki_path = self.vault_config.get("pki_path", "pki")
        self.audit_all_operations = self.config.get("audit_all_operations", True)
        
        logger.info("Vault crypto plugin initialized successfully")
    
    def _initialize_vault_client(self):
        """Initialize HashiCorp Vault client."""
        try:
            # Vault connection parameters
            vault_url = self.vault_config.get("url", os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"))
            vault_token = self.vault_config.get("token", os.getenv("VAULT_TOKEN"))
            vault_namespace = self.vault_config.get("namespace", os.getenv("VAULT_NAMESPACE"))
            ca_cert = self.vault_config.get("ca_cert", os.getenv("VAULT_CACERT"))
            
            if not vault_token:
                raise ValueError("Vault token required. Set VAULT_TOKEN or provide in config.")
            
            # Create Vault client
            client = hvac.Client(
                url=vault_url,
                token=vault_token,
                namespace=vault_namespace,
                cert=ca_cert
            )
            
            # Test authentication with real Vault
            if not client.is_authenticated():
                logger.warning("Vault authentication failed. Plug will use fallback mode.")
                return None
            
            logger.info(f"Connected to Vault at {vault_url}")
            
            return client
            
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Vault client: {str(e)}")
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process cryptographic operation using HashiCorp Vault.
        
        Args:
            ctx: Operation context with parameters
            cfg: Plug configuration
            
        Returns:
            Cryptographic operation result
        """
        try:
            # Extract operation parameters
            operation = ctx.get("operation")
            if not operation:
                return {
                    "success": False,
                    "error": "Operation parameter is required"
                }
            
            # Route to appropriate handler
            if operation in ["encrypt", "decrypt"]:
                result = await self._handle_encryption_operation(ctx, cfg)
            elif operation in ["sign", "verify"]:
                result = await self._handle_signing_operation(ctx, cfg)
            elif operation in ["generate_key", "rotate_key"]:
                result = await self._handle_key_operation(ctx, cfg)
            elif operation in ["create_certificate", "sign_certificate"]:
                result = await self._handle_pki_operation(ctx, cfg)
            elif operation == "get_public_key":
                result = await self._handle_public_key_operation(ctx, cfg)
            elif operation in ["seal_data", "unseal_data"]:
                result = await self._handle_kv_operation(ctx, cfg)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operation: {operation}"
                }
            
            # Add audit information
            if self.audit_all_operations and result.get("success"):
                await self._audit_operation(operation, ctx, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Vault crypto operation error: {str(e)}")
            return {
                "success": False,
                "error": f"Vault operation failed: {str(e)}"
            }
    
    async def _handle_encryption_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle encryption/decryption operations via Vault Transit engine."""
        try:
            operation = ctx.get("operation")
            key_name = ctx.get("key_name")
            mount_path = ctx.get("vault_config", {}).get("mount_path", self.default_mount_path)
            
            if not key_name:
                return {"success": False, "error": "key_name is required for encryption operations"}
            
            if operation == "encrypt":
                data = ctx.get("data")
                if not data:
                    return {"success": False, "error": "data is required for encryption"}
                
                # Convert data to string if needed
                if not isinstance(data, str):
                    data = str(data)
                
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for encryption
                    context = ctx.get("encryption_context")
                    ciphertext = await self.backend.encrypt_data(key_name, data, context)
                except Exception as e:
                    logger.error(f"Encryption failed: {str(e)}")
                    return {"success": False, "error": f"Encryption failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "ciphertext": ciphertext,
                        "key_name": key_name
                    },
                    "vault_metadata": {
                        "vault_path": f"{mount_path}/encrypt/{key_name}",
                        "operation": "encrypt"
                    }
                }
            
            elif operation == "decrypt":
                ciphertext = ctx.get("data")  # For decrypt, 'data' contains the ciphertext
                if not ciphertext:
                    return {"success": False, "error": "ciphertext data is required for decryption"}
                
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for decryption
                    context = ctx.get("encryption_context")
                    plaintext = await self.backend.decrypt_data(key_name, ciphertext, context)
                except Exception as e:
                    logger.error(f"Decryption failed: {str(e)}")
                    return {"success": False, "error": f"Decryption failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "plaintext": plaintext,
                        "key_name": key_name
                    },
                    "vault_metadata": {
                        "vault_path": f"{mount_path}/decrypt/{key_name}",
                        "operation": "decrypt"
                    }
                }
                
        except VaultError as e:
            logger.error(f"Vault encryption error: {str(e)}")
            return {"success": False, "error": f"Vault encryption error: {str(e)}"}
        except Exception as e:
            logger.error(f"Encryption operation error: {str(e)}")
            return {"success": False, "error": f"Encryption operation failed: {str(e)}"}
    
    async def _handle_signing_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle signing/verification operations via Vault Transit engine."""
        try:
            operation = ctx.get("operation")
            key_name = ctx.get("key_name")
            message = ctx.get("message")
            mount_path = ctx.get("vault_config", {}).get("mount_path", self.default_mount_path)
            algorithm = ctx.get("algorithm", "rsa-pss")
            
            if not key_name or not message:
                return {"success": False, "error": "key_name and message are required"}
            
            # Convert algorithm to Vault format
            vault_algorithms = {
                "rsa-pss": "pss",
                "rsa-pkcs1v15": "pkcs1v15", 
                "ecdsa-p256": "ecdsa-p256",
                "ecdsa-p384": "ecdsa-p384",
                "ed25519": "ed25519"
            }
            vault_algorithm = vault_algorithms.get(algorithm, "pss")
            
            if operation == "sign":
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for signing
                    signature = await self.backend.sign_data(key_name, message, vault_algorithm)
                except Exception as e:
                    logger.error(f"Signing failed: {str(e)}")
                    return {"success": False, "error": f"Signing failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "signature": signature,
                        "algorithm": algorithm,
                        "key_name": key_name
                    },
                    "vault_metadata": {
                        "vault_path": f"{mount_path}/sign/{key_name}",
                        "operation": "sign"
                    }
                }
            
            elif operation == "verify":
                signature = ctx.get("signature")
                if not signature:
                    return {"success": False, "error": "signature is required for verification"}
                
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for verification
                    valid = await self.backend.verify_signature(key_name, message, signature, vault_algorithm)
                except Exception as e:
                    logger.error(f"Verification failed: {str(e)}")
                    return {"success": False, "error": f"Verification failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "valid": valid,
                        "algorithm": algorithm,
                        "key_name": key_name
                    },
                    "vault_metadata": {
                        "vault_path": f"{mount_path}/verify/{key_name}",
                        "operation": "verify"
                    }
                }
                
        except VaultError as e:
            logger.error(f"Vault signing error: {str(e)}")
            return {"success": False, "error": f"Vault signing error: {str(e)}"}
        except Exception as e:
            logger.error(f"Signing operation error: {str(e)}")
            return {"success": False, "error": f"Signing operation failed: {str(e)}"}
    
    async def _handle_key_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle key generation and rotation operations."""
        try:
            operation = ctx.get("operation")
            key_name = ctx.get("key_name")
            mount_path = ctx.get("vault_config", {}).get("mount_path", self.default_mount_path)
            
            if not key_name:
                return {"success": False, "error": "key_name is required"}
            
            if operation == "generate_key":
                key_type = ctx.get("key_type", "aes256-gcm96")
                exportable = ctx.get("exportable", False)
                allow_plaintext_backup = ctx.get("allow_plaintext_backup", False)
                
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for key creation
                    key_info = await self.backend.create_key(
                        key_name=key_name,
                        key_type=key_type,
                        exportable=exportable,
                        allow_plaintext_backup=allow_plaintext_backup
                    )
                    key_version = key_info.get("key_version", 1)
                    creation_time = key_info.get("creation_time", datetime.now(timezone.utc).isoformat())
                except Exception as e:
                    logger.error(f"Key generation failed: {str(e)}")
                    return {"success": False, "error": f"Key generation failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "key_name": key_name,
                        "key_version": key_version,
                        "key_type": key_type,
                        "exportable": exportable
                    },
                    "vault_metadata": {
                        "creation_time": creation_time,
                        "vault_path": f"{mount_path}/keys/{key_name}",
                        "operation": "generate_key"
                    }
                }
            
            elif operation == "rotate_key":
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for key rotation
                    rotation_info = await self.backend.rotate_key(key_name)
                    key_version = rotation_info.get("new_version", 2)
                except Exception as e:
                    logger.error(f"Key rotation failed: {str(e)}")
                    return {"success": False, "error": f"Key rotation failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "key_name": key_name,
                        "key_version": key_version
                    },
                    "vault_metadata": {
                        "vault_path": f"{mount_path}/keys/{key_name}",
                        "operation": "rotate_key"
                    }
                }
                
        except VaultError as e:
            logger.error(f"Vault key operation error: {str(e)}")
            return {"success": False, "error": f"Vault key operation error: {str(e)}"}
        except Exception as e:
            logger.error(f"Key operation error: {str(e)}")
            return {"success": False, "error": f"Key operation failed: {str(e)}"}
    
    async def _handle_pki_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle PKI certificate operations via Vault PKI engine."""
        try:
            operation = ctx.get("operation")
            pki_path = ctx.get("vault_config", {}).get("pki_path", self.default_pki_path)
            
            if operation == "create_certificate":
                cert_config = ctx.get("certificate_config", {})
                role_name = ctx.get("vault_config", {}).get("role_name", "default")
                
                common_name = cert_config.get("common_name")
                if not common_name:
                    return {"success": False, "error": "common_name is required for certificate creation"}
                
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for certificate creation
                    cert_result = await self.backend.create_certificate(
                        common_name=common_name,
                        ttl=cert_config.get("ttl", "8760h"),
                        alt_names=cert_config.get("alt_names"),
                        ip_sans=cert_config.get("ip_sans")
                    )
                    certificate = cert_result["certificate"]
                    private_key = cert_result["private_key"]
                    serial_number = cert_result["serial_number"]
                except Exception as e:
                    logger.error(f"Certificate creation failed: {str(e)}")
                    return {"success": False, "error": f"Certificate creation failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "certificate": certificate,
                        "private_key": private_key,
                        "serial_number": serial_number,
                        "common_name": common_name
                    },
                    "vault_metadata": {
                        "vault_path": f"{pki_path}/issue/{role_name}",
                        "operation": "create_certificate"
                    }
                }
                
        except VaultError as e:
            logger.error(f"Vault PKI operation error: {str(e)}")
            return {"success": False, "error": f"Vault PKI operation error: {str(e)}"}
        except Exception as e:
            logger.error(f"PKI operation error: {str(e)}")
            return {"success": False, "error": f"PKI operation failed: {str(e)}"}
    
    async def _handle_public_key_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle public key retrieval operations."""
        try:
            key_name = ctx.get("key_name")
            mount_path = ctx.get("vault_config", {}).get("mount_path", self.default_mount_path)
            
            if not key_name:
                return {"success": False, "error": "key_name is required"}
            
            if not self.backend:
                return {"success": False, "error": "Vault backend not available - configure Vault connection"}
            
            try:
                # Use real Vault backend for public key retrieval
                key_info = await self.backend.get_key_info(key_name)
                latest_version = str(key_info['latest_version'])
                public_key = key_info['keys'][latest_version].get('public_key', '')
            except Exception as e:
                logger.error(f"Public key retrieval failed: {str(e)}")
                return {"success": False, "error": f"Public key retrieval failed: {str(e)}"}
            
            return {
                "success": True,
                "result": {
                    "public_key": public_key,
                    "key_name": key_name
                },
                "vault_metadata": {
                    "vault_path": f"{mount_path}/keys/{key_name}",
                    "operation": "get_public_key"
                }
            }
            
        except VaultError as e:
            logger.error(f"Vault public key error: {str(e)}")
            return {"success": False, "error": f"Vault public key error: {str(e)}"}
        except Exception as e:
            logger.error(f"Public key operation error: {str(e)}")
            return {"success": False, "error": f"Public key operation failed: {str(e)}"}
    
    async def _handle_kv_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle KV store operations for secure data storage."""
        try:
            operation = ctx.get("operation")
            key_name = ctx.get("key_name")
            
            if not key_name:
                return {"success": False, "error": "key_name is required"}
            
            if operation == "seal_data":
                data = ctx.get("data")
                if not data:
                    return {"success": False, "error": "data is required for sealing"}
                
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for secret storage
                    await self.backend.store_secret(key_name, {"data": data})
                except Exception as e:
                    logger.error(f"Secret sealing failed: {str(e)}")
                    return {"success": False, "error": f"Secret sealing failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "key_name": key_name,
                        "sealed": True
                    },
                    "vault_metadata": {
                        "vault_path": f"secret/data/{key_name}",
                        "operation": "seal_data"
                    }
                }
            
            elif operation == "unseal_data":
                if not self.backend:
                    return {"success": False, "error": "Vault backend not available - configure Vault connection"}
                
                try:
                    # Use real Vault backend for secret retrieval
                    secret_result = await self.backend.retrieve_secret(key_name)
                    data = secret_result["data"]["data"]
                except Exception as e:
                    logger.error(f"Secret unsealing failed: {str(e)}")
                    return {"success": False, "error": f"Secret unsealing failed: {str(e)}"}
                
                return {
                    "success": True,
                    "result": {
                        "data": data,
                        "key_name": key_name
                    },
                    "vault_metadata": {
                        "vault_path": f"secret/data/{key_name}",
                        "operation": "unseal_data"
                    }
                }
                
        except VaultError as e:
            logger.error(f"Vault KV operation error: {str(e)}")
            return {"success": False, "error": f"Vault KV operation error: {str(e)}"}
        except Exception as e:
            logger.error(f"KV operation error: {str(e)}")
            return {"success": False, "error": f"KV operation failed: {str(e)}"}
    
    async def _audit_operation(self, operation: str, ctx: Dict[str, Any], result: Dict[str, Any]):
        """Audit cryptographic operation with structured logging."""
        try:
            audit_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation": operation,
                "key_name": ctx.get("key_name"),
                "success": result.get("success"),
                "vault_path": result.get("vault_metadata", {}).get("vault_path"),
                "user": ctx.get("user_id", "unknown")
            }
            
            # This would integrate with audit logging plugin
            logger.info(f"Vault crypto audit: {json.dumps(audit_entry)}")
            
        except Exception as e:
            logger.warning(f"Audit logging error: {str(e)}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Vault connectivity and engine status."""
        try:
            if not self.backend:
                return {
                    "healthy": False,
                    "vault_status": "backend_unavailable",
                    "error": "Vault backend not available - configure Vault connection"
                }
            
            # Use real Vault backend for health check
            return await self.backend.get_health_status()
            
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }


# Plug entry point for PlugPipe compatibility
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Plug entry point for PlugPipe compatibility.
    
    This function demonstrates the plugin-first approach by leveraging HashiCorp Vault's
    proven cryptographic engine instead of implementing custom crypto operations.
    
    Args:
        ctx: Plug execution context with crypto operation parameters
        cfg: Plug configuration including Vault settings
        
    Returns:
        Cryptographic operation result
    """
    try:
        # Create plugin instance
        plugin = VaultCryptoPlug(cfg)
        
        # Execute cryptographic operation
        result = await plugin.process(ctx, cfg)
        
        return result
        
    except Exception as e:
        logger.error(f"Vault crypto plugin error: {str(e)}")
        return {
            "success": False,
            "error": f"Vault crypto error: {str(e)}"
        }


# Health check for monitoring systems
async def health_check(cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """Health check for Vault crypto plugin."""
    try:
        plugin = VaultCryptoPlug(cfg)
        return await plugin.health_check()
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test execution
    import asyncio
    
    async def test():
        # Test with real Vault configuration
        config = {
            "vault_config": {
                "url": "http://127.0.0.1:8200",
                "token": "test-token",
                "transit_path": "transit",
                "pki_path": "pki"
            }
        }
        
        # Test encryption
        encrypt_ctx = {
            "operation": "encrypt",
            "data": "test message",
            "key_name": "test-key"
        }
        
        result = await process(encrypt_ctx, config)
        print("Encryption test:", json.dumps(result, indent=2))
        
        # Test health check
        health = await health_check(config)
        print("Health check:", json.dumps(health, indent=2))
    
    asyncio.run(test())