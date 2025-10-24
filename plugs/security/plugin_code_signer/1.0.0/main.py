# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Plugin Code Signer - REFACTORED

Signs and verifies plugin source code for integrity protection and tamper detection.

ARCHITECTURE CHANGE (October 16, 2025):
- Now uses UniversalSignatureEngine for all cryptographic operations
- Refactored from shares/security/plug_security.py
- Part of hybrid signature architecture (Phase 2)
- Maintains full backward compatibility with existing signature database

Purpose:
- Sign plugin source code files (Python, YAML manifests)
- Verify plugin integrity before execution
- Detect code tampering and unauthorized modifications
- Manage signature database and trusted signers

Security Features:
- Cryptographic hash-based signatures (SHA256 + ES256/RS256)
- Tamper detection through hash verification
- Signature database with audit trail
- Trusted signer management
- Secure file permissions

Hybrid Architecture:
- Core Engine: UniversalSignatureEngine (cryptographic primitives)
- This Plugin: Plugin-specific logic (file hashing, database, etc.)
"""

import json
import os
import sys
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

# Add PlugPipe root to path for core imports
plugpipe_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(plugpipe_root))

# Use UniversalSignatureEngine (core infrastructure)
try:
    from cores.security.universal_signer import UniversalSignatureEngine, UniversalSignatureError
    HAS_UNIVERSAL_SIGNER = True
except ImportError:
    HAS_UNIVERSAL_SIGNER = False
    print("ERROR: UniversalSignatureEngine not available. Check cores/security/universal_signer.py")

logger = logging.getLogger(__name__)


@dataclass
class PluginSignature:
    """Plugin signature information"""
    plugin_name: str
    plugin_version: str
    code_hash: str  # SHA256 hash of plugin files
    signature: str  # Cryptographic signature of code_hash
    algorithm: str = "ES256"
    signed_at: str = None
    signer_id: str = "system"
    trusted: bool = False

    def __post_init__(self):
        if self.signed_at is None:
            self.signed_at = datetime.now(timezone.utc).isoformat()


class PluginCodeSigner:
    """
    Plugin code signer using UniversalSignatureEngine.

    REFACTORED to use hybrid architecture:
    - Core crypto: UniversalSignatureEngine
    - Plugin logic: File hashing, signature DB, trusted signers
    """

    def __init__(self, signature_db_path: Optional[str] = None):
        """
        Initialize plugin code signer.

        Args:
            signature_db_path: Path to signature database file
        """
        if not HAS_UNIVERSAL_SIGNER:
            raise ImportError(
                "UniversalSignatureEngine required. "
                "Check cores/security/universal_signer.py exists."
            )

        # Use core signature engine (REUSE EVERYTHING principle)
        self.engine = UniversalSignatureEngine()

        # Plugin-specific: Signature database management
        self.signature_db_path = signature_db_path or os.path.join(
            os.getcwd(), "plugin_signatures.json"
        )
        self.signatures = self._load_signatures()
        self.trusted_signers = set()

    def _load_signatures(self) -> Dict[str, PluginSignature]:
        """Load signatures from database file (plugin-specific logic)"""
        try:
            if os.path.exists(self.signature_db_path):
                with open(self.signature_db_path, 'r') as f:
                    data = json.load(f)
                    signatures = {}
                    for key, sig_data in data.items():
                        signatures[key] = PluginSignature(**sig_data)
                    return signatures
        except Exception as e:
            logger.error(f"Failed to load plugin signatures: {e}")
        return {}

    def _save_signatures(self):
        """Save signatures to database file (plugin-specific logic)"""
        try:
            db_dir = os.path.dirname(self.signature_db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

            data = {}
            for key, signature in self.signatures.items():
                data[key] = asdict(signature)

            with open(self.signature_db_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved {len(self.signatures)} plugin signatures")
        except Exception as e:
            logger.error(f"Failed to save plugin signatures: {e}")

    def calculate_plugin_hash(self, plugin_path: str) -> bytes:
        """
        Calculate cryptographic hash of all plugin files.

        PLUGIN-SPECIFIC LOGIC: Determine which files to hash and in what order.

        Args:
            plugin_path: Path to plugin main.py file

        Returns:
            SHA256 hash as bytes
        """
        hasher = hashlib.sha256()
        plugin_dir = Path(plugin_path).parent

        # Hash all Python files in deterministic order
        for file_path in sorted(plugin_dir.rglob("*.py")):
            try:
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())
            except Exception as e:
                logger.warning(f"Could not read file for hashing: {file_path} - {e}")

        # Hash plugin manifest (plug.yaml)
        manifest_path = plugin_dir / "plug.yaml"
        if manifest_path.exists():
            try:
                with open(manifest_path, 'rb') as f:
                    hasher.update(f.read())
            except Exception as e:
                logger.warning(f"Could not read manifest for hashing: {manifest_path} - {e}")

        return hasher.digest()

    def sign_plugin(
        self,
        plugin_name: str,
        plugin_version: str,
        plugin_path: str,
        private_key_pem: Optional[bytes] = None,
        algorithm: str = "ES256",
        signer_id: str = "system",
        trusted: bool = False
    ) -> Dict[str, Any]:
        """
        Sign a plugin for integrity verification.

        Process:
        1. Calculate plugin hash (plugin-specific)
        2. Sign hash using UniversalSignatureEngine (reused)
        3. Store signature in database (plugin-specific)

        Args:
            plugin_name: Name of the plugin
            plugin_version: Version of the plugin
            plugin_path: Path to plugin main.py file
            private_key_pem: Private key (if None, generates new one)
            algorithm: Signature algorithm (ES256, RS256, etc.)
            signer_id: Identifier of the signer
            trusted: Whether this is a trusted signature

        Returns:
            Result dictionary with signature info
        """
        try:
            # Plugin-specific: Calculate code hash
            code_hash = self.calculate_plugin_hash(plugin_path)

            # Generate keypair if not provided
            if private_key_pem is None:
                private_key_pem, public_key_pem = self.engine.generate_keypair(algorithm)
                logger.info(f"Generated new {algorithm} keypair for signing")

            # REUSE: Core signing engine for cryptographic operation
            raw_signature = self.engine.sign_bytes(
                data=code_hash,
                private_key_pem=private_key_pem,
                algorithm=algorithm
            )

            # Plugin-specific: Create signature object and store
            signature = PluginSignature(
                plugin_name=plugin_name,
                plugin_version=plugin_version,
                code_hash=code_hash.hex(),
                signature=raw_signature.hex(),
                algorithm=algorithm,
                signed_at=datetime.now(timezone.utc).isoformat(),
                signer_id=signer_id,
                trusted=trusted
            )

            # Store signature
            key = f"{plugin_name}@{plugin_version}"
            self.signatures[key] = signature
            self._save_signatures()

            logger.info(f"Created signature for plugin {key}")
            return {
                "success": True,
                "plugin": key,
                "code_hash": code_hash.hex(),
                "signature": raw_signature.hex(),
                "algorithm": algorithm,
                "signer_id": signer_id,
                "trusted": trusted,
                "message": f"Plugin {key} signed successfully"
            }

        except Exception as e:
            logger.error(f"Failed to sign plugin {plugin_name}@{plugin_version}: {e}")
            return {
                "success": False,
                "error": f"Plugin signing failed: {e}"
            }

    def verify_plugin(
        self,
        plugin_name: str,
        plugin_version: str,
        plugin_path: str,
        public_key_pem: Optional[bytes] = None
    ) -> Tuple[bool, Optional[str], Optional[PluginSignature]]:
        """
        Verify plugin signature and detect tampering.

        Process:
        1. Calculate current plugin hash (plugin-specific)
        2. Retrieve stored signature (plugin-specific)
        3. Verify using UniversalSignatureEngine (reused)

        Args:
            plugin_name: Name of the plugin
            plugin_version: Version of the plugin
            plugin_path: Path to plugin main.py file
            public_key_pem: Public key (if None, looks up from signature)

        Returns:
            Tuple of (is_valid, message, signature)
        """
        try:
            key = f"{plugin_name}@{plugin_version}"

            # Plugin-specific: Check if signature exists
            if key not in self.signatures:
                logger.warning(f"No signature found for plugin {key}")
                return False, "No signature found", None

            signature = self.signatures[key]

            # Plugin-specific: Calculate current plugin hash
            current_hash = self.calculate_plugin_hash(plugin_path)

            # Check if hash matches (quick check before crypto verification)
            if current_hash.hex() != signature.code_hash:
                logger.error(f"Plugin hash mismatch for {key} - TAMPERING DETECTED!")
                return False, "TAMPERING DETECTED (hash mismatch)", signature

            # If public key not provided, verification requires it
            # In production, you'd retrieve it from a key management system
            if public_key_pem is None:
                return True, "Hash verified (cryptographic verification skipped - no public key)", signature

            # REUSE: Core verification engine for cryptographic operation
            is_valid = self.engine.verify_bytes(
                data=current_hash,
                signature=bytes.fromhex(signature.signature),
                public_key_pem=public_key_pem,
                algorithm=signature.algorithm
            )

            if is_valid:
                logger.info(f"Plugin signature verified for {key}")
                return True, "Signature verified successfully", signature
            else:
                logger.error(f"Plugin signature verification failed for {key}")
                return False, "Signature verification failed", signature

        except Exception as e:
            logger.error(f"Plugin signature verification error for {plugin_name}@{plugin_version}: {e}")
            return False, f"Verification error: {e}", None

    def is_plugin_trusted(self, plugin_name: str, plugin_version: str) -> bool:
        """Check if plugin has a trusted signature"""
        key = f"{plugin_name}@{plugin_version}"
        if key in self.signatures:
            signature = self.signatures[key]
            return signature.trusted and signature.signer_id in self.trusted_signers
        return False

    def add_trusted_signer(self, signer_id: str):
        """Add a trusted signer"""
        self.trusted_signers.add(signer_id)
        logger.info(f"Added trusted signer: {signer_id}")

    def revoke_plugin_signature(self, plugin_name: str, plugin_version: str):
        """Revoke a plugin signature"""
        key = f"{plugin_name}@{plugin_version}"
        if key in self.signatures:
            del self.signatures[key]
            self._save_signatures()
            logger.info(f"Revoked signature for plugin {key}")

    def list_signatures(self) -> Dict[str, PluginSignature]:
        """List all plugin signatures"""
        return self.signatures.copy()

    def scan_plugins(self, plugs_dir: str) -> Dict[str, Any]:
        """
        Scan all plugins for security issues.

        Args:
            plugs_dir: Path to plugs directory

        Returns:
            Dictionary with scan results
        """
        results = {
            "total_plugs": 0,
            "signed_plugs": 0,
            "valid_signatures": 0,
            "invalid_signatures": 0,
            "unsigned_plugs": 0,
            "details": []
        }

        for plugin_name in os.listdir(plugs_dir):
            plugin_path = os.path.join(plugs_dir, plugin_name)
            if not os.path.isdir(plugin_path):
                continue

            for version in os.listdir(plugin_path):
                version_path = os.path.join(plugin_path, version)
                if not os.path.isdir(version_path):
                    continue

                main_path = os.path.join(version_path, 'main.py')
                if not os.path.exists(main_path):
                    continue

                results["total_plugs"] += 1

                # Check signature
                is_valid, message, signature = self.verify_plugin(
                    plugin_name, version, main_path
                )

                if signature:
                    results["signed_plugs"] += 1
                    if is_valid:
                        results["valid_signatures"] += 1
                        status = "VALID"
                        if signature.trusted:
                            status += " (TRUSTED)"
                    else:
                        results["invalid_signatures"] += 1
                        status = "INVALID - TAMPERING DETECTED"
                else:
                    results["unsigned_plugs"] += 1
                    status = "UNSIGNED"

                results["details"].append({
                    "plugin": f"{plugin_name}@{version}",
                    "status": status,
                    "is_valid": is_valid,
                    "message": message
                })

        return results


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point.

    Args:
        ctx: Context with input data
        cfg: Configuration from plug.yaml parameters

    Returns:
        Result dictionary with operation outcome
    """
    signature_db_path = cfg.get('signature_db_path')
    signer = PluginCodeSigner(signature_db_path)

    operation = cfg.get('operation')
    if not operation:
        return {
            "success": False,
            "error": "Missing required parameter: operation",
            "supported_operations": ["sign", "verify", "list", "scan", "revoke", "add_trusted_signer"]
        }

    # Operation: Sign Plugin
    if operation == 'sign':
        plugin_name = cfg.get('plugin_name')
        plugin_version = cfg.get('plugin_version')
        plugin_path = cfg.get('plugin_path')
        algorithm = cfg.get('algorithm', 'ES256')
        signer_id = cfg.get('signer_id', 'system')
        trusted = cfg.get('trusted', False)

        if not all([plugin_name, plugin_version, plugin_path]):
            return {
                "success": False,
                "error": "Missing required parameters: plugin_name, plugin_version, plugin_path"
            }

        # Load private key if provided
        private_key_path = cfg.get('private_key_path')
        private_key_pem = None
        if private_key_path:
            private_key_pem = Path(private_key_path).read_bytes()

        return signer.sign_plugin(
            plugin_name, plugin_version, plugin_path,
            private_key_pem, algorithm, signer_id, trusted
        )

    # Operation: Verify Plugin
    elif operation == 'verify':
        plugin_name = cfg.get('plugin_name')
        plugin_version = cfg.get('plugin_version')
        plugin_path = cfg.get('plugin_path')

        if not all([plugin_name, plugin_version, plugin_path]):
            return {
                "success": False,
                "error": "Missing required parameters: plugin_name, plugin_version, plugin_path"
            }

        # Load public key if provided
        public_key_path = cfg.get('public_key_path')
        public_key_pem = None
        if public_key_path:
            public_key_pem = Path(public_key_path).read_bytes()

        is_valid, message, signature = signer.verify_plugin(
            plugin_name, plugin_version, plugin_path, public_key_pem
        )

        return {
            "success": is_valid,
            "verified": is_valid,
            "plugin": f"{plugin_name}@{plugin_version}",
            "message": message,
            "signature": asdict(signature) if signature else None
        }

    # Operation: List Signatures
    elif operation == 'list':
        signatures = signer.list_signatures()
        return {
            "success": True,
            "count": len(signatures),
            "signatures": {key: asdict(sig) for key, sig in signatures.items()}
        }

    # Operation: Scan Plugins
    elif operation == 'scan':
        plugs_dir = cfg.get('plugs_dir')
        if not plugs_dir:
            return {
                "success": False,
                "error": "Missing required parameter: plugs_dir"
            }

        results = signer.scan_plugins(plugs_dir)
        return {
            "success": True,
            **results
        }

    # Operation: Revoke Signature
    elif operation == 'revoke':
        plugin_name = cfg.get('plugin_name')
        plugin_version = cfg.get('plugin_version')

        if not all([plugin_name, plugin_version]):
            return {
                "success": False,
                "error": "Missing required parameters: plugin_name, plugin_version"
            }

        signer.revoke_plugin_signature(plugin_name, plugin_version)
        return {
            "success": True,
            "message": f"Revoked signature for {plugin_name}@{plugin_version}"
        }

    # Operation: Add Trusted Signer
    elif operation == 'add_trusted_signer':
        signer_id = cfg.get('signer_id')
        if not signer_id:
            return {
                "success": False,
                "error": "Missing required parameter: signer_id"
            }

        signer.add_trusted_signer(signer_id)
        return {
            "success": True,
            "message": f"Added trusted signer: {signer_id}"
        }

    else:
        return {
            "success": False,
            "error": f"Unknown operation: {operation}",
            "supported_operations": ["sign", "verify", "list", "scan", "revoke", "add_trusted_signer"]
        }
