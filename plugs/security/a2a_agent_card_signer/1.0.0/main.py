# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
A2A Agent Card Signer Plugin - REFACTORED

Implements JWS (JSON Web Signature) cryptographic signing and verification
for A2A protocol agent cards according to RFC 7515.

ARCHITECTURE CHANGE (October 16, 2025):
- Now uses UniversalSignatureEngine for all cryptographic operations
- Removed python-jose dependency (eliminates duplication)
- Manual JWS construction according to RFC 7515
- Maintains full backward compatibility

Security Features:
- ES256 (ECDSA P-256) and RS256 (RSA-2048) signature algorithms
- Integrity verification and tampering detection
- Public key infrastructure support
- JWKS (JSON Web Key Set) export for key distribution

References:
- RFC 7515: JSON Web Signature (JWS)
- RFC 7517: JSON Web Key (JWK)
- RFC 7518: JSON Web Algorithms (JWA)
- A2A Protocol Specification: https://a2a-protocol.org/
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
import base64
import copy

# Add PlugPipe root to path for core imports
plugpipe_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(plugpipe_root))

# Use UniversalSignatureEngine (core infrastructure, NOT python-jose)
try:
    from cores.security.universal_signer import UniversalSignatureEngine, UniversalSignatureError
    HAS_UNIVERSAL_SIGNER = True
except ImportError:
    HAS_UNIVERSAL_SIGNER = False
    print("ERROR: UniversalSignatureEngine not available. Check cores/security/universal_signer.py")


class A2AAgentCardSigner:
    """
    JWS signer/verifier for A2A agent cards.

    REFACTORED to use UniversalSignatureEngine (hybrid architecture).
    This plugin handles JWS format-specific logic (RFC 7515).
    Core cryptography delegated to UniversalSignatureEngine.
    """

    # Supported algorithms (RFC 7518) - delegates to UniversalSignatureEngine
    SUPPORTED_ALGORITHMS = {
        'ES256': 'ECDSA with P-256 and SHA-256',
        'ES384': 'ECDSA with P-384 and SHA-384',
        'ES512': 'ECDSA with P-521 and SHA-512',
        'RS256': 'RSA-PSS with 2048-bit key and SHA-256',
        'RS384': 'RSA-PSS with 3072-bit key and SHA-384',
        'RS512': 'RSA-PSS with 4096-bit key and SHA-512',
        'ED25519': 'EdDSA with Curve25519'
    }

    def __init__(self):
        """Initialize signer with UniversalSignatureEngine"""
        if not HAS_UNIVERSAL_SIGNER:
            raise ImportError(
                "UniversalSignatureEngine required. "
                "Check cores/security/universal_signer.py exists."
            )

        # Use core signature engine (REUSE EVERYTHING principle)
        self.engine = UniversalSignatureEngine()

    def generate_keypair(self, algorithm: str = 'ES256', output_path: Optional[str] = None) -> Dict[str, str]:
        """
        Generate a new keypair for agent card signing.

        REFACTORED: Now delegates to UniversalSignatureEngine.

        Args:
            algorithm: Signature algorithm (ES256, RS256, etc.)
            output_path: Directory to save keys (optional)

        Returns:
            Dictionary with private_key and public_key (PEM format)
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use one of: {list(self.SUPPORTED_ALGORITHMS.keys())}")

        try:
            # Delegate to core engine (REUSE)
            private_pem_bytes, public_pem_bytes = self.engine.generate_keypair(algorithm)

            # Convert bytes to string for backward compatibility
            private_pem = private_pem_bytes.decode('utf-8')
            public_pem = public_pem_bytes.decode('utf-8')

            # Save to filesystem if output_path provided (plugin-specific logic)
            if output_path:
                output_dir = Path(output_path)
                output_dir.mkdir(parents=True, exist_ok=True)

                private_key_path = output_dir / f"private_key_{algorithm.lower()}.pem"
                public_key_path = output_dir / f"public_key_{algorithm.lower()}.pem"

                private_key_path.write_text(private_pem)
                public_key_path.write_text(public_pem)

                # Set secure permissions (owner read/write only)
                os.chmod(private_key_path, 0o600)
                os.chmod(public_key_path, 0o644)

                return {
                    "success": True,
                    "algorithm": algorithm,
                    "private_key_path": str(private_key_path),
                    "public_key_path": str(public_key_path),
                    "private_key": private_pem,
                    "public_key": public_pem,
                    "message": f"Keypair generated successfully ({algorithm})"
                }
            else:
                return {
                    "success": True,
                    "algorithm": algorithm,
                    "private_key": private_pem,
                    "public_key": public_pem,
                    "message": "Keypair generated in memory (no files written)"
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"Keypair generation failed: {e}"
            }

    def sign_agent_card(
        self,
        agent_card: Dict[str, Any],
        private_key_pem: str,
        algorithm: str = 'ES256'
    ) -> Dict[str, Any]:
        """
        Sign an A2A agent card with JWS (RFC 7515).

        REFACTORED: Manual JWS construction using UniversalSignatureEngine.
        No longer uses python-jose library.

        Args:
            agent_card: Agent card dictionary (without signature)
            private_key_pem: Private key in PEM format
            algorithm: Signature algorithm

        Returns:
            Signed agent card with signature field
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        try:
            # A2A-specific: Extract agentCard content (don't sign the wrapper)
            agent_card_content = agent_card.get("agentCard", agent_card)

            # A2A-specific: Prepare canonical JSON payload
            payload = json.dumps(
                agent_card_content,
                sort_keys=True,
                separators=(',', ':')
            ).encode('utf-8')

            # A2A-specific: Create JWS protected header (RFC 7515)
            protected_header = {
                "alg": algorithm,
                "typ": "JWT",  # RFC 7515 section 4.1.9
                "iat": int(datetime.now(timezone.utc).timestamp()),
                "iss": agent_card_content.get("id", "unknown")
            }

            # A2A-specific: Base64url encode protected header
            protected_json = json.dumps(protected_header, separators=(',', ':')).encode('utf-8')
            protected_b64 = base64.urlsafe_b64encode(protected_json).rstrip(b'=').decode('utf-8')

            # A2A-specific: Base64url encode payload
            payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b'=').decode('utf-8')

            # A2A-specific: Create JWS signing input (RFC 7515 section 5.1)
            signing_input = f"{protected_b64}.{payload_b64}".encode('utf-8')

            # REUSE: Core signing engine for cryptographic operation
            raw_signature = self.engine.sign_bytes(
                data=signing_input,
                private_key_pem=private_key_pem.encode('utf-8'),
                algorithm=algorithm
            )

            # A2A-specific: Base64url encode signature
            signature_b64 = base64.urlsafe_b64encode(raw_signature).rstrip(b'=').decode('utf-8')

            # A2A-specific: Create signature object (A2A spec format)
            signature_object = {
                "protected": protected_b64,
                "signature": signature_b64
            }

            # Add signature to agent card (deep copy to avoid modifying original)
            signed_card = copy.deepcopy(agent_card)
            if "agentCard" in signed_card:
                signed_card["agentCard"]["signature"] = signature_object
            else:
                signed_card["signature"] = signature_object

            return {
                "success": True,
                "signed_card": signed_card,
                "algorithm": algorithm,
                "signature": signature_object,
                "message": "Agent card signed successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Signing failed: {e}"
            }

    def verify_agent_card_signature(
        self,
        signed_agent_card: Dict[str, Any],
        public_key_pem: str
    ) -> Dict[str, Any]:
        """
        Verify JWS signature on an agent card.

        REFACTORED: Manual JWS deconstruction using UniversalSignatureEngine.
        No longer uses python-jose library.

        Args:
            signed_agent_card: Agent card with signature field
            public_key_pem: Public key in PEM format

        Returns:
            Verification result with details
        """
        try:
            # A2A-specific: Extract signature object
            if "agentCard" in signed_agent_card:
                signature_obj = signed_agent_card["agentCard"].get("signature")
                agent_card_data = signed_agent_card["agentCard"].copy()
                agent_card_data.pop("signature", None)
            else:
                signature_obj = signed_agent_card.get("signature")
                agent_card_data = signed_agent_card.copy()
                agent_card_data.pop("signature", None)

            if not signature_obj:
                return {
                    "success": False,
                    "verified": False,
                    "error": "No signature found in agent card"
                }

            # A2A-specific: Extract JWS components
            protected_b64 = signature_obj.get("protected")
            signature_b64 = signature_obj.get("signature")

            if not protected_b64 or not signature_b64:
                return {
                    "success": False,
                    "verified": False,
                    "error": "Invalid signature object (missing protected or signature)"
                }

            # A2A-specific: Decode protected header to get algorithm
            protected_json = base64.urlsafe_b64decode(protected_b64 + '==')
            protected_header = json.loads(protected_json)
            algorithm = protected_header.get("alg")

            if algorithm not in self.SUPPORTED_ALGORITHMS:
                return {
                    "success": False,
                    "verified": False,
                    "error": f"Unsupported algorithm in signature: {algorithm}"
                }

            # A2A-specific: Reconstruct canonical JSON payload
            payload = json.dumps(
                agent_card_data,
                sort_keys=True,
                separators=(',', ':')
            ).encode('utf-8')

            # A2A-specific: Base64url encode payload
            payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b'=').decode('utf-8')

            # A2A-specific: Reconstruct JWS signing input (RFC 7515)
            signing_input = f"{protected_b64}.{payload_b64}".encode('utf-8')

            # A2A-specific: Decode signature from base64url
            raw_signature = base64.urlsafe_b64decode(signature_b64 + '==')

            # REUSE: Core verification engine for cryptographic operation
            is_valid = self.engine.verify_bytes(
                data=signing_input,
                signature=raw_signature,
                public_key_pem=public_key_pem.encode('utf-8'),
                algorithm=algorithm
            )

            if is_valid:
                return {
                    "success": True,
                    "verified": True,
                    "algorithm": algorithm,
                    "protected_header": protected_header,
                    "message": "Signature verified successfully"
                }
            else:
                return {
                    "success": False,
                    "verified": False,
                    "error": "Signature verification failed (invalid signature or tampered data)"
                }

        except Exception as e:
            return {
                "success": False,
                "verified": False,
                "error": f"Signature verification failed: {str(e)}"
            }

    def export_public_key_jwks(
        self,
        public_key_pem: str,
        key_id: str = "plugpipe-signing-key"
    ) -> Dict[str, Any]:
        """
        Export public key in JWKS (JSON Web Key Set) format for distribution.

        REFACTORED: Delegates JWK creation to UniversalSignatureEngine.

        Args:
            public_key_pem: Public key in PEM format
            key_id: Key identifier

        Returns:
            JWKS dictionary (RFC 7517)
        """
        try:
            # REUSE: Core JWK export
            jwk_dict = self.engine.export_public_key_jwk(
                public_key_pem=public_key_pem.encode('utf-8'),
                key_id=key_id
            )

            # A2A-specific: Wrap in JWKS structure (RFC 7517)
            jwks = {
                "keys": [jwk_dict]
            }

            return {
                "success": True,
                "jwks": jwks,
                "message": "Public key exported in JWKS format"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to export JWKS: {str(e)}"
            }


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point.

    Args:
        ctx: Context with input data
        cfg: Configuration from plug.yaml parameters

    Returns:
        Result dictionary with operation outcome
    """
    signer = A2AAgentCardSigner()

    operation = cfg.get('operation')
    if not operation:
        return {
            "success": False,
            "error": "Missing required parameter: operation",
            "supported_operations": ["sign", "verify", "generate_keypair", "export_public_key"]
        }

    # Operation: Generate Keypair
    if operation == 'generate_keypair':
        algorithm = cfg.get('algorithm', 'ES256')
        output_path = cfg.get('output_path')

        return signer.generate_keypair(algorithm, output_path)

    # Operation: Sign Agent Card
    elif operation == 'sign':
        # Load agent card
        agent_card_path = cfg.get('agent_card_path')
        agent_card_data = cfg.get('agent_card_data')

        if agent_card_path:
            with open(agent_card_path, 'r') as f:
                agent_card = json.load(f)
        elif agent_card_data:
            agent_card = agent_card_data
        else:
            return {
                "success": False,
                "error": "Missing agent_card_path or agent_card_data parameter"
            }

        # Load private key
        private_key_path = cfg.get('private_key_path')
        if not private_key_path:
            return {
                "success": False,
                "error": "Missing private_key_path parameter"
            }

        private_key_pem = Path(private_key_path).read_text()
        algorithm = cfg.get('algorithm', 'ES256')

        # Sign the card
        result = signer.sign_agent_card(agent_card, private_key_pem, algorithm)

        # Save signed card if output_path provided
        output_path = cfg.get('output_path')
        if output_path and result.get('success'):
            with open(output_path, 'w') as f:
                json.dump(result['signed_card'], f, indent=2)
            result['output_path'] = output_path

        return result

    # Operation: Verify Signature
    elif operation == 'verify':
        # Load signed agent card
        agent_card_path = cfg.get('agent_card_path')
        agent_card_data = cfg.get('agent_card_data')

        if agent_card_path:
            with open(agent_card_path, 'r') as f:
                signed_card = json.load(f)
        elif agent_card_data:
            signed_card = agent_card_data
        else:
            return {
                "success": False,
                "error": "Missing agent_card_path or agent_card_data parameter"
            }

        # Load public key
        public_key_path = cfg.get('public_key_path')
        if not public_key_path:
            return {
                "success": False,
                "error": "Missing public_key_path parameter"
            }

        public_key_pem = Path(public_key_path).read_text()

        return signer.verify_agent_card_signature(signed_card, public_key_pem)

    # Operation: Export Public Key (JWKS)
    elif operation == 'export_public_key':
        public_key_path = cfg.get('public_key_path')
        if not public_key_path:
            return {
                "success": False,
                "error": "Missing public_key_path parameter"
            }

        public_key_pem = Path(public_key_path).read_text()
        key_id = cfg.get('key_id', 'plugpipe-signing-key')

        result = signer.export_public_key_jwks(public_key_pem, key_id)

        # Save JWKS if output_path provided
        output_path = cfg.get('output_path')
        if output_path and result.get('success'):
            with open(output_path, 'w') as f:
                json.dump(result['jwks'], f, indent=2)
            result['output_path'] = output_path

        return result

    else:
        return {
            "success": False,
            "error": f"Unknown operation: {operation}",
            "supported_operations": ["sign", "verify", "generate_keypair", "export_public_key"]
        }


# MCP Tool Handlers (for LLM integration)
def sign_agent_card_tool(agent_card: Dict[str, Any], algorithm: str = 'ES256') -> Dict[str, Any]:
    """MCP tool: Sign an agent card"""
    # This would use a configured signing key
    # Implementation depends on key management strategy
    return {
        "error": "MCP tool requires configured signing key. Use CLI for direct signing."
    }


def verify_agent_card_signature_tool(agent_card: Dict[str, Any], public_key_url: str = None) -> Dict[str, Any]:
    """MCP tool: Verify agent card signature"""
    signer = A2AAgentCardSigner()

    # Fetch public key from URL if provided
    if public_key_url:
        try:
            import requests
            response = requests.get(public_key_url)
            if response.status_code == 200:
                jwks = response.json()
                # Would need JWK to PEM conversion
                return {"success": False, "error": "JWK to PEM conversion not yet implemented"}
            else:
                return {"success": False, "error": f"Failed to fetch public key from {public_key_url}"}
        except ImportError:
            return {"success": False, "error": "requests library not available"}
    else:
        return {"success": False, "error": "public_key_url required for verification"}
