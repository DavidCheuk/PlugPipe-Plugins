#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Universal Disclaimer Plugin - Legal Protection for All PlugPipe Interfaces

REVOLUTIONARY LEGAL PROTECTION: Provides centralized disclaimer management
across CLI, API, MCP, and Frontend interfaces with user acknowledgment tracking.

Core Capabilities:
- Universal disclaimer text management
- Multi-interface disclaimer generation (CLI, API, MCP, Frontend)  
- User acknowledgment tracking and persistence
- Context-aware disclaimers for plugin operations
- Compliance audit trail generation
- Enterprise-grade legal protection

PLUGIN-FIRST ARCHITECTURE: Single source of truth for all legal disclaimers
across the PlugPipe ecosystem, ensuring consistent legal protection.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import pathlib

logger = logging.getLogger(__name__)

class InterfaceType(Enum):
    """Supported PlugPipe interfaces"""
    CLI = "cli"
    API = "api" 
    MCP = "mcp"
    FRONTEND = "frontend"
    PLUGIN_ACTION = "plugin_action"

class ActionType(Enum):
    """Disclaimer actions"""
    SHOW_BANNER = "show_banner"
    REQUIRE_ACKNOWLEDGMENT = "require_acknowledgment"
    GET_DISCLAIMER = "get_disclaimer"
    CHECK_ACCEPTANCE = "check_acceptance"
    ADD_HEADERS = "add_headers"

class AcceptanceStatus(Enum):
    """User acceptance status"""
    ACCEPTED = "accepted"
    DECLINED = "declined"
    PENDING = "pending"
    EXPIRED = "expired"

@dataclass
class DisclaimerContent:
    """Legal disclaimer content"""
    brief_message: str
    full_text: str
    version: str = "1.0.0"
    effective_date: str = "2025-08-26"

@dataclass
class UserAcknowledgment:
    """User acknowledgment record"""
    user_id: str
    interface: str
    timestamp: str
    status: AcceptanceStatus
    version: str
    tracking_id: str
    context: Optional[Dict[str, Any]] = None

class UniversalDisclaimerPlugin:
    """Universal legal disclaimer plugin for all PlugPipe interfaces"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.disclaimer_content = self._load_disclaimer_content()
        self.acknowledgment_store = self._get_acknowledgment_store()
    
    def _load_disclaimer_content(self) -> DisclaimerContent:
        """Load legal disclaimer content"""
        brief_message = (
            "PlugPipe is provided 'AS IS' without warranties. "
            "Use at your own risk. No liability accepted."
        )
        
        full_text = """
PLUGPIPE UNIVERSAL INTEGRATION HUB - LEGAL DISCLAIMER

BY USING PLUGPIPE, YOU ACKNOWLEDGE AND AGREE TO THE FOLLOWING:

1. NO WARRANTIES
   PlugPipe is provided 'AS IS' without any express or implied warranties,
   including but not limited to merchantability, fitness for a particular 
   purpose, or non-infringement.

2. ASSUMPTION OF RISK
   You acknowledge that using integration plugins, AI-generated code, and
   third-party services involves inherent risks including:
   • Data loss, corruption, or security breaches
   • Service interruptions or failures
   • Plugin malfunctions or security vulnerabilities  
   • Integration failures or compatibility issues
   • AI-generated content that may be incorrect or insecure
   • Unauthorized access to connected systems

3. NO LIABILITY
   PlugPipe, its contributors, and associated parties shall not be liable
   for any direct, indirect, incidental, consequential, or punitive damages
   arising from your use of PlugPipe, regardless of the theory of liability.

4. USER RESPONSIBILITY
   You are solely responsible for:
   • Testing plugins in non-production environments before deployment
   • Implementing appropriate security measures and access controls
   • Backing up your data and systems before using PlugPipe
   • Compliance with applicable laws and third-party service terms
   • Monitoring and maintaining your PlugPipe deployments
   • Reviewing plugin code and security before installation

5. THIRD-PARTY SERVICES
   PlugPipe integrates with third-party services. You are responsible
   for complying with their terms of service and privacy policies.

6. PLUGIN RISKS
   Community-contributed plugins may contain bugs, security vulnerabilities,
   or malicious code. Review and test all plugins thoroughly before use.

7. AI-GENERATED CONTENT
   AI-generated plugins and configurations may be incorrect, insecure, or
   inappropriate for your use case. Human review is essential.

8. INDEMNIFICATION
   You agree to indemnify and hold harmless PlugPipe and its contributors
   from any claims, damages, or expenses arising from your use of PlugPipe.

By continuing to use PlugPipe, you confirm that you have read, understood,
and agree to be bound by this disclaimer and assume all associated risks.

Version: 1.0.0 | Effective Date: 2025-08-26
        """.strip()
        
        return DisclaimerContent(
            brief_message=brief_message,
            full_text=full_text
        )
    
    def _get_acknowledgment_store(self) -> str:
        """Get path for acknowledgment storage"""
        store_dir = os.path.expanduser("~/.plugpipe")
        os.makedirs(store_dir, exist_ok=True)
        return os.path.join(store_dir, "disclaimer_acknowledgments.json")
    
    def _load_acknowledgments(self) -> Dict[str, UserAcknowledgment]:
        """Load user acknowledgments from storage"""
        try:
            if os.path.exists(self.acknowledgment_store):
                with open(self.acknowledgment_store, 'r') as f:
                    data = json.load(f)
                    return {
                        key: UserAcknowledgment(**val) 
                        for key, val in data.items()
                    }
        except Exception as e:
            logger.warning(f"Failed to load acknowledgments: {e}")
        
        return {}
    
    def _save_acknowledgments(self, acknowledgments: Dict[str, UserAcknowledgment]):
        """Save user acknowledgments to storage"""
        try:
            data = {key: asdict(ack) for key, ack in acknowledgments.items()}
            with open(self.acknowledgment_store, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save acknowledgments: {e}")
    
    def _generate_tracking_id(self, context: Dict[str, Any]) -> str:
        """Generate unique tracking ID for acknowledgment"""
        content = f"{context.get('user_id', 'anonymous')}-{context.get('interface', 'unknown')}-{datetime.now().timestamp()}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _is_acknowledgment_valid(self, acknowledgment: UserAcknowledgment) -> bool:
        """Check if acknowledgment is still valid (not expired)"""
        try:
            ack_time = datetime.fromisoformat(acknowledgment.timestamp.replace('Z', '+00:00'))
            # Acknowledgments expire after 30 days
            expiry = ack_time + timedelta(days=30)
            return datetime.now(timezone.utc) < expiry
        except Exception:
            return False
    
    def show_banner(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate banner disclaimer for display"""
        interface = context.get('interface', 'unknown')
        
        if interface == 'cli':
            banner = f"""
{'=' * 80}
🚨 PLUGPIPE LEGAL DISCLAIMER
{'=' * 80}
{self.disclaimer_content.brief_message}

⚠️  RISKS: Data loss, security vulnerabilities, service failures, AI errors
📋 YOUR RESPONSIBILITY: Test safely, backup data, review code, monitor systems
🚫 NO LIABILITY: PlugPipe accepts no responsibility for damages or losses

By continuing, you acknowledge these risks and agree to use at your own risk.
{'=' * 80}
            """.strip()
        elif interface == 'frontend':
            banner = {
                'type': 'banner',
                'message': self.disclaimer_content.brief_message,
                'severity': 'warning',
                'dismissible': True,
                'show_full_terms_link': True
            }
        else:
            banner = self.disclaimer_content.brief_message
        
        return {
            'success': True,
            'disclaimer': {
                'message': self.disclaimer_content.brief_message,
                'banner': banner,
                'acceptance_required': False,
                'format': 'banner'
            }
        }
    
    def require_acknowledgment(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle user acknowledgment requirement"""
        user_id = context.get('user_id', 'anonymous')
        interface = context.get('interface', 'unknown')
        force_reaccept = context.get('force_reaccept', False)
        
        # Check existing acknowledgment
        acknowledgments = self._load_acknowledgments()
        ack_key = f"{user_id}-{interface}"
        
        existing_ack = acknowledgments.get(ack_key)
        if existing_ack and not force_reaccept and self._is_acknowledgment_valid(existing_ack):
            return {
                'success': True,
                'disclaimer': {
                    'acceptance_required': False,
                    'acceptance_status': 'accepted',
                    'message': 'Previously accepted'
                }
            }
        
        # Generate new acknowledgment requirement
        tracking_id = self._generate_tracking_id(context)
        
        return {
            'success': True,
            'disclaimer': {
                'message': self.disclaimer_content.brief_message,
                'full_text': self.disclaimer_content.full_text,
                'acceptance_required': True,
                'acceptance_status': 'pending',
                'tracking_id': tracking_id,
                'version': self.disclaimer_content.version
            },
            'metadata': {
                'interface': interface,
                'tracking_id': tracking_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }
    
    def record_acknowledgment(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Record user acknowledgment"""
        user_id = context.get('user_id', 'anonymous')
        interface = context.get('interface', 'unknown')
        accepted = context.get('accepted', False)
        tracking_id = context.get('tracking_id', self._generate_tracking_id(context))
        
        acknowledgment = UserAcknowledgment(
            user_id=user_id,
            interface=interface,
            timestamp=datetime.now(timezone.utc).isoformat(),
            status=AcceptanceStatus.ACCEPTED if accepted else AcceptanceStatus.DECLINED,
            version=self.disclaimer_content.version,
            tracking_id=tracking_id,
            context=context
        )
        
        acknowledgments = self._load_acknowledgments()
        ack_key = f"{user_id}-{interface}"
        acknowledgments[ack_key] = acknowledgment
        self._save_acknowledgments(acknowledgments)
        
        logger.info(f"Disclaimer acknowledgment recorded: {ack_key} = {acknowledgment.status.value}")
        
        return {
            'success': True,
            'disclaimer': {
                'acceptance_status': acknowledgment.status.value,
                'tracking_id': tracking_id,
                'recorded_at': acknowledgment.timestamp
            }
        }
    
    def check_acceptance(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Check user acceptance status"""
        user_id = context.get('user_id', 'anonymous')
        interface = context.get('interface', 'unknown')
        
        acknowledgments = self._load_acknowledgments()
        ack_key = f"{user_id}-{interface}"
        
        existing_ack = acknowledgments.get(ack_key)
        if not existing_ack:
            status = AcceptanceStatus.PENDING
        elif not self._is_acknowledgment_valid(existing_ack):
            status = AcceptanceStatus.EXPIRED
        else:
            status = existing_ack.status
        
        return {
            'success': True,
            'disclaimer': {
                'acceptance_status': status.value,
                'acceptance_required': status in [AcceptanceStatus.PENDING, AcceptanceStatus.EXPIRED],
                'last_accepted': existing_ack.timestamp if existing_ack else None
            }
        }
    
    def add_headers(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate HTTP headers with disclaimer information"""
        headers = {
            'X-PlugPipe-Disclaimer': self.disclaimer_content.brief_message,
            'X-PlugPipe-Legal-Notice': 'https://github.com/plugpipe/plugpipe/blob/main/LEGAL_DISCLAIMER.md',
            'X-PlugPipe-Risk-Warning': 'Contains community plugins. Review security before use.',
            'X-PlugPipe-Disclaimer-Version': self.disclaimer_content.version,
            'X-PlugPipe-Legal-Timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return {
            'success': True,
            'headers': headers,
            'disclaimer': {
                'message': 'Disclaimer headers generated',
                'header_count': len(headers)
            }
        }
    
    def get_disclaimer(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get disclaimer content in requested format"""
        format_type = context.get('format', 'json')
        include_full = context.get('include_full', False)
        
        disclaimer_data = {
            'message': self.disclaimer_content.brief_message,
            'version': self.disclaimer_content.version,
            'effective_date': self.disclaimer_content.effective_date,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if include_full:
            disclaimer_data['full_text'] = self.disclaimer_content.full_text
        
        if format_type == 'text':
            text_content = disclaimer_data['full_text'] if include_full else disclaimer_data['message']
            return {
                'success': True,
                'disclaimer': {'content': text_content, 'format': 'text'}
            }
        elif format_type == 'html':
            html_content = f"""
            <div class="plugpipe-disclaimer">
                <h3>Legal Disclaimer</h3>
                <p>{disclaimer_data['message']}</p>
                {f'<pre>{disclaimer_data["full_text"]}</pre>' if include_full else ''}
            </div>
            """
            return {
                'success': True,
                'disclaimer': {'content': html_content, 'format': 'html'}
            }
        
        return {
            'success': True,
            'disclaimer': disclaimer_data
        }
    
    def generate_plugin_disclaimer(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate plugin-specific disclaimer"""
        plugin_name = context.get('plugin_name', 'unknown')
        operation = context.get('operation', 'execute')
        
        plugin_warning = f"""
PLUGIN OPERATION WARNING - {plugin_name.upper()}

You are about to {operation} the plugin '{plugin_name}'.

⚠️  PLUGIN-SPECIFIC RISKS:
• Plugin code has not been audited by PlugPipe team
• May contain security vulnerabilities or malicious code  
• Could cause data loss, corruption, or system instability
• May access sensitive data from connected services
• Could make unauthorized network requests
• May not work as expected or cause integration failures

📋 BEFORE PROCEEDING:
• Review plugin code and permissions
• Test in non-production environment first
• Ensure proper backups are in place
• Understand what data the plugin can access

🚫 NO LIABILITY: PlugPipe accepts no responsibility for plugin behavior,
   security issues, or damages from using this plugin.

BY PROCEEDING, YOU ACKNOWLEDGE THESE RISKS AND AGREE TO USE THIS PLUGIN
AT YOUR OWN RISK AND RESPONSIBILITY.
        """.strip()
        
        return {
            'success': True,
            'disclaimer': {
                'message': f"Plugin '{plugin_name}' carries security and operational risks",
                'plugin_warning': plugin_warning,
                'plugin_name': plugin_name,
                'operation': operation,
                'acceptance_required': True
            }
        }

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process disclaimer requests across all PlugPipe interfaces
    
    Args:
        ctx: Execution context with user and session information
        cfg: Configuration with disclaimer parameters
    
    Returns:
        Disclaimer response with content and metadata
    """
    try:
        plugin = UniversalDisclaimerPlugin(cfg)
        
        interface = cfg.get('interface', 'unknown')
        action = cfg.get('action', 'get_disclaimer')
        context = cfg.get('context', {})
        
        # Add execution context to disclaimer context
        context.update({
            'interface': interface,
            'user_id': ctx.get('user_id', ctx.get('user', 'anonymous')),
            'session_id': ctx.get('session_id', 'unknown'),
            'request_id': ctx.get('request_id', 'unknown')
        })
        
        # Route to appropriate handler
        if action == 'show_banner':
            result = plugin.show_banner(context)
        elif action == 'require_acknowledgment':
            result = plugin.require_acknowledgment(context)
        elif action == 'record_acknowledgment':
            result = plugin.record_acknowledgment(context)
        elif action == 'check_acceptance':
            result = plugin.check_acceptance(context)
        elif action == 'add_headers':
            result = plugin.add_headers(context)
        elif action == 'get_disclaimer':
            result = plugin.get_disclaimer(context)
        elif action == 'plugin_disclaimer':
            result = plugin.generate_plugin_disclaimer(context)
        else:
            raise ValueError(f"Unknown disclaimer action: {action}")
        
        # Add metadata
        result['metadata'] = {
            'plugin': 'universal_disclaimer',
            'version': '1.0.0',
            'interface': interface,
            'action': action,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tracking_id': context.get('tracking_id', 'unknown')
        }
        
        logger.info(f"Disclaimer {action} processed for {interface} interface")
        return result
        
    except Exception as e:
        logger.error(f"Disclaimer plugin error: {e}")
        return {
            'success': False,
            'error': str(e),
            'disclaimer': {
                'message': 'Disclaimer service temporarily unavailable',
                'fallback': True
            },
            'metadata': {
                'plugin': 'universal_disclaimer',
                'version': '1.0.0',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        }

# Plugin metadata
plug_metadata = {
    'name': 'legal.universal_disclaimer',
    'owner': 'PlugPipe Legal Team',
    'version': '1.0.0',
    'status': 'production',
    'description': 'Universal legal disclaimer plugin for all PlugPipe interfaces',
    'category': 'legal',
    'revolutionary_capabilities': [
        'universal_interface_disclaimer_management',
        'automated_risk_acknowledgment_tracking', 
        'context_aware_legal_protection',
        'multi_format_disclaimer_generation',
        'compliance_audit_trail_creation'
    ],
    'interfaces_supported': ['cli', 'api', 'mcp', 'frontend', 'plugin_action'],
    'legal_protection_coverage': 'comprehensive'
}