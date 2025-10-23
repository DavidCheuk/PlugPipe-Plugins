#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
ACME Corporation Custom Disclaimer Plugin

ENTERPRISE CUSTOMIZATION: Company-specific legal disclaimers that meet
ACME Corp's specific legal requirements, branding, and governance needs.

Key Features:
- ACME Corp branded disclaimers
- Custom liability terms
- Corporate governance compliance
- Legal team controlled updates
- Enterprise audit integration
"""

import os
import sys
from typing import Dict, Any
from datetime import datetime, timezone
import importlib.util

# Import base universal disclaimer functionality
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../universal_disclaimer/1.0.0'))

try:
    import main as universal_disclaimer
except ImportError:
    # Fallback if universal disclaimer not available
    universal_disclaimer = None

class ACMECorpDisclaimerPlugin:
    """ACME Corporation customized disclaimer plugin"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.company_name = "ACME Corporation"
        self.legal_entity = "ACME Corp Inc."
        
        # Load base universal disclaimer if available
        if universal_disclaimer:
            self.base_plugin = universal_disclaimer.UniversalDisclaimerPlugin(config)
        else:
            self.base_plugin = None
    
    def get_company_disclaimer_content(self):
        """Get ACME Corp specific disclaimer content"""
        brief_message = (
            f"{self.company_name} PlugPipe deployment is provided 'AS IS' "
            f"without warranties. Use subject to ACME Corp policies and at your own risk."
        )
        
        full_text = f"""
{self.company_name.upper()} PLUGPIPE DEPLOYMENT - LEGAL DISCLAIMER

BY USING THIS {self.company_name.upper()} PLUGPIPE DEPLOYMENT, YOU ACKNOWLEDGE:

1. CORPORATE GOVERNANCE
   This PlugPipe deployment is managed by {self.legal_entity} and subject to:
   • ACME Corp Information Technology Policies
   • ACME Corp Security and Privacy Standards  
   • ACME Corp Employee Code of Conduct
   • All applicable {self.legal_entity} employment agreements

2. ENTERPRISE USAGE TERMS
   • This system is for authorized ACME Corp business use only
   • All activities are logged and monitored for security and compliance
   • Unauthorized use may result in disciplinary action and/or termination
   • Data processed may be subject to ACME Corp data governance policies

3. ACME CORP SPECIFIC RISKS
   • Integration failures may impact ACME Corp business operations
   • Data loss could affect ACME Corp customer commitments
   • Security vulnerabilities may expose ACME Corp confidential information
   • Plugin malfunctions could disrupt ACME Corp service delivery

4. EMPLOYEE RESPONSIBILITIES
   As an ACME Corp employee/contractor, you are responsible for:
   • Following all ACME Corp IT security protocols
   • Protecting ACME Corp and customer confidential information
   • Testing integrations in approved development environments
   • Reporting security incidents through proper ACME Corp channels
   • Obtaining manager approval for production system changes

5. LIABILITY LIMITATION
   {self.legal_entity} provides this PlugPipe deployment without warranties.
   While ACME Corp maintains appropriate business insurance and risk management,
   users remain responsible for following established procedures and protocols.

6. COMPLIANCE REQUIREMENTS
   Usage must comply with:
   • SOX compliance requirements for financial data
   • GDPR and privacy regulations for customer data
   • Industry-specific regulations applicable to ACME Corp
   • ACME Corp vendor management and procurement policies

For questions regarding this disclaimer or ACME Corp PlugPipe policies,
contact: legal@acmecorp.com

Version: 1.0.0 | Effective: 2025-08-26 | {self.legal_entity}
        """.strip()
        
        return {
            'brief_message': brief_message,
            'full_text': full_text,
            'company': self.company_name,
            'legal_entity': self.legal_entity,
            'version': '1.0.0'
        }
    
    def show_banner(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ACME Corp branded banner disclaimer"""
        interface = context.get('interface', 'unknown')
        disclaimer_content = self.get_company_disclaimer_content()
        
        if interface == 'cli':
            banner = f"""
{'=' * 80}
🏢 {self.company_name.upper()} PLUGPIPE - LEGAL DISCLAIMER
{'=' * 80}
{disclaimer_content['brief_message']}

⚠️  ENTERPRISE RISKS: Business disruption, data exposure, compliance violations
📋 EMPLOYEE DUTY: Follow ACME Corp IT policies and security protocols
🚫 CORPORATE LIABILITY: Subject to ACME Corp employment terms and policies

By continuing, you acknowledge ACME Corp governance and assume responsibility.
Contact: legal@acmecorp.com for questions
{'=' * 80}
            """.strip()
        elif interface == 'frontend':
            banner = {
                'type': 'enterprise_banner',
                'company': self.company_name,
                'message': disclaimer_content['brief_message'],
                'severity': 'warning',
                'branding': 'acme_corp',
                'contact': 'legal@acmecorp.com'
            }
        else:
            banner = disclaimer_content['brief_message']
        
        return {
            'success': True,
            'disclaimer': {
                'message': disclaimer_content['brief_message'],
                'banner': banner,
                'company': self.company_name,
                'format': 'enterprise_banner'
            }
        }
    
    async def process_action(self, action: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process disclaimer action with ACME Corp customizations"""
        
        if action == 'show_banner':
            return self.show_banner(context)
        
        elif action == 'get_disclaimer':
            disclaimer_content = self.get_company_disclaimer_content()
            format_type = context.get('format', 'json')
            include_full = context.get('include_full', False)
            
            result_content = disclaimer_content['full_text' if include_full else 'brief_message']
            
            return {
                'success': True,
                'disclaimer': {
                    'content': result_content,
                    'company': self.company_name,
                    'legal_entity': self.legal_entity,
                    'format': format_type,
                    'version': disclaimer_content['version']
                }
            }
        
        elif action == 'add_headers':
            return {
                'success': True,
                'headers': {
                    'X-ACME-Disclaimer': f'{self.company_name} system - authorized use only',
                    'X-ACME-Legal-Entity': self.legal_entity,
                    'X-ACME-Contact': 'legal@acmecorp.com',
                    'X-PlugPipe-Enterprise': 'ACME Corp Deployment',
                    'X-PlugPipe-Governance': 'ACME Corp IT Policies Apply'
                }
            }
        
        elif self.base_plugin:
            # Delegate to universal disclaimer for standard actions
            # but add ACME Corp metadata
            result = await self.base_plugin.process_action(action, context)
            if result.get('success'):
                result['disclaimer']['company'] = self.company_name
                result['disclaimer']['enterprise'] = True
            return result
        
        else:
            return {
                'success': False,
                'error': 'Action not supported and universal disclaimer not available',
                'disclaimer': {
                    'message': self.get_company_disclaimer_content()['brief_message'],
                    'fallback': True
                }
            }

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    ACME Corp disclaimer processing with enterprise customizations
    """
    try:
        plugin = ACMECorpDisclaimerPlugin(cfg)
        
        action = cfg.get('action', 'get_disclaimer')
        context = cfg.get('context', {})
        
        # Add ACME Corp context
        context.update({
            'company': 'ACME Corporation',
            'deployment': 'enterprise',
            'governance': 'acme_corp_policies'
        })
        
        result = await plugin.process_action(action, context)
        
        # Add ACME Corp metadata
        result['metadata'] = {
            'plugin': 'acme_corp_disclaimer',
            'version': '1.0.0',
            'company': 'ACME Corporation',
            'legal_entity': 'ACME Corp Inc.',
            'enterprise': True,
            'governance': 'acme_corp_policies',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return result
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'disclaimer': {
                'message': 'ACME Corp disclaimer service temporarily unavailable',
                'fallback': True,
                'company': 'ACME Corporation'
            },
            'metadata': {
                'plugin': 'acme_corp_disclaimer',
                'error': str(e),
                'company': 'ACME Corporation'
            }
        }

# Plugin metadata
plug_metadata = {
    'name': 'legal.acme_corp_disclaimer',
    'owner': 'ACME Corp Legal Team',
    'version': '1.0.0',
    'status': 'production',
    'description': 'ACME Corporation enterprise legal disclaimer with company governance',
    'category': 'legal',
    'enterprise': True,
    'company': 'ACME Corporation',
    'legal_entity': 'ACME Corp Inc.',
    'governance': 'acme_corp_policies'
}