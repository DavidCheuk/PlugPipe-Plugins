#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Certificate Factory Plugin

Factory plugin that provides unified certificate management across multiple providers
following PlugPipe's "reuse everything, reinvent nothing" and plugin-first principles.

This factory plugin automatically selects the best certificate provider based on:
- Use case requirements (public vs private certificates)
- Enterprise constraints (compliance, audit requirements)  
- Infrastructure context (cloud provider, Kubernetes environment)
- Cost optimization (free vs paid certificate providers)

Supported Providers:
- HashiCorp Vault PKI (private CA, dynamic certificates)
- Let's Encrypt ACME (public CA, free certificates)
- AWS Certificate Manager (AWS-integrated certificates)
- DigiCert Trust Lifecycle Manager (enterprise certificates)
- Venafi/CyberArk Certificate Manager (enterprise PKI platform)
- Microsoft Certificate Authority (Windows/AD integration)
- Kubernetes cert-manager (cloud-native certificates)
"""

import asyncio
import importlib.util
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

# Add project root to path for plugin imports
PROJECT_ROOT = Path(__file__).parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)

class CertificateFactory:
    """
    Certificate Factory for selecting and managing certificate providers
    
    Implements intelligent provider selection based on use case, enterprise requirements,
    and infrastructure context while maintaining vendor neutrality.
    """
    
    def __init__(self):
        self.logger = logger
        self.providers = {}
        self.provider_configs = {}
        
        # Provider capability matrix
        self.provider_capabilities = {
            "hashicorp_vault": {
                "certificate_types": ["private"],
                "use_cases": ["internal_services", "microservices", "kubernetes", "development"],
                "features": ["dynamic_certificates", "short_ttl", "policy_based_access", "automatic_rotation"],
                "infrastructure": ["on_premise", "kubernetes", "cloud_agnostic"],
                "cost": "infrastructure_dependent",
                "compliance": ["SOC2", "HIPAA", "enterprise_audit"],
                "integration_complexity": "medium"
            },
            "lets_encrypt_acme": {
                "certificate_types": ["public"],
                "use_cases": ["web_servers", "public_apis", "cdn", "development"],
                "features": ["free_certificates", "automated_renewal", "domain_validation"],
                "infrastructure": ["internet_facing", "domain_ownership_required"],
                "cost": "free",
                "compliance": ["basic_ssl", "web_security"],
                "integration_complexity": "low"
            },
            "aws_certificate_manager": {
                "certificate_types": ["public", "private"],
                "use_cases": ["aws_workloads", "elastic_load_balancer", "cloudfront", "api_gateway"],
                "features": ["aws_native", "automatic_renewal", "load_balancer_integration"],
                "infrastructure": ["aws_cloud"],
                "cost": "included_with_aws_services",
                "compliance": ["AWS_security_standards", "enterprise_compliance"],
                "integration_complexity": "low_for_aws"
            },
            "digicert": {
                "certificate_types": ["public", "private", "code_signing", "email"],
                "use_cases": ["enterprise_pki", "compliance", "global_deployments", "code_signing"],
                "features": ["enterprise_support", "quantum_safe", "multi_cloud", "extended_validation"],
                "infrastructure": ["multi_cloud", "on_premise", "hybrid"],
                "cost": "paid_premium",
                "compliance": ["SOC2", "HIPAA", "PCI_DSS", "FIPS_140-2", "quantum_safe"],
                "integration_complexity": "medium"
            },
            "venafi_cyberark": {
                "certificate_types": ["public", "private", "all"],
                "use_cases": ["enterprise_security", "compliance", "audit_trails", "machine_identity"],
                "features": ["policy_enforcement", "compliance_reporting", "machine_identity_protection"],
                "infrastructure": ["enterprise", "multi_cloud", "hybrid"],
                "cost": "paid_enterprise",
                "compliance": ["enterprise_audit", "SOC2", "HIPAA", "PCI_DSS", "regulatory"],
                "integration_complexity": "high"
            },
            "kubernetes_cert_manager": {
                "certificate_types": ["public", "private"],
                "use_cases": ["kubernetes_workloads", "ingress_certificates", "service_mesh"],
                "features": ["kubernetes_native", "automatic_renewal", "multiple_issuers", "crd_based"],
                "infrastructure": ["kubernetes"],
                "cost": "infrastructure_dependent",
                "compliance": ["kubernetes_security", "cloud_native_security"],
                "integration_complexity": "low_for_k8s"
            }
        }
    
    def select_provider(self, requirements: Dict[str, Any]) -> str:
        """
        Intelligently select the best certificate provider based on requirements
        
        Args:
            requirements: Dictionary containing:
                - certificate_type: "public", "private", "code_signing", "email"
                - use_case: Primary use case for the certificate
                - infrastructure: Target infrastructure (aws, kubernetes, on_premise, etc.)
                - compliance_requirements: List of compliance standards needed
                - cost_preference: "free", "low_cost", "enterprise", "any"
                - integration_complexity_preference: "low", "medium", "high", "any"
                - availability_requirements: "high", "standard"
        
        Returns:
            str: Selected provider name
        """
        cert_type = requirements.get('certificate_type', 'public')
        use_case = requirements.get('use_case', 'web_servers')
        infrastructure = requirements.get('infrastructure', 'cloud_agnostic')
        compliance = requirements.get('compliance_requirements', [])
        cost_pref = requirements.get('cost_preference', 'any')
        complexity_pref = requirements.get('integration_complexity_preference', 'any')
        
        scores = {}
        
        for provider_name, capabilities in self.provider_capabilities.items():
            score = 0
            
            # Certificate type compatibility (critical)
            if cert_type in capabilities['certificate_types'] or 'all' in capabilities['certificate_types']:
                score += 100
            else:
                continue  # Skip providers that don't support the certificate type
            
            # Use case compatibility (high priority)
            if use_case in capabilities['use_cases']:
                score += 50
            elif any(uc in capabilities['use_cases'] for uc in [use_case.split('_')[0]]):
                score += 25
            
            # Infrastructure compatibility (high priority)
            if infrastructure in capabilities['infrastructure'] or 'cloud_agnostic' in capabilities['infrastructure']:
                score += 40
            
            # Compliance requirements (high priority for enterprise)
            compliance_match = 0
            for req in compliance:
                if req in capabilities['compliance']:
                    compliance_match += 1
            if compliance and compliance_match > 0:
                score += (compliance_match / len(compliance)) * 30
            
            # Cost preference (medium priority)
            cost_scores = {
                'free': {'free': 30, 'infrastructure_dependent': 15, 'included_with_aws_services': 10, 'paid_premium': 0, 'paid_enterprise': 0},
                'low_cost': {'free': 30, 'infrastructure_dependent': 25, 'included_with_aws_services': 20, 'paid_premium': 5, 'paid_enterprise': 0},
                'enterprise': {'paid_enterprise': 30, 'paid_premium': 25, 'infrastructure_dependent': 15, 'included_with_aws_services': 10, 'free': 5},
                'any': {'free': 15, 'infrastructure_dependent': 15, 'included_with_aws_services': 15, 'paid_premium': 15, 'paid_enterprise': 15}
            }
            provider_cost = capabilities['cost']
            if cost_pref in cost_scores and provider_cost in cost_scores[cost_pref]:
                score += cost_scores[cost_pref][provider_cost]
            
            # Integration complexity preference (low priority)
            complexity_scores = {
                'low': {'low': 10, 'low_for_aws': 10, 'low_for_k8s': 10, 'medium': 5, 'high': 0},
                'medium': {'medium': 10, 'low': 8, 'low_for_aws': 8, 'low_for_k8s': 8, 'high': 5},
                'high': {'high': 10, 'medium': 8, 'low': 5, 'low_for_aws': 5, 'low_for_k8s': 5},
                'any': {'low': 8, 'low_for_aws': 8, 'low_for_k8s': 8, 'medium': 8, 'high': 8}
            }
            provider_complexity = capabilities['integration_complexity']
            if complexity_pref in complexity_scores and provider_complexity in complexity_scores[complexity_pref]:
                score += complexity_scores[complexity_pref][provider_complexity]
            
            scores[provider_name] = score
        
        # Select provider with highest score
        if not scores:
            return "certificate_manager_abstract"  # Fallback to abstract plugin
        
        selected_provider = max(scores.keys(), key=lambda k: scores[k])
        
        self.logger.info(f"Selected certificate provider: {selected_provider}")
        self.logger.debug(f"Provider selection scores: {scores}")
        
        return selected_provider
    
    async def load_provider_plugin(self, provider_name: str) -> Any:
        """Dynamically load provider plugin"""
        if provider_name in self.providers:
            return self.providers[provider_name]
        
        # Map provider names to plugin paths
        provider_plugins = {
            "hashicorp_vault": "plugs/security/vault_certificate_manager/1.0.0/main.py",
            "lets_encrypt_acme": "plugs/security/acme_certificate_manager/1.0.0/main.py", 
            "aws_certificate_manager": "plugs/cloud/aws_certificate_manager/1.0.0/main.py",
            "digicert": "plugs/security/digicert_certificate_manager/1.0.0/main.py",
            "venafi_cyberark": "plugs/security/venafi_certificate_manager/1.0.0/main.py",
            "kubernetes_cert_manager": "plugs/cloud/k8s_cert_manager/1.0.0/main.py",
            "certificate_manager_abstract": "plugs/security/certificate_manager_abstract/1.0.0/main.py"
        }
        
        plugin_path = provider_plugins.get(provider_name)
        if not plugin_path:
            self.logger.warning(f"Unknown provider: {provider_name}, using abstract plugin")
            plugin_path = provider_plugins["certificate_manager_abstract"]
            provider_name = "certificate_manager_abstract"
        
        full_path = PROJECT_ROOT / plugin_path
        
        if not full_path.exists():
            self.logger.warning(f"Provider plugin not found: {full_path}, using abstract plugin")
            full_path = PROJECT_ROOT / provider_plugins["certificate_manager_abstract"]
        
        try:
            spec = importlib.util.spec_from_file_location(f"{provider_name}_plugin", str(full_path))
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            
            # Cache the loaded provider
            self.providers[provider_name] = plugin_module
            return plugin_module
            
        except Exception as e:
            self.logger.error(f"Failed to load provider plugin {provider_name}: {e}")
            # Fallback to abstract plugin
            try:
                abstract_path = PROJECT_ROOT / provider_plugins["certificate_manager_abstract"]
                spec = importlib.util.spec_from_file_location("abstract_plugin", str(abstract_path))
                plugin_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(plugin_module)
                self.providers["certificate_manager_abstract"] = plugin_module
                return plugin_module
            except Exception as fallback_error:
                self.logger.error(f"Failed to load abstract plugin fallback: {fallback_error}")
                raise

class CertificateFactoryPlugin:
    """
    PlugPipe Certificate Factory Plugin
    
    Factory plugin that intelligently selects and delegates to appropriate certificate
    providers based on requirements and context.
    """
    
    def __init__(self):
        self.factory = CertificateFactory()
        self.logger = logger
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process certificate factory operations
        
        Supported operations:
        - select_provider: Intelligently select certificate provider
        - issue_certificate: Issue certificate via selected provider
        - get_providers: List available certificate providers
        - get_provider_capabilities: Get detailed provider information
        - delegate_operation: Delegate any operation to selected provider
        """
        operation = cfg.get('operation', 'get_status')
        
        try:
            if operation == 'get_status':
                return await self._get_factory_status(ctx, cfg)
            elif operation == 'select_provider':
                return await self._select_provider_operation(ctx, cfg)
            elif operation == 'get_providers':
                return await self._get_providers(ctx, cfg)
            elif operation == 'get_provider_capabilities':
                return await self._get_provider_capabilities(ctx, cfg)
            elif operation == 'delegate_operation':
                return await self._delegate_operation(ctx, cfg)
            elif operation in ['issue_certificate', 'renew_certificate', 'revoke_certificate', 
                             'get_certificate', 'list_certificates', 'validate_certificate']:
                # Auto-delegate certificate operations
                return await self._auto_delegate_certificate_operation(ctx, cfg)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operation: {operation}",
                    "supported_operations": [
                        "get_status", "select_provider", "get_providers", 
                        "get_provider_capabilities", "delegate_operation",
                        "issue_certificate", "renew_certificate", "revoke_certificate",
                        "get_certificate", "list_certificates", "validate_certificate"
                    ]
                }
                
        except Exception as e:
            self.logger.error(f"Certificate factory plugin error: {e}")
            return {
                "success": False,
                "error": str(e),
                "plugin": "certificate_factory"
            }
    
    async def _get_factory_status(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get certificate factory status"""
        return {
            "success": True,
            "plugin": "certificate_factory",
            "version": "1.0.0",
            "description": "Intelligent certificate provider factory with automatic selection",
            "providers_available": len(self.factory.provider_capabilities),
            "providers": list(self.factory.provider_capabilities.keys()),
            "selection_criteria": [
                "certificate_type", "use_case", "infrastructure", 
                "compliance_requirements", "cost_preference", "integration_complexity"
            ],
            "enterprise_ready": True,
            "automatic_provider_selection": True
        }
    
    async def _select_provider_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Select optimal certificate provider based on requirements"""
        requirements = cfg.get('requirements', {})
        
        if not requirements:
            return {
                "success": False,
                "error": "Requirements object needed for provider selection",
                "example_requirements": {
                    "certificate_type": "public",
                    "use_case": "web_servers",
                    "infrastructure": "aws_cloud",
                    "compliance_requirements": ["SOC2"],
                    "cost_preference": "low_cost"
                }
            }
        
        selected_provider = self.factory.select_provider(requirements)
        provider_info = self.factory.provider_capabilities.get(selected_provider, {})
        
        return {
            "success": True,
            "selected_provider": selected_provider,
            "provider_info": provider_info,
            "requirements": requirements,
            "selection_reasoning": f"Selected based on compatibility with {requirements.get('certificate_type', 'public')} certificates and {requirements.get('use_case', 'general')} use case"
        }
    
    async def _get_providers(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get list of available certificate providers"""
        return {
            "success": True,
            "providers": self.factory.provider_capabilities,
            "provider_count": len(self.factory.provider_capabilities),
            "categories": {
                "public_ca": ["lets_encrypt_acme", "digicert", "aws_certificate_manager"],
                "private_ca": ["hashicorp_vault", "digicert", "venafi_cyberark"],
                "enterprise": ["digicert", "venafi_cyberark"],
                "cloud_native": ["kubernetes_cert_manager", "aws_certificate_manager"],
                "free_options": ["lets_encrypt_acme"]
            }
        }
    
    async def _get_provider_capabilities(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed capabilities for specific provider"""
        provider = cfg.get('provider')
        if not provider:
            return {
                "success": False,
                "error": "Provider name required",
                "available_providers": list(self.factory.provider_capabilities.keys())
            }
        
        if provider not in self.factory.provider_capabilities:
            return {
                "success": False,
                "error": f"Provider '{provider}' not found",
                "available_providers": list(self.factory.provider_capabilities.keys())
            }
        
        return {
            "success": True,
            "provider": provider,
            "capabilities": self.factory.provider_capabilities[provider],
            "detailed_info": True
        }
    
    async def _delegate_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Delegate operation to specific provider"""
        provider = cfg.get('provider')
        target_operation = cfg.get('target_operation')
        
        if not provider or not target_operation:
            return {
                "success": False,
                "error": "Both 'provider' and 'target_operation' required for delegation"
            }
        
        # Load provider plugin
        provider_plugin = await self.factory.load_provider_plugin(provider)
        
        # Prepare configuration for target operation
        delegated_cfg = cfg.copy()
        delegated_cfg['operation'] = target_operation
        
        # Execute operation via provider plugin
        if hasattr(provider_plugin, 'process'):
            result = await provider_plugin.process(ctx, delegated_cfg)
            result['delegated_to'] = provider
            return result
        else:
            return {
                "success": False,
                "error": f"Provider plugin '{provider}' does not support delegation",
                "provider": provider
            }
    
    async def _auto_delegate_certificate_operation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically select provider and delegate certificate operation"""
        operation = cfg.get('operation')
        
        # Extract requirements from configuration
        requirements = cfg.get('requirements', {})
        
        # Auto-infer requirements if not provided
        if not requirements:
            requirements = self._infer_requirements_from_config(cfg)
        
        # Select optimal provider
        selected_provider = self.factory.select_provider(requirements)
        
        # Load and delegate to provider
        provider_plugin = await self.factory.load_provider_plugin(selected_provider)
        
        # Execute operation
        if hasattr(provider_plugin, 'process'):
            result = await provider_plugin.process(ctx, cfg)
            result['provider_used'] = selected_provider
            result['auto_selected'] = True
            return result
        else:
            return {
                "success": False,
                "error": f"Provider plugin '{selected_provider}' does not support operation: {operation}",
                "provider": selected_provider
            }
    
    def _infer_requirements_from_config(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Infer provider selection requirements from operation configuration"""
        requirements = {}
        
        # Infer certificate type
        common_name = cfg.get('common_name', '')
        sans = cfg.get('subject_alternative_names', [])
        
        if common_name.startswith('*.') or any(domain.startswith('*.') for domain in sans):
            requirements['certificate_type'] = 'public'
        elif any(internal in common_name.lower() for internal in ['localhost', '127.0.0.1', '.local', '.internal']):
            requirements['certificate_type'] = 'private'
        else:
            requirements['certificate_type'] = 'public'  # Default to public
        
        # Infer use case from configuration context
        if cfg.get('kubernetes_context') or cfg.get('ingress_name'):
            requirements['use_case'] = 'kubernetes_workloads'
            requirements['infrastructure'] = 'kubernetes'
        elif cfg.get('aws_context') or cfg.get('load_balancer_arn'):
            requirements['use_case'] = 'aws_workloads'
            requirements['infrastructure'] = 'aws_cloud'
        else:
            requirements['use_case'] = 'web_servers'
            requirements['infrastructure'] = 'cloud_agnostic'
        
        # Default preferences
        requirements['cost_preference'] = cfg.get('cost_preference', 'any')
        requirements['compliance_requirements'] = cfg.get('compliance_requirements', [])
        
        return requirements

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "certificate_factory",
    "version": "1.0.0",
    "description": "Intelligent certificate provider factory with automatic provider selection based on requirements",
    "author": "PlugPipe Security Team",
    "category": "security",
    "tags": ["certificates", "factory", "pki", "automation", "provider_selection"],
    "requirements": [],
    "supported_operations": [
        "get_status", "select_provider", "get_providers", "get_provider_capabilities", 
        "delegate_operation", "issue_certificate", "renew_certificate", "revoke_certificate"
    ]
}

# Create plugin instance for PlugPipe
plugin_instance = CertificateFactoryPlugin()

# Main process function for PlugPipe
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for PlugPipe"""
    return await plugin_instance.process(ctx, cfg)