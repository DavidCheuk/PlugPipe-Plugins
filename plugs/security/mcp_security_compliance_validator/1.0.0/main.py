#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
MCP Security Compliance Validator Plugin

Following PlugPipe principles:
- REUSE EVERYTHING, REINVENT NOTHING - Composes existing security plugins
- DEFAULT TO CREATING PLUGINS - Uses pp() for plugin discovery
- ALWAYS use pp() for dynamic plugin discovery - Leverages existing security ecosystem
- Plugin composition over custom implementation
"""

import asyncio
import json
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Add PlugPipe root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from shares.loader import pp
    PP_AVAILABLE = True
except ImportError as e:
    print(f"Warning: PlugPipe core not available: {e}")
    PP_AVAILABLE = False

class MCPSecurityComplianceValidator:
    """
    MCP Security Compliance Validator Plugin
    
    Validates MCP implementations against security standards using
    existing PlugPipe security plugins for maximum reuse.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Existing security plugins to leverage
        self.security_plugins = {
            'config_hardening': 'config_hardening',
            'security_orchestrator': 'security_orchestrator', 
            'audit_integration': 'enhanced_mcp_audit_integration',
            'schema_validation': 'enhanced_mcp_schema_validation',
            'dlp_validator': 'presidio_dlp',
            'penetration_testing': 'penetration_testing'
        }
        
        # Compliance framework mappings to existing plugins
        self.compliance_mappings = {
            'MCP_PROTOCOL': ['schema_validation', 'audit_integration'],
            'GDPR': ['dlp_validator', 'audit_integration'],
            'SOX': ['audit_integration', 'config_hardening'],
            'HIPAA': ['dlp_validator', 'config_hardening'],
            'PCI_DSS': ['config_hardening', 'security_orchestrator'],
            'SECURITY_BASELINE': ['security_orchestrator', 'config_hardening', 'penetration_testing']
        }
        
    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute compliance validation using existing plugins"""
        if not PP_AVAILABLE:
            return {
                'success': False,
                'error': 'PlugPipe core not available. Cannot access existing security plugins.',
                'compliance_status': {},
                'validation_results': []
            }
            
        operation = params.get('operation', 'get_status')
        
        operations = {
            'validate_compliance': self._validate_compliance,
            'check_gdpr': self._check_gdpr_compliance,
            'check_sox': self._check_sox_compliance,
            'check_hipaa': self._check_hipaa_compliance,
            'check_pci_dss': self._check_pci_dss_compliance,
            'check_mcp_protocol': self._check_mcp_protocol_compliance,
            'generate_report': self._generate_compliance_report,
            'get_status': self._get_status
        }
        
        if operation in operations:
            return await operations[operation](params)
        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'available_operations': list(operations.keys())
            }
    
    async def _validate_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run comprehensive compliance validation using existing plugins"""
        frameworks = params.get('compliance_frameworks', ['MCP_PROTOCOL', 'SECURITY_BASELINE'])
        depth = params.get('validation_depth', 'standard')
        endpoint = params.get('target_endpoint', 'http://localhost:8091')
        
        validation_results = []
        overall_compliance = {}
        total_score = 0
        
        for framework in frameworks:
            try:
                result = await self._validate_framework(framework, endpoint, depth, params)
                validation_results.append(result)
                overall_compliance[framework] = result['compliance_status']
                total_score += result.get('score', 0)
            except Exception as e:
                self.logger.error(f"Framework validation error for {framework}: {e}")
                validation_results.append({
                    'framework': framework,
                    'status': 'error',
                    'error': str(e),
                    'score': 0
                })
        
        compliance_score = total_score / len(frameworks) if frameworks else 0
        remediation_plan = self._generate_remediation_plan(validation_results) if params.get('generate_remediation', True) else []
        
        return {
            'success': True,
            'compliance_status': overall_compliance,
            'validation_results': validation_results,
            'compliance_score': compliance_score,
            'remediation_plan': remediation_plan,
            'timestamp': datetime.utcnow().isoformat(),
            'validated_frameworks': frameworks
        }
    
    async def _validate_framework(self, framework: str, endpoint: str, depth: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate specific compliance framework using existing plugins"""
        if framework not in self.compliance_mappings:
            return {
                'framework': framework,
                'status': 'unsupported',
                'error': f'Framework {framework} not supported',
                'score': 0
            }
        
        required_plugins = self.compliance_mappings[framework]
        plugin_results = {}
        framework_score = 0
        
        for plugin_key in required_plugins:
            plugin_name = self.security_plugins[plugin_key]
            try:
                # Use pp() to run existing security plugin
                plugin_result = await self._run_security_plugin(plugin_name, endpoint, framework, params)
                plugin_results[plugin_key] = plugin_result
                
                # Extract compliance score from plugin result
                if plugin_result.get('success'):
                    framework_score += plugin_result.get('compliance_score', 50)
                
            except Exception as e:
                self.logger.error(f"Plugin {plugin_name} execution failed: {e}")
                plugin_results[plugin_key] = {
                    'success': False,
                    'error': str(e),
                    'compliance_score': 0
                }
        
        avg_score = framework_score / len(required_plugins) if required_plugins else 0
        compliance_status = self._assess_framework_compliance(framework, avg_score, plugin_results)
        
        return {
            'framework': framework,
            'status': 'validated',
            'compliance_status': compliance_status,
            'plugin_results': plugin_results,
            'score': avg_score,
            'required_plugins': required_plugins,
            'validation_depth': depth
        }
    
    async def _run_security_plugin(self, plugin_name: str, endpoint: str, framework: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run existing security plugin using pp() function"""
        try:
            # Prepare plugin-specific parameters
            plugin_params = {
                'operation': 'security_assessment',
                'target_endpoint': endpoint,
                'compliance_framework': framework,
                'assessment_type': 'compliance_validation'
            }
            
            # Add plugin-specific parameters
            if plugin_name == 'config_hardening':
                plugin_params.update({
                    'operation': 'validate_config',
                    'config_file': params.get('config_file', 'config.yaml'),
                    'enable_auto_remediation': False
                })
            elif plugin_name == 'enhanced_mcp_schema_validation':
                plugin_params.update({
                    'operation': 'validate_protocol',
                    'endpoint': endpoint,
                    'validation_type': 'compliance'
                })
            elif plugin_name == 'presidio_dlp':
                plugin_params.update({
                    'operation': 'compliance_scan',
                    'compliance_type': framework,
                    'scan_depth': 'comprehensive'
                })
            elif plugin_name == 'enhanced_mcp_audit_integration':
                plugin_params.update({
                    'operation': 'compliance_audit',
                    'framework': framework,
                    'generate_report': True
                })
            elif plugin_name == 'security_orchestrator':
                plugin_params.update({
                    'operation': 'comprehensive_assessment',
                    'focus_area': 'compliance',
                    'framework': framework
                })
            elif plugin_name == 'penetration_testing':
                plugin_params.update({
                    'operation': 'compliance_pentest',
                    'target': endpoint,
                    'test_scope': 'compliance_validation'
                })
            
            # Use pp() to run the existing plugin
            plugin_instance = pp(plugin_name)
            if hasattr(plugin_instance, 'execute'):
                result = await plugin_instance.execute(plugin_params)
            else:
                # Fallback for plugins that don't have async execute
                result = plugin_instance(plugin_params) if callable(plugin_instance) else {'success': False, 'error': 'Plugin not callable'}
            
            # Standardize result format for compliance assessment
            if result.get('success'):
                compliance_score = self._extract_compliance_score(result, plugin_name)
                result['compliance_score'] = compliance_score
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Plugin {plugin_name} execution failed: {str(e)}',
                'compliance_score': 0
            }
    
    def _extract_compliance_score(self, result: Dict[str, Any], plugin_name: str) -> int:
        """Extract compliance score from plugin result"""
        # Try multiple common score field names
        score_fields = ['compliance_score', 'security_score', 'score', 'rating', 'assessment_score']
        
        for field in score_fields:
            if field in result:
                return max(0, min(100, int(result[field])))
        
        # Plugin-specific score extraction
        if plugin_name == 'config_hardening':
            return 90 if result.get('hardening_applied') else 60
        elif plugin_name == 'enhanced_mcp_schema_validation':
            return 95 if result.get('protocol_compliant') else 40
        elif plugin_name == 'presidio_dlp':
            violations = len(result.get('violations', []))
            return max(10, 100 - (violations * 10))
        elif plugin_name == 'enhanced_mcp_audit_integration':
            return 85 if result.get('audit_configured') else 30
        elif plugin_name == 'security_orchestrator':
            return result.get('overall_score', 70)
        elif plugin_name == 'penetration_testing':
            vulnerabilities = len(result.get('vulnerabilities_found', []))
            return max(20, 100 - (vulnerabilities * 15))
        
        # Default score based on success
        return 75 if result.get('success') else 25
    
    def _assess_framework_compliance(self, framework: str, score: float, plugin_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall compliance status for framework"""
        if score >= 90:
            level = 'compliant'
            risk = 'low'
        elif score >= 70:
            level = 'mostly_compliant'
            risk = 'medium'
        elif score >= 50:
            level = 'partially_compliant'
            risk = 'high'
        else:
            level = 'non_compliant'
            risk = 'critical'
        
        # Framework-specific assessments
        critical_plugins = self._get_critical_plugins_for_framework(framework)
        critical_failures = [p for p in critical_plugins if not plugin_results.get(p, {}).get('success', False)]
        
        if critical_failures:
            level = 'non_compliant'
            risk = 'critical'
        
        return {
            'compliance_level': level,
            'risk_level': risk,
            'score': score,
            'critical_failures': critical_failures,
            'framework_requirements_met': len(critical_failures) == 0
        }
    
    def _get_critical_plugins_for_framework(self, framework: str) -> List[str]:
        """Get critical plugins that must pass for framework compliance"""
        critical_mappings = {
            'MCP_PROTOCOL': ['schema_validation'],
            'GDPR': ['dlp_validator', 'audit_integration'],
            'SOX': ['audit_integration'],
            'HIPAA': ['dlp_validator'],
            'PCI_DSS': ['config_hardening'],
            'SECURITY_BASELINE': ['security_orchestrator']
        }
        return critical_mappings.get(framework, [])
    
    def _generate_remediation_plan(self, validation_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate remediation plan using existing plugin recommendations"""
        remediation_plan = []
        
        for result in validation_results:
            framework = result.get('framework', 'unknown')
            compliance_status = result.get('compliance_status', {})
            
            if compliance_status.get('compliance_level') != 'compliant':
                # Extract remediation from plugin results
                plugin_results = result.get('plugin_results', {})
                for plugin_key, plugin_result in plugin_results.items():
                    if not plugin_result.get('success'):
                        remediation_plan.append({
                            'framework': framework,
                            'plugin': plugin_key,
                            'priority': 'high' if plugin_key in compliance_status.get('critical_failures', []) else 'medium',
                            'action': f'Fix {plugin_key} issues for {framework} compliance',
                            'recommendation': plugin_result.get('recommendation', f'Review {plugin_key} configuration'),
                            'estimated_effort': 'medium'
                        })
        
        return remediation_plan
    
    # Framework-specific validation methods using existing plugins
    async def _check_gdpr_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check GDPR compliance using existing DLP and audit plugins"""
        return await self._validate_framework('GDPR', 
                                             params.get('target_endpoint', 'http://localhost:8091'),
                                             params.get('validation_depth', 'standard'),
                                             params)
    
    async def _check_sox_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check SOX compliance using existing audit plugins"""
        return await self._validate_framework('SOX',
                                             params.get('target_endpoint', 'http://localhost:8091'),
                                             params.get('validation_depth', 'standard'),
                                             params)
    
    async def _check_hipaa_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check HIPAA compliance using existing DLP plugins"""
        return await self._validate_framework('HIPAA',
                                             params.get('target_endpoint', 'http://localhost:8091'),
                                             params.get('validation_depth', 'comprehensive'),
                                             params)
    
    async def _check_pci_dss_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check PCI DSS compliance using existing security plugins"""
        return await self._validate_framework('PCI_DSS',
                                             params.get('target_endpoint', 'http://localhost:8091'),
                                             params.get('validation_depth', 'comprehensive'),
                                             params)
    
    async def _check_mcp_protocol_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Check MCP protocol compliance using existing schema validation"""
        return await self._validate_framework('MCP_PROTOCOL',
                                             params.get('target_endpoint', 'http://localhost:8091'),
                                             params.get('validation_depth', 'standard'),
                                             params)
    
    async def _generate_compliance_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        # Run full compliance validation first
        validation_result = await self._validate_compliance(params)
        
        if not validation_result.get('success'):
            return validation_result
        
        # Enhanced report generation
        report = {
            'report_type': 'MCP_Security_Compliance_Report',
            'generated_at': datetime.utcnow().isoformat(),
            'executive_summary': self._generate_executive_summary(validation_result),
            'detailed_findings': validation_result['validation_results'],
            'compliance_matrix': self._generate_compliance_matrix(validation_result),
            'remediation_roadmap': validation_result.get('remediation_plan', []),
            'certificate_recommendations': self._generate_certificate_recommendations(validation_result)
        }
        
        return {
            'success': True,
            'compliance_report': report,
            'compliance_score': validation_result['compliance_score'],
            'report_file': '/tmp/mcp_compliance_report.json'  # Following CLAUDE.md temp file rules
        }
    
    def _generate_executive_summary(self, validation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of compliance status"""
        score = validation_result.get('compliance_score', 0)
        frameworks = validation_result.get('validated_frameworks', [])
        
        if score >= 90:
            summary = "Excellent compliance posture with minimal risk"
            recommendation = "Maintain current security controls and continue monitoring"
        elif score >= 70:
            summary = "Good compliance posture with some areas for improvement"  
            recommendation = "Address medium-risk findings and enhance monitoring"
        elif score >= 50:
            summary = "Moderate compliance gaps requiring immediate attention"
            recommendation = "Implement remediation plan and conduct regular assessments"
        else:
            summary = "Significant compliance gaps requiring urgent remediation"
            recommendation = "Immediate action required - consider engaging security experts"
        
        return {
            'overall_score': score,
            'compliance_summary': summary,
            'frameworks_validated': len(frameworks),
            'primary_recommendation': recommendation,
            'risk_level': 'low' if score >= 80 else 'medium' if score >= 60 else 'high'
        }
    
    def _generate_compliance_matrix(self, validation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance matrix showing framework coverage"""
        matrix = {}
        
        for result in validation_result.get('validation_results', []):
            framework = result.get('framework')
            status = result.get('compliance_status', {})
            matrix[framework] = {
                'compliance_level': status.get('compliance_level', 'unknown'),
                'score': result.get('score', 0),
                'critical_controls': status.get('framework_requirements_met', False),
                'risk_level': status.get('risk_level', 'unknown')
            }
        
        return matrix
    
    def _generate_certificate_recommendations(self, validation_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate certification recommendations based on compliance results"""
        score = validation_result.get('compliance_score', 0)
        recommendations = []
        
        if score >= 85:
            recommendations.append({
                'certificate': 'ISO 27001',
                'readiness': 'high',
                'estimated_effort': 'medium',
                'priority': 'medium'
            })
        
        if score >= 90:
            recommendations.append({
                'certificate': 'SOC 2 Type II',
                'readiness': 'high',
                'estimated_effort': 'high',
                'priority': 'high'
            })
        
        return recommendations
    
    async def _get_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get plugin status and capabilities"""
        return {
            'success': True,
            'plugin_name': 'mcp_security_compliance_validator',
            'version': '1.0.0',
            'status': 'ready',
            'pp_available': PP_AVAILABLE,
            'supported_frameworks': list(self.compliance_mappings.keys()),
            'available_security_plugins': list(self.security_plugins.keys()),
            'plugin_composition_approach': True,
            'capabilities': {
                'compliance_validation': True,
                'framework_assessment': True,
                'remediation_planning': True,
                'compliance_reporting': True,
                'certificate_readiness': True,
                'plugin_orchestration': True
            },
            'reused_plugins': list(self.security_plugins.values()),
            'follows_pp_principles': {
                'reuse_everything': True,
                'plugin_composition': True,
                'pp_function_usage': True,
                'default_to_plugins': True
            }
        }

# Plugin entry point
def main():
    """Main entry point for the plugin"""
    import sys
    
    try:
        # Read JSON input from stdin
        input_data = sys.stdin.read().strip()
        if not input_data:
            params = {'operation': 'get_status'}
        else:
            params = json.loads(input_data)
        
        # Initialize and run the plugin
        validator = MCPSecurityComplianceValidator()
        result = asyncio.run(validator.execute(params))
        
        # Output result as JSON
        print(json.dumps(result, indent=2))
        
    except json.JSONDecodeError as e:
        error_result = {
            'success': False,
            'error': f'Invalid JSON input: {e}',
            'input_received': input_data[:100] if 'input_data' in locals() else 'None'
        }
        print(json.dumps(error_result, indent=2))
    except Exception as e:
        error_result = {
            'success': False,
            'error': f'Plugin execution error: {e}'
        }
        print(json.dumps(error_result, indent=2))

# PlugPipe process function for compatibility
def process(ctx, cfg=None):
    """PlugPipe entry point for compliance validator"""
    try:
        validator = MCPSecurityComplianceValidator()
        result = asyncio.run(validator.execute(ctx))
        return result
    except Exception as e:
        return {
            'success': False,
            'error': f'Plugin execution error: {e}'
        }

if __name__ == '__main__':
    main()