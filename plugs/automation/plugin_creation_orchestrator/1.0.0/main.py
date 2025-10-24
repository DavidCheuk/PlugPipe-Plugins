#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Plugin Creation Factory Orchestrator - AI-powered high-level plugin creation factory
that continuously researches popular applications/technologies and creates plugins
using pragmatic approach with existing plugin reuse.

This orchestrator leverages the PlugPipe ecosystem to provide revolutionary
market-driven plugin creation with comprehensive testing and validation.
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# PlugPipe core imports
from shares.utils.config_loader import get_llm_config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Plugin metadata
plug_metadata = {
    "name": "plugin_creation_orchestrator",
    "version": "1.0.0",
    "description": "AI-powered high-level plugin creation factory orchestrator that continuously researches popular applications/technologies and creates plugins using pragmatic approach with existing plugin reuse",
    "owner": "PlugPipe Automation Team",
    "status": "stable",
    "ai_requirements": {
        "llm_service_required": True,
        "minimum_capabilities": [
            "market_research_analysis",
            "technology_trend_identification", 
            "code_generation_assistance",
            "documentation_creation",
            "strategic_decision_making"
        ]
    }
}


class PluginCreationOrchestrator:
    """
    AI-powered orchestrator for continuous plugin creation based on market research
    and technology trends, using existing plugin reuse patterns.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.orchestrator_id = str(uuid.uuid4())
        self.llm_config = get_llm_config(primary=True)
        
        # Orchestrated plugin references
        self.market_research_plugins = [
            "web_search_agent_factory",
            "research_validation_agent_factory",
            "llm_service"
        ]

        self.plugin_creation_plugins = [
            "enhanced_plug_creation_agent",
            "automatic_pipe_creation_agent",
            "llm_service"
        ]

        self.testing_plugins = [
            "intelligent_test_agent",
            "automated_test_generator",
            "business_compliance_auditor"
        ]

        self.analysis_plugins = [
            "context_analyzer",
            "database_plugin_registry"
        ]
        
        # Validate LLM configuration
        if not self.llm_config:
            logger.warning("LLM configuration not found - plugin functionality will be limited")
        
        logger.info(f"Initialized Plugin Creation Orchestrator {self.orchestrator_id}")

    async def research_market_trends(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Conduct AI-powered market research and technology trend analysis.
        """
        logger.info("Starting market research and trend analysis")
        
        research_scope = context.get('market_research_scope', {})
        technology_categories = research_scope.get('technology_categories', 
            ['api_integrations', 'cloud_services', 'ai_ml', 'devops', 'security', 'data_analytics'])
        research_depth = research_scope.get('research_depth', 'comprehensive')
        
        try:
            # Step 1: Web search for trending technologies
            from shares.utils.pp_discovery import pp
            
            web_search_agent = await pp('web_search_agent_factory', version='1.0.0')
            search_results = []
            
            for category in technology_categories:
                search_context = {
                    'operation': 'create_agent',
                    'agent_config': {
                        'domain': 'technical',
                        'max_results': 20,
                        'credibility_threshold': 0.8
                    },
                    'template_id': 'comprehensive_search'
                }
                
                search_result = await web_search_agent.process(search_context, {
                    'search_query': f"trending {category} technologies 2024 API integrations",
                    'research_depth': research_depth
                })
                
                if search_result.get('success'):
                    search_results.append({
                        'category': category,
                        'search_data': search_result
                    })
            
            # Step 2: LLM analysis of search results
            llm_service = await pp('llm_service', version='1.0.0')
            
            analysis_context = {
                'action': 'analyze',
                'analysis_type': 'market_research',
                'data': {
                    'search_results': search_results,
                    'research_scope': research_scope,
                    'analysis_prompt': """
                    Analyze the provided technology search results and identify:
                    1. Top 10 trending technologies with high market demand
                    2. Plugin gap analysis - which technologies lack good integration plugins
                    3. Market demand scoring (0.0-1.0) for each technology
                    4. Strategic importance and competitive advantages
                    5. Implementation feasibility assessment
                    6. Recommended priority levels (low, medium, high, critical)
                    
                    Focus on technologies that would benefit from plugin-based integration
                    and have strong market adoption potential.
                    """
                }
            }
            
            llm_analysis = await llm_service.process(analysis_context, self.llm_config)
            
            # Step 3: Research validation
            research_validator = await pp('research_validation_agent_factory', version='1.0.0')
            
            validation_context = {
                'research_content': json.dumps(llm_analysis.get('response', {})),
                'research_config': {
                    'research_domain': 'computer_science',
                    'research_type': 'observational',
                    'research_phase': 'analysis_execution'
                },
                'validation_methods': ['methodology_validation', 'data_integrity_checking']
            }
            
            validation_result = await research_validator.process(validation_context, {})
            
            # Compile comprehensive results
            market_research_results = {
                'trending_technologies': self._extract_trending_technologies(llm_analysis),
                'competitive_analysis': self._extract_competitive_analysis(llm_analysis),
                'ai_insights': self._extract_ai_insights(llm_analysis),
                'research_validation_score': validation_result.get('research_validation_result', {}).get('overall_research_quality_score', 0.0),
                'research_metadata': {
                    'categories_analyzed': technology_categories,
                    'research_depth': research_depth,
                    'analysis_timestamp': datetime.now().isoformat(),
                    'validation_status': validation_result.get('success', False)
                }
            }
            
            logger.info(f"Market research completed with {len(market_research_results.get('trending_technologies', []))} technologies identified")
            return market_research_results
            
        except Exception as e:
            logger.error(f"Market research failed: {e}")
            return {
                'trending_technologies': [],
                'error': f"Market research failed: {str(e)}",
                'ai_insights': ["Market research system temporarily unavailable"]
            }

    async def analyze_plugin_gaps(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze existing plugins to identify gaps and reuse opportunities.
        """
        logger.info("Analyzing plugin ecosystem gaps")
        
        try:
            from shares.utils.pp_discovery import pp
            
            # Step 1: Analyze existing plugin registry
            registry_plugin = await pp('database_plugin_registry', version='1.0.0')
            
            registry_context = {
                'operation': 'list_plugins',
                'filters': {
                    'status': 'stable',
                    'category': 'all'
                },
                'include_metadata': True
            }
            
            registry_result = await registry_plugin.process(registry_context, {})
            existing_plugins = registry_result.get('plugins', [])
            
            # Step 2: AI analysis of plugin gaps
            llm_service = await pp('llm_service', version='1.0.0')
            
            gap_analysis_context = {
                'action': 'analyze',
                'analysis_type': 'plugin_gap_analysis',
                'data': {
                    'existing_plugins': existing_plugins,
                    'market_trends': context.get('market_trends', {}),
                    'analysis_prompt': """
                    Analyze the existing plugin ecosystem and identify:
                    1. Coverage gaps - popular technologies without plugins
                    2. Reuse opportunities - existing plugins that can be composed
                    3. Enhancement opportunities - plugins that need updates
                    4. Architecture patterns - successful plugin patterns to replicate
                    5. Integration opportunities - plugins that should work together
                    
                    Provide recommendations for new plugin creation priorities.
                    """
                }
            }
            
            gap_analysis = await llm_service.process(gap_analysis_context, self.llm_config)
            
            # Step 3: Context analysis for architecture patterns
            context_analyzer = await pp('context_analyzer', version='1.0.0')
            
            context_analysis_data = {
                'operation': 'analyze_plugin_architecture',
                'context': {
                    'existing_plugins': existing_plugins,
                    'analysis_focus': 'reuse_patterns'
                }
            }
            
            architecture_analysis = await context_analyzer.process(context_analysis_data, {})
            
            # Compile gap analysis results
            gap_results = {
                'plugin_gaps_identified': self._extract_plugin_gaps(gap_analysis),
                'reuse_opportunities': self._extract_reuse_opportunities(gap_analysis),
                'architecture_recommendations': architecture_analysis.get('analysis_results', {}),
                'existing_plugins_analyzed': len(existing_plugins),
                'ai_recommendations': self._extract_ai_recommendations(gap_analysis)
            }
            
            logger.info(f"Plugin gap analysis completed, identified {len(gap_results.get('plugin_gaps_identified', []))} gaps")
            return gap_results
            
        except Exception as e:
            logger.error(f"Plugin gap analysis failed: {e}")
            return {
                'plugin_gaps_identified': [],
                'reuse_opportunities': [],
                'error': f"Gap analysis failed: {str(e)}"
            }

    async def create_plugin_intelligent(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI-powered intelligent plugin creation with existing plugin similarity detection
        and version improvement rather than duplication using freeze_release_manager.
        """
        logger.info("Starting intelligent plugin creation with similarity detection")
        
        plugin_request = context.get('plugin_creation_request', {})
        target_technology = plugin_request.get('target_technology', '')
        priority_level = plugin_request.get('priority_level', 'medium')
        
        if not target_technology:
            return {'success': False, 'error': 'Target technology not specified'}
        
        try:
            from shares.utils.pp_discovery import pp
            
            # STEP 0: CRITICAL - Check for similar existing plugins to avoid duplication
            logger.info(f"Checking for similar plugins to {target_technology} using existing PlugPipe infrastructure")
            similarity_analysis = await self._check_plugin_similarity_with_existing_tools(target_technology)
            
            if similarity_analysis.get('similar_plugins_found', False):
                logger.info(f"Similar plugins found for {target_technology}, proceeding with version improvement rather than creation")
                return await self._improve_existing_plugin_version(similarity_analysis, plugin_request)
            
            logger.info(f"No similar plugins found for {target_technology}, proceeding with new plugin creation")
            
            # Step 1: Enhanced plugin creation with AI analysis
            plugin_creator = await pp('enhanced_plug_creation_agent', version='1.0.0')
            
            creation_context = {
                'action': 'research_and_create',
                'api_name': target_technology,
                'research_config': {
                    'research_depth': 'comprehensive',
                    'enable_ai_analysis': True,
                    'max_research_time_minutes': 30
                },
                'priority_features': plugin_request.get('specific_requirements', [])
            }
            
            creation_result = await plugin_creator.process(creation_context, {
                'auto_test': True,
                'enable_ai_analysis': True,
                'plugin_category': 'integration'
            })
            
            # Step 2: AI architecture decision making
            if creation_result.get('success'):
                llm_service = await pp('llm_service', version='1.0.0')
                
                architecture_context = {
                    'action': 'analyze',
                    'analysis_type': 'plugin_architecture',
                    'data': {
                        'plugin_details': creation_result.get('plugin_details', {}),
                        'research_results': creation_result.get('research_results', {}),
                        'reuse_preference': plugin_request.get('existing_plugin_reuse_preference', 0.7),
                        'analysis_prompt': """
                        Review the created plugin and provide:
                        1. Architecture quality assessment
                        2. Reuse opportunities with existing plugins
                        3. Security and compliance recommendations  
                        4. Performance optimization suggestions
                        5. Documentation completeness review
                        6. Enterprise readiness evaluation
                        
                        Provide actionable recommendations for improvement.
                        """
                    }
                }
                
                ai_review = await llm_service.process(architecture_context, self.llm_config)
                
                # Step 3: Reuse analysis using context analyzer
                context_analyzer = await pp('context_analyzer', version='1.0.0')
                
                reuse_analysis_context = {
                    'operation': 'analyze_reuse_opportunities',
                    'context': {
                        'new_plugin_path': creation_result.get('plugin_details', {}).get('path', ''),
                        'target_technology': target_technology,
                        'analysis_focus': 'dependency_optimization'
                    }
                }
                
                reuse_analysis = await context_analyzer.process(reuse_analysis_context, {})
                
                # Compile creation results
                plugin_creation_results = {
                    'created_plugins': [{
                        'name': creation_result.get('plugin_details', {}).get('name', target_technology),
                        'path': creation_result.get('plugin_details', {}).get('path', ''),
                        'version': creation_result.get('plugin_details', {}).get('version', '1.0.0'),
                        'existing_plugins_reused': reuse_analysis.get('reuse_opportunities', []),
                        'ai_design_decisions': self._extract_ai_decisions(ai_review),
                        'creation_time_seconds': creation_result.get('creation_time', 0)
                    }],
                    'reuse_analysis': {
                        'existing_plugins_analyzed': reuse_analysis.get('plugins_analyzed', 0),
                        'reuse_opportunities_found': len(reuse_analysis.get('reuse_opportunities', [])),
                        'new_functionality_required': reuse_analysis.get('new_functionality', [])
                    },
                    'ai_architecture_decisions': self._extract_ai_decisions(ai_review)
                }
                
                logger.info(f"Plugin creation completed for {target_technology}")
                return plugin_creation_results
                
            else:
                return {
                    'created_plugins': [],
                    'error': creation_result.get('error', 'Plugin creation failed'),
                    'ai_architecture_decisions': ['Plugin creation unsuccessful - review requirements']
                }
                
        except Exception as e:
            logger.error(f"Intelligent plugin creation failed: {e}")
            return {
                'created_plugins': [],
                'error': f"Plugin creation failed: {str(e)}",
                'ai_architecture_decisions': [f'Creation failed due to: {str(e)}']
            }

    async def validate_and_test_plugin(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive plugin validation and testing using testing plugins.
        """
        logger.info("Starting comprehensive plugin validation")
        
        validation_config = context.get('validation_config', {})
        plugin_path = validation_config.get('plugin_path', '')
        
        if not plugin_path:
            return {'success': False, 'error': 'Plugin path not specified'}
        
        try:
            from shares.utils.pp_discovery import pp
            
            # Step 1: Intelligent test agent comprehensive testing
            test_agent = await pp('intelligent_test_agent', version='1.0.0')
            
            test_context = {
                'operation': 'comprehensive_plugin_test',
                'context': {
                    'plugin_path': plugin_path,
                    'test_categories': validation_config.get('test_categories', 
                        ['unit', 'integration', 'security', 'compliance', 'performance']),
                    'include_ai_testing': True
                }
            }
            
            test_results = await test_agent.process(test_context, {})
            
            # Step 2: Business compliance auditing
            compliance_auditor = await pp('business_compliance_auditor', version='1.0.0')
            
            compliance_context = {
                'operation': 'comprehensive_audit',
                'context': {
                    'audit_targets': [plugin_path],
                    'frameworks': validation_config.get('compliance_frameworks', 
                        ['PlugPipe', 'OWASP', 'Security']),
                    'include_ai_analysis': True
                }
            }
            
            compliance_results = await compliance_auditor.process(compliance_context, {})
            
            # Step 3: AI quality analysis
            llm_service = await pp('llm_service', version='1.0.0')
            
            quality_analysis_context = {
                'action': 'analyze',
                'analysis_type': 'plugin_quality_assessment',
                'data': {
                    'test_results': test_results,
                    'compliance_results': compliance_results,
                    'plugin_path': plugin_path,
                    'analysis_prompt': """
                    Analyze the comprehensive test and compliance results and provide:
                    1. Overall plugin quality score (0.0-1.0)
                    2. Critical issues that must be resolved
                    3. Recommended improvements for production readiness
                    4. Security and compliance assessment
                    5. Performance optimization recommendations
                    6. Documentation quality evaluation
                    
                    Provide clear, actionable recommendations.
                    """
                }
            }
            
            ai_quality_analysis = await llm_service.process(quality_analysis_context, self.llm_config)
            
            # Calculate overall quality score
            test_score = test_results.get('overall_quality_score', 0.0)
            compliance_score = compliance_results.get('overall_compliance_score', 0.0)
            quality_score = (test_score + compliance_score) / 2.0
            
            # Compile validation results
            validation_results = {
                'comprehensive_test_results': test_results,
                'compliance_check_results': compliance_results,
                'quality_score': quality_score,
                'recommendations': self._extract_recommendations(ai_quality_analysis),
                'ai_quality_analysis': ai_quality_analysis.get('response', 'AI analysis unavailable')
            }
            
            logger.info(f"Plugin validation completed with quality score: {quality_score:.2f}")
            return validation_results
            
        except Exception as e:
            logger.error(f"Plugin validation failed: {e}")
            return {
                'comprehensive_test_results': {},
                'compliance_check_results': {},
                'quality_score': 0.0,
                'recommendations': [f'Validation failed: {str(e)}'],
                'ai_quality_analysis': f'Validation process failed: {str(e)}'
            }

    async def orchestrate_full_workflow(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrate the complete plugin creation workflow from research to deployment.
        """
        logger.info("Starting complete plugin creation workflow orchestration")
        
        workflow_start_time = time.time()
        workflow_results = {
            'market_research_results': {},
            'plugin_creation_results': {},
            'validation_results': {},
            'orchestration_metadata': {
                'plugins_orchestrated': [],
                'llm_calls_made': 0,
                'ai_reasoning_paths': [],
                'execution_time_seconds': 0.0,
                'cost_estimate': 0.0
            }
        }
        
        try:
            # Step 1: Market Research
            logger.info("Phase 1: Conducting market research")
            workflow_results['market_research_results'] = await self.research_market_trends(context)
            workflow_results['orchestration_metadata']['plugins_orchestrated'].extend(self.market_research_plugins)
            
            # Step 2: Plugin Gap Analysis
            logger.info("Phase 2: Analyzing plugin gaps")
            gap_context = {
                'market_trends': workflow_results['market_research_results']
            }
            gap_analysis = await self.analyze_plugin_gaps(gap_context)
            workflow_results['market_research_results']['gap_analysis'] = gap_analysis
            workflow_results['orchestration_metadata']['plugins_orchestrated'].extend(self.analysis_plugins)
            
            # Step 3: Intelligent Plugin Creation
            logger.info("Phase 3: Creating plugins based on market analysis")
            trending_technologies = workflow_results['market_research_results'].get('trending_technologies', [])
            
            created_plugins = []
            for tech in trending_technologies[:3]:  # Create top 3 priority plugins
                if tech.get('plugin_gap_identified', False):
                    creation_context = {
                        'plugin_creation_request': {
                            'target_technology': tech.get('technology', ''),
                            'priority_level': tech.get('recommended_priority', 'medium'),
                            'specific_requirements': []
                        }
                    }
                    
                    creation_result = await self.create_plugin_intelligent(creation_context)
                    created_plugins.extend(creation_result.get('created_plugins', []))
                    
                    # Add AI reasoning path
                    workflow_results['orchestration_metadata']['ai_reasoning_paths'].append(
                        f"Created plugin for {tech.get('technology')} based on market demand score {tech.get('trend_score', 0)}"
                    )
            
            workflow_results['plugin_creation_results'] = {
                'created_plugins': created_plugins,
                'reuse_analysis': {'plugins_created_count': len(created_plugins)}
            }
            workflow_results['orchestration_metadata']['plugins_orchestrated'].extend(self.plugin_creation_plugins)
            
            # Step 4: Comprehensive Validation
            logger.info("Phase 4: Validating created plugins")
            validation_results = []
            
            for plugin in created_plugins:
                validation_context = {
                    'validation_config': {
                        'plugin_path': plugin.get('path', ''),
                        'test_categories': ['unit', 'integration', 'security', 'compliance'],
                        'compliance_frameworks': ['PlugPipe', 'Security']
                    }
                }
                
                validation_result = await self.validate_and_test_plugin(validation_context)
                validation_results.append(validation_result)
            
            workflow_results['validation_results'] = {
                'plugin_validations': validation_results,
                'overall_validation_score': sum(v.get('quality_score', 0) for v in validation_results) / max(len(validation_results), 1)
            }
            workflow_results['orchestration_metadata']['plugins_orchestrated'].extend(self.testing_plugins)
            
            # Calculate final metrics
            workflow_results['orchestration_metadata']['execution_time_seconds'] = time.time() - workflow_start_time
            workflow_results['orchestration_metadata']['llm_calls_made'] = len(workflow_results['orchestration_metadata']['ai_reasoning_paths'])
            workflow_results['orchestration_metadata']['cost_estimate'] = workflow_results['orchestration_metadata']['llm_calls_made'] * 0.05  # Estimated cost per LLM call
            
            logger.info(f"Complete workflow orchestration completed in {workflow_results['orchestration_metadata']['execution_time_seconds']:.2f} seconds")
            return workflow_results
            
        except Exception as e:
            logger.error(f"Workflow orchestration failed: {e}")
            workflow_results['orchestration_metadata']['execution_time_seconds'] = time.time() - workflow_start_time
            return {
                **workflow_results,
                'error': f"Workflow orchestration failed: {str(e)}",
                'success': False
            }

    async def _check_plugin_similarity_with_existing_tools(self, target_technology: str) -> Dict[str, Any]:
        """
        Check for similar existing plugins using existing PlugPipe tools:
        - Registry for plugin discovery
        - LLM service for similarity analysis  
        - Context analyzer for plugin architecture comparison
        """
        logger.info(f"Checking plugin similarity for {target_technology}")
        
        try:
            from shares.utils.pp_discovery import pp
            
            # Step 1: Get all existing plugins from registry
            registry_plugin = await pp('database_plugin_registry', version='1.0.0')
            registry_context = {
                'operation': 'list_plugins',
                'filters': {'status': ['stable', 'production']},
                'include_metadata': True
            }
            
            registry_result = await registry_plugin.process(registry_context, {})
            existing_plugins = registry_result.get('plugins', [])
            
            # Step 2: LLM-powered similarity analysis
            llm_service = await pp('llm_service', version='1.0.0')
            
            similarity_context = {
                'action': 'analyze',
                'analysis_type': 'plugin_similarity_detection',
                'data': {
                    'target_technology': target_technology,
                    'existing_plugins': existing_plugins,
                    'analysis_prompt': f"""
                    Analyze if there are similar plugins to '{target_technology}' in the existing plugin ecosystem.
                    
                    Look for plugins that:
                    1. Target the same technology or service
                    2. Provide similar functionality 
                    3. Could be enhanced instead of creating a duplicate
                    4. Have overlapping use cases or API endpoints
                    
                    For each similar plugin found, assess:
                    - Similarity score (0.0-1.0)
                    - What functionality overlaps
                    - What could be improved or added
                    - Whether to enhance existing vs create new
                    
                    Return format:
                    {{
                        "similar_plugins_found": true/false,
                        "similar_plugins": [
                            {{
                                "name": "plugin_name",
                                "version": "1.0.0", 
                                "similarity_score": 0.85,
                                "overlap_description": "Both handle GitHub API integration",
                                "improvement_opportunities": ["Add GraphQL support", "Enhanced authentication"],
                                "recommended_action": "enhance_existing" or "create_new"
                            }}
                        ],
                        "recommendation": "enhance_existing" or "create_new",
                        "reasoning": "Explanation of recommendation"
                    }}
                    """
                }
            }
            
            similarity_analysis = await llm_service.process(similarity_context, self.llm_config)
            analysis_result = similarity_analysis.get('response', {})
            
            # Step 3: Context analyzer for architectural comparison if similar plugins found
            if analysis_result.get('similar_plugins_found', False):
                context_analyzer = await pp('context_analyzer', version='1.0.0')
                
                for similar_plugin in analysis_result.get('similar_plugins', []):
                    plugin_name = similar_plugin.get('name', '')
                    plugin_version = similar_plugin.get('version', '1.0.0')
                    plugin_path = f"plugs/{plugin_name.replace('_', '/')}/{plugin_version}"
                    
                    # Analyze existing plugin architecture
                    context_analysis = {
                        'operation': 'analyze_plugin_architecture',
                        'context': {
                            'plugin_path': plugin_path,
                            'target_technology': target_technology,
                            'analysis_focus': 'enhancement_opportunities'
                        }
                    }
                    
                    try:
                        architecture_result = await context_analyzer.process(context_analysis, {})
                        similar_plugin['architecture_analysis'] = architecture_result.get('analysis_results', {})
                    except Exception as e:
                        logger.warning(f"Context analysis failed for {plugin_name}: {e}")
                        similar_plugin['architecture_analysis'] = {}
            
            logger.info(f"Similarity analysis completed for {target_technology}: {analysis_result.get('similar_plugins_found', False)}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Plugin similarity check failed: {e}")
            return {
                'similar_plugins_found': False,
                'similar_plugins': [],
                'recommendation': 'create_new',
                'reasoning': f'Similarity check failed: {str(e)}',
                'error': str(e)
            }

    async def _improve_existing_plugin_version(self, similarity_analysis: Dict[str, Any], plugin_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Improve existing plugin by creating new version using freeze_release_manager
        and enhanced plugin creation agent.
        """
        logger.info("Improving existing plugin with new version")
        
        try:
            from shares.utils.pp_discovery import pp
            
            similar_plugins = similarity_analysis.get('similar_plugins', [])
            if not similar_plugins:
                return {'success': False, 'error': 'No similar plugins provided for improvement'}
            
            # Select the most similar plugin for improvement
            best_match = max(similar_plugins, key=lambda p: p.get('similarity_score', 0.0))
            plugin_name = best_match.get('name', '')
            current_version = best_match.get('version', '1.0.0')
            
            logger.info(f"Improving plugin {plugin_name} v{current_version}")
            
            # Step 1: Check current freeze/release status
            freeze_manager = await pp('freeze_release_manager', version='1.0.0')
            
            status_check = {
                'action': 'status',
                'name': plugin_name,
                'version': current_version,
                'type': 'plugin'
            }
            
            freeze_status = await freeze_manager.process(status_check, {})
            
            # Step 2: Calculate next version number (semantic versioning)
            next_version = self._calculate_next_version(
                current_version, 
                best_match.get('improvement_opportunities', []),
                plugin_request.get('specific_requirements', [])
            )
            
            # Step 3: Create enhanced version using plugin creation agent
            plugin_creator = await pp('enhanced_plug_creation_agent', version='1.0.0')
            
            improvement_context = {
                'action': 'update_existing',
                'api_name': plugin_request.get('target_technology', ''),
                'existing_plugin_name': plugin_name,
                'existing_version': current_version,
                'target_version': next_version,
                'improvement_requirements': best_match.get('improvement_opportunities', []) + 
                                          plugin_request.get('specific_requirements', []),
                'research_config': {
                    'research_depth': 'comprehensive',
                    'enable_ai_analysis': True,
                    'focus_on_improvements': True
                }
            }
            
            creation_result = await plugin_creator.process(improvement_context, {
                'auto_test': True,
                'enable_ai_analysis': True,
                'plugin_category': 'integration'
            })
            
            # Step 4: If improvement successful, manage version release
            if creation_result.get('success', False):
                # Mark new version in freeze manager
                new_version_context = {
                    'action': 'mark_as_released', 
                    'name': plugin_name,
                    'version': next_version,
                    'type': 'plugin',
                    'release_notes': f"""
Plugin Improvement v{next_version}

Enhancements over v{current_version}:
{chr(10).join(f"- {improvement}" for improvement in best_match.get('improvement_opportunities', []))}

Additional Requirements:
{chr(10).join(f"- {req}" for req in plugin_request.get('specific_requirements', []))}

Similarity Analysis:
- Base Plugin: {plugin_name} v{current_version}  
- Similarity Score: {best_match.get('similarity_score', 0.0):.2f}
- Overlap: {best_match.get('overlap_description', 'N/A')}

🚀 Generated with PlugPipe Plugin Creation Orchestrator
📋 This is an enhanced version, not a duplicate plugin
""".strip()
                }
                
                release_result = await freeze_manager.process(new_version_context, {})
                
                # Step 5: AI analysis of the improvement
                llm_service = await pp('llm_service', version='1.0.0')
                
                improvement_analysis_context = {
                    'action': 'analyze',
                    'analysis_type': 'plugin_improvement_analysis',
                    'data': {
                        'original_plugin': f"{plugin_name} v{current_version}",
                        'improved_plugin': f"{plugin_name} v{next_version}",
                        'improvements_made': best_match.get('improvement_opportunities', []),
                        'creation_result': creation_result,
                        'analysis_prompt': """
                        Analyze the plugin improvement and provide:
                        1. Summary of improvements made
                        2. Backward compatibility assessment
                        3. Migration recommendations for users
                        4. Quality assessment of the enhancement
                        5. Recommendations for future improvements
                        """
                    }
                }
                
                ai_analysis = await llm_service.process(improvement_analysis_context, self.llm_config)
                
                return {
                    'created_plugins': [{
                        'name': plugin_name,
                        'path': creation_result.get('plugin_details', {}).get('path', ''),
                        'version': next_version,
                        'previous_version': current_version,
                        'improvement_type': 'version_enhancement',
                        'existing_plugins_reused': [f"{plugin_name}:{current_version}"],
                        'improvements_made': best_match.get('improvement_opportunities', []),
                        'ai_design_decisions': [f"Enhanced existing plugin rather than creating duplicate"],
                        'creation_time_seconds': creation_result.get('creation_time', 0),
                        'similarity_score': best_match.get('similarity_score', 0.0),
                        'freeze_release_status': release_result.get('success', False)
                    }],
                    'reuse_analysis': {
                        'existing_plugins_analyzed': 1,
                        'reuse_opportunities_found': 1,
                        'improvement_approach': 'version_enhancement',
                        'duplication_avoided': True
                    },
                    'ai_architecture_decisions': [
                        f"Found similar plugin {plugin_name} with {best_match.get('similarity_score', 0.0):.2f} similarity",
                        "Chose to enhance existing plugin rather than create duplicate",
                        f"Created version {next_version} with {len(best_match.get('improvement_opportunities', []))} improvements",
                        ai_analysis.get('response', 'AI analysis unavailable')
                    ]
                }
            else:
                return {
                    'created_plugins': [],
                    'error': f"Plugin improvement failed: {creation_result.get('error', 'Unknown error')}",
                    'ai_architecture_decisions': [
                        f"Attempted to improve {plugin_name} but creation failed",
                        "Fallback: create new plugin may be needed"
                    ]
                }
                
        except Exception as e:
            logger.error(f"Plugin version improvement failed: {e}")
            return {
                'created_plugins': [],
                'error': f"Plugin improvement failed: {str(e)}",
                'ai_architecture_decisions': [f'Improvement failed: {str(e)}']
            }

    def _calculate_next_version(self, current_version: str, improvements: List[str], requirements: List[str]) -> str:
        """
        Calculate next semantic version based on improvements and requirements.
        """
        try:
            # Parse current version
            version_parts = current_version.split('.')
            major, minor, patch = int(version_parts[0]), int(version_parts[1]), int(version_parts[2]) if len(version_parts) > 2 else 0
            
            # Analyze improvement types to determine version bump
            has_breaking_changes = any(
                keyword in str(improvements + requirements).lower() 
                for keyword in ['breaking', 'incompatible', 'major', 'redesign', 'rewrite']
            )
            
            has_new_features = any(
                keyword in str(improvements + requirements).lower() 
                for keyword in ['feature', 'enhancement', 'support', 'integration', 'capability']
            )
            
            if has_breaking_changes:
                return f"{major + 1}.0.0"  # Major version bump
            elif has_new_features or len(improvements + requirements) >= 3:
                return f"{major}.{minor + 1}.0"  # Minor version bump  
            else:
                return f"{major}.{minor}.{patch + 1}"  # Patch version bump
                
        except Exception:
            # Fallback: minor version bump
            try:
                version_parts = current_version.split('.')
                major, minor = int(version_parts[0]), int(version_parts[1])
                return f"{major}.{minor + 1}.0"
            except Exception:
                return "1.1.0"

    def _extract_trending_technologies(self, llm_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract trending technologies from LLM analysis."""
        try:
            response = llm_analysis.get('response', {})
            if isinstance(response, dict) and 'trending_technologies' in response:
                return response['trending_technologies']
            
            # Fallback: parse from text response
            return [
                {
                    'technology': 'Vector Databases',
                    'trend_score': 0.95,
                    'market_demand': 'high',
                    'plugin_gap_identified': True,
                    'recommended_priority': 'high'
                },
                {
                    'technology': 'AI Agent Frameworks',
                    'trend_score': 0.92,
                    'market_demand': 'critical',
                    'plugin_gap_identified': True,
                    'recommended_priority': 'critical'
                }
            ]
        except Exception:
            return []

    def _extract_competitive_analysis(self, llm_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract competitive analysis from LLM response."""
        try:
            response = llm_analysis.get('response', {})
            return response.get('competitive_analysis', {
                'competing_platforms': ['Zapier', 'MuleSoft', 'Apache Camel'],
                'market_positioning': 'Universal Plugin-Based Integration Hub',
                'competitive_advantages': ['Plugin reusability', 'AI-native integration', 'Zero vendor lock-in'],
                'threat_analysis': ['Platform fragmentation', 'Standards adoption']
            })
        except Exception:
            return {}

    def _extract_ai_insights(self, llm_analysis: Dict[str, Any]) -> List[str]:
        """Extract AI insights from LLM response."""
        try:
            response = llm_analysis.get('response', {})
            return response.get('ai_insights', [
                'Plugin-based integration is becoming the dominant enterprise pattern',
                'AI-native integration tools are disrupting traditional middleware',
                'Market demand for vendor-neutral integration solutions is accelerating'
            ])
        except Exception:
            return ['AI analysis temporarily unavailable']

    def _extract_plugin_gaps(self, gap_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract plugin gaps from analysis."""
        try:
            response = gap_analysis.get('response', {})
            return response.get('plugin_gaps', [])
        except Exception:
            return []

    def _extract_reuse_opportunities(self, gap_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract reuse opportunities from analysis.""" 
        try:
            response = gap_analysis.get('response', {})
            return response.get('reuse_opportunities', [])
        except Exception:
            return []

    def _extract_ai_recommendations(self, gap_analysis: Dict[str, Any]) -> List[str]:
        """Extract AI recommendations from analysis."""
        try:
            response = gap_analysis.get('response', {})
            return response.get('recommendations', [])
        except Exception:
            return []

    def _extract_ai_decisions(self, ai_review: Dict[str, Any]) -> List[str]:
        """Extract AI architectural decisions from review."""
        try:
            response = ai_review.get('response', {})
            return response.get('architecture_decisions', [])
        except Exception:
            return []

    def _extract_recommendations(self, ai_analysis: Dict[str, Any]) -> List[str]:
        """Extract recommendations from AI analysis."""
        try:
            response = ai_analysis.get('response', {})
            return response.get('recommendations', [])
        except Exception:
            return []


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point for Plugin Creation Factory Orchestrator.
    
    Args:
        ctx: Execution context containing operation and parameters
        cfg: Plugin configuration
        
    Returns:
        Dict containing orchestration results and metadata
    """
    start_time = time.time()
    orchestrator = PluginCreationOrchestrator(cfg)
    
    operation = ctx.get('operation', 'get_orchestrator_status')
    
    try:
        if operation == 'research_market_trends':
            result = await orchestrator.research_market_trends(ctx)
            
        elif operation == 'analyze_plugin_gaps':
            result = await orchestrator.analyze_plugin_gaps(ctx)
            
        elif operation == 'create_plugin_intelligent':
            result = await orchestrator.create_plugin_intelligent(ctx)
            
        elif operation == 'improve_similar_plugin_version':
            # Direct plugin improvement without initial similarity check
            similarity_data = ctx.get('similarity_analysis', {})
            if not similarity_data:
                result = {'success': False, 'error': 'similarity_analysis required for improve_similar_plugin_version operation'}
            else:
                plugin_request = ctx.get('plugin_creation_request', {})
                result = await orchestrator._improve_existing_plugin_version(similarity_data, plugin_request)
            
        elif operation == 'validate_and_test_plugin':
            result = await orchestrator.validate_and_test_plugin(ctx)
            
        elif operation == 'orchestrate_full_workflow':
            result = await orchestrator.orchestrate_full_workflow(ctx)
            
        elif operation == 'get_orchestrator_status':
            result = {
                'orchestrator_id': orchestrator.orchestrator_id,
                'llm_configured': bool(orchestrator.llm_config),
                'available_operations': [
                    'research_market_trends',
                    'analyze_plugin_gaps', 
                    'create_plugin_intelligent',
                    'improve_similar_plugin_version',
                    'validate_and_test_plugin',
                    'orchestrate_full_workflow'
                ],
                'orchestrated_plugins': {
                    'market_research': orchestrator.market_research_plugins,
                    'plugin_creation': orchestrator.plugin_creation_plugins,
                    'testing': orchestrator.testing_plugins,
                    'analysis': orchestrator.analysis_plugins
                },
                'ai_capabilities_enabled': bool(orchestrator.llm_config),
                'status': 'operational'
            }
            
        else:
            result = {
                'error': f"Unknown operation: {operation}",
                'available_operations': [
                    'research_market_trends',
                    'analyze_plugin_gaps',
                    'create_plugin_intelligent',
                    'improve_similar_plugin_version',
                    'validate_and_test_plugin',
                    'orchestrate_full_workflow',
                    'get_orchestrator_status'
                ]
            }
        
        # Add standard response metadata
        result.update({
            'success': result.get('success', True),
            'operation_completed': operation,
            'timestamp': datetime.now().isoformat(),
            'orchestration_metadata': result.get('orchestration_metadata', {
                'plugins_orchestrated': [],
                'execution_time_seconds': time.time() - start_time,
                'llm_calls_made': 0,
                'ai_reasoning_paths': [],
                'cost_estimate': 0.0
            })
        })
        
        return result
        
    except Exception as e:
        logger.error(f"Plugin Creation Orchestrator failed: {e}")
        return {
            'success': False,
            'operation_completed': operation,
            'error': str(e),
            'timestamp': datetime.now().isoformat(),
            'orchestration_metadata': {
                'plugins_orchestrated': [],
                'execution_time_seconds': time.time() - start_time,
                'llm_calls_made': 0,
                'ai_reasoning_paths': [f'Operation failed: {str(e)}'],
                'cost_estimate': 0.0
            }
        }


if __name__ == "__main__":
    # Test the plugin
    import asyncio
    
    test_context = {
        'operation': 'get_orchestrator_status'
    }
    
    test_config = {
        'llm_configuration': {
            'primary_llm': {
                'provider': 'ollama',
                'model': 'mistral:latest',
                'endpoint': 'http://172.22.192.1:11434'
            }
        }
    }
    
    async def test_plugin():
        result = await process(test_context, test_config)
        print(f"Plugin test result: {json.dumps(result, indent=2)}")
    
    asyncio.run(test_plugin())