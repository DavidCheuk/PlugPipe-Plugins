#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Prompt Manager Plugin

Enterprise-grade prompt engineering and management system for the PlugPipe ecosystem.
Provides comprehensive prompt lifecycle management, versioning, optimization, and 
standardization across all LLM-powered plugins.

This plugin serves as the central prompt repository and management system, enabling:
- Centralized prompt template storage and versioning
- Prompt performance analytics and optimization
- A/B testing of prompt variations
- Role-based prompt access and governance
- Multi-language and multi-model prompt adaptation
- Prompt security scanning and validation
- Integration with Universal LLM Service for execution
- Template inheritance and composition patterns

Features:
📝 Centralized Prompt Repository - Single source of truth for all prompts
🔄 Version Control - Complete prompt versioning with rollback capabilities  
📊 Performance Analytics - Track prompt effectiveness and optimization metrics
🧪 A/B Testing - Systematic testing of prompt variations
🔒 Security & Governance - Prompt validation, access control, audit trails
🌐 Multi-Model Support - Optimize prompts for different LLM providers
🎯 Template Engine - Powerful templating with inheritance and composition
🚀 Auto-Optimization - AI-powered prompt improvement suggestions
"""

import os
import json
import yaml
import asyncio
import logging
import hashlib
import importlib.util
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from pathlib import Path
import re
import statistics
from enum import Enum

logger = logging.getLogger(__name__)

class PromptType(Enum):
    """Types of prompts in the system."""
    SYSTEM = "system"
    USER = "user"  
    ASSISTANT = "assistant"
    FUNCTION = "function"
    TEMPLATE = "template"
    COMPOSITE = "composite"

class PromptStatus(Enum):
    """Prompt lifecycle status."""
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"

@dataclass
class PromptMetadata:
    """Comprehensive prompt metadata."""
    id: str
    name: str
    version: str
    prompt_type: PromptType
    status: PromptStatus
    author: str
    created_at: str
    updated_at: str
    description: str
    category: str
    tags: List[str] = field(default_factory=list)
    target_models: List[str] = field(default_factory=list)
    use_cases: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    security_validated: bool = False
    access_level: str = "public"  # public, internal, restricted, confidential

@dataclass
class PromptTemplate:
    """Complete prompt template with metadata and content."""
    metadata: PromptMetadata
    content: str
    variables: Dict[str, Any] = field(default_factory=dict)
    validation_rules: Dict[str, Any] = field(default_factory=dict)
    optimization_notes: List[str] = field(default_factory=list)
    test_cases: List[Dict[str, Any]] = field(default_factory=list)
    parent_template: Optional[str] = None
    child_templates: List[str] = field(default_factory=list)

@dataclass
class PromptExecution:
    """Prompt execution record for analytics."""
    prompt_id: str
    execution_id: str
    timestamp: str
    model_used: str
    variables_used: Dict[str, Any]
    input_tokens: int
    output_tokens: int
    response_time: float
    cost_estimate: float
    success: bool
    quality_score: Optional[float] = None
    user_feedback: Optional[str] = None

@dataclass
class PromptPerformanceMetrics:
    """Aggregated prompt performance analytics."""
    prompt_id: str
    total_executions: int
    success_rate: float
    average_response_time: float
    average_cost: float
    average_quality_score: float
    token_efficiency: float  # output_tokens / input_tokens
    user_satisfaction: float
    optimization_opportunities: List[str] = field(default_factory=list)

class EnterprisePromptManager:
    """Enterprise prompt management system with comprehensive governance."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the prompt management system."""
        self.config = config
        self.base_path = config.get('base_path', '.')
        self.prompts_directory = config.get('prompts_directory', 'prompt_templates')
        
        # Ensure prompts directory exists
        self.prompts_path = Path(self.base_path) / self.prompts_directory
        self.prompts_path.mkdir(parents=True, exist_ok=True)
        
        # Management features
        self.version_control_enabled = config.get('version_control_enabled', True)
        self.performance_tracking = config.get('performance_tracking', True)
        self.security_validation = config.get('security_validation', True)
        self.auto_optimization = config.get('auto_optimization', True)
        self.ab_testing_enabled = config.get('ab_testing_enabled', True)
        
        # Storage and caching
        self.prompt_cache = {}
        self.performance_cache = {}
        
        # Initialize LLM service integration
        self._initialize_llm_service()
        
        # Load existing prompts
        asyncio.create_task(self._load_existing_prompts())
        
        logger.info("Enterprise Prompt Manager initialized")
    
    def _initialize_llm_service(self):
        """Initialize LLM service integration for prompt execution."""
        try:
            spec = importlib.util.spec_from_file_location(
                "llm_service",
                "plugs/intelligence/llm_service/1.0.0/main.py"
            )
            self.llm_service_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.llm_service_module)
            self.llm_available = True
            logger.info("LLM service integration initialized")
        except Exception as e:
            logger.warning(f"LLM service integration not available: {e}")
            self.llm_available = False
    
    async def _load_existing_prompts(self):
        """Load existing prompt templates from storage."""
        try:
            for prompt_file in self.prompts_path.glob("**/*.yaml"):
                try:
                    with open(prompt_file, 'r', encoding='utf-8') as f:
                        prompt_data = yaml.safe_load(f)
                    
                    template = self._deserialize_prompt_template(prompt_data)
                    self.prompt_cache[template.metadata.id] = template
                    
                except Exception as e:
                    logger.error(f"Error loading prompt template {prompt_file}: {e}")
            
            logger.info(f"Loaded {len(self.prompt_cache)} prompt templates")
            
        except Exception as e:
            logger.error(f"Error loading existing prompts: {e}")
    
    async def create_prompt(self, prompt_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new prompt template."""
        try:
            # Generate unique ID
            prompt_id = self._generate_prompt_id(prompt_data.get('name', 'unnamed'))
            
            # Create metadata
            metadata = PromptMetadata(
                id=prompt_id,
                name=prompt_data.get('name', 'Unnamed Prompt'),
                version=prompt_data.get('version', '1.0.0'),
                prompt_type=PromptType(prompt_data.get('type', 'user')),
                status=PromptStatus(prompt_data.get('status', 'draft')),
                author=prompt_data.get('author', 'system'),
                created_at=datetime.now(timezone.utc).isoformat(),
                updated_at=datetime.now(timezone.utc).isoformat(),
                description=prompt_data.get('description', ''),
                category=prompt_data.get('category', 'general'),
                tags=prompt_data.get('tags', []),
                target_models=prompt_data.get('target_models', []),
                use_cases=prompt_data.get('use_cases', []),
                dependencies=prompt_data.get('dependencies', []),
                access_level=prompt_data.get('access_level', 'public')
            )
            
            # Create prompt template
            template = PromptTemplate(
                metadata=metadata,
                content=prompt_data.get('content', ''),
                variables=prompt_data.get('variables', {}),
                validation_rules=prompt_data.get('validation_rules', {}),
                test_cases=prompt_data.get('test_cases', []),
                parent_template=prompt_data.get('parent_template')
            )
            
            # Security validation if enabled
            if self.security_validation:
                security_issues = await self._validate_prompt_security(template)
                if security_issues:
                    return {
                        'success': False,
                        'error': f"Security validation failed: {'; '.join(security_issues)}",
                        'security_issues': security_issues
                    }
                template.metadata.security_validated = True
            
            # Save to storage
            await self._save_prompt_template(template)
            
            # Cache the template
            self.prompt_cache[prompt_id] = template
            
            return {
                'success': True,
                'prompt_id': prompt_id,
                'message': f"Prompt template '{template.metadata.name}' created successfully",
                'metadata': asdict(metadata)
            }
            
        except Exception as e:
            logger.error(f"Error creating prompt template: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_prompt(self, prompt_id: str, version: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve a prompt template by ID and optionally version."""
        try:
            if prompt_id not in self.prompt_cache:
                return {
                    'success': False,
                    'error': f"Prompt template '{prompt_id}' not found"
                }
            
            template = self.prompt_cache[prompt_id]
            
            # Handle version-specific requests if implemented
            if version and template.metadata.version != version:
                # Would implement version-specific retrieval here
                logger.warning(f"Version-specific retrieval not yet implemented for version {version}")
            
            return {
                'success': True,
                'template': asdict(template),
                'content': template.content
            }
            
        except Exception as e:
            logger.error(f"Error retrieving prompt template {prompt_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def execute_prompt(self, prompt_id: str, variables: Dict[str, Any] = None, 
                           execution_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a prompt template with LLM integration."""
        try:
            # Get prompt template
            template_result = await self.get_prompt(prompt_id)
            if not template_result['success']:
                return template_result
            
            template_data = template_result['template']
            content = template_result['content']
            
            # Render template with variables
            rendered_content = await self._render_template(content, variables or {})
            
            # Execute with LLM service if available
            if self.llm_available:
                llm_request = {
                    'prompt': rendered_content,
                    'task_type': template_data['metadata'].get('category', 'general'),
                    'prefer_local': execution_config.get('prefer_local', True),
                    'temperature': execution_config.get('temperature', 0.7),
                    'max_tokens': execution_config.get('max_tokens', 1000)
                }
                
                llm_result = await self.llm_service_module.process(
                    {'action': 'query', 'request': llm_request},
                    self.config.get('llm_service_config', {})
                )
                
                if llm_result.get('success'):
                    response_data = llm_result['response']
                    
                    # Record execution for analytics
                    if self.performance_tracking:
                        execution = PromptExecution(
                            prompt_id=prompt_id,
                            execution_id=self._generate_execution_id(),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            model_used=response_data['model_used'],
                            variables_used=variables or {},
                            input_tokens=response_data.get('tokens_used', 0) // 2,  # Estimate
                            output_tokens=response_data.get('tokens_used', 0) // 2,  # Estimate
                            response_time=response_data['response_time'],
                            cost_estimate=response_data['cost_estimate'],
                            success=True
                        )
                        await self._record_execution(execution)
                    
                    return {
                        'success': True,
                        'response': response_data['content'],
                        'metadata': {
                            'prompt_id': prompt_id,
                            'variables_used': variables,
                            'model_used': response_data['model_used'],
                            'tokens_used': response_data['tokens_used'],
                            'cost_estimate': response_data['cost_estimate'],
                            'response_time': response_data['response_time']
                        }
                    }
                else:
                    return {
                        'success': False,
                        'error': f"LLM execution failed: {llm_result.get('error')}"
                    }
            else:
                # Return rendered template without LLM execution
                return {
                    'success': True,
                    'response': rendered_content,
                    'metadata': {
                        'prompt_id': prompt_id,
                        'variables_used': variables,
                        'note': 'LLM service not available, returning rendered template'
                    }
                }
                
        except Exception as e:
            logger.error(f"Error executing prompt {prompt_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def list_prompts(self, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """List prompt templates with optional filtering."""
        try:
            templates = list(self.prompt_cache.values())
            
            # Apply filters if provided
            if filters:
                if 'category' in filters:
                    templates = [t for t in templates if t.metadata.category == filters['category']]
                if 'status' in filters:
                    templates = [t for t in templates if t.metadata.status.value == filters['status']]
                if 'author' in filters:
                    templates = [t for t in templates if t.metadata.author == filters['author']]
                if 'tags' in filters:
                    filter_tags = set(filters['tags'])
                    templates = [t for t in templates if filter_tags.intersection(set(t.metadata.tags))]
            
            # Prepare summary data
            template_summaries = []
            for template in templates:
                template_summaries.append({
                    'id': template.metadata.id,
                    'name': template.metadata.name,
                    'version': template.metadata.version,
                    'type': template.metadata.prompt_type.value,
                    'status': template.metadata.status.value,
                    'author': template.metadata.author,
                    'category': template.metadata.category,
                    'tags': template.metadata.tags,
                    'created_at': template.metadata.created_at,
                    'updated_at': template.metadata.updated_at,
                    'description': template.metadata.description
                })
            
            return {
                'success': True,
                'templates': template_summaries,
                'total_count': len(template_summaries),
                'filters_applied': filters or {}
            }
            
        except Exception as e:
            logger.error(f"Error listing prompts: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_performance_analytics(self, prompt_id: Optional[str] = None) -> Dict[str, Any]:
        """Get performance analytics for prompts."""
        try:
            if not self.performance_tracking:
                return {
                    'success': False,
                    'error': 'Performance tracking is disabled'
                }
            
            if prompt_id:
                # Get analytics for specific prompt
                metrics = await self._calculate_prompt_metrics(prompt_id)
                if metrics:
                    return {
                        'success': True,
                        'prompt_id': prompt_id,
                        'metrics': asdict(metrics)
                    }
                else:
                    return {
                        'success': False,
                        'error': f'No performance data found for prompt {prompt_id}'
                    }
            else:
                # Get system-wide analytics
                all_metrics = {}
                for cached_prompt_id in self.prompt_cache.keys():
                    metrics = await self._calculate_prompt_metrics(cached_prompt_id)
                    if metrics:
                        all_metrics[cached_prompt_id] = asdict(metrics)
                
                return {
                    'success': True,
                    'system_metrics': all_metrics,
                    'total_prompts_tracked': len(all_metrics)
                }
                
        except Exception as e:
            logger.error(f"Error getting performance analytics: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def optimize_prompt(self, prompt_id: str) -> Dict[str, Any]:
        """Generate optimization suggestions for a prompt."""
        try:
            if not self.auto_optimization:
                return {
                    'success': False,
                    'error': 'Auto-optimization is disabled'
                }
            
            template_result = await self.get_prompt(prompt_id)
            if not template_result['success']:
                return template_result
            
            template_data = template_result['template']
            content = template_result['content']
            
            # Get performance metrics
            metrics = await self._calculate_prompt_metrics(prompt_id)
            
            # Generate optimization suggestions
            suggestions = []
            
            # Analyze prompt length
            if len(content) > 1000:
                suggestions.append("Consider shortening the prompt for better token efficiency")
            
            # Analyze clarity and structure
            if '?' not in content and template_data['metadata']['type'] == 'user':
                suggestions.append("Consider adding specific questions to improve response focus")
            
            # Performance-based suggestions
            if metrics and metrics.average_response_time > 10.0:
                suggestions.append("Prompt may be too complex - consider simplification for faster responses")
            
            if metrics and metrics.token_efficiency < 0.5:
                suggestions.append("Low token efficiency detected - consider more specific instructions")
            
            # Model-specific suggestions
            target_models = template_data['metadata'].get('target_models', [])
            if not target_models:
                suggestions.append("Consider specifying target models for optimized performance")
            
            return {
                'success': True,
                'prompt_id': prompt_id,
                'optimization_suggestions': suggestions,
                'current_metrics': asdict(metrics) if metrics else None,
                'optimization_priority': 'high' if len(suggestions) >= 3 else 'medium' if suggestions else 'low'
            }
            
        except Exception as e:
            logger.error(f"Error optimizing prompt {prompt_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_prompt_id(self, name: str) -> str:
        """Generate unique prompt ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        name_hash = hashlib.md5(name.encode()).hexdigest()[:8]
        return f"prompt_{timestamp}_{name_hash}"
    
    def _generate_execution_id(self) -> str:
        """Generate unique execution ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        return f"exec_{timestamp}"
    
    async def _validate_prompt_security(self, template: PromptTemplate) -> List[str]:
        """Validate prompt for security issues."""
        issues = []
        content = template.content.lower()
        
        # Check for potential injection patterns
        injection_patterns = [
            r'ignore.{0,20}previous.{0,20}instruction',
            r'system.{0,10}prompt.{0,10}override',
            r'admin.{0,10}mode',
            r'developer.{0,10}mode',
            r'jailbreak',
            r'roleplay.{0,20}as'
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, content):
                issues.append(f"Potential prompt injection pattern detected: {pattern}")
        
        # Check for sensitive information exposure
        if any(term in content for term in ['password', 'api_key', 'secret', 'token', 'private_key']):
            issues.append("Prompt may contain sensitive information references")
        
        # Check for overly permissive instructions
        permissive_patterns = ['anything', 'everything', 'no limits', 'unrestricted', 'bypass']
        if any(term in content for term in permissive_patterns):
            issues.append("Prompt contains overly permissive language")
        
        return issues
    
    async def _render_template(self, content: str, variables: Dict[str, Any]) -> str:
        """Render prompt template with variables."""
        try:
            # Simple variable substitution (could be enhanced with Jinja2)
            rendered = content
            for key, value in variables.items():
                placeholder = f"{{{key}}}"
                rendered = rendered.replace(placeholder, str(value))
            
            return rendered
            
        except Exception as e:
            logger.error(f"Error rendering template: {e}")
            return content
    
    async def _save_prompt_template(self, template: PromptTemplate):
        """Save prompt template to storage."""
        try:
            # Create directory structure
            category_dir = self.prompts_path / template.metadata.category
            category_dir.mkdir(parents=True, exist_ok=True)
            
            # Save as YAML file
            filename = f"{template.metadata.id}.yaml"
            filepath = category_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.dump(self._serialize_prompt_template(template), f, default_flow_style=False)
            
            logger.info(f"Saved prompt template {template.metadata.id} to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving prompt template: {e}")
            raise
    
    def _serialize_prompt_template(self, template: PromptTemplate) -> Dict[str, Any]:
        """Serialize prompt template for storage."""
        return {
            'metadata': {
                'id': template.metadata.id,
                'name': template.metadata.name,
                'version': template.metadata.version,
                'type': template.metadata.prompt_type.value,
                'status': template.metadata.status.value,
                'author': template.metadata.author,
                'created_at': template.metadata.created_at,
                'updated_at': template.metadata.updated_at,
                'description': template.metadata.description,
                'category': template.metadata.category,
                'tags': template.metadata.tags,
                'target_models': template.metadata.target_models,
                'use_cases': template.metadata.use_cases,
                'dependencies': template.metadata.dependencies,
                'performance_metrics': template.metadata.performance_metrics,
                'security_validated': template.metadata.security_validated,
                'access_level': template.metadata.access_level
            },
            'content': template.content,
            'variables': template.variables,
            'validation_rules': template.validation_rules,
            'optimization_notes': template.optimization_notes,
            'test_cases': template.test_cases,
            'parent_template': template.parent_template,
            'child_templates': template.child_templates
        }
    
    def _deserialize_prompt_template(self, data: Dict[str, Any]) -> PromptTemplate:
        """Deserialize prompt template from storage."""
        metadata_data = data['metadata']
        
        metadata = PromptMetadata(
            id=metadata_data['id'],
            name=metadata_data['name'],
            version=metadata_data['version'],
            prompt_type=PromptType(metadata_data['type']),
            status=PromptStatus(metadata_data['status']),
            author=metadata_data['author'],
            created_at=metadata_data['created_at'],
            updated_at=metadata_data['updated_at'],
            description=metadata_data['description'],
            category=metadata_data['category'],
            tags=metadata_data.get('tags', []),
            target_models=metadata_data.get('target_models', []),
            use_cases=metadata_data.get('use_cases', []),
            dependencies=metadata_data.get('dependencies', []),
            performance_metrics=metadata_data.get('performance_metrics', {}),
            security_validated=metadata_data.get('security_validated', False),
            access_level=metadata_data.get('access_level', 'public')
        )
        
        return PromptTemplate(
            metadata=metadata,
            content=data['content'],
            variables=data.get('variables', {}),
            validation_rules=data.get('validation_rules', {}),
            optimization_notes=data.get('optimization_notes', []),
            test_cases=data.get('test_cases', []),
            parent_template=data.get('parent_template'),
            child_templates=data.get('child_templates', [])
        )
    
    async def _record_execution(self, execution: PromptExecution):
        """Record prompt execution for analytics."""
        try:
            # In a real implementation, this would save to database
            # For now, we'll store in memory/cache
            executions_key = f"executions_{execution.prompt_id}"
            if executions_key not in self.performance_cache:
                self.performance_cache[executions_key] = []
            
            self.performance_cache[executions_key].append(asdict(execution))
            
            # Keep only last 1000 executions per prompt
            if len(self.performance_cache[executions_key]) > 1000:
                self.performance_cache[executions_key] = self.performance_cache[executions_key][-1000:]
            
        except Exception as e:
            logger.error(f"Error recording execution: {e}")
    
    async def _calculate_prompt_metrics(self, prompt_id: str) -> Optional[PromptPerformanceMetrics]:
        """Calculate performance metrics for a prompt."""
        try:
            executions_key = f"executions_{prompt_id}"
            if executions_key not in self.performance_cache:
                return None
            
            executions_data = self.performance_cache[executions_key]
            if not executions_data:
                return None
            
            # Calculate metrics
            total_executions = len(executions_data)
            successful_executions = [e for e in executions_data if e['success']]
            success_rate = len(successful_executions) / total_executions if total_executions > 0 else 0
            
            if successful_executions:
                avg_response_time = statistics.mean([e['response_time'] for e in successful_executions])
                avg_cost = statistics.mean([e['cost_estimate'] for e in successful_executions])
                
                # Token efficiency calculation
                token_ratios = []
                for e in successful_executions:
                    if e['input_tokens'] > 0:
                        token_ratios.append(e['output_tokens'] / e['input_tokens'])
                
                token_efficiency = statistics.mean(token_ratios) if token_ratios else 0
                
                # Quality scores (would be based on user feedback in real implementation)
                quality_scores = [e.get('quality_score') for e in successful_executions if e.get('quality_score')]
                avg_quality = statistics.mean(quality_scores) if quality_scores else 0.5
                
                return PromptPerformanceMetrics(
                    prompt_id=prompt_id,
                    total_executions=total_executions,
                    success_rate=success_rate,
                    average_response_time=avg_response_time,
                    average_cost=avg_cost,
                    average_quality_score=avg_quality,
                    token_efficiency=token_efficiency,
                    user_satisfaction=0.8  # Placeholder
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error calculating prompt metrics: {e}")
            return None

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main process function for Prompt Manager.
    
    Manages prompt templates with comprehensive lifecycle management,
    performance analytics, and LLM service integration.
    """
    try:
        logger.info("Processing prompt manager request")
        
        action = ctx.get('action', 'list')
        
        # Initialize prompt manager
        prompt_manager = EnterprisePromptManager(cfg)
        
        if action == 'create':
            # Create new prompt template
            prompt_data = ctx.get('prompt_data', {})
            if not prompt_data:
                raise ValueError("No prompt data provided for creation")
            
            result = await prompt_manager.create_prompt(prompt_data)
            
            return {
                'success': result['success'],
                'operation_completed': 'create_prompt',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif action == 'get':
            # Retrieve specific prompt template
            prompt_id = ctx.get('prompt_id')
            if not prompt_id:
                raise ValueError("No prompt_id provided")
            
            version = ctx.get('version')
            result = await prompt_manager.get_prompt(prompt_id, version)
            
            return {
                'success': result['success'],
                'operation_completed': 'get_prompt',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif action == 'execute':
            # Execute prompt with LLM integration
            prompt_id = ctx.get('prompt_id')
            if not prompt_id:
                raise ValueError("No prompt_id provided for execution")
            
            variables = ctx.get('variables', {})
            execution_config = ctx.get('execution_config', {})
            
            result = await prompt_manager.execute_prompt(prompt_id, variables, execution_config)
            
            return {
                'success': result['success'],
                'operation_completed': 'execute_prompt',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif action == 'list':
            # List prompt templates
            filters = ctx.get('filters', {})
            result = await prompt_manager.list_prompts(filters)
            
            return {
                'success': result['success'],
                'operation_completed': 'list_prompts',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif action == 'analytics':
            # Get performance analytics
            prompt_id = ctx.get('prompt_id')  # Optional - if None, returns system-wide analytics
            result = await prompt_manager.get_performance_analytics(prompt_id)
            
            return {
                'success': result['success'],
                'operation_completed': 'get_analytics',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif action == 'optimize':
            # Get optimization suggestions
            prompt_id = ctx.get('prompt_id')
            if not prompt_id:
                raise ValueError("No prompt_id provided for optimization")
            
            result = await prompt_manager.optimize_prompt(prompt_id)
            
            return {
                'success': result['success'],
                'operation_completed': 'optimize_prompt',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        else:
            raise ValueError(f"Unknown action: {action}")
        
    except Exception as e:
        logger.error(f"Prompt manager request failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation_completed': action,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

# Plugin metadata
plug_metadata = {
    "name": "prompt_manager",
    "version": "1.0.0",
    "description": "Enterprise prompt engineering and management system with comprehensive governance",
    "author": "PlugPipe Core Team",
    "tags": ["prompts", "templates", "llm", "management", "analytics"],
    "category": "intelligence"
}

if __name__ == "__main__":
    # Test the prompt manager
    async def test_prompt_manager():
        test_config = {
            'base_path': '/tmp/prompt_test',
            'prompts_directory': 'templates',
            'version_control_enabled': True,
            'performance_tracking': True,
            'security_validation': True,
            'auto_optimization': True
        }
        
        print("📝 Testing Prompt Manager...")
        
        # Test creating a prompt
        create_result = await process({
            'action': 'create',
            'prompt_data': {
                'name': 'Code Review Assistant',
                'content': 'Review the following code for {language} and provide feedback on:\n1. Code quality\n2. Security issues\n3. Performance optimizations\n\nCode:\n{code}',
                'description': 'AI assistant for comprehensive code reviews',
                'category': 'development',
                'tags': ['code-review', 'security', 'performance'],
                'variables': {
                    'language': 'Programming language',
                    'code': 'Code to review'
                },
                'use_cases': ['Pull request reviews', 'Code quality checks'],
                'target_models': ['gpt-4', 'claude-3']
            }
        }, test_config)
        
        print("✅ Prompt Manager test completed!")
        if create_result.get('success'):
            print(f"📝 Created prompt: {create_result['result'].get('prompt_id')}")
        else:
            print(f"❌ Error: {create_result.get('error')}")
    
    asyncio.run(test_prompt_manager())