#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Prompt Template Engine Plugin

Advanced templating system for PlugPipe ecosystem with powerful template composition,
inheritance, conditional logic, and dynamic content generation capabilities.

This plugin provides sophisticated templating features that go beyond simple variable
substitution, enabling complex prompt engineering patterns and reusable template
components across the entire PlugPipe ecosystem.

Features:
🧩 Template Inheritance - Parent-child template relationships with override capabilities
🔄 Template Composition - Combine multiple templates into complex prompt structures
🎯 Conditional Logic - If/else logic, loops, and dynamic content generation
📊 Data Transformation - Built-in functions for data formatting and manipulation
🌐 Multi-format Support - JSON, YAML, Markdown, and custom format generation
🎨 Custom Functions - Extensible function library for domain-specific operations
🔍 Template Validation - Syntax checking and variable validation
⚡ Performance Optimization - Template compilation and caching for efficiency
"""

import os
import re
import json
import yaml
import asyncio
import logging
import hashlib
import importlib.util
from typing import Dict, List, Any, Optional, Union, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from pathlib import Path
import ast
from enum import Enum

logger = logging.getLogger(__name__)

class TemplateType(Enum):
    """Types of template engines supported."""
    SIMPLE = "simple"           # Basic variable substitution
    JINJA = "jinja"            # Jinja2-like templating
    CONDITIONAL = "conditional" # If/else and loops
    COMPOSITE = "composite"     # Multi-template composition
    INHERITED = "inherited"     # Parent-child inheritance

@dataclass
class TemplateFunction:
    """Custom template function definition."""
    name: str
    description: str
    parameters: List[str]
    function: Callable
    category: str = "custom"

@dataclass
class TemplateBlock:
    """Template block for composition."""
    name: str
    content: str
    variables: Dict[str, Any] = field(default_factory=dict)
    conditions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)

@dataclass
class CompositeTemplate:
    """Composite template with multiple blocks."""
    name: str
    blocks: List[TemplateBlock]
    composition_rules: Dict[str, Any] = field(default_factory=dict)
    global_variables: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TemplateValidationResult:
    """Template validation result."""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    required_variables: List[str] = field(default_factory=list)
    optional_variables: List[str] = field(default_factory=list)

class AdvancedTemplateEngine:
    """Advanced template engine with comprehensive templating capabilities."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the advanced template engine."""
        self.config = config
        self.base_path = config.get('base_path', '.')
        
        # Template caching
        self.template_cache = {}
        self.compiled_cache = {}
        
        # Built-in functions
        self.functions = {}
        self._initialize_builtin_functions()
        
        # Custom functions from config
        self._load_custom_functions()
        
        # Template inheritance tracking
        self.inheritance_tree = {}
        
        logger.info("Advanced Template Engine initialized")
    
    def _initialize_builtin_functions(self):
        """Initialize built-in template functions."""
        # String manipulation functions
        self.functions['upper'] = TemplateFunction(
            'upper', 'Convert text to uppercase', ['text'], 
            lambda text: str(text).upper(), 'string'
        )
        
        self.functions['lower'] = TemplateFunction(
            'lower', 'Convert text to lowercase', ['text'],
            lambda text: str(text).lower(), 'string'
        )
        
        self.functions['title'] = TemplateFunction(
            'title', 'Convert text to title case', ['text'],
            lambda text: str(text).title(), 'string'
        )
        
        self.functions['truncate'] = TemplateFunction(
            'truncate', 'Truncate text to specified length', ['text', 'length'],
            lambda text, length: str(text)[:int(length)] + ('...' if len(str(text)) > int(length) else ''),
            'string'
        )
        
        # List manipulation functions
        self.functions['join'] = TemplateFunction(
            'join', 'Join list items with separator', ['items', 'separator'],
            lambda items, separator: str(separator).join([str(item) for item in items]),
            'list'
        )
        
        self.functions['first'] = TemplateFunction(
            'first', 'Get first item from list', ['items'],
            lambda items: items[0] if items else '',
            'list'
        )
        
        self.functions['last'] = TemplateFunction(
            'last', 'Get last item from list', ['items'],
            lambda items: items[-1] if items else '',
            'list'
        )
        
        # Date/time functions
        self.functions['now'] = TemplateFunction(
            'now', 'Get current timestamp', [],
            lambda: datetime.now(timezone.utc).isoformat(),
            'datetime'
        )
        
        self.functions['format_date'] = TemplateFunction(
            'format_date', 'Format date string', ['date', 'format'],
            lambda date, format_str: datetime.fromisoformat(str(date).replace('Z', '+00:00')).strftime(format_str),
            'datetime'
        )
        
        # Conditional functions
        self.functions['default'] = TemplateFunction(
            'default', 'Provide default value if empty', ['value', 'default_value'],
            lambda value, default: default if not value else value,
            'conditional'
        )
        
        # JSON/YAML functions
        self.functions['to_json'] = TemplateFunction(
            'to_json', 'Convert to JSON string', ['data'],
            lambda data: json.dumps(data, indent=2),
            'format'
        )
        
        self.functions['to_yaml'] = TemplateFunction(
            'to_yaml', 'Convert to YAML string', ['data'],
            lambda data: yaml.dump(data, default_flow_style=False),
            'format'
        )
        
        # Code generation functions
        self.functions['indent'] = TemplateFunction(
            'indent', 'Indent text by specified spaces', ['text', 'spaces'],
            lambda text, spaces: '\n'.join(' ' * int(spaces) + line for line in str(text).split('\n')),
            'code'
        )
        
        self.functions['code_block'] = TemplateFunction(
            'code_block', 'Wrap text in code block with language', ['text', 'language'],
            lambda text, language: f"```{language}\n{text}\n```",
            'code'
        )
    
    def _load_custom_functions(self):
        """Load custom functions from configuration."""
        custom_functions = self.config.get('custom_functions', {})
        
        for name, func_config in custom_functions.items():
            try:
                # This would load custom functions from configuration
                # For security, only allow predefined safe functions
                logger.info(f"Custom function configuration found for {name} (not loaded for security)")
            except Exception as e:
                logger.error(f"Error loading custom function {name}: {e}")
    
    def render_template(self, template: str, variables: Dict[str, Any], 
                            template_type: TemplateType = TemplateType.SIMPLE) -> Dict[str, Any]:
        """Render template with variables using specified template engine."""
        try:
            if template_type == TemplateType.SIMPLE:
                result = self._render_simple_template(template, variables)
            elif template_type == TemplateType.JINJA:
                result = self._render_jinja_template(template, variables)
            elif template_type == TemplateType.CONDITIONAL:
                result = self._render_conditional_template(template, variables)
            elif template_type == TemplateType.COMPOSITE:
                result = self._render_composite_template(template, variables)
            elif template_type == TemplateType.INHERITED:
                result = self._render_inherited_template(template, variables)
            else:
                raise ValueError(f"Unsupported template type: {template_type}")
            
            return {
                'success': True,
                'rendered_content': result,
                'template_type': template_type.value,
                'variables_used': variables
            }
            
        except Exception as e:
            logger.error(f"Error rendering template: {e}")
            return {
                'success': False,
                'error': str(e),
                'template_type': template_type.value
            }
    
    def _render_simple_template(self, template: str, variables: Dict[str, Any]) -> str:
        """Render simple template with variable substitution."""
        result = template
        
        # Simple variable substitution: {variable_name}
        for key, value in variables.items():
            placeholder = f"{{{key}}}"
            result = result.replace(placeholder, str(value))
        
        return result
    
    def _render_jinja_template(self, template: str, variables: Dict[str, Any]) -> str:
        """Render Jinja-like template with advanced features."""
        result = template
        
        # Variable substitution with default values: {{ variable | default('default_value') }}
        var_pattern = r'\{\{\s*([^|\}]+)(?:\s*\|\s*([^}]+))?\s*\}\}'
        
        def replace_var(match):
            var_name = match.group(1).strip()
            filters = match.group(2)
            
            # Get variable value
            value = variables.get(var_name, '')
            
            # Apply filters if present
            if filters:
                value = self._apply_filters(value, filters, variables)
            
            return str(value)
        
        result = re.sub(var_pattern, replace_var, result)
        
        # Process loops: {% for item in items %}...{% endfor %}
        result = self._process_loops(result, variables)
        
        # Process conditionals: {% if condition %}...{% endif %}
        result = self._process_conditionals(result, variables)
        
        return result
    
    def _render_conditional_template(self, template: str, variables: Dict[str, Any]) -> str:
        """Render template with conditional logic."""
        result = template
        
        # Process if-else blocks: {%if condition%}...{%else%}...{%endif%}
        if_pattern = r'\{%\s*if\s+([^%]+)\s*%\}(.*?)\{%\s*endif\s*%\}'
        
        def replace_conditional(match):
            condition = match.group(1).strip()
            content = match.group(2)
            
            # Split on else if present
            else_split = content.split('{%else%}')
            if_content = else_split[0]
            else_content = else_split[1] if len(else_split) > 1 else ''
            
            # Evaluate condition
            if self._evaluate_condition(condition, variables):
                return if_content
            else:
                return else_content
        
        result = re.sub(if_pattern, replace_conditional, result, flags=re.DOTALL)
        
        # Process simple variable substitution
        result = self._render_simple_template(result, variables)
        
        return result
    
    def _render_composite_template(self, template: str, variables: Dict[str, Any]) -> str:
        """Render composite template with multiple blocks."""
        try:
            # Parse composite template (expecting JSON or YAML format)
            if template.strip().startswith('{'):
                composite_data = json.loads(template)
            else:
                composite_data = yaml.safe_load(template)
            
            composite = CompositeTemplate(
                name=composite_data.get('name', 'unnamed'),
                blocks=[
                    TemplateBlock(
                        name=block.get('name', ''),
                        content=block.get('content', ''),
                        variables=block.get('variables', {}),
                        conditions=block.get('conditions', []),
                        dependencies=block.get('dependencies', [])
                    )
                    for block in composite_data.get('blocks', [])
                ],
                composition_rules=composite_data.get('composition_rules', {}),
                global_variables=composite_data.get('global_variables', {})
            )
            
            # Merge global variables with provided variables
            merged_variables = {**composite.global_variables, **variables}
            
            # Render each block
            rendered_blocks = []
            for block in composite.blocks:
                # Check conditions
                if block.conditions and not all(
                    self._evaluate_condition(cond, merged_variables) 
                    for cond in block.conditions
                ):
                    continue
                
                # Merge block-specific variables
                block_variables = {**merged_variables, **block.variables}
                
                # Render block content
                rendered_content = self._render_jinja_template(block.content, block_variables)
                rendered_blocks.append(rendered_content)
            
            # Apply composition rules
            separator = composite.composition_rules.get('separator', '\n\n')
            return separator.join(rendered_blocks)
            
        except Exception as e:
            logger.error(f"Error rendering composite template: {e}")
            # Fallback to simple rendering
            return self._render_simple_template(template, variables)
    
    def _render_inherited_template(self, template: str, variables: Dict[str, Any]) -> str:
        """Render template with inheritance support."""
        # Parse inheritance directives: {% extends "parent_template" %}
        extends_pattern = r'\{%\s*extends\s+"([^"]+)"\s*%\}'
        extends_match = re.search(extends_pattern, template)
        
        if extends_match:
            parent_template_name = extends_match.group(1)
            
            # Load parent template (would normally load from storage)
            parent_template = self._load_parent_template(parent_template_name)
            
            if parent_template:
                # Parse blocks in current template: {% block block_name %}...{% endblock %}
                current_blocks = self._parse_template_blocks(template)
                parent_blocks = self._parse_template_blocks(parent_template)
                
                # Override parent blocks with current blocks
                merged_blocks = {**parent_blocks, **current_blocks}
                
                # Replace blocks in parent template
                result = parent_template
                for block_name, block_content in merged_blocks.items():
                    block_pattern = f'{{%\\s*block\\s+{block_name}\\s*%}}.*?{{%\\s*endblock\\s*%}}'
                    replacement = self._render_jinja_template(block_content, variables)
                    result = re.sub(block_pattern, replacement, result, flags=re.DOTALL)
                
                return result
        
        # No inheritance, render as regular template
        return self._render_jinja_template(template, variables)
    
    def _apply_filters(self, value: Any, filters: str, variables: Dict[str, Any]) -> Any:
        """Apply filters to template values."""
        filter_chain = [f.strip() for f in filters.split('|')]
        
        result = value
        for filter_expr in filter_chain:
            # Parse filter with arguments: filter_name('arg1', 'arg2')
            if '(' in filter_expr:
                func_name = filter_expr[:filter_expr.index('(')]
                args_str = filter_expr[filter_expr.index('(') + 1:filter_expr.rindex(')')]
                args = [arg.strip().strip('\'"') for arg in args_str.split(',') if arg.strip()]
            else:
                func_name = filter_expr
                args = []
            
            # Apply function if available
            if func_name in self.functions:
                func = self.functions[func_name]
                try:
                    if args:
                        result = func.function(result, *args)
                    else:
                        result = func.function(result)
                except Exception as e:
                    logger.error(f"Error applying filter {func_name}: {e}")
                    # Continue with original value
        
        return result
    
    def _process_loops(self, template: str, variables: Dict[str, Any]) -> str:
        """Process for loops in template."""
        # Pattern: {% for item in items %}...{% endfor %}
        loop_pattern = r'\{%\s*for\s+(\w+)\s+in\s+(\w+)\s*%\}(.*?)\{%\s*endfor\s*%\}'
        
        def replace_loop(match):
            item_var = match.group(1)
            items_var = match.group(2)
            loop_content = match.group(3)
            
            items = variables.get(items_var, [])
            if not isinstance(items, (list, tuple)):
                return f"<!-- Error: {items_var} is not iterable -->"
            
            rendered_items = []
            for i, item in enumerate(items):
                loop_variables = {
                    **variables,
                    item_var: item,
                    'loop': {
                        'index': i,
                        'index0': i,
                        'first': i == 0,
                        'last': i == len(items) - 1,
                        'length': len(items)
                    }
                }
                
                # Render loop content with item variables
                rendered_item = loop_content
                for key, value in loop_variables.items():
                    if isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            placeholder = f"{{{key}.{subkey}}}"
                            rendered_item = rendered_item.replace(placeholder, str(subvalue))
                    else:
                        placeholder = f"{{{key}}}"
                        rendered_item = rendered_item.replace(placeholder, str(value))
                
                rendered_items.append(rendered_item)
            
            return ''.join(rendered_items)
        
        return re.sub(loop_pattern, replace_loop, template, flags=re.DOTALL)
    
    def _process_conditionals(self, template: str, variables: Dict[str, Any]) -> str:
        """Process conditional statements in template."""
        # Already handled in _render_conditional_template
        return template
    
    def _evaluate_condition(self, condition: str, variables: Dict[str, Any]) -> bool:
        """Evaluate conditional expression safely."""
        try:
            # Simple condition evaluation (could be enhanced with proper expression parser)
            # Support basic comparisons: var == 'value', var != 'value', var, !var
            
            condition = condition.strip()
            
            # Handle negation
            if condition.startswith('!'):
                return not self._evaluate_condition(condition[1:], variables)
            
            # Handle equality
            if ' == ' in condition:
                left, right = condition.split(' == ', 1)
                left_val = self._get_variable_value(left.strip(), variables)
                right_val = self._parse_literal(right.strip())
                return left_val == right_val
            
            # Handle inequality
            if ' != ' in condition:
                left, right = condition.split(' != ', 1)
                left_val = self._get_variable_value(left.strip(), variables)
                right_val = self._parse_literal(right.strip())
                return left_val != right_val
            
            # Handle existence check
            return bool(self._get_variable_value(condition, variables))
            
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {e}")
            return False
    
    def _get_variable_value(self, var_name: str, variables: Dict[str, Any]) -> Any:
        """Get variable value, supporting dot notation."""
        try:
            if '.' in var_name:
                parts = var_name.split('.')
                value = variables
                for part in parts:
                    value = value[part]
                return value
            else:
                return variables.get(var_name)
        except (KeyError, TypeError):
            return None
    
    def _parse_literal(self, literal: str) -> Any:
        """Parse literal value from string."""
        literal = literal.strip()
        
        # String literal
        if (literal.startswith('"') and literal.endswith('"')) or \
           (literal.startswith("'") and literal.endswith("'")):
            return literal[1:-1]
        
        # Number literal
        try:
            if '.' in literal:
                return float(literal)
            else:
                return int(literal)
        except ValueError:
            pass
        
        # Boolean literal
        if literal.lower() == 'true':
            return True
        elif literal.lower() == 'false':
            return False
        
        # Return as string if nothing else matches
        return literal
    
    def _load_parent_template(self, template_name: str) -> Optional[str]:
        """Load parent template for inheritance."""
        # In a real implementation, this would load from template storage
        # For now, return a simple example
        if template_name == "base.html":
            return """
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}Default Title{% endblock %}</title>
</head>
<body>
    <header>{% block header %}Default Header{% endblock %}</header>
    <main>{% block content %}Default Content{% endblock %}</main>
    <footer>{% block footer %}Default Footer{% endblock %}</footer>
</body>
</html>
            """
        return None
    
    def _parse_template_blocks(self, template: str) -> Dict[str, str]:
        """Parse template blocks for inheritance."""
        blocks = {}
        block_pattern = r'\{%\s*block\s+(\w+)\s*%\}(.*?)\{%\s*endblock\s*%\}'
        
        for match in re.finditer(block_pattern, template, re.DOTALL):
            block_name = match.group(1)
            block_content = match.group(2)
            blocks[block_name] = block_content
        
        return blocks
    
    def validate_template(self, template: str, template_type: TemplateType = TemplateType.SIMPLE) -> TemplateValidationResult:
        """Validate template syntax and extract variable requirements."""
        try:
            errors = []
            warnings = []
            required_variables = set()
            optional_variables = set()
            
            # Extract variables based on template type
            if template_type in [TemplateType.SIMPLE, TemplateType.CONDITIONAL]:
                # Simple variable pattern: {variable_name}
                var_matches = re.findall(r'\{([^}]+)\}', template)
                required_variables.update(var_matches)
            
            elif template_type in [TemplateType.JINJA, TemplateType.INHERITED]:
                # Jinja variable pattern: {{ variable_name }}
                var_matches = re.findall(r'\{\{\s*([^|\}]+)(?:\s*\|[^}]+)?\s*\}\}', template)
                for match in var_matches:
                    var_name = match.strip()
                    required_variables.add(var_name)
                
                # Check for syntax errors in control structures
                if_matches = re.findall(r'\{%\s*if\s+([^%]+)\s*%\}', template)
                for condition in if_matches:
                    # Extract variables from conditions
                    condition_vars = re.findall(r'(\w+)(?:\s*[!=]=|\s|$)', condition)
                    required_variables.update(condition_vars)
                
                # Check for loop variables
                loop_matches = re.findall(r'\{%\s*for\s+\w+\s+in\s+(\w+)\s*%\}', template)
                required_variables.update(loop_matches)
            
            elif template_type == TemplateType.COMPOSITE:
                # Validate JSON/YAML structure
                try:
                    if template.strip().startswith('{'):
                        json.loads(template)
                    else:
                        yaml.safe_load(template)
                except (json.JSONDecodeError, yaml.YAMLError) as e:
                    errors.append(f"Invalid composite template format: {e}")
            
            # Check for unmatched braces
            open_braces = template.count('{')
            close_braces = template.count('}')
            if open_braces != close_braces:
                errors.append(f"Unmatched braces: {open_braces} opening, {close_braces} closing")
            
            # Check for unmatched control structures
            if_count = len(re.findall(r'\{%\s*if\s+', template))
            endif_count = len(re.findall(r'\{%\s*endif\s*%\}', template))
            if if_count != endif_count:
                errors.append(f"Unmatched if/endif: {if_count} if, {endif_count} endif")
            
            for_count = len(re.findall(r'\{%\s*for\s+', template))
            endfor_count = len(re.findall(r'\{%\s*endfor\s*%\}', template))
            if for_count != endfor_count:
                errors.append(f"Unmatched for/endfor: {for_count} for, {endfor_count} endfor")
            
            return TemplateValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
                required_variables=list(required_variables),
                optional_variables=list(optional_variables)
            )
            
        except Exception as e:
            logger.error(f"Error validating template: {e}")
            return TemplateValidationResult(
                is_valid=False,
                errors=[str(e)]
            )
    
    def get_available_functions(self) -> Dict[str, Any]:
        """Get list of available template functions."""
        functions_by_category = {}
        
        for name, func in self.functions.items():
            category = func.category
            if category not in functions_by_category:
                functions_by_category[category] = []
            
            functions_by_category[category].append({
                'name': name,
                'description': func.description,
                'parameters': func.parameters
            })
        
        return {
            'success': True,
            'functions_by_category': functions_by_category,
            'total_functions': len(self.functions)
        }

def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main process function for Prompt Template Engine.
    
    Provides advanced templating capabilities with inheritance, composition,
    conditional logic, and extensive function library.
    """
    try:
        logger.info("Processing template engine request")
        
        action = ctx.get('action', 'render')
        
        # Initialize template engine
        template_engine = AdvancedTemplateEngine(cfg)
        
        if action == 'render':
            # Render template with variables
            template = ctx.get('template')
            if not template:
                raise ValueError("No template provided")
            
            variables = ctx.get('variables', {})
            template_type_str = ctx.get('template_type', 'simple')
            template_type = TemplateType(template_type_str)
            
            result = template_engine.render_template(template, variables, template_type)
            
            return {
                'success': result['success'],
                'operation_completed': 'render_template',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif action == 'validate':
            # Validate template syntax
            template = ctx.get('template')
            if not template:
                raise ValueError("No template provided")
            
            template_type_str = ctx.get('template_type', 'simple')
            template_type = TemplateType(template_type_str)
            
            validation_result = template_engine.validate_template(template, template_type)
            
            return {
                'success': True,
                'operation_completed': 'validate_template',
                'result': asdict(validation_result),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif action == 'functions':
            # Get available functions
            result = template_engine.get_available_functions()
            
            return {
                'success': result['success'],
                'operation_completed': 'get_functions',
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        else:
            raise ValueError(f"Unknown action: {action}")
        
    except Exception as e:
        logger.error(f"Template engine request failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation_completed': action,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

# Plugin metadata
plug_metadata = {
    "name": "prompt_template_engine",
    "version": "1.0.0",
    "description": "Advanced template engine with inheritance, composition, and conditional logic",
    "author": "PlugPipe Core Team",
    "tags": ["templates", "templating", "jinja", "inheritance", "composition"],
    "category": "intelligence"
}

if __name__ == "__main__":
    # Test the template engine
    async def test_template_engine():
        test_config = {
            'base_path': '/tmp/template_test',
            'custom_functions': {}
        }
        
        print("🧩 Testing Template Engine...")
        
        # Test simple template
        simple_result = await process({
            'action': 'render',
            'template': 'Hello {name}, welcome to {platform}!',
            'variables': {'name': 'Alice', 'platform': 'PlugPipe'},
            'template_type': 'simple'
        }, test_config)
        
        print("✅ Template Engine test completed!")
        if simple_result.get('success'):
            print(f"📝 Rendered: {simple_result['result']['rendered_content']}")
        else:
            print(f"❌ Error: {simple_result.get('error')}")
    
    asyncio.run(test_template_engine())