#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Unified Scaffolding Tool - COMPLETE VERSION
Creates proper PlugPipe unified directory structure following conventions:
- PLUGS: plugs/category/name/version/ directory structure with main.py and plug.yaml
- PIPES: pipes/name/version/ directory structure with pipe.yaml workflow definitions
- Both follow the same namespace and versioning system
- Full SBOM metadata and validation support
"""

import os
import sys
import json
import re
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# Security validation patterns
VALID_NAME_PATTERN = re.compile(r'^[a-z0-9_]+$')
VALID_VERSION_PATTERN = re.compile(r'^\d+\.\d+\.\d+$')
DANGEROUS_PATTERNS = [
    r'\.\.',           # Directory traversal
    r'[;&|`$]',        # Command injection
    r'<script',        # XSS
    r'javascript:',    # JavaScript injection
    r'file://',        # File URI
    r'\\x[0-9a-f]{2}', # Hex encoded chars
]

def validate_input_security(value: str, field_name: str) -> bool:
    """
    Validate input for security issues

    Args:
        value: Input value to validate
        field_name: Name of the field being validated

    Returns:
        bool: True if safe, False if dangerous
    """
    if not value or len(value.strip()) == 0:
        logging.warning(f"Empty {field_name} provided")
        return False

    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            logging.error(f"Dangerous pattern detected in {field_name}: {pattern}")
            return False

    # Check length limits
    if len(value) > 200:
        logging.error(f"{field_name} too long (max 200 chars): {len(value)}")
        return False

    return True

def validate_component_name(name: str) -> bool:
    """
    Validate component name follows security standards

    Args:
        name: Component name to validate

    Returns:
        bool: True if valid, False if invalid
    """
    if not VALID_NAME_PATTERN.match(name):
        logging.error(f"Invalid component name: {name}. Use only lowercase letters, numbers, and underscores")
        return False

    if len(name) < 3:
        logging.error(f"Component name too short: {name}. Minimum 3 characters")
        return False

    if len(name) > 50:
        logging.error(f"Component name too long: {name}. Maximum 50 characters")
        return False

    return True

def validate_version(version: str) -> bool:
    """
    Validate version follows semantic versioning

    Args:
        version: Version string to validate

    Returns:
        bool: True if valid, False if invalid
    """
    if not VALID_VERSION_PATTERN.match(version):
        logging.error(f"Invalid version format: {version}. Use semantic versioning (e.g., 1.0.0)")
        return False

    return True

def sanitize_description(description: str) -> str:
    """
    Sanitize description by removing dangerous content

    Args:
        description: Raw description

    Returns:
        str: Sanitized description
    """
    # Remove HTML/XML tags
    description = re.sub(r'<[^>]+>', '', description)

    # Remove control characters except newlines and tabs
    description = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', description)

    # Limit length
    if len(description) > 500:
        description = description[:497] + "..."
        logging.warning("Description truncated to 500 characters")

    return description.strip()

def validate_category(category: str, component_type: str) -> bool:
    """
    Validate category is from allowed list

    Args:
        category: Category to validate
        component_type: Type of component (plug, pipe, glue)

    Returns:
        bool: True if valid, False if invalid
    """
    allowed_categories = {
        'plug': ['general', 'security', 'processing', 'integration', 'auth', 'governance', 'monitoring', 'core'],
        'pipe': ['workflow', 'etl', 'data_processing', 'automation', 'deployment', 'testing'],
        'glue': ['integration', 'transformation', 'authentication', 'interface']
    }

    if category not in allowed_categories.get(component_type, []):
        logging.error(f"Invalid category '{category}' for {component_type}. Allowed: {allowed_categories.get(component_type, [])}")
        return False

    return True

def secure_path_creation(base_path: str, *path_parts: str) -> Optional[Path]:
    """
    Securely create path preventing directory traversal

    Args:
        base_path: Base directory path
        *path_parts: Path components to join

    Returns:
        Path: Secure path or None if invalid
    """
    try:
        # Resolve base path
        base = Path(base_path).resolve()

        # Join path parts
        target = base
        for part in path_parts:
            # Validate each part
            if '..' in part or '/' in part or '\\' in part:
                logging.error(f"Invalid path component: {part}")
                return None
            target = target / part

        # Ensure target is within base
        target_resolved = target.resolve()
        if not str(target_resolved).startswith(str(base)):
            logging.error(f"Path traversal detected: {target}")
            return None

        return target
    except Exception as e:
        logging.error(f"Path creation error: {e}")
        return None

# Template for main.py
MAIN_PY_TEMPLATE = '''#!/usr/bin/env python3
"""
{name} Plugin for PlugPipe
{description}

Category: {category}
Version: {version}
Owner: {owner}
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

def process(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point following PlugPipe contract.
    
    Args:
        context: Plugin execution context with input_data and configuration
        
    Returns:
        Dict containing plugin results and status
    """
    try:
        # Extract input data from context
        input_data = context.get('input_data', {{}})
        
        # Plugin implementation logic goes here
        result = {{
            'success': True,
            'plugin_name': '{name}',
            'timestamp': datetime.now().isoformat(),
            'message': 'Plugin {name} executed successfully',
            'processed_data': input_data,
            'metadata': {{
                'category': '{category}',
                'version': '{version}',
                'owner': '{owner}'
            }}
        }}
        
        logger.info(f"✅ Plugin {name} completed successfully")
        return result
        
    except Exception as e:
        error_msg = f"Plugin {name} failed: {{str(e)}}"
        logger.error(f"❌ {{error_msg}}")
        return {{
            'success': False,
            'plugin_name': '{name}',
            'timestamp': datetime.now().isoformat(),
            'error': error_msg
        }}

# Plugin metadata following PlugPipe standards
plug_metadata = {{
    "name": "{name}",
    "owner": "{owner}",
    "version": "{version}",
    "status": "experimental",
    "description": "{description}",
    "category": "{category}",
    "input_schema": {{
        "type": "object",
        "properties": {{
            "input_data": {{
                "type": "object",
                "description": "Input data for processing"
            }}
        }},
        "additionalProperties": True
    }},
    "output_schema": {{
        "type": "object",
        "properties": {{
            "success": {{"type": "boolean"}},
            "plugin_name": {{"type": "string"}},
            "timestamp": {{"type": "string"}},
            "message": {{"type": "string"}},
            "processed_data": {{"type": "object"}},
            "metadata": {{"type": "object"}},
            "error": {{"type": "string"}}
        }},
        "required": ["success", "plugin_name", "timestamp"]
    }},
    "config_schema": {{
        "type": "object",
        "properties": {{}},
        "additionalProperties": True
    }},
    "sbom": {{
        "components": [],
        "dependencies": []
    }}
}}

if __name__ == "__main__":
    # Test plugin functionality
    test_context = {{
        'input_data': {{'test': 'data'}}
    }}
    result = process(test_context)
    print("Plugin Test Result:")
    print(json.dumps(result, indent=2, default=str))
'''

# Template for plug.yaml manifest
PLUG_YAML_TEMPLATE = '''name: {name}
owner: {owner}
version: {version}
status: experimental
description: {description}
category: {category}
type: {name}

# Plugin metadata
metadata:
  created_at: "{timestamp}"
  updated_at: "{timestamp}"
  license: MIT
  homepage: https://plugpipe.com/plugins/{category}/{name}
  repository: https://github.com/plugpipe/plugins
  keywords:
    - {category}
    - plugin
    - scaffolded

# Input/Output schemas
input_schema:
  type: object
  properties:
    input_data:
      type: object
      description: Input data for processing
  additionalProperties: true

output_schema:
  type: object
  properties:
    success:
      type: boolean
    plugin_name:
      type: string
    timestamp:
      type: string
    message:
      type: string
    processed_data:
      type: object
    metadata:
      type: object
    error:
      type: string
  required:
    - success
    - plugin_name
    - timestamp

config_schema:
  type: object
  properties: {{}}
  additionalProperties: true

# Plugin capabilities
capabilities:
  - basic_processing
  - standard_plugin_contract
  - json_input_output

# Dependencies (if any)
dependencies:
  python_packages: []

# PlugPipe principles compliance
plugpipe_principles:
  everything_is_plugin: true
  write_once_use_everywhere: true
  no_glue_code: true
  secure_by_design: true
  reuse_not_reinvent: true

# Testing
test_coverage: basic
test_framework: pytest

# Documentation
documentation:
  readme: included
  api_reference: basic
'''

# Template for basic SBOM
SBOM_JSON_TEMPLATE = '''{{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:plugin-{name}-{timestamp}",
  "version": 1,
  "metadata": {{
    "timestamp": "{timestamp}",
    "tools": [
      {{
        "vendor": "PlugPipe",
        "name": "scaffold_plug.py",
        "version": "1.0.0"
      }}
    ],
    "component": {{
      "type": "library",
      "bom-ref": "{name}@{version}",
      "name": "{name}",
      "version": "{version}",
      "description": "{description}",
      "scope": "required"
    }}
  }},
  "components": [],
  "dependencies": [
    {{
      "ref": "{name}@{version}",
      "dependsOn": []
    }}
  ]
}}'''

# Template for glue.yaml transformation specification
GLUE_YAML_TEMPLATE = '''name: {name}
version: {version}
description: {description}
author: {owner}
category: {category}
status: active
source_schema: {source_schema}
target_schema: {target_schema}
created_at: '{timestamp_date}'
updated_at: '{timestamp_date}'
tags:
{tags}

# Transformation mappings
mappings:
  - source_field: "input_data"
    target_field: "processed_data"
    transform: "direct"
    error_policy: "fail"
  - source_field: "metadata"
    target_field: "transformation_metadata"
    transform: "enhance"
    error_policy: "skip"
  - source_field: "context"
    target_field: "execution_context"
    transform: "preserve"
    error_policy: "default"

# Error handling policy
error_policy: {error_policy}

# Transformation configuration
transformation_config:
  preserve_metadata: true
  validate_schemas: true
  log_transformations: true
  retry_on_failure: false

# Glue code implementation details
implementation:
  entry_point: "main.py"
  async_capable: true
  streaming_support: false
  batch_processing: true

# Quality assurance
quality:
  test_coverage_requirement: 80
  schema_validation_required: true
  performance_benchmark: true
  documentation_required: true

# PlugPipe principles compliance
plugpipe_principles:
  everything_is_plugin: true
  write_once_use_everywhere: true
  no_glue_code: false  # This IS glue code, but standardized
  secure_by_design: true
  reuse_not_reinvent: true
'''

# Template for pipe.yaml workflow
PIPE_YAML_TEMPLATE = '''apiVersion: "v1"
kind: PipeSpec
metadata:
  name: {name}
  owner: {owner}
  version: {version}
  tags:
    - pipeline
    - {category}
    - scaffolded
  doc: "{description}"
  created_at: "{timestamp}"
  updated_at: "{timestamp}"

# Pipeline inputs schema
inputs:
  input_data:
    type: object
    description: Input data for pipeline processing
    default: {{}}

# Pipeline workflow definition
pipeline:
  - id: start_step
    uses: {name}_processor
    with:
      operation: "initialize"
      message: "Starting {name} pipeline"
    doc: "Initialize the {name} pipeline"

  - id: process_step
    uses: {name}_processor
    with:
      operation: "process"
      input: "${{{{pipeline.start_step.output}}}}"
    doc: "Main processing step for {name}"
    depends_on: [start_step]

  - id: finalize_step
    uses: {name}_processor
    with:
      operation: "finalize"
      input: "${{{{pipeline.process_step.output}}}}"
    doc: "Finalize {name} pipeline processing"
    depends_on: [process_step]

# Pipeline execution summary
summary:
  format: table
  doc: "{name} pipeline execution summary"
  fields:
    - name: "Pipeline"
      value: "{name}"
    - name: "Status"
      value: "${{{{pipeline.finalize_step.success}}}}"
    - name: "Processing Time"
      value: "${{{{pipeline.execution_time}}}}"

# Pipeline metadata
pipeline_metadata:
  category: {category}
  complexity: basic
  estimated_duration: "< 5 minutes"
  resource_requirements:
    cpu: minimal
    memory: minimal
    disk: minimal

# Plugin dependencies (if using specific plugins)
plugin_dependencies:
  - name: {name}_processor
    version: ">=1.0.0"
    required: true
    description: "Main processing plugin for {name} pipeline"

# PlugPipe principles compliance
plugpipe_principles:
  everything_is_plugin: true
  write_once_use_everywhere: true
  no_glue_code: true
  secure_by_design: true
  reuse_not_reinvent: true

# Testing configuration
testing:
  test_inputs:
    - name: "basic_test"
      input:
        input_data:
          test: "sample data"
      expected_output:
        success: true
        processed: true
        
# Documentation
documentation:
  readme: included
  examples: basic
  troubleshooting: basic
'''

def scaffold_plugin(name: str, owner: str, description: str, category: str = "general", version: str = "1.0.0"):
    """
    Create proper PlugPipe plugin directory structure.
    
    Args:
        name: Plugin name
        owner: Plugin owner
        description: Plugin description
        category: Plugin category (default: general)
        version: Plugin version (default: 1.0.0)
    """
    # Create proper PlugPipe directory structure with security validation
    plugin_path = secure_path_creation(".", "plugs", category, name, version)
    if not plugin_path:
        raise ValueError(f"Invalid path components for plugin: {category}/{name}/{version}")
    plugin_path.mkdir(parents=True, exist_ok=True)
    
    # Create SBOM directory
    sbom_path = plugin_path / "sbom"
    sbom_path.mkdir(exist_ok=True)
    
    # Generate timestamp
    timestamp = datetime.now().isoformat()
    
    # Create main.py
    main_py_path = plugin_path / "main.py"
    with open(main_py_path, 'w') as f:
        f.write(MAIN_PY_TEMPLATE.format(
            name=name,
            owner=owner,
            description=description,
            category=category,
            version=version
        ))
    
    # Create plug.yaml manifest
    plug_yaml_path = plugin_path / "plug.yaml"
    with open(plug_yaml_path, 'w') as f:
        f.write(PLUG_YAML_TEMPLATE.format(
            name=name,
            owner=owner,
            description=description,
            category=category,
            version=version,
            timestamp=timestamp
        ))
    
    # Create basic SBOM
    sbom_json_path = sbom_path / "sbom.json"
    with open(sbom_json_path, 'w') as f:
        f.write(SBOM_JSON_TEMPLATE.format(
            name=name,
            description=description,
            version=version,
            timestamp=timestamp
        ))
    
    # Create lib_sbom.json (empty for scaffolded plugins)
    lib_sbom_path = sbom_path / "lib_sbom.json"
    with open(lib_sbom_path, 'w') as f:
        f.write(json.dumps({
            "libraries": [],
            "generated_at": timestamp,
            "plugin": f"{name}@{version}"
        }, indent=2))
    
    print(f"✅ Scaffolded PlugPipe plugin: {plugin_path}")
    print(f"   📁 Directory: {plugin_path}")
    print(f"   📄 Main module: {main_py_path}")
    print(f"   📋 Manifest: {plug_yaml_path}")
    print(f"   📦 SBOM: {sbom_json_path}")
    print(f"   📚 Library SBOM: {lib_sbom_path}")
    print(f"")
    print(f"🔧 Next steps:")
    print(f"   1. Implement plugin logic in {main_py_path}")
    print(f"   2. Update schemas in {plug_yaml_path}")
    print(f"   3. Generate proper SBOM: ./pp sbom generate {plugin_path}")
    print(f"   4. Validate plugin: ./pp validate plugins")
    print(f"   5. Test plugin functionality")

def scaffold_glue(name: str, owner: str, description: str, category: str = "integration", version: str = "1.0.0",
                  source_schema: str = None, target_schema: str = None):
    """
    Create proper PlugPipe glue (integration code) directory structure.

    Args:
        name: Glue name
        owner: Glue owner
        description: Glue description
        category: Glue category (default: integration)
        version: Glue version (default: 1.0.0)
        source_schema: Source schema name (default: derived from name)
        target_schema: Target schema name (default: derived from name)
    """
    # Default schemas if not provided
    if not source_schema:
        source_schema = f"{name}_input"
    if not target_schema:
        target_schema = f"{name}_output"

    # Create proper PlugPipe glue directory structure with security validation
    glue_path = secure_path_creation(".", "glues", category, name, version)
    if not glue_path:
        raise ValueError(f"Invalid path components for glue: {category}/{name}/{version}")
    glue_path.mkdir(parents=True, exist_ok=True)

    # Create SBOM directory
    sbom_path = glue_path / "sbom"
    sbom_path.mkdir(exist_ok=True)

    # Generate timestamp
    timestamp = datetime.now().isoformat()
    timestamp_date = datetime.now().strftime("%Y-%m-%d")

    # Generate tags for YAML (remove duplicates and ensure unique)
    tags_list = [category, "glue-component", "scaffolded"]
    if category != "transformation":
        tags_list.append("transformation")
    # Remove duplicates while preserving order
    tags_list = list(dict.fromkeys(tags_list))
    tags_yaml = "\n".join([f"- {tag}" for tag in tags_list])

    # Determine error policy based on category
    error_policy_map = {
        "integration": "fail_fast",
        "transformation": "continue_on_error",
        "authentication": "fail_fast",
        "interface": "fail_safe"
    }
    error_policy = error_policy_map.get(category, "continue_on_error")

    # Create glue.yaml transformation specification
    glue_yaml_path = glue_path / "glue.yaml"
    with open(glue_yaml_path, 'w') as f:
        f.write(GLUE_YAML_TEMPLATE.format(
            name=name,
            owner=owner,
            description=description,
            category=category,
            version=version,
            source_schema=source_schema,
            target_schema=target_schema,
            timestamp_date=timestamp_date,
            tags=tags_yaml,
            error_policy=error_policy
        ))

    # Create plug.yaml for dual discoverability
    plug_yaml_path = glue_path / "plug.yaml"
    with open(plug_yaml_path, 'w') as f:
        f.write(PLUG_YAML_TEMPLATE.format(
            name=name,
            owner=owner,
            description=description,
            category=category,
            version=version,
            timestamp=timestamp
        ))

    # Create main.py with glue-specific template
    main_py_path = glue_path / "main.py"
    with open(main_py_path, 'w') as f:
        f.write(MAIN_PY_TEMPLATE.format(
            name=name,
            owner=owner,
            description=description,
            category=category,
            version=version
        ))

    # Create glue-specific SBOM
    sbom_json_path = sbom_path / "sbom.json"
    with open(sbom_json_path, 'w') as f:
        f.write(SBOM_JSON_TEMPLATE.format(
            name=name,
            description=description,
            version=version,
            timestamp=timestamp
        ))

    # Create schema specifications
    source_schema_path = glue_path / f"{source_schema}.json"
    with open(source_schema_path, 'w') as f:
        f.write(json.dumps({
            "type": "object",
            "properties": {
                "input_data": {"type": "object"},
                "metadata": {"type": "object"},
                "context": {"type": "object"}
            },
            "required": ["input_data"],
            "description": f"Source schema for {name} glue transformation"
        }, indent=2))

    target_schema_path = glue_path / f"{target_schema}.json"
    with open(target_schema_path, 'w') as f:
        f.write(json.dumps({
            "type": "object",
            "properties": {
                "processed_data": {"type": "object"},
                "transformation_metadata": {"type": "object"},
                "execution_context": {"type": "object"}
            },
            "required": ["processed_data"],
            "description": f"Target schema for {name} glue transformation"
        }, indent=2))

    print(f"✅ Scaffolded PlugPipe glue: {glue_path}")
    print(f"   📁 Directory: {glue_path}")
    print(f"   🔧 Glue specification: {glue_yaml_path}")
    print(f"   📋 Plugin manifest: {plug_yaml_path}")
    print(f"   📄 Main module: {main_py_path}")
    print(f"   📊 Source schema: {source_schema_path}")
    print(f"   📊 Target schema: {target_schema_path}")
    print(f"   📦 SBOM: {sbom_json_path}")
    print(f"")
    print(f"🔧 Next steps:")
    print(f"   1. Implement transformation logic in {main_py_path}")
    print(f"   2. Update transformation mappings in {glue_yaml_path}")
    print(f"   3. Customize schemas in {source_schema_path} and {target_schema_path}")
    print(f"   4. Test glue functionality: ./pp glue run {name}")
    print(f"   5. Validate dual discoverability: ./pp list | grep {name}")

def scaffold_pipe(name: str, owner: str, description: str, category: str = "workflow", version: str = "1.0.0"):
    """
    Create proper PlugPipe pipe (workflow) directory structure.
    
    Args:
        name: Pipe name
        owner: Pipe owner
        description: Pipe description
        category: Pipe category (default: workflow) 
        version: Pipe version (default: 1.0.0)
    """
    # Create proper PlugPipe pipe directory structure with security validation
    pipe_path = secure_path_creation(".", "pipes", name, version)
    if not pipe_path:
        raise ValueError(f"Invalid path components for pipe: {name}/{version}")
    pipe_path.mkdir(parents=True, exist_ok=True)
    
    # Create SBOM directory (pipes also need SBOM for governance)
    sbom_path = pipe_path / "sbom"
    sbom_path.mkdir(exist_ok=True)
    
    # Generate timestamp
    timestamp = datetime.now().isoformat()
    
    # Create pipe.yaml workflow definition
    pipe_yaml_path = pipe_path / "pipe.yaml"
    with open(pipe_yaml_path, 'w') as f:
        f.write(PIPE_YAML_TEMPLATE.format(
            name=name,
            owner=owner,
            description=description,
            category=category,
            version=version,
            timestamp=timestamp
        ))
    
    # Create basic SBOM for pipe
    sbom_json_path = sbom_path / "sbom.json"
    with open(sbom_json_path, 'w') as f:
        f.write(SBOM_JSON_TEMPLATE.format(
            name=name,
            description=description,
            version=version,
            timestamp=timestamp
        ))
    
    # Create lib_sbom.json (tracks pipeline dependencies)
    lib_sbom_path = sbom_path / "lib_sbom.json"
    with open(lib_sbom_path, 'w') as f:
        f.write(json.dumps({
            "pipeline_dependencies": [f"{name}_processor@>=1.0.0"],
            "plugin_dependencies": [],
            "generated_at": timestamp,
            "pipe": f"{name}@{version}"
        }, indent=2))
    
    print(f"✅ Scaffolded PlugPipe pipe: {pipe_path}")
    print(f"   📁 Directory: {pipe_path}")
    print(f"   🔄 Workflow definition: {pipe_yaml_path}")
    print(f"   📦 SBOM: {sbom_json_path}")
    print(f"   📚 Dependency SBOM: {lib_sbom_path}")
    print(f"")
    print(f"🔧 Next steps:")
    print(f"   1. Customize pipeline steps in {pipe_yaml_path}")
    print(f"   2. Update plugin dependencies as needed")
    print(f"   3. Generate proper SBOM: ./pp sbom generate {pipe_path}")
    print(f"   4. Test pipeline: ./pp run {pipe_path}")
    print(f"   5. Validate pipeline structure")

def main():
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    if len(sys.argv) < 5:
        print("PlugPipe Trinity Scaffolding Tool (Security Hardened)")
        print("Creates proper PlugPipe directory structure following trinity architecture")
        print("")
        print("Usage: python scaffold_plug.py <type> <name> <owner> <description> [category] [version] [options...]")
        print("")
        print("Arguments:")
        print("  type        Scaffold type: 'plug', 'pipe', or 'glue' (required)")
        print("  name        Component name (required, lowercase alphanumeric + underscore)")
        print("  owner       Component owner (required)")
        print("  description Component description (required)")
        print("  category    Component category (default varies by type)")
        print("  version     Component version (default: 1.0.0, semantic versioning)")
        print("")
        print("Additional Glue Options (after version):")
        print("  source_schema  Source schema name (default: name_input)")
        print("  target_schema  Target schema name (default: name_output)")
        print("")
        print("Security Features:")
        print("  ✅ Input validation and sanitization")
        print("  ✅ Directory traversal protection")
        print("  ✅ Command injection prevention")
        print("  ✅ Category whitelist validation")
        print("  ✅ Semantic versioning enforcement")
        print("")
        print("Examples:")
        print("  # Create a plugin")
        print("  python scaffold_plug.py plug my_plugin 'My Team' 'A sample plugin'")
        print("  python scaffold_plug.py plug data_processor 'Data Team' 'Processes data' processing 2.0.0")
        print("")
        print("  # Create a pipeline")
        print("  python scaffold_plug.py pipe my_pipeline 'Workflow Team' 'A sample pipeline'")
        print("  python scaffold_plug.py pipe data_workflow 'Data Team' 'Data processing workflow' etl 1.1.0")
        print("")
        print("  # Create a glue component")
        print("  python scaffold_plug.py glue auth_bridge 'Auth Team' 'OAuth to SAML bridge' authentication")
        print("  python scaffold_plug.py glue api_transformer 'API Team' 'REST to GraphQL transformer' transformation 1.2.0 rest_api graphql_api")
        print("")
        print("Note: Trinity architecture supports plug/pipe/glue with unified namespace and versioning")
        sys.exit(1)
    
    scaffold_type = sys.argv[1].lower()
    name = sys.argv[2]
    owner = sys.argv[3]
    description = sys.argv[4]

    # Set default categories based on type
    default_categories = {
        "plug": "general",
        "pipe": "workflow",
        "glue": "integration"
    }

    category = sys.argv[5] if len(sys.argv) > 5 else default_categories.get(scaffold_type, "general")
    version = sys.argv[6] if len(sys.argv) > 6 else "1.0.0"

    # Additional options for glue
    source_schema = sys.argv[7] if len(sys.argv) > 7 else None
    target_schema = sys.argv[8] if len(sys.argv) > 8 else None

    # 🔒 SECURITY VALIDATION
    print("🔒 Running security validation...")

    # Validate scaffold type
    if scaffold_type not in ["plug", "pipe", "glue"]:
        print("❌ Security Error: Invalid scaffold type. Must be 'plug', 'pipe', or 'glue'")
        sys.exit(1)

    # Validate component name
    if not validate_component_name(name):
        print("❌ Security Error: Invalid component name")
        sys.exit(1)

    # Validate owner
    if not validate_input_security(owner, "owner"):
        print("❌ Security Error: Invalid owner")
        sys.exit(1)

    # Sanitize description
    original_description = description
    description = sanitize_description(description)
    if description != original_description:
        print(f"⚠️  Description was sanitized for security")

    # Validate description
    if not validate_input_security(description, "description"):
        print("❌ Security Error: Invalid description")
        sys.exit(1)

    # Validate category
    if not validate_category(category, scaffold_type):
        print("❌ Security Error: Invalid category")
        sys.exit(1)

    # Validate version
    if not validate_version(version):
        print("❌ Security Error: Invalid version format")
        sys.exit(1)

    # Validate schema names for glue
    if scaffold_type == "glue":
        if source_schema and not validate_component_name(source_schema):
            print("❌ Security Error: Invalid source schema name")
            sys.exit(1)
        if target_schema and not validate_component_name(target_schema):
            print("❌ Security Error: Invalid target schema name")
            sys.exit(1)

    print("✅ Security validation passed")

    # Create the appropriate component
    if scaffold_type == "plug":
        scaffold_plugin(name, owner, description, category, version)
    elif scaffold_type == "pipe":
        scaffold_pipe(name, owner, description, category, version)
    elif scaffold_type == "glue":
        scaffold_glue(name, owner, description, category, version, source_schema, target_schema)
    
    print(f"")
    print(f"🎯 PlugPipe Trinity Architecture:")
    print(f"   All components (plug/pipe/glue) follow unified namespace and versioning")
    if scaffold_type == "plug":
        print(f"   📦 Plugin: plugs/{category}/{name}/{version}/")
    elif scaffold_type == "pipe":
        print(f"   🔄 Pipeline: pipes/{name}/{version}/")
    elif scaffold_type == "glue":
        print(f"   🔧 Glue: glues/{category}/{name}/{version}/")
        print(f"   🔄 Transformation: {source_schema or f'{name}_input'} → {target_schema or f'{name}_output'}")
    print(f"   📦 All components include SBOM metadata and validation support")
    print(f"   🔍 Glue components have dual discoverability (plugin + glue registries)")

if __name__ == "__main__":
    main()