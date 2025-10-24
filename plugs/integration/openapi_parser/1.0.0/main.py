#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
OpenAPI Parser Plugin - Reusable OpenAPI/Swagger Specification Parser

Leverages proven JSON Schema validation and OpenAPI tools to parse, validate,
and extract information from OpenAPI specifications. Follows the PlugPipe
principle of reusing existing battle-tested tools rather than reinventing.

Key Features:
- OpenAPI 3.x and Swagger 2.0 support
- JSON Schema validation using jsonschema library
- YAML parsing using PyYAML
- Reference resolution ($ref handling) 
- Authentication scheme analysis
- MCP tool generation from endpoints
- Extensible architecture for additional formats

Reused Components:
- jsonschema: Industry standard JSON Schema validation
- PyYAML: Proven YAML parsing library
- openapi-spec-validator: OpenAPI-specific validation
- requests: HTTP client for URL-based specs
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
from urllib.parse import urlparse
import yaml

# Proven libraries - reuse, don't reinvent
try:
    import jsonschema
    from jsonschema import validate, ValidationError
    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from openapi_spec_validator import validate_spec
    from openapi_spec_validator.exceptions import OpenAPIValidationError
    OPENAPI_VALIDATOR_AVAILABLE = True
except ImportError:
    OPENAPI_VALIDATOR_AVAILABLE = False

logger = logging.getLogger(__name__)


class OpenAPIParser:
    """
    OpenAPI/Swagger specification parser and analyzer.
    Leverages existing proven libraries for all parsing and validation.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.spec_cache = {}
        
    async def parse_specification(self, specification: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OpenAPI specification from various sources."""
        try:
            # Load specification content
            spec_content = await self._load_specification_content(specification)
            
            # Parse JSON/YAML content
            parsed_spec = self._parse_content(spec_content, specification.get('format', 'json'))
            
            # Resolve references if requested
            if options.get('resolve_references', True):
                parsed_spec = self._resolve_references(parsed_spec)
            
            # Extract metadata
            metadata = self._extract_metadata(parsed_spec)
            
            return {
                "success": True,
                "operation_completed": "parse_spec",
                "parsed_spec": parsed_spec,
                "metadata": metadata,
                "spec_info": {
                    "openapi_version": parsed_spec.get("openapi") or parsed_spec.get("swagger"),
                    "title": parsed_spec.get("info", {}).get("title", "Unknown API"),
                    "version": parsed_spec.get("info", {}).get("version", "Unknown"),
                    "description": parsed_spec.get("info", {}).get("description", "")
                }
            }
            
        except Exception as e:
            logger.error(f"Specification parsing failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "operation_completed": "parse_spec"
            }
    
    async def validate_specification(self, specification: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """Validate OpenAPI specification using proven validation libraries."""
        try:
            # Load and parse specification
            spec_content = await self._load_specification_content(specification)
            parsed_spec = self._parse_content(spec_content, specification.get('format', 'json'))
            
            validation_results = {
                "valid": True,
                "errors": [],
                "warnings": [],
                "schema_version": "unknown"
            }
            
            # Detect OpenAPI version
            if "openapi" in parsed_spec:
                validation_results["schema_version"] = parsed_spec["openapi"]
                
                # Use openapi-spec-validator if available
                if OPENAPI_VALIDATOR_AVAILABLE and options.get('validate_schema', True):
                    try:
                        validate_spec(parsed_spec)
                        validation_results["validation_method"] = "openapi-spec-validator"
                    except OpenAPIValidationError as e:
                        validation_results["valid"] = False
                        validation_results["errors"].append(str(e))
                else:
                    # Basic structural validation
                    basic_validation = self._basic_openapi_validation(parsed_spec)
                    validation_results.update(basic_validation)
                    
            elif "swagger" in parsed_spec:
                validation_results["schema_version"] = parsed_spec["swagger"]
                # Basic Swagger 2.0 validation
                swagger_validation = self._basic_swagger_validation(parsed_spec)
                validation_results.update(swagger_validation)
            else:
                validation_results["valid"] = False
                validation_results["errors"].append("Neither 'openapi' nor 'swagger' field found")
            
            # Additional semantic validation
            semantic_issues = self._semantic_validation(parsed_spec)
            validation_results["warnings"].extend(semantic_issues)
            
            return {
                "success": True,
                "operation_completed": "validate_spec",
                "validation_results": validation_results,
                "spec_summary": {
                    "paths_count": len(parsed_spec.get("paths", {})),
                    "schemas_count": len(parsed_spec.get("components", {}).get("schemas", {})),
                    "security_schemes_count": len(self._get_security_schemes(parsed_spec))
                }
            }
            
        except Exception as e:
            logger.error(f"Specification validation failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "operation_completed": "validate_spec"
            }
    
    async def extract_endpoints(self, specification: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """Extract endpoint information from OpenAPI specification."""
        try:
            # Load and parse specification
            spec_content = await self._load_specification_content(specification)
            parsed_spec = self._parse_content(spec_content, specification.get('format', 'json'))
            
            endpoints = []
            paths = parsed_spec.get("paths", {})
            
            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                
                for method, operation in path_item.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                        if not isinstance(operation, dict):
                            continue
                        
                        # Skip deprecated endpoints if requested
                        if operation.get("deprecated", False) and not options.get('include_deprecated', True):
                            continue
                        
                        endpoint = {
                            "path": path,
                            "method": method.upper(),
                            "operation_id": operation.get("operationId"),
                            "summary": operation.get("summary", ""),
                            "description": operation.get("description", ""),
                            "tags": operation.get("tags", []),
                            "parameters": self._extract_parameters(operation, path_item),
                            "request_body": self._extract_request_body(operation),
                            "responses": self._extract_responses(operation),
                            "security": operation.get("security", []),
                            "deprecated": operation.get("deprecated", False)
                        }
                        
                        endpoints.append(endpoint)
            
            return {
                "success": True,
                "operation_completed": "extract_endpoints",
                "endpoints": endpoints,
                "summary": {
                    "total_endpoints": len(endpoints),
                    "methods_used": list(set(ep["method"] for ep in endpoints)),
                    "paths_count": len(set(ep["path"] for ep in endpoints)),
                    "deprecated_count": sum(1 for ep in endpoints if ep["deprecated"])
                }
            }
            
        except Exception as e:
            logger.error(f"Endpoint extraction failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "operation_completed": "extract_endpoints"
            }
    
    async def analyze_authentication(self, specification: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze authentication schemes in OpenAPI specification."""
        try:
            # Load and parse specification
            spec_content = await self._load_specification_content(specification)
            parsed_spec = self._parse_content(spec_content, specification.get('format', 'json'))
            
            # Extract security schemes
            security_schemes = self._get_security_schemes(parsed_spec)
            
            # Analyze global security requirements
            global_security = parsed_spec.get("security", [])
            
            # Analyze per-endpoint security
            endpoint_security = {}
            paths = parsed_spec.get("paths", {})
            
            for path, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                
                for method, operation in path_item.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                        endpoint_key = f"{method.upper()} {path}"
                        endpoint_security[endpoint_key] = operation.get("security", global_security)
            
            # Categorize authentication types
            auth_analysis = self._categorize_auth_schemes(security_schemes)
            
            return {
                "success": True,
                "operation_completed": "analyze_auth",
                "authentication": {
                    "security_schemes": security_schemes,
                    "global_security": global_security,
                    "endpoint_security": endpoint_security,
                    "auth_analysis": auth_analysis
                },
                "security_summary": {
                    "total_schemes": len(security_schemes),
                    "auth_types": list(auth_analysis.keys()),
                    "endpoints_with_custom_auth": len([ep for ep, sec in endpoint_security.items() if sec != global_security]),
                    "unsecured_endpoints": len([ep for ep, sec in endpoint_security.items() if not sec])
                }
            }
            
        except Exception as e:
            logger.error(f"Authentication analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "operation_completed": "analyze_auth"
            }
    
    async def convert_to_mcp_tools(self, specification: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """Convert OpenAPI endpoints to MCP tool definitions."""
        try:
            # First extract endpoints
            endpoints_result = await self.extract_endpoints(specification, options)
            if not endpoints_result.get("success", False):
                return endpoints_result
            
            endpoints = endpoints_result["endpoints"]
            mcp_tools = []
            
            for endpoint in endpoints:
                # Generate tool name
                tool_name = self._generate_mcp_tool_name(endpoint)
                
                # Generate input schema from parameters and request body
                input_schema = self._generate_mcp_input_schema(endpoint)
                
                # Generate tool description
                description = self._generate_mcp_tool_description(endpoint)
                
                tool = {
                    "name": tool_name,
                    "description": description,
                    "input_schema": input_schema,
                    "metadata": {
                        "path": endpoint["path"],
                        "method": endpoint["method"],
                        "operation_id": endpoint.get("operation_id"),
                        "tags": endpoint.get("tags", []),
                        "deprecated": endpoint.get("deprecated", False)
                    }
                }
                
                mcp_tools.append(tool)
            
            return {
                "success": True,
                "operation_completed": "convert_to_mcp_tools",
                "mcp_tools": mcp_tools,
                "conversion_summary": {
                    "tools_generated": len(mcp_tools),
                    "source_endpoints": len(endpoints),
                    "tool_categories": list(set(tag for tool in mcp_tools for tag in tool["metadata"]["tags"]))
                }
            }
            
        except Exception as e:
            logger.error(f"MCP tool conversion failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "operation_completed": "convert_to_mcp_tools"
            }
    
    async def _load_specification_content(self, specification: Dict[str, Any]) -> str:
        """Load specification content from various sources."""
        source_type = specification["source_type"]
        source = specification["source"]
        
        if source_type == "inline":
            if isinstance(source, str):
                return source
            else:
                return json.dumps(source)
        
        elif source_type == "file":
            spec_path = Path(source)
            if not spec_path.exists():
                raise FileNotFoundError(f"Specification file not found: {source}")
            
            with open(spec_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        elif source_type == "url":
            if not REQUESTS_AVAILABLE:
                raise ImportError("requests library not available for URL loading")
            
            response = requests.get(source, timeout=30)
            response.raise_for_status()
            return response.text
        
        else:
            raise ValueError(f"Unsupported source type: {source_type}")
    
    def _parse_content(self, content: str, format_type: str) -> Dict[str, Any]:
        """Parse JSON or YAML content."""
        try:
            if format_type.lower() == 'yaml':
                return yaml.safe_load(content)
            else:
                return json.loads(content)
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            raise ValueError(f"Failed to parse {format_type} content: {e}")
    
    def _resolve_references(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Basic $ref resolution for local references."""
        # Simplified reference resolution - full implementation would handle external refs
        def resolve_refs(obj, root):
            if isinstance(obj, dict):
                if "$ref" in obj:
                    ref_path = obj["$ref"]
                    if ref_path.startswith("#/"):
                        path_parts = ref_path[2:].split("/")
                        resolved = root
                        for part in path_parts:
                            resolved = resolved.get(part, {})
                        return resolved
                else:
                    return {k: resolve_refs(v, root) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [resolve_refs(item, root) for item in obj]
            return obj
        
        return resolve_refs(spec, spec)
    
    def _extract_metadata(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata from specification."""
        info = spec.get("info", {})
        return {
            "title": info.get("title", "Unknown API"),
            "version": info.get("version", "Unknown"),
            "description": info.get("description", ""),
            "contact": info.get("contact", {}),
            "license": info.get("license", {}),
            "servers": spec.get("servers", []),
            "tags": spec.get("tags", []),
            "external_docs": spec.get("externalDocs", {})
        }
    
    def _basic_openapi_validation(self, spec: Dict[str, Any]) -> Dict[str, bool]:
        """Basic OpenAPI 3.x structural validation."""
        errors = []
        warnings = []
        
        # Required fields
        required_fields = ["openapi", "info", "paths"]
        for field in required_fields:
            if field not in spec:
                errors.append(f"Missing required field: {field}")
        
        # Info object validation
        if "info" in spec:
            info = spec["info"]
            if not info.get("title"):
                errors.append("Info object missing required 'title' field")
            if not info.get("version"):
                errors.append("Info object missing required 'version' field")
        
        # Paths validation
        if "paths" in spec and not isinstance(spec["paths"], dict):
            errors.append("Paths must be an object")
        
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}
    
    def _basic_swagger_validation(self, spec: Dict[str, Any]) -> Dict[str, bool]:
        """Basic Swagger 2.0 structural validation."""
        errors = []
        warnings = []
        
        # Required fields for Swagger 2.0
        required_fields = ["swagger", "info", "paths"]
        for field in required_fields:
            if field not in spec:
                errors.append(f"Missing required field: {field}")
        
        # Check swagger version
        if spec.get("swagger") != "2.0":
            warnings.append(f"Swagger version {spec.get('swagger')} may not be fully supported")
        
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}
    
    def _semantic_validation(self, spec: Dict[str, Any]) -> List[str]:
        """Perform semantic validation checks."""
        warnings = []
        
        # Check for empty paths
        paths = spec.get("paths", {})
        if not paths:
            warnings.append("No paths defined in specification")
        
        # Check for operations without summaries
        for path, path_item in paths.items():
            if isinstance(path_item, dict):
                for method, operation in path_item.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch'] and isinstance(operation, dict):
                        if not operation.get("summary"):
                            warnings.append(f"Operation {method.upper()} {path} missing summary")
        
        return warnings
    
    def _get_security_schemes(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security schemes from OpenAPI spec."""
        # OpenAPI 3.x
        if "components" in spec and "securitySchemes" in spec["components"]:
            return spec["components"]["securitySchemes"]
        
        # Swagger 2.0
        if "securityDefinitions" in spec:
            return spec["securityDefinitions"]
        
        return {}
    
    def _categorize_auth_schemes(self, security_schemes: Dict[str, Any]) -> Dict[str, List[str]]:
        """Categorize authentication schemes by type."""
        categories = {
            "api_key": [],
            "http": [],
            "oauth2": [],
            "openid_connect": []
        }
        
        for name, scheme in security_schemes.items():
            scheme_type = scheme.get("type", "unknown")
            if scheme_type in categories:
                categories[scheme_type].append(name)
            else:
                categories.setdefault("other", []).append(name)
        
        return {k: v for k, v in categories.items() if v}
    
    def _extract_parameters(self, operation: Dict[str, Any], path_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract parameters from operation and path item."""
        parameters = []
        
        # Path-level parameters
        path_params = path_item.get("parameters", [])
        parameters.extend(path_params)
        
        # Operation-level parameters
        op_params = operation.get("parameters", [])
        parameters.extend(op_params)
        
        return parameters
    
    def _extract_request_body(self, operation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract request body from operation."""
        return operation.get("requestBody")
    
    def _extract_responses(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Extract responses from operation."""
        return operation.get("responses", {})
    
    def _generate_mcp_tool_name(self, endpoint: Dict[str, Any]) -> str:
        """Generate MCP tool name from endpoint."""
        method = endpoint["method"].lower()
        path = endpoint["path"]
        
        # Clean path for tool name
        clean_path = re.sub(r'[{}]', '', path)  # Remove path parameters brackets
        clean_path = re.sub(r'[^a-zA-Z0-9_/]', '_', clean_path)  # Replace special chars
        clean_path = clean_path.strip('_/').replace('/', '_').replace('__', '_')
        
        if endpoint.get("operation_id"):
            return endpoint["operation_id"]
        else:
            return f"{method}_{clean_path}" if clean_path else method
    
    def _generate_mcp_input_schema(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Generate MCP input schema from endpoint parameters."""
        schema = {
            "type": "object",
            "properties": {},
            "required": []
        }
        
        # Add path parameters
        for param in endpoint.get("parameters", []):
            if isinstance(param, dict):
                param_name = param.get("name")
                if param_name:
                    param_schema = param.get("schema", {"type": "string"})
                    schema["properties"][param_name] = {
                        "type": param_schema.get("type", "string"),
                        "description": param.get("description", f"Parameter {param_name}")
                    }
                    
                    if param.get("required", False):
                        schema["required"].append(param_name)
        
        # Add request body properties
        request_body = endpoint.get("request_body")
        if request_body and isinstance(request_body, dict):
            content = request_body.get("content", {})
            for media_type, media_schema in content.items():
                if "schema" in media_schema:
                    # Add request body as nested object
                    schema["properties"]["request_body"] = media_schema["schema"]
                    if request_body.get("required", False):
                        schema["required"].append("request_body")
                    break
        
        return schema
    
    def _generate_mcp_tool_description(self, endpoint: Dict[str, Any]) -> str:
        """Generate MCP tool description from endpoint."""
        parts = []
        
        if endpoint.get("summary"):
            parts.append(endpoint["summary"])
        
        if endpoint.get("description") and endpoint["description"] != endpoint.get("summary"):
            parts.append(endpoint["description"])
        
        if not parts:
            parts.append(f"{endpoint['method']} {endpoint['path']}")
        
        if endpoint.get("tags"):
            parts.append(f"Tags: {', '.join(endpoint['tags'])}")
        
        return " | ".join(parts)


# Main plugin entry point
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main process function for OpenAPI Parser Plugin.
    
    Parses, validates, and extracts information from OpenAPI specifications
    using proven libraries and battle-tested validation approaches.
    """
    try:
        parser = OpenAPIParser(cfg)
        
        operation = cfg.get("operation", "parse_spec")
        specification = cfg.get("specification", {})
        parsing_options = cfg.get("parsing_options", {})
        
        if operation == "parse_spec":
            return await parser.parse_specification(specification, parsing_options)
            
        elif operation == "validate_spec":
            return await parser.validate_specification(specification, parsing_options)
            
        elif operation == "extract_endpoints":
            return await parser.extract_endpoints(specification, parsing_options)
            
        elif operation == "analyze_auth":
            return await parser.analyze_authentication(specification, parsing_options)
            
        elif operation == "convert_to_mcp_tools":
            return await parser.convert_to_mcp_tools(specification, parsing_options)
            
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "supported_operations": ["parse_spec", "validate_spec", "extract_endpoints", "analyze_auth", "convert_to_mcp_tools"]
            }
    
    except Exception as e:
        logger.error(f"OpenAPI Parser failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "operation_completed": cfg.get("operation", "unknown")
        }


# Plugin metadata
plug_metadata = {
    'name': 'openapi_parser',
    'owner': 'PlugPipe Integration Team',
    'version': '1.0.0',
    'status': 'stable',
    'description': 'OpenAPI/Swagger specification parser leveraging proven validation libraries',
    'capabilities': [
        'openapi_parsing',
        'swagger_parsing',
        'specification_validation',
        'endpoint_extraction',
        'mcp_tool_generation'
    ],
    'dependencies': {
        'python_packages': ['jsonschema', 'pyyaml', 'requests'],
        'optional_packages': ['openapi-spec-validator']
    }
}


# Test functionality
if __name__ == "__main__":
    async def test_parser():
        test_config = {
            "operation": "parse_spec",
            "specification": {
                "source_type": "file",
                "source": "example_openapi_spec.json",
                "format": "json"
            },
            "parsing_options": {
                "validate_schema": True,
                "resolve_references": True
            }
        }
        
        result = await process({}, test_config)
        print(f"Test result: {json.dumps(result, indent=2)}")
    
    asyncio.run(test_parser())