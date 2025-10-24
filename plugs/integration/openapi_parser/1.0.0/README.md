# OpenAPI Parser Plugin

## Overview

The **OpenAPI Parser Plugin** is a comprehensive, reusable parser for OpenAPI/Swagger specifications that leverages proven validation libraries and battle-tested tools. Built following PlugPipe principles of "reuse everything, reinvent nothing," it provides parsing, validation, and MCP tool generation capabilities for enterprise API integration workflows.

## Key Features

### 📋 **Comprehensive Parsing**
- **OpenAPI 3.0.x & 3.1.x**: Full support for latest OpenAPI specifications
- **Swagger 2.0**: Legacy Swagger specification support
- **Multi-format Input**: JSON, YAML, file, URL, and inline specifications
- **Reference Resolution**: Automatic `$ref` reference resolution

### 🛡️ **Validation & Analysis**
- **JSON Schema Validation**: Using industry-standard `jsonschema` library
- **OpenAPI-Specific Validation**: Integration with `openapi-spec-validator`
- **Semantic Validation**: Business logic and best practice checks
- **Authentication Analysis**: Security scheme detection and categorization

### 🔄 **MCP Integration**
- **Tool Generation**: Convert API endpoints to MCP tool definitions
- **Schema Mapping**: Automatic input schema generation for MCP tools
- **Metadata Preservation**: Operation IDs, tags, and descriptions
- **Authentication Mapping**: Security requirement analysis

### 🏗️ **Enterprise Features**
- **Batch Processing**: Parse multiple specifications
- **Error Handling**: Comprehensive error reporting and recovery
- **Performance Optimization**: Caching and efficient parsing
- **Extensible Architecture**: Easy to add new format support

## Supported Formats

| Format | Versions | Input Methods | Status |
|--------|----------|---------------|---------|
| OpenAPI | 3.0.x, 3.1.x | JSON, YAML, File, URL | ✅ Full support |
| Swagger | 2.0 | JSON, YAML, File, URL | ✅ Full support |
| GraphQL | Schema Definition | 🚧 Future enhancement |
| RAML | 0.8, 1.0 | 🚧 Future enhancement |
| API Blueprint | Latest | 🚧 Future enhancement |

## Installation & Dependencies

### Required Dependencies
```bash
# Core dependencies (automatically installed)
pip install jsonschema>=4.0.0 pyyaml>=6.0 requests>=2.31.0

# Optional enhanced validation
pip install openapi-spec-validator>=0.5.0
```

### External Dependencies
```bash
# Optional: Advanced OpenAPI tooling
npm install -g swagger-parser
```

## Quick Start

### 1. Parse OpenAPI Specification
```bash
# Create input configuration
echo '{
    "operation": "parse_spec",
    "specification": {
        "source_type": "file",
        "source": "api_spec.json",
        "format": "json"
    },
    "parsing_options": {
        "validate_schema": true,
        "resolve_references": true
    }
}' > parse_config.json

# Run parser
./pp run openapi_parser --input parse_config.json
```

### 2. Validate Specification
```json
{
    "operation": "validate_spec",
    "specification": {
        "source_type": "url",
        "source": "https://petstore.swagger.io/v2/swagger.json",
        "format": "json"
    },
    "parsing_options": {
        "validate_schema": true
    }
}
```

### 3. Convert to MCP Tools
```json
{
    "operation": "convert_to_mcp_tools",
    "specification": {
        "source_type": "file", 
        "source": "ecommerce_api.yaml",
        "format": "yaml"
    },
    "parsing_options": {
        "include_deprecated": false,
        "extract_examples": true
    }
}
```

## Operations Reference

### Core Operations

#### `parse_spec`
Parse and extract structured information from API specification.

**Input Schema:**
```json
{
    "operation": "parse_spec",
    "specification": {
        "source_type": "inline|file|url",
        "source": "spec_content|file_path|url",
        "format": "json|yaml"
    },
    "parsing_options": {
        "validate_schema": true,
        "resolve_references": true,
        "extract_examples": false
    }
}
```

**Output Schema:**
```json
{
    "success": true,
    "operation_completed": "parse_spec",
    "parsed_spec": {
        "openapi": "3.0.0",
        "info": {...},
        "paths": {...},
        "components": {...}
    },
    "metadata": {
        "title": "API Title",
        "version": "1.0.0",
        "description": "API Description",
        "servers": [...],
        "contact": {...}
    },
    "spec_info": {
        "openapi_version": "3.0.0",
        "title": "Example API",
        "version": "1.0.0"
    }
}
```

#### `validate_spec`
Validate API specification against OpenAPI/Swagger schemas.

**Input:**
```json
{
    "operation": "validate_spec",
    "specification": {
        "source_type": "file",
        "source": "api_spec.json"
    },
    "parsing_options": {
        "validate_schema": true
    }
}
```

**Output:**
```json
{
    "success": true,
    "operation_completed": "validate_spec",
    "validation_results": {
        "valid": true,
        "schema_version": "3.0.0",
        "errors": [],
        "warnings": ["Operation GET /users missing summary"],
        "validation_method": "openapi-spec-validator"
    },
    "spec_summary": {
        "paths_count": 15,
        "schemas_count": 8,
        "security_schemes_count": 2
    }
}
```

#### `extract_endpoints`
Extract detailed endpoint information from API specification.

**Input:**
```json
{
    "operation": "extract_endpoints",
    "specification": {
        "source_type": "file",
        "source": "api_spec.json"
    },
    "parsing_options": {
        "include_deprecated": false
    }
}
```

**Output:**
```json
{
    "success": true,
    "operation_completed": "extract_endpoints", 
    "endpoints": [
        {
            "path": "/users",
            "method": "GET",
            "operation_id": "listUsers",
            "summary": "List all users",
            "description": "Retrieve a paginated list of users",
            "tags": ["users"],
            "parameters": [
                {
                    "name": "limit",
                    "in": "query",
                    "schema": {"type": "integer"}
                }
            ],
            "request_body": null,
            "responses": {
                "200": {
                    "description": "List of users"
                }
            },
            "security": [],
            "deprecated": false
        }
    ],
    "summary": {
        "total_endpoints": 12,
        "methods_used": ["GET", "POST", "PUT", "DELETE"],
        "paths_count": 8,
        "deprecated_count": 2
    }
}
```

#### `analyze_auth`
Analyze authentication schemes and security requirements.

**Input:**
```json
{
    "operation": "analyze_auth",
    "specification": {
        "source_type": "file",
        "source": "api_spec.json"
    }
}
```

**Output:**
```json
{
    "success": true,
    "operation_completed": "analyze_auth",
    "authentication": {
        "security_schemes": {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header", 
                "name": "X-API-Key"
            },
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer"
            }
        },
        "global_security": [
            {"ApiKeyAuth": []}
        ],
        "endpoint_security": {
            "GET /users": [{"BearerAuth": []}],
            "POST /users": [{"ApiKeyAuth": []}]
        },
        "auth_analysis": {
            "api_key": ["ApiKeyAuth"],
            "http": ["BearerAuth"]
        }
    },
    "security_summary": {
        "total_schemes": 2,
        "auth_types": ["api_key", "http"],
        "endpoints_with_custom_auth": 2,
        "unsecured_endpoints": 0
    }
}
```

#### `convert_to_mcp_tools`
Convert API endpoints to MCP tool definitions.

**Input:**
```json
{
    "operation": "convert_to_mcp_tools",
    "specification": {
        "source_type": "file",
        "source": "api_spec.json"
    },
    "parsing_options": {
        "include_deprecated": false,
        "extract_examples": true
    }
}
```

**Output:**
```json
{
    "success": true,
    "operation_completed": "convert_to_mcp_tools",
    "mcp_tools": [
        {
            "name": "listUsers",
            "description": "List all users | Retrieve a paginated list of users | Tags: users",
            "input_schema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of users to return"
                    },
                    "offset": {
                        "type": "integer", 
                        "description": "Starting offset for pagination"
                    }
                },
                "required": []
            },
            "metadata": {
                "path": "/users",
                "method": "GET",
                "operation_id": "listUsers",
                "tags": ["users"],
                "deprecated": false
            }
        }
    ],
    "conversion_summary": {
        "tools_generated": 8,
        "source_endpoints": 8,
        "tool_categories": ["users", "orders", "products"]
    }
}
```

## Advanced Usage

### URL-based Parsing
```json
{
    "operation": "parse_spec",
    "specification": {
        "source_type": "url",
        "source": "https://petstore.swagger.io/v2/swagger.json",
        "format": "json"
    },
    "parsing_options": {
        "validate_schema": true,
        "resolve_references": true
    }
}
```

### Inline Specification
```json
{
    "operation": "validate_spec",
    "specification": {
        "source_type": "inline",
        "source": {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {}
        }
    }
}
```

### YAML Format Parsing
```json
{
    "operation": "parse_spec",
    "specification": {
        "source_type": "file",
        "source": "api_spec.yaml",
        "format": "yaml"
    },
    "parsing_options": {
        "validate_schema": true
    }
}
```

## Integration Examples

### Example 1: Complete API Analysis Workflow

**Step 1: Validate Specification**
```bash
./pp run openapi_parser --input validate_config.json
```

**validate_config.json:**
```json
{
    "operation": "validate_spec",
    "specification": {
        "source_type": "file",
        "source": "petstore_api.json",
        "format": "json"
    }
}
```

**Step 2: Extract Endpoints** 
```json
{
    "operation": "extract_endpoints",
    "specification": {
        "source_type": "file",
        "source": "petstore_api.json"
    },
    "parsing_options": {
        "include_deprecated": false
    }
}
```

**Step 3: Analyze Authentication**
```json
{
    "operation": "analyze_auth",
    "specification": {
        "source_type": "file",
        "source": "petstore_api.json"
    }
}
```

**Step 4: Generate MCP Tools**
```json
{
    "operation": "convert_to_mcp_tools",
    "specification": {
        "source_type": "file",
        "source": "petstore_api.json"
    }
}
```

### Example 2: Batch Processing Multiple APIs

```bash
# Process multiple API specifications
for api in user_api.json order_api.json product_api.json; do
    echo "Processing $api..."
    ./pp run openapi_parser --input "{
        \"operation\": \"convert_to_mcp_tools\",
        \"specification\": {
            \"source_type\": \"file\",
            \"source\": \"$api\",
            \"format\": \"json\"
        }
    }"
done
```

### Example 3: Integration with API2MCP Factory

The OpenAPI Parser is designed to work seamlessly with the API2MCP Factory:

```json
{
    "operation": "convert_api",
    "api_specification": {
        "format": "openapi",
        "source": "ecommerce_api.json"
    },
    "conversion_options": {
        "backend": "fastmcp",
        "use_parser": "openapi_parser"
    }
}
```

## Error Handling

### Common Errors and Solutions

#### Invalid JSON/YAML Format
```json
{
    "success": false,
    "error": "Failed to parse json content: Expecting ',' delimiter",
    "operation_completed": "parse_spec"
}
```

**Solution:** Validate JSON/YAML syntax using external tools.

#### Missing Required Fields
```json
{
    "success": false,
    "validation_results": {
        "valid": false,
        "errors": ["Missing required field: info"]
    }
}
```

**Solution:** Add missing required OpenAPI fields.

#### File Not Found
```json
{
    "success": false,
    "error": "Specification file not found: missing_file.json",
    "operation_completed": "parse_spec"
}
```

**Solution:** Verify file path and permissions.

#### URL Request Failed
```json
{
    "success": false,
    "error": "HTTP 404: Not Found",
    "operation_completed": "parse_spec"
}
```

**Solution:** Check URL availability and network connectivity.

### Debug Mode

Enable detailed error information:

```json
{
    "operation": "parse_spec",
    "debug": true,
    "verbose": true,
    "specification": {...}
}
```

## Performance Characteristics

### Parsing Performance
| Specification Size | Parse Time | Memory Usage |
|-------------------|------------|--------------|
| Small (< 1MB) | < 1 second | ~10MB |
| Medium (1-10MB) | 1-5 seconds | ~50MB |
| Large (10-50MB) | 5-30 seconds | ~200MB |
| Very Large (50MB+) | 30+ seconds | ~500MB+ |

### Optimization Tips
1. **Disable reference resolution** for faster parsing when not needed
2. **Use file input** instead of URL for better performance
3. **Cache parsed specifications** for repeated operations
4. **Filter deprecated endpoints** to reduce processing time

## Architecture & Extension

### Plugin Architecture
```
OpenAPIParser
├── _load_specification_content()  # Multi-source loading
├── _parse_content()              # JSON/YAML parsing
├── _resolve_references()         # $ref resolution
├── _extract_metadata()           # Metadata extraction
├── _basic_openapi_validation()   # Schema validation
└── _generate_mcp_*()            # MCP tool generation
```

### Adding New Operations
1. Add operation to `input_schema.properties.operation.enum`
2. Implement handler method in `OpenAPIParser` class
3. Add operation route in `process()` function
4. Update documentation and tests

### Custom Validation Rules
```python
def _custom_validation(self, spec: Dict[str, Any]) -> List[str]:
    """Add custom validation rules."""
    warnings = []
    
    # Example: Check for missing operation summaries
    for path, methods in spec.get("paths", {}).items():
        for method, operation in methods.items():
            if not operation.get("summary"):
                warnings.append(f"Missing summary: {method.upper()} {path}")
    
    return warnings
```

### Format Extension
To add support for new API formats (GraphQL, RAML, etc.):

1. Create format-specific parser class
2. Implement `ConversionBackendInterface` methods
3. Add format detection logic
4. Update plugin manifest with new capabilities

## Testing

### Unit Tests
```bash
# Direct plugin testing
python plugs/integration/openapi_parser/1.0.0/main.py

# PlugPipe CLI testing
PLUGPIPE_DEMO_MODE=true ./pp run openapi_parser --input test_config.json
```

### Test Specifications
The plugin includes test support for various OpenAPI specifications:

- **Petstore API**: Classic OpenAPI example
- **E-commerce API**: Complex enterprise example  
- **Minimal API**: Basic validation testing
- **Invalid Specs**: Error handling testing

### Comprehensive Testing
```bash
# Run comprehensive plugin testing
./pp run intelligent_test_agent --input parser_test_config.json
```

## Dependencies & Compatibility

### Python Compatibility
- **Python**: 3.8+
- **Required**: `jsonschema`, `pyyaml`, `requests`
- **Optional**: `openapi-spec-validator`

### PlugPipe Integration
- **Plugin System**: Fully compatible with PlugPipe plugin architecture
- **Registry**: Auto-discoverable via PlugPipe registry
- **SBOM**: Complete Software Bill of Materials included
- **CLI**: Full integration with `./pp` command interface

### External Tool Integration
- **Swagger Tools**: Optional integration with swagger-parser
- **JSON Schema**: Full JSON Schema validation support
- **HTTP Libraries**: Robust URL-based specification loading

## Best Practices

### Specification Validation
1. **Always validate** specifications before processing
2. **Use semantic validation** for business logic checks
3. **Handle warnings appropriately** - warnings don't prevent processing
4. **Test with real-world APIs** to ensure compatibility

### Performance Optimization
1. **Cache specifications** when processing multiple operations
2. **Disable unnecessary features** for faster processing
3. **Use batch operations** when processing multiple specs
4. **Monitor memory usage** with large specifications

### Error Recovery
1. **Implement graceful degradation** for validation failures
2. **Provide detailed error messages** for debugging
3. **Log operations** for audit and troubleshooting
4. **Test error scenarios** thoroughly

### Integration Patterns
1. **Compose with other parsers** for multi-format support
2. **Pipeline with API2MCP Factory** for complete workflows
3. **Integrate with validation tools** for enterprise compliance
4. **Use with CI/CD systems** for automated API processing

## Contributing

1. Follow PlugPipe development guidelines in `CLAUDE.md`
2. Leverage existing libraries ("reuse everything, reinvent nothing")  
3. Add comprehensive tests for new operations
4. Update SBOM with new dependencies
5. Maintain backward compatibility with existing operations

## Troubleshooting

### Common Issues

#### 1. Import Errors
```python
ImportError: No module named 'jsonschema'
```
**Solution:** `pip install jsonschema>=4.0.0`

#### 2. YAML Parsing Errors
```python
yaml.scanner.ScannerError: mapping values are not allowed here
```
**Solution:** Validate YAML syntax with external validator.

#### 3. Memory Issues with Large Specs
```python
MemoryError: Unable to allocate array
```
**Solution:** Process specifications in chunks or use streaming parsing.

#### 4. Network Timeouts
```python
requests.exceptions.Timeout: HTTPSConnectionPool
```
**Solution:** Increase timeout or use local file copy.

### Debug Information

Enable comprehensive debugging:
```bash
export PYTHONPATH=.
export DEBUG=true
./pp run openapi_parser --input debug_config.json
```

## License

This plugin is part of the PlugPipe ecosystem and follows the PlugPipe license terms.

## Support & Community

- **Documentation**: This README and PlugPipe documentation
- **Issues**: Report via PlugPipe issue tracking system
- **Community**: PlugPipe development community forums
- **Enterprise**: PlugPipe enterprise support channels

---

**Built following PlugPipe principles: Comprehensive, reusable, battle-tested parsing for the enterprise.**