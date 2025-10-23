# API2MCP Factory Plugin

## Overview

The **API2MCP Factory Plugin** is an enterprise-grade solution that converts existing API specifications into MCP (Model Context Protocol) servers effortlessly. Built following PlugPipe principles of "reuse everything, reinvent nothing," it leverages proven conversion tools and existing PlugPipe components to enable seamless API-to-MCP migration for LLM integration.

## Key Features

### 🏭 **Multi-Backend Architecture**
- **OpenAPI-MCP-Generator**: TypeScript-based conversion using the most popular OpenAPI to MCP tool
- **FastMCP Integration**: Leverages existing PlugPipe FastMCP server/client plugins
- **Extensible Backend System**: Ready for Stainless, Speakeasy, and other proven tools

### 🔄 **Enterprise Operations**
- **Single API Conversion**: Convert individual API specifications
- **Batch Processing**: Convert multiple APIs in one operation
- **Specification Validation**: Validate API specs before conversion
- **Backend Health Monitoring**: Monitor conversion backend availability
- **Factory Status**: Real-time factory health and configuration

### 🛡️ **Security & Compliance**
- **Authentication Mapping**: Preserve API security schemes in MCP servers
- **Enterprise Security Levels**: Standard, Enhanced, Enterprise validation
- **SBOM Generation**: Automatic Software Bill of Materials creation
- **Plugin Registration**: Automatic PlugPipe plugin generation with proper manifests

### 🔌 **PlugPipe Integration**
- **Reuses Core Components**: Built on `core/agent_factory` and `database/factory` patterns
- **FastMCP Integration**: Leverages `fastmcp_server` and `fastmcp_client` plugins
- **Plugin Generation**: Automatically creates PlugPipe plugins for generated MCP servers
- **Registry Compatible**: Full integration with PlugPipe plugin discovery

## Supported API Formats

| Format | Version Support | Backend Support |
|--------|----------------|-----------------|
| OpenAPI/Swagger | 2.0, 3.0.x, 3.1.x | ✅ All backends |
| GraphQL | Schema Definition | 🚧 Future enhancement |
| RAML | 0.8, 1.0 | 🚧 Future enhancement |
| API Blueprint | Latest | 🚧 Future enhancement |

## Installation & Dependencies

### Required Dependencies
```bash
# Python packages (automatically installed)
pip install requests>=2.31.0 pyyaml>=6.0 jsonschema>=4.0.0 fastapi>=0.100.0 pydantic>=2.0.0

# Node.js packages (for openapi-mcp-generator backend)
npm install -g openapi-mcp-generator openapi-generator-cli graphql-tools
```

### PlugPipe Plugin Dependencies
- `fastmcp_server` - MCP server implementation
- `fastmcp_client` - MCP client functionality  
- `core/agent_factory` - Dynamic agent creation
- `openapi_parser` - OpenAPI specification parsing (created alongside)

## Quick Start

### 1. Check Factory Status
```bash
# Using PlugPipe CLI
./pp run api2mcp_factory --input '{"operation": "get_status"}'

# Or create a JSON file
echo '{"operation": "get_status"}' > status_check.json
./pp run api2mcp_factory --input status_check.json
```

### 2. List Available Backends
```json
{
    "operation": "list_backends"
}
```

### 3. Convert API Specification
```json
{
    "operation": "convert_api",
    "api_specification": {
        "format": "openapi",
        "source": "path/to/api_spec.json"
    },
    "conversion_options": {
        "backend": "fastmcp",
        "server_name": "my_api_mcp_server",
        "include_authentication": true,
        "generate_plugpipe_plugin": true
    }
}
```

## Operations Reference

### Factory Operations

#### `get_status`
Get factory health and configuration status.

**Input:**
```json
{
    "operation": "get_status"
}
```

**Output:**
```json
{
    "success": true,
    "factory_status": {
        "factory_id": "uuid",
        "active_backend": "fastmcp",
        "total_backends": 2,
        "healthy_backends": 2,
        "factory_healthy": true
    }
}
```

#### `list_backends`
List available conversion backends and their health.

**Input:**
```json
{
    "operation": "list_backends"
}
```

**Output:**
```json
{
    "success": true,
    "backend_status": {
        "available_backends": ["openapi-mcp-generator", "fastmcp"],
        "active_backend": "openapi-mcp-generator",
        "backend_details": {
            "openapi-mcp-generator": {
                "healthy": true,
                "supported_formats": ["openapi"]
            }
        }
    }
}
```

#### `convert_api`
Convert a single API specification to MCP server.

**Input Schema:**
```json
{
    "operation": "convert_api",
    "api_specification": {
        "format": "openapi|graphql|raml|blueprint",
        "source": "file_path|url|inline_spec"
    },
    "conversion_options": {
        "backend": "fastmcp|openapi-mcp-generator|stainless|speakeasy",
        "output_format": "typescript|python|go",
        "server_name": "string",
        "description": "string",
        "include_authentication": true,
        "generate_plugpipe_plugin": true
    },
    "security_config": {
        "auth_types": ["api_key", "bearer", "oauth2", "basic"],
        "security_level": "standard|enhanced|enterprise"
    }
}
```

**Output Schema:**
```json
{
    "success": true,
    "operation_completed": "convert_api",
    "mcp_server": {
        "name": "string",
        "backend_used": "string",
        "tools_generated": 5,
        "server_config": {},
        "authentication_config": {}
    },
    "plugpipe_plugin": {
        "name": "string",
        "version": "1.0.0",
        "path": "string",
        "sbom_generated": true
    },
    "conversion_metadata": {
        "conversion_timestamp": "ISO-8601",
        "backend_used": "string",
        "dependencies_installed": []
    }
}
```

#### `batch_convert`
Convert multiple API specifications in one operation.

**Input:**
```json
{
    "operation": "batch_convert",
    "batch_options": {
        "api_specs": [
            {
                "name": "api1",
                "api_specification": {...},
                "conversion_options": {...}
            }
        ],
        "output_directory": "./batch_output"
    }
}
```

#### `validate_spec`
Validate API specification before conversion.

**Input:**
```json
{
    "operation": "validate_spec",
    "api_specification": {
        "format": "openapi",
        "source": "path/to/spec.json"
    }
}
```

## Backend Configuration

### FastMCP Backend
Uses existing PlugPipe FastMCP server plugin for MCP protocol implementation.

**Advantages:**
- ✅ Full PlugPipe integration
- ✅ Proven MCP protocol support
- ✅ Enterprise security features
- ✅ No external dependencies

**Configuration:**
```json
{
    "backend": "fastmcp",
    "output_format": "fastmcp_config",
    "server_options": {
        "host": "127.0.0.1",
        "port": 8002,
        "start_server": false
    }
}
```

### OpenAPI-MCP-Generator Backend
Uses the popular TypeScript-based openapi-mcp-generator tool.

**Advantages:**
- ✅ Most popular OpenAPI to MCP converter
- ✅ TypeScript output with full typing
- ✅ Comprehensive OpenAPI 3.x support
- ✅ Active community support

**Requirements:**
- Node.js and npm
- `openapi-mcp-generator` package

**Configuration:**
```json
{
    "backend": "openapi-mcp-generator",
    "output_format": "typescript",
    "generator_options": {
        "validation": true,
        "authentication": "auto"
    }
}
```

## Integration Examples

### Example 1: E-commerce API Conversion

**API Specification** (OpenAPI 3.0):
```json
{
    "openapi": "3.0.0",
    "info": {
        "title": "E-commerce API",
        "version": "1.0.0"
    },
    "paths": {
        "/products": {
            "get": {
                "summary": "List products",
                "parameters": [
                    {
                        "name": "category",
                        "in": "query",
                        "schema": {"type": "string"}
                    }
                ]
            }
        }
    }
}
```

**Conversion Command:**
```bash
./pp run api2mcp_factory --input ecommerce_conversion.json
```

**ecommerce_conversion.json:**
```json
{
    "operation": "convert_api",
    "api_specification": {
        "format": "openapi",
        "source": "ecommerce_api.json"
    },
    "conversion_options": {
        "backend": "fastmcp",
        "server_name": "ecommerce_mcp_server",
        "description": "E-commerce API MCP server",
        "include_authentication": true,
        "generate_plugpipe_plugin": true
    },
    "security_config": {
        "security_level": "enterprise",
        "auth_types": ["api_key", "bearer"]
    }
}
```

**Generated Output:**
- MCP server with 3 tools (get_products, post_products, get_products_id)
- PlugPipe plugin: `ecommerce_mcp_server` v1.0.0
- Authentication mapping for API key and bearer token
- Complete SBOM with dependency tracking

### Example 2: Batch Conversion

```json
{
    "operation": "batch_convert",
    "batch_options": {
        "api_specs": [
            {
                "name": "user_api",
                "api_specification": {
                    "format": "openapi",
                    "source": "user_api.json"
                },
                "conversion_options": {
                    "backend": "fastmcp",
                    "server_name": "user_mcp_server"
                }
            },
            {
                "name": "payment_api",
                "api_specification": {
                    "format": "openapi", 
                    "source": "payment_api.json"
                },
                "conversion_options": {
                    "backend": "openapi-mcp-generator",
                    "server_name": "payment_mcp_server",
                    "output_format": "typescript"
                }
            }
        ],
        "output_directory": "./converted_apis"
    }
}
```

## Error Handling

### Common Errors and Solutions

#### Backend Not Available
```json
{
    "success": false,
    "error": "Backend 'openapi-mcp-generator' not available",
    "solution": "Install required Node.js dependencies"
}
```

**Solution:**
```bash
npm install -g openapi-mcp-generator
```

#### Invalid API Specification
```json
{
    "success": false,
    "error": "Invalid API specification",
    "validation_results": {
        "valid": false,
        "errors": ["Missing required field: openapi"]
    }
}
```

**Solution:** Validate and fix API specification format.

#### Plugin Generation Failed
```json
{
    "success": true,
    "plugpipe_plugin": {
        "success": false,
        "error": "Directory creation failed"
    }
}
```

**Solution:** Check file permissions and disk space.

## Performance & Scalability

### Performance Characteristics
- **Single API Conversion**: ~5-30 seconds depending on API complexity
- **Batch Processing**: Parallel conversion of up to 10 APIs
- **Memory Usage**: ~50-200MB per conversion process
- **Disk Usage**: ~1-10MB per generated MCP server

### Scalability Recommendations
- Use batch processing for multiple APIs
- Monitor backend health regularly
- Configure appropriate timeouts for large APIs
- Consider external storage for generated artifacts

## Security Considerations

### Authentication Mapping
The factory preserves API authentication schemes in generated MCP servers:

| API Auth Type | MCP Implementation | Security Level |
|---------------|-------------------|----------------|
| API Key | Header-based authentication | Standard |
| Bearer Token | Authorization header | Enhanced |
| OAuth2 | Token-based flow | Enterprise |
| Basic Auth | Base64 encoded | Standard |

### Security Validation
- **Input Sanitization**: All API specifications are validated
- **Backend Isolation**: Conversion processes run in controlled environments
- **Plugin Security**: Generated plugins include security metadata
- **Audit Logging**: All operations are logged for compliance

### Enterprise Security Features
- **RBAC Integration**: Role-based access control for factory operations
- **Encryption**: Generated artifacts can be encrypted at rest
- **Certificate Management**: Support for SSL/TLS certificate embedding
- **Compliance**: SOC2, GDPR, HIPAA compliance features available

## Troubleshooting

### Debug Mode
Enable debug mode for detailed logging:

```json
{
    "operation": "convert_api",
    "debug": true,
    "verbose": true,
    "api_specification": {...}
}
```

### Common Issues

#### 1. Backend Health Check Failed
```bash
# Check backend status
./pp run api2mcp_factory --input '{"operation": "list_backends"}'

# Install missing dependencies
npm install -g openapi-mcp-generator
```

#### 2. Conversion Timeout
```json
{
    "conversion_options": {
        "timeout": 300,
        "backend": "fastmcp"
    }
}
```

#### 3. Plugin Registration Failed
```bash
# Verify plugin directory structure
ls -la generated_plugins/

# Check SBOM generation
./pp sbom validate generated_plugins/my_server/1.0.0
```

## Development & Extension

### Adding New Backends
1. Implement `ConversionBackendInterface`
2. Add backend to `API2MCPFactory._initialize_backends()`
3. Update plugin manifest with new dependencies
4. Add tests and documentation

### Custom Authentication Handlers
```python
class CustomAuthBackend(ConversionBackendInterface):
    async def convert_spec(self, api_spec, options):
        # Custom authentication logic
        return mcp_server_config
```

### Testing
```bash
# Run plugin tests
PLUGPIPE_DEMO_MODE=true ./pp run api2mcp_factory --input test_config.json

# Comprehensive testing
./pp run intelligent_test_agent --input comprehensive_test.json
```

## Contributing

1. Follow PlugPipe development guidelines in `CLAUDE.md`
2. Use existing components wherever possible ("reuse everything, reinvent nothing")
3. Add comprehensive tests for new features
4. Update SBOM and documentation
5. Validate plugin compliance with PlugPipe standards

## License

This plugin is part of the PlugPipe ecosystem and follows the PlugPipe license terms.

## Support

- **Documentation**: See PlugPipe docs and this README
- **Issues**: Report via PlugPipe issue tracking
- **Community**: PlugPipe development community
- **Enterprise**: Contact PlugPipe enterprise support

---

**Built with ❤️ following PlugPipe principles: "Reuse everything, reinvent nothing."**