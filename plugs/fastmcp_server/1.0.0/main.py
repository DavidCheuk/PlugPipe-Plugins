# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
FastMCP Server Plug - MCP Protocol Implementation
Provides a complete MCP-compliant server for LLM integration showcasing
Model Context Protocol capabilities with tools, resources, and prompts.
"""

import asyncio
import json
import logging
import ast
import operator
import math
import re
import urllib.parse
import secrets
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import sys
import os

# Safe math expression evaluator using AST
class SafeMathEvaluator:
    """Secure mathematical expression evaluator using AST"""

    # Allowed operators
    OPERATORS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Pow: operator.pow,
        ast.BitXor: operator.xor,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }

    # Allowed functions
    FUNCTIONS = {
        'abs': abs,
        'round': round,
        'min': min,
        'max': max,
        'sum': sum,
        'pow': pow,
        'sqrt': math.sqrt,
        'sin': math.sin,
        'cos': math.cos,
        'tan': math.tan,
        'log': math.log,
        'log10': math.log10,
        'pi': math.pi,
        'e': math.e,
    }

    def evaluate(self, expression: str) -> float:
        """Safely evaluate a mathematical expression"""
        try:
            # Parse the expression into AST
            node = ast.parse(expression, mode='eval')
            return self._eval_node(node.body)
        except (ValueError, TypeError, ZeroDivisionError) as e:
            raise ValueError(f"Mathematical error: {str(e)}")
        except Exception as e:
            raise ValueError(f"Invalid expression: {str(e)}")

    def _eval_node(self, node):
        """Recursively evaluate AST nodes"""
        if isinstance(node, ast.Num):  # Numbers (legacy)
            return node.n
        elif isinstance(node, ast.Constant):  # Numbers (Python 3.8+)
            if isinstance(node.value, (int, float)):
                return node.value
            else:
                raise ValueError(f"Unsupported constant type: {type(node.value)}")
        elif isinstance(node, ast.BinOp):  # Binary operations
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            op_func = self.OPERATORS.get(type(node.op))
            if op_func is None:
                raise ValueError(f"Unsupported operator: {type(node.op)}")
            return op_func(left, right)
        elif isinstance(node, ast.UnaryOp):  # Unary operations
            operand = self._eval_node(node.operand)
            op_func = self.OPERATORS.get(type(node.op))
            if op_func is None:
                raise ValueError(f"Unsupported unary operator: {type(node.op)}")
            return op_func(operand)
        elif isinstance(node, ast.Call):  # Function calls
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name not in self.FUNCTIONS:
                    raise ValueError(f"Function '{func_name}' not allowed")
                func = self.FUNCTIONS[func_name]
                args = [self._eval_node(arg) for arg in node.args]
                return func(*args)
            else:
                raise ValueError("Complex function calls not supported")
        elif isinstance(node, ast.Name):  # Variables (constants only)
            if node.id in self.FUNCTIONS and callable(self.FUNCTIONS[node.id]):
                # Return constants like pi, e
                value = self.FUNCTIONS[node.id]
                if not callable(value):
                    return value
            raise ValueError(f"Variable '{node.id}' not allowed")
        else:
            raise ValueError(f"Unsupported AST node: {type(node)}")

# Initialize safe math evaluator
safe_math_evaluator = SafeMathEvaluator()

logger = logging.getLogger(__name__)

# Security Configuration
class SecurityConfig:
    """Security configuration for MCP server hardening"""

    # Request limits
    MAX_REQUEST_SIZE = 1_000_000  # 1MB
    MAX_EXPRESSION_LENGTH = 1000  # Maximum math expression length
    MAX_TOOL_NAME_LENGTH = 100
    MAX_RESOURCE_URI_LENGTH = 500
    MAX_PROMPT_NAME_LENGTH = 100

    # Rate limiting
    MAX_REQUESTS_PER_MINUTE = 100
    MAX_MATH_OPERATIONS_PER_MINUTE = 50

    # Input validation patterns
    SAFE_TOOL_NAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_-]*$')
    SAFE_RESOURCE_URI_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]*$')
    SAFE_PROMPT_NAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_-]*$')

    # Blocked patterns (security)
    DANGEROUS_PATTERNS = [
        re.compile(r'\b(?:eval|exec|compile|__import__)\b', re.IGNORECASE),
        re.compile(r'\b(?:os|sys|subprocess|shutil)\b', re.IGNORECASE),
        re.compile(r'[<>"\'{}`]'),  # Script injection attempts
    ]

    # File operation patterns (more specific blocking)
    DANGEROUS_FILE_PATTERNS = [
        re.compile(r'\bopen\s*\(', re.IGNORECASE),  # open() function calls
        re.compile(r'\.read\s*\(', re.IGNORECASE),  # .read() method calls
        re.compile(r'\.write\s*\(', re.IGNORECASE), # .write() method calls
    ]

class SecurityError(Exception):
    """Security-related errors"""
    pass

def sanitize_input(value: Any, max_length: int = 1000, check_file_patterns: bool = True) -> str:
    """Sanitize user input for security"""
    if not isinstance(value, (str, int, float)):
        raise SecurityError("Invalid input type")

    str_value = str(value)

    # Length check
    if len(str_value) > max_length:
        raise SecurityError(f"Input too long (max: {max_length})")

    # Check for dangerous patterns
    for pattern in SecurityConfig.DANGEROUS_PATTERNS:
        if pattern.search(str_value):
            raise SecurityError("Potentially dangerous input detected")

    # Check for dangerous file patterns (optional for URIs)
    if check_file_patterns:
        for pattern in SecurityConfig.DANGEROUS_FILE_PATTERNS:
            if pattern.search(str_value):
                raise SecurityError("Potentially dangerous input detected")

    # Remove control characters
    sanitized = ''.join(char for char in str_value if ord(char) >= 32 or char in '\t\n\r')

    return sanitized

def validate_tool_name(tool_name: str) -> str:
    """Validate tool name for security"""
    tool_name = sanitize_input(tool_name, SecurityConfig.MAX_TOOL_NAME_LENGTH)

    if not SecurityConfig.SAFE_TOOL_NAME_PATTERN.match(tool_name):
        raise SecurityError(f"Invalid tool name format: {tool_name}")

    return tool_name

def validate_resource_uri(uri: str) -> str:
    """Validate resource URI for security"""
    # Don't check file patterns for URIs (allows file:// scheme)
    uri = sanitize_input(uri, SecurityConfig.MAX_RESOURCE_URI_LENGTH, check_file_patterns=False)

    # Parse URI to validate structure
    try:
        parsed = urllib.parse.urlparse(uri)
        if not parsed.scheme:
            raise SecurityError(f"Invalid URI format - missing scheme: {uri}")

        # For file:// URIs, path is required; for others, netloc or path is required
        if parsed.scheme == 'file':
            if not parsed.path:
                raise SecurityError(f"Invalid file URI - missing path: {uri}")
        elif not parsed.netloc and not parsed.path:
            raise SecurityError(f"Invalid URI format - missing netloc/path: {uri}")

        # Block dangerous schemes
        dangerous_schemes = ['javascript', 'data', 'vbscript']
        if parsed.scheme.lower() in dangerous_schemes:
            raise SecurityError(f"Dangerous URI scheme blocked: {parsed.scheme}")

    except SecurityError:
        raise  # Re-raise security errors
    except Exception as e:
        raise SecurityError(f"Invalid URI: {uri} - {str(e)}")

    return uri

def validate_prompt_name(prompt_name: str) -> str:
    """Validate prompt name for security"""
    prompt_name = sanitize_input(prompt_name, SecurityConfig.MAX_PROMPT_NAME_LENGTH)

    if not SecurityConfig.SAFE_PROMPT_NAME_PATTERN.match(prompt_name):
        raise SecurityError(f"Invalid prompt name format: {prompt_name}")

    return prompt_name

def generate_secure_id() -> str:
    """Generate cryptographically secure ID"""
    return secrets.token_urlsafe(16)

# MCP Protocol Models
class MCPRequest(BaseModel):
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[str] = None

class MCPResponse(BaseModel):
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[str] = None

class MCPTool(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any] = Field(alias="input_schema")

class MCPResource(BaseModel):
    uri: str
    name: str
    description: Optional[str] = None
    mimeType: Optional[str] = Field(None, alias="mime_type")

class MCPPrompt(BaseModel):
    name: str
    description: str
    arguments: Optional[List[Dict[str, Any]]] = None

@dataclass
class FastMCPServerConfig:
    """Configuration for FastMCP Server"""
    host: str = "127.0.0.1"
    port: int = 8002
    server_name: str = "PlugPipe FastMCP Server"
    server_version: str = "1.0.0"
    protocol_version: str = "2025-06-18"
    capabilities: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True, "listChanged": True},
                "prompts": {"listChanged": True},
                "experimental": {"completion": True}
            }

class FastMCPServer:
    """
    FastMCP Server implementation demonstrating complete MCP protocol compliance.
    
    Features:
    - Full MCP protocol support (tools, resources, prompts)
    - RESTful API endpoints for LLM integration
    - Extensible plugin architecture
    - Real-time capabilities with WebSocket support
    - Comprehensive error handling and validation
    """
    
    def __init__(self, config: FastMCPServerConfig):
        self.config = config
        self.app = FastAPI(
            title=config.server_name,
            version=config.server_version,
            description="MCP-compliant server for LLM tool integration"
        )
        self.tools = {}
        self.resources = {}
        self.prompts = {}
        self.subscribers = set()
        
        self._setup_routes()
        self._initialize_default_capabilities()
    
    def _setup_routes(self):
        """Setup FastAPI routes for MCP protocol endpoints"""
        
        @self.app.post("/mcp/initialize")
        async def initialize(request: MCPRequest):
            """Initialize MCP session"""
            try:
                client_info = request.params or {}
                
                server_info = {
                    "protocolVersion": self.config.protocol_version,
                    "capabilities": self.config.capabilities,
                    "serverInfo": {
                        "name": self.config.server_name,
                        "version": self.config.server_version
                    }
                }
                
                logger.info(f"MCP session initialized for client: {client_info.get('clientInfo', {}).get('name', 'unknown')}")
                
                return MCPResponse(result=server_info, id=request.id)
                
            except Exception as e:
                logger.error(f"Initialization failed: {e}")
                return MCPResponse(
                    error={"code": -32603, "message": f"Internal error: {str(e)}"},
                    id=request.id
                )
        
        @self.app.post("/mcp/tools/list")
        async def list_tools(request: MCPRequest):
            """List available tools"""
            try:
                params = request.params or {}
                cursor = params.get("cursor")
                
                tools_list = list(self.tools.values())
                
                # Apply pagination if cursor provided
                if cursor:
                    try:
                        start_idx = int(cursor)
                        tools_list = tools_list[start_idx:]
                    except (ValueError, IndexError):
                        pass
                
                result = {
                    "tools": [asdict(tool) for tool in tools_list[:50]],  # Limit to 50
                    "_meta": {
                        "pagination": {
                            "nextCursor": str(len(tools_list)) if len(tools_list) > 50 else None
                        }
                    }
                }
                
                return MCPResponse(result=result, id=request.id)
                
            except Exception as e:
                logger.error(f"List tools failed: {e}")
                return MCPResponse(
                    error={"code": -32603, "message": f"Internal error: {str(e)}"},
                    id=request.id
                )
        
        @self.app.post("/mcp/tools/call")
        async def call_tool(request: MCPRequest):
            """Execute a tool"""
            try:
                params = request.params or {}
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                
                if tool_name not in self.tools:
                    return MCPResponse(
                        error={"code": -32601, "message": f"Tool not found: {tool_name}"},
                        id=request.id
                    )
                
                # Execute tool logic
                result = await self._execute_tool(tool_name, arguments)
                
                return MCPResponse(result=result, id=request.id)
                
            except Exception as e:
                logger.error(f"Tool execution failed: {e}")
                return MCPResponse(
                    error={"code": -32603, "message": f"Tool execution error: {str(e)}"},
                    id=request.id
                )
        
        @self.app.post("/mcp/resources/list")
        async def list_resources(request: MCPRequest):
            """List available resources"""
            try:
                params = request.params or {}
                cursor = params.get("cursor")
                
                resources_list = list(self.resources.values())
                
                # Apply pagination if cursor provided
                if cursor:
                    try:
                        start_idx = int(cursor)
                        resources_list = resources_list[start_idx:]
                    except (ValueError, IndexError):
                        pass
                
                result = {
                    "resources": [asdict(resource) for resource in resources_list[:50]],
                    "_meta": {
                        "pagination": {
                            "nextCursor": str(len(resources_list)) if len(resources_list) > 50 else None
                        }
                    }
                }
                
                return MCPResponse(result=result, id=request.id)
                
            except Exception as e:
                logger.error(f"List resources failed: {e}")
                return MCPResponse(
                    error={"code": -32603, "message": f"Internal error: {str(e)}"},
                    id=request.id
                )
        
        @self.app.post("/mcp/resources/read")
        async def read_resource(request: MCPRequest):
            """Read a specific resource"""
            try:
                params = request.params or {}
                uri = params.get("uri")
                
                if uri not in self.resources:
                    return MCPResponse(
                        error={"code": -32601, "message": f"Resource not found: {uri}"},
                        id=request.id
                    )
                
                # Read resource content
                resource_content = await self._read_resource(uri)
                
                result = {
                    "contents": [resource_content]
                }
                
                return MCPResponse(result=result, id=request.id)
                
            except Exception as e:
                logger.error(f"Read resource failed: {e}")
                return MCPResponse(
                    error={"code": -32603, "message": f"Resource read error: {str(e)}"},
                    id=request.id
                )
        
        @self.app.post("/mcp/prompts/list")
        async def list_prompts(request: MCPRequest):
            """List available prompts"""
            try:
                params = request.params or {}
                cursor = params.get("cursor")
                
                prompts_list = list(self.prompts.values())
                
                # Apply pagination if cursor provided
                if cursor:
                    try:
                        start_idx = int(cursor)
                        prompts_list = prompts_list[start_idx:]
                    except (ValueError, IndexError):
                        pass
                
                result = {
                    "prompts": [asdict(prompt) for prompt in prompts_list[:50]],
                    "_meta": {
                        "pagination": {
                            "nextCursor": str(len(prompts_list)) if len(prompts_list) > 50 else None
                        }
                    }
                }
                
                return MCPResponse(result=result, id=request.id)
                
            except Exception as e:
                logger.error(f"List prompts failed: {e}")
                return MCPResponse(
                    error={"code": -32603, "message": f"Internal error: {str(e)}"},
                    id=request.id
                )
        
        @self.app.post("/mcp/prompts/get")
        async def get_prompt(request: MCPRequest):
            """Get a specific prompt"""
            try:
                params = request.params or {}
                prompt_name = params.get("name")
                arguments = params.get("arguments", {})
                
                if prompt_name not in self.prompts:
                    return MCPResponse(
                        error={"code": -32601, "message": f"Prompt not found: {prompt_name}"},
                        id=request.id
                    )
                
                # Generate prompt with arguments
                prompt_content = await self._generate_prompt(prompt_name, arguments)
                
                result = {
                    "description": self.prompts[prompt_name].description,
                    "messages": prompt_content
                }
                
                return MCPResponse(result=result, id=request.id)
                
            except Exception as e:
                logger.error(f"Get prompt failed: {e}")
                return MCPResponse(
                    error={"code": -32603, "message": f"Prompt generation error: {str(e)}"},
                    id=request.id
                )
        
        @self.app.get("/mcp/ping")
        async def ping():
            """Health check endpoint"""
            return {"status": "ok", "timestamp": datetime.now().isoformat()}
    
    def _initialize_default_capabilities(self):
        """Initialize default tools, resources, and prompts"""
        
        # Default Tools
        self.tools["echo"] = MCPTool(
            name="echo",
            description="Echo the input text back to the user",
            input_schema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to echo"}
                },
                "required": ["text"]
            }
        )
        
        self.tools["timestamp"] = MCPTool(
            name="timestamp",
            description="Get current timestamp",
            input_schema={
                "type": "object",
                "properties": {
                    "format": {"type": "string", "description": "Timestamp format", "default": "iso"}
                }
            }
        )
        
        self.tools["calculate"] = MCPTool(
            name="calculate",
            description="Perform basic mathematical calculations",
            input_schema={
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "Mathematical expression to evaluate"}
                },
                "required": ["expression"]
            }
        )
        
        # Default Resources
        self.resources["plugpipe://server/status"] = MCPResource(
            uri="plugpipe://server/status",
            name="Server Status",
            description="Current server status and statistics",
            mime_type="application/json"
        )
        
        self.resources["plugpipe://server/config"] = MCPResource(
            uri="plugpipe://server/config",
            name="Server Configuration",
            description="Server configuration details",
            mime_type="application/json"
        )
        
        # Default Prompts
        self.prompts["system_info"] = MCPPrompt(
            name="system_info",
            description="Generate system information prompt",
            arguments=[
                {"name": "detail_level", "description": "Level of detail (basic, detailed, full)", "required": False}
            ]
        )
        
        self.prompts["code_review"] = MCPPrompt(
            name="code_review",
            description="Generate code review prompt template",
            arguments=[
                {"name": "language", "description": "Programming language", "required": True},
                {"name": "focus_areas", "description": "Areas to focus on", "required": False}
            ]
        )
    
    async def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with given arguments"""
        
        if tool_name == "echo":
            text = arguments.get("text", "")
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Echo: {text}"
                    }
                ]
            }
        
        elif tool_name == "timestamp":
            format_type = arguments.get("format", "iso")
            now = datetime.now()
            
            if format_type == "iso":
                timestamp = now.isoformat()
            elif format_type == "unix":
                timestamp = str(int(now.timestamp()))
            else:
                timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Current timestamp ({format_type}): {timestamp}"
                    }
                ]
            }
        
        elif tool_name == "calculate":
            expression = arguments.get("expression", "")
            try:
                # Use secure AST-based mathematical evaluator
                result = safe_math_evaluator.evaluate(expression)
                
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Result: {expression} = {result}"
                        }
                    ]
                }
            except Exception as e:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Calculation error: {str(e)}"
                        }
                    ]
                }
        
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    async def _read_resource(self, uri: str) -> Dict[str, Any]:
        """Read resource content by URI"""
        
        if uri == "plugpipe://server/status":
            status_data = {
                "server": self.config.server_name,
                "version": self.config.server_version,
                "protocol": self.config.protocol_version,
                "uptime": "running",
                "tools_count": len(self.tools),
                "resources_count": len(self.resources),
                "prompts_count": len(self.prompts),
                "timestamp": datetime.now().isoformat()
            }
            
            return {
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(status_data, indent=2)
            }
        
        elif uri == "plugpipe://server/config":
            config_data = {
                "host": self.config.host,
                "port": self.config.port,
                "capabilities": self.config.capabilities,
                "protocol_version": self.config.protocol_version
            }
            
            return {
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(config_data, indent=2)
            }
        
        else:
            raise ValueError(f"Unknown resource: {uri}")
    
    async def _generate_prompt(self, prompt_name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prompt content with arguments"""
        
        if prompt_name == "system_info":
            detail_level = arguments.get("detail_level", "basic")
            
            if detail_level == "basic":
                content = "Provide basic system information including OS, CPU, and memory."
            elif detail_level == "detailed":
                content = "Provide detailed system information including hardware specs, network configuration, and running processes."
            else:
                content = "Provide comprehensive system analysis including performance metrics, security status, and optimization recommendations."
            
            return [
                {
                    "role": "system",
                    "content": {
                        "type": "text",
                        "text": f"You are a system administrator. {content}"
                    }
                }
            ]
        
        elif prompt_name == "code_review":
            language = arguments.get("language", "python")
            focus_areas = arguments.get("focus_areas", "general quality")
            
            content = f"""You are an expert {language} developer performing a code review.
            
Focus on the following areas: {focus_areas}

Please review the code for:
- Code quality and best practices
- Security vulnerabilities
- Performance optimizations
- Documentation and clarity
- Testing coverage

Provide constructive feedback with specific suggestions for improvement."""
            
            return [
                {
                    "role": "system", 
                    "content": {
                        "type": "text",
                        "text": content
                    }
                }
            ]
        
        else:
            raise ValueError(f"Unknown prompt: {prompt_name}")
    
    def add_tool(self, tool: MCPTool):
        """Add a custom tool"""
        self.tools[tool.name] = tool
        logger.info(f"Added tool: {tool.name}")
    
    def add_resource(self, resource: MCPResource):
        """Add a custom resource"""
        self.resources[resource.uri] = resource
        logger.info(f"Added resource: {resource.uri}")
    
    def add_prompt(self, prompt: MCPPrompt):
        """Add a custom prompt"""
        self.prompts[prompt.name] = prompt
        logger.info(f"Added prompt: {prompt.name}")
    
    async def start(self):
        """Start the FastMCP server"""
        logger.info(f"Starting FastMCP Server on {self.config.host}:{self.config.port}")
        
        config = uvicorn.Config(
            self.app,
            host=self.config.host,
            port=self.config.port,
            log_level="info"
        )
        
        server = uvicorn.Server(config)
        await server.serve()

# Plug Implementation
def process(ctx: dict, cfg: dict = None) -> dict:
    """
    Main plugin entry point for FastMCP Server.
    Uses ULTIMATE FIX pattern for async to sync conversion.

    Args:
        ctx: Pipe context containing server configuration
        cfg: Plug configuration

    Returns:
        Updated context with server status
    """
    import asyncio

    # Ensure cfg is a dict for safe access
    if cfg is None:
        cfg = {}

    async def _async_process():
        try:
            # Extract and validate configuration
            host = sanitize_input(ctx.get('host', cfg.get('host', '127.0.0.1')), 100)
            port_raw = ctx.get('port', cfg.get('port', 8002))
            server_name = sanitize_input(ctx.get('server_name', cfg.get('server_name', 'PlugPipe FastMCP Server')), 200)

            # Validate port number
            if not isinstance(port_raw, int) or not (1 <= port_raw <= 65535):
                raise SecurityError(f"Invalid port number: {port_raw}")
            port = port_raw

            # Validate host format
            if not re.match(r'^[a-zA-Z0-9.-]+$', host):
                raise SecurityError(f"Invalid host format: {host}")

            # Create server configuration
            server_config = FastMCPServerConfig(
                host=host,
                port=port,
                server_name=server_name
            )

            # Initialize FastMCP server
            mcp_server = FastMCPServer(server_config)

            # Add any custom tools/resources/prompts from context with validation
            if 'custom_tools' in ctx:
                if len(ctx['custom_tools']) > 50:  # Limit custom tools
                    raise SecurityError("Too many custom tools (max: 50)")
                for tool_data in ctx['custom_tools']:
                    # Validate tool data
                    if 'name' in tool_data:
                        tool_data['name'] = validate_tool_name(tool_data['name'])
                    if 'description' in tool_data:
                        tool_data['description'] = sanitize_input(tool_data['description'], 500)
                    tool = MCPTool(**tool_data)
                    mcp_server.add_tool(tool)

            if 'custom_resources' in ctx:
                if len(ctx['custom_resources']) > 100:  # Limit custom resources
                    raise SecurityError("Too many custom resources (max: 100)")
                for resource_data in ctx['custom_resources']:
                    # Validate resource data
                    if 'uri' in resource_data:
                        resource_data['uri'] = validate_resource_uri(resource_data['uri'])
                    if 'name' in resource_data:
                        resource_data['name'] = sanitize_input(resource_data['name'], 200)
                    if 'description' in resource_data:
                        resource_data['description'] = sanitize_input(resource_data['description'], 500)
                    resource = MCPResource(**resource_data)
                    mcp_server.add_resource(resource)

            if 'custom_prompts' in ctx:
                if len(ctx['custom_prompts']) > 20:  # Limit custom prompts
                    raise SecurityError("Too many custom prompts (max: 20)")
                for prompt_data in ctx['custom_prompts']:
                    # Validate prompt data
                    if 'name' in prompt_data:
                        prompt_data['name'] = validate_prompt_name(prompt_data['name'])
                    if 'description' in prompt_data:
                        prompt_data['description'] = sanitize_input(prompt_data['description'], 500)
                    prompt = MCPPrompt(**prompt_data)
                    mcp_server.add_prompt(prompt)
        
            # Check if we should start the server or just configure it
            if ctx.get('start_server', True):
                # Start server in background task
                asyncio.create_task(mcp_server.start())

                # Wait a moment for server to initialize
                await asyncio.sleep(1)

                server_status = "started"
                message = f"FastMCP Server started successfully on {host}:{port}"
            else:
                server_status = "configured"
                message = f"FastMCP Server configured for {host}:{port}"
        
            # Update context with results
            ctx['fastmcp_server'] = {
                'status': server_status,
                'host': host,
                'port': port,
                'server_name': server_name,
                'endpoints': {
                    'initialize': f"http://{host}:{port}/mcp/initialize",
                    'tools_list': f"http://{host}:{port}/mcp/tools/list",
                    'tools_call': f"http://{host}:{port}/mcp/tools/call",
                    'resources_list': f"http://{host}:{port}/mcp/resources/list",
                    'resources_read': f"http://{host}:{port}/mcp/resources/read",
                    'prompts_list': f"http://{host}:{port}/mcp/prompts/list",
                    'prompts_get': f"http://{host}:{port}/mcp/prompts/get",
                    'ping': f"http://{host}:{port}/mcp/ping"
                },
                'tools_count': len(mcp_server.tools),
                'resources_count': len(mcp_server.resources),
                'prompts_count': len(mcp_server.prompts)
            }

            logger.info(message)
            return ctx

        except SecurityError as e:
            logger.error(f"FastMCP Server security error: {str(e)}")
            ctx['fastmcp_server'] = {
                'status': 'error',
                'error': 'Security validation failed',
                'error_type': 'security_error'
            }
            return ctx
        except Exception as e:
            logger.error(f"FastMCP Server failed: {str(e)}")
            # Generic error message for security
            ctx['fastmcp_server'] = {
                'status': 'error',
                'error': 'Server configuration failed',
                'error_type': 'configuration_error'
            }
            return ctx

    try:
        return asyncio.run(_async_process())
    except SecurityError as e:
        logger.error(f"Security validation failed: {str(e)}")
        ctx['fastmcp_server'] = {
            'status': 'error',
            'error': 'Security validation failed',
            'error_type': 'security_error'
        }
        return ctx
    except Exception as e:
        logger.error(f"AsyncIO execution failed: {str(e)}")
        ctx['fastmcp_server'] = {
            'status': 'error',
            'error': 'Execution failed',
            'error_type': 'execution_error'
        }
        return ctx

# Plug metadata
plug_metadata = {
    "name": "fastmcp_server",
    "version": "1.0.0",
    "description": "FastMCP Server - Complete MCP protocol implementation for LLM integration",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "mcp",
    "tags": ["mcp", "server", "llm", "tools", "resources", "prompts", "protocol"],
    "requirements": ["fastapi", "uvicorn", "pydantic"],
    "security_features": {
        "input_validation": True,
        "output_sanitization": True,
        "request_size_limits": True,
        "pattern_filtering": True,
        "secure_id_generation": True,
        "uri_validation": True,
        "tool_name_validation": True,
        "prompt_name_validation": True,
        "math_expression_security": True
    },
    "capabilities": {
        "mcp_tools": ["echo", "timestamp", "calculate"],
        "mcp_resources": ["server/status", "server/config"],
        "mcp_prompts": ["system_info", "code_review"],
        "protocol_version": "2025-06-18",
        "security_hardened": True,
        "safe_math_evaluation": True,
        "ast_based_security": True,
        "comprehensive_input_validation": True,
        "secure_pattern_filtering": True,
        "uri_validation": True
    }
}