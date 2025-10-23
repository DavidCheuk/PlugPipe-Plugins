#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Terraform Infrastructure as Code Plugin

Provides comprehensive Terraform integration for universal infrastructure management
across multiple cloud providers and platforms with enterprise-grade features.

Key Features:
- Multi-cloud Terraform operations (AWS, GCP, Azure, etc.)
- State management and remote backends
- Plan analysis and cost estimation
- Workspace management
- Module operations
- Compliance and policy validation
- Enterprise security integration
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import yaml
import shutil

logger = logging.getLogger(__name__)

class TerraformWorkspace:
    """Manages Terraform workspace operations."""
    
    def __init__(self, workspace_dir: str, config: Dict[str, Any]):
        self.workspace_dir = workspace_dir
        self.config = config
        self.workspace_name = config.get('workspace', 'default')
        self.backend_config = config.get('backend', {})
        self.variables = config.get('variables', {})
        self.initialized = False
        
    async def initialize(self) -> bool:
        """Initialize Terraform workspace."""
        try:
            # Ensure workspace directory exists
            os.makedirs(self.workspace_dir, exist_ok=True)
            
            # Initialize Terraform
            init_cmd = ['terraform', 'init']
            
            # Add backend configuration if provided
            if self.backend_config:
                for key, value in self.backend_config.items():
                    init_cmd.extend(['-backend-config', f'{key}={value}'])
            
            result = await self._run_terraform_command(init_cmd)
            if not result['success']:
                return False
            
            # Select or create workspace
            if self.workspace_name != 'default':
                await self._ensure_workspace()
            
            self.initialized = True
            logger.info(f"Terraform workspace '{self.workspace_name}' initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Terraform workspace: {e}")
            return False
    
    async def _ensure_workspace(self) -> bool:
        """Ensure workspace exists and is selected."""
        try:
            # List existing workspaces
            list_result = await self._run_terraform_command(['terraform', 'workspace', 'list'])
            
            if self.workspace_name not in list_result.get('output', ''):
                # Create new workspace
                create_result = await self._run_terraform_command(
                    ['terraform', 'workspace', 'new', self.workspace_name]
                )
                if not create_result['success']:
                    return False
            else:
                # Select existing workspace
                select_result = await self._run_terraform_command(
                    ['terraform', 'workspace', 'select', self.workspace_name]
                )
                if not select_result['success']:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to ensure workspace: {e}")
            return False
    
    async def _run_terraform_command(self, cmd: List[str], input_data: str = None) -> Dict[str, Any]:
        """Run Terraform command with proper error handling."""
        try:
            # Change to workspace directory
            original_dir = os.getcwd()
            os.chdir(self.workspace_dir)
            
            # Prepare environment
            env = os.environ.copy()
            env.update(self.config.get('environment_vars', {}))
            
            # Run command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await process.communicate(
                input=input_data.encode() if input_data else None
            )
            
            result = {
                'success': process.returncode == 0,
                'returncode': process.returncode,
                'output': stdout.decode() if stdout else '',
                'error': stderr.decode() if stderr else '',
                'command': ' '.join(cmd)
            }
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': ' '.join(cmd)
            }
        finally:
            # Restore original directory
            try:
                os.chdir(original_dir)
            except:
                pass
    
    async def plan(self, destroy: bool = False) -> Dict[str, Any]:
        """Generate Terraform execution plan."""
        try:
            cmd = ['terraform', 'plan', '-no-color', '-input=false']
            
            if destroy:
                cmd.append('-destroy')
            
            # Add variable files
            var_files = self.config.get('var_files', [])
            for var_file in var_files:
                cmd.extend(['-var-file', var_file])
            
            # Add variables
            for key, value in self.variables.items():
                cmd.extend(['-var', f'{key}={value}'])
            
            # Save plan to file
            plan_file = os.path.join(self.workspace_dir, 'terraform.tfplan')
            cmd.extend(['-out', plan_file])
            
            result = await self._run_terraform_command(cmd)
            
            if result['success']:
                # Parse plan output for analysis
                analysis = await self._analyze_plan_output(result['output'])
                result.update(analysis)
                result['plan_file'] = plan_file
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _analyze_plan_output(self, plan_output: str) -> Dict[str, Any]:
        """Analyze Terraform plan output."""
        analysis = {
            'resources_to_add': 0,
            'resources_to_change': 0,
            'resources_to_destroy': 0,
            'total_resources': 0,
            'has_changes': False,
            'estimated_cost': None,
            'security_findings': []
        }
        
        try:
            # Parse plan summary
            lines = plan_output.split('\n')
            for line in lines:
                if 'to add' in line and 'to change' in line and 'to destroy' in line:
                    # Extract numbers from plan summary
                    import re
                    numbers = re.findall(r'(\d+)', line)
                    if len(numbers) >= 3:
                        analysis['resources_to_add'] = int(numbers[0])
                        analysis['resources_to_change'] = int(numbers[1]) 
                        analysis['resources_to_destroy'] = int(numbers[2])
                        analysis['total_resources'] = sum([
                            analysis['resources_to_add'],
                            analysis['resources_to_change'],
                            analysis['resources_to_destroy']
                        ])
                        analysis['has_changes'] = analysis['total_resources'] > 0
                        break
            
            # Basic security analysis
            security_keywords = ['public', 'open', '0.0.0.0/0', 'admin', 'root']
            for keyword in security_keywords:
                if keyword in plan_output.lower():
                    analysis['security_findings'].append({
                        'type': 'potential_security_risk',
                        'description': f'Found {keyword} in plan output',
                        'severity': 'medium'
                    })
            
        except Exception as e:
            logger.warning(f"Failed to analyze plan output: {e}")
        
        return analysis
    
    async def apply(self, plan_file: str = None, auto_approve: bool = False) -> Dict[str, Any]:
        """Apply Terraform configuration."""
        try:
            cmd = ['terraform', 'apply', '-no-color', '-input=false']
            
            if auto_approve:
                cmd.append('-auto-approve')
            
            if plan_file and os.path.exists(plan_file):
                cmd.append(plan_file)
            else:
                # Add variable files and variables if not using plan file
                var_files = self.config.get('var_files', [])
                for var_file in var_files:
                    cmd.extend(['-var-file', var_file])
                
                for key, value in self.variables.items():
                    cmd.extend(['-var', f'{key}={value}'])
            
            result = await self._run_terraform_command(cmd)
            
            if result['success']:
                # Get outputs after successful apply
                outputs = await self.get_outputs()
                result['outputs'] = outputs
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def destroy(self, auto_approve: bool = False) -> Dict[str, Any]:
        """Destroy Terraform-managed infrastructure."""
        try:
            cmd = ['terraform', 'destroy', '-no-color', '-input=false']
            
            if auto_approve:
                cmd.append('-auto-approve')
            
            # Add variable files
            var_files = self.config.get('var_files', [])
            for var_file in var_files:
                cmd.extend(['-var-file', var_file])
            
            # Add variables
            for key, value in self.variables.items():
                cmd.extend(['-var', f'{key}={value}'])
            
            result = await self._run_terraform_command(cmd)
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def get_outputs(self) -> Dict[str, Any]:
        """Get Terraform outputs."""
        try:
            result = await self._run_terraform_command(['terraform', 'output', '-json'])
            
            if result['success'] and result['output']:
                return json.loads(result['output'])
            
            return {}
            
        except Exception as e:
            logger.error(f"Failed to get outputs: {e}")
            return {}
    
    async def get_state(self) -> Dict[str, Any]:
        """Get Terraform state information."""
        try:
            result = await self._run_terraform_command(['terraform', 'show', '-json'])
            
            if result['success'] and result['output']:
                return json.loads(result['output'])
            
            return {}
            
        except Exception as e:
            logger.error(f"Failed to get state: {e}")
            return {}
    
    async def validate(self) -> Dict[str, Any]:
        """Validate Terraform configuration."""
        try:
            result = await self._run_terraform_command(['terraform', 'validate', '-json'])
            
            if result['output']:
                validation_result = json.loads(result['output'])
                result['validation'] = validation_result
                result['is_valid'] = validation_result.get('valid', False)
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}


class TerraformPlugin:
    """
    Enterprise Terraform Plugin for universal infrastructure as code management.
    
    Provides comprehensive Terraform integration with multi-cloud support,
    state management, security analysis, and enterprise features.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.terraform_config = config.get('terraform', {})
        self.workspaces: Dict[str, TerraformWorkspace] = {}
        self.plugin_id = f"terraform_{uuid.uuid4().hex[:8]}"
        self.created_at = datetime.now()
        self.operations_count = 0
        
        # Terraform configuration
        self.terraform_version = self.terraform_config.get('version', 'latest')
        self.default_workspace = self.terraform_config.get('default_workspace', 'default')
        self.state_backend = self.terraform_config.get('state_backend', 'local')
        self.auto_approve = self.terraform_config.get('auto_approve', False)
        
        logger.info(f"Terraform Plugin initialized: {self.plugin_id}")
    
    @property
    def supported_operations(self) -> List[str]:
        """Get list of supported operations."""
        return [
            'init',
            'plan', 
            'apply',
            'destroy',
            'validate',
            'get_outputs',
            'get_state',
            'workspace_operations',
            'module_operations',
            'import_resource',
            'state_operations'
        ]
    
    async def process(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process Terraform operations.
        
        Args:
            ctx: Pipeline context
            config: Operation configuration
            
        Returns:
            Operation result
        """
        try:
            operation = config.get('operation', 'plan')
            workspace_name = config.get('workspace', self.default_workspace)
            
            # Initialize workspace if needed
            workspace = await self._get_or_create_workspace(workspace_name, config)
            if not workspace:
                return {'success': False, 'error': 'Failed to initialize workspace'}
            
            self.operations_count += 1
            
            if operation == 'init':
                return await self._handle_init(workspace, config)
            elif operation == 'plan':
                return await self._handle_plan(workspace, config)
            elif operation == 'apply':
                return await self._handle_apply(workspace, config)
            elif operation == 'destroy':
                return await self._handle_destroy(workspace, config)
            elif operation == 'validate':
                return await self._handle_validate(workspace, config)
            elif operation == 'get_outputs':
                return await self._handle_get_outputs(workspace, config)
            elif operation == 'get_state':
                return await self._handle_get_state(workspace, config)
            elif operation == 'workspace_operations':
                return await self._handle_workspace_operations(config)
            elif operation == 'module_operations':
                return await self._handle_module_operations(workspace, config)
            elif operation == 'import_resource':
                return await self._handle_import_resource(workspace, config)
            elif operation == 'state_operations':
                return await self._handle_state_operations(workspace, config)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported operation: {operation}',
                    'supported_operations': self.supported_operations
                }
        
        except Exception as e:
            logger.error(f"Terraform operation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _get_or_create_workspace(self, workspace_name: str, config: Dict[str, Any]) -> Optional[TerraformWorkspace]:
        """Get existing workspace or create new one."""
        try:
            if workspace_name in self.workspaces:
                return self.workspaces[workspace_name]
            
            # Create workspace directory
            workspace_dir = config.get('workspace_dir')
            if not workspace_dir:
                workspace_dir = os.path.join(tempfile.gettempdir(), f'terraform_{workspace_name}_{uuid.uuid4().hex[:8]}')
            
            # Prepare workspace configuration
            workspace_config = {
                'workspace': workspace_name,
                'backend': config.get('backend', {}),
                'variables': config.get('variables', {}),
                'var_files': config.get('var_files', []),
                'environment_vars': config.get('environment_vars', {})
            }
            
            # Create workspace
            workspace = TerraformWorkspace(workspace_dir, workspace_config)
            
            # Copy Terraform configuration files if provided
            terraform_files = config.get('terraform_files', {})
            if terraform_files:
                await self._setup_terraform_files(workspace_dir, terraform_files)
            
            # Initialize workspace
            if await workspace.initialize():
                self.workspaces[workspace_name] = workspace
                return workspace
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to create workspace: {e}")
            return None
    
    async def _setup_terraform_files(self, workspace_dir: str, terraform_files: Dict[str, str]) -> None:
        """Setup Terraform configuration files in workspace."""
        try:
            for filename, content in terraform_files.items():
                file_path = os.path.join(workspace_dir, filename)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                if isinstance(content, str):
                    with open(file_path, 'w') as f:
                        f.write(content)
                elif isinstance(content, dict):
                    with open(file_path, 'w') as f:
                        json.dump(content, f, indent=2)
        
        except Exception as e:
            logger.error(f"Failed to setup Terraform files: {e}")
    
    async def _handle_init(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform init operation."""
        try:
            # Workspace is already initialized, but we can reinitialize if requested
            force_init = config.get('force_init', False)
            
            if force_init or not workspace.initialized:
                success = await workspace.initialize()
                return {
                    'success': success,
                    'operation': 'init',
                    'workspace': workspace.workspace_name,
                    'message': 'Terraform workspace initialized successfully' if success else 'Failed to initialize workspace'
                }
            else:
                return {
                    'success': True,
                    'operation': 'init',
                    'workspace': workspace.workspace_name,
                    'message': 'Workspace already initialized'
                }
        
        except Exception as e:
            return {'success': False, 'operation': 'init', 'error': str(e)}
    
    async def _handle_plan(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform plan operation."""
        try:
            destroy = config.get('destroy', False)
            result = await workspace.plan(destroy=destroy)
            
            return {
                'success': result['success'],
                'operation': 'plan',
                'workspace': workspace.workspace_name,
                'plan_output': result.get('output', ''),
                'plan_file': result.get('plan_file'),
                'resources_to_add': result.get('resources_to_add', 0),
                'resources_to_change': result.get('resources_to_change', 0), 
                'resources_to_destroy': result.get('resources_to_destroy', 0),
                'has_changes': result.get('has_changes', False),
                'security_findings': result.get('security_findings', []),
                'error': result.get('error')
            }
        
        except Exception as e:
            return {'success': False, 'operation': 'plan', 'error': str(e)}
    
    async def _handle_apply(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform apply operation."""
        try:
            plan_file = config.get('plan_file')
            auto_approve = config.get('auto_approve', self.auto_approve)
            
            result = await workspace.apply(plan_file=plan_file, auto_approve=auto_approve)
            
            return {
                'success': result['success'],
                'operation': 'apply',
                'workspace': workspace.workspace_name,
                'apply_output': result.get('output', ''),
                'outputs': result.get('outputs', {}),
                'error': result.get('error')
            }
        
        except Exception as e:
            return {'success': False, 'operation': 'apply', 'error': str(e)}
    
    async def _handle_destroy(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform destroy operation.""" 
        try:
            auto_approve = config.get('auto_approve', False)  # Require explicit approval for destroy
            
            if not auto_approve:
                return {
                    'success': False,
                    'operation': 'destroy',
                    'error': 'Destroy operation requires explicit auto_approve=true for safety'
                }
            
            result = await workspace.destroy(auto_approve=auto_approve)
            
            return {
                'success': result['success'],
                'operation': 'destroy',
                'workspace': workspace.workspace_name,
                'destroy_output': result.get('output', ''),
                'error': result.get('error')
            }
        
        except Exception as e:
            return {'success': False, 'operation': 'destroy', 'error': str(e)}
    
    async def _handle_validate(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform validate operation."""
        try:
            result = await workspace.validate()
            
            return {
                'success': result['success'],
                'operation': 'validate',
                'workspace': workspace.workspace_name,
                'is_valid': result.get('is_valid', False),
                'validation_output': result.get('output', ''),
                'validation_details': result.get('validation', {}),
                'error': result.get('error')
            }
        
        except Exception as e:
            return {'success': False, 'operation': 'validate', 'error': str(e)}
    
    async def _handle_get_outputs(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get outputs operation."""
        try:
            outputs = await workspace.get_outputs()
            
            return {
                'success': True,
                'operation': 'get_outputs',
                'workspace': workspace.workspace_name,
                'outputs': outputs
            }
        
        except Exception as e:
            return {'success': False, 'operation': 'get_outputs', 'error': str(e)}
    
    async def _handle_get_state(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get state operation."""
        try:
            state = await workspace.get_state()
            
            return {
                'success': True,
                'operation': 'get_state',
                'workspace': workspace.workspace_name,
                'state': state
            }
        
        except Exception as e:
            return {'success': False, 'operation': 'get_state', 'error': str(e)}
    
    async def _handle_workspace_operations(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle workspace management operations."""
        try:
            workspace_operation = config.get('workspace_operation', 'list')
            
            if workspace_operation == 'list':
                return {
                    'success': True,
                    'operation': 'workspace_operations',
                    'workspace_operation': 'list',
                    'workspaces': list(self.workspaces.keys())
                }
            elif workspace_operation == 'delete':
                workspace_name = config.get('workspace_name')
                if workspace_name in self.workspaces:
                    del self.workspaces[workspace_name]
                    return {
                        'success': True,
                        'operation': 'workspace_operations',
                        'workspace_operation': 'delete',
                        'message': f'Workspace {workspace_name} deleted'
                    }
                else:
                    return {
                        'success': False,
                        'operation': 'workspace_operations',
                        'error': f'Workspace {workspace_name} not found'
                    }
            else:
                return {
                    'success': False,
                    'operation': 'workspace_operations',
                    'error': f'Unsupported workspace operation: {workspace_operation}'
                }
        
        except Exception as e:
            return {'success': False, 'operation': 'workspace_operations', 'error': str(e)}
    
    async def _handle_module_operations(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform module operations."""
        try:
            module_operation = config.get('module_operation', 'get')
            
            if module_operation == 'get':
                result = await workspace._run_terraform_command(['terraform', 'get', '-update'])
                return {
                    'success': result['success'],
                    'operation': 'module_operations',
                    'module_operation': 'get',
                    'output': result.get('output', ''),
                    'error': result.get('error')
                }
            else:
                return {
                    'success': False,
                    'operation': 'module_operations',
                    'error': f'Unsupported module operation: {module_operation}'
                }
        
        except Exception as e:
            return {'success': False, 'operation': 'module_operations', 'error': str(e)}
    
    async def _handle_import_resource(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform import operation."""
        try:
            resource_address = config.get('resource_address')
            resource_id = config.get('resource_id')
            
            if not resource_address or not resource_id:
                return {
                    'success': False,
                    'operation': 'import_resource',
                    'error': 'Both resource_address and resource_id are required'
                }
            
            result = await workspace._run_terraform_command([
                'terraform', 'import', resource_address, resource_id
            ])
            
            return {
                'success': result['success'],
                'operation': 'import_resource',
                'resource_address': resource_address,
                'resource_id': resource_id,
                'output': result.get('output', ''),
                'error': result.get('error')
            }
        
        except Exception as e:
            return {'success': False, 'operation': 'import_resource', 'error': str(e)}
    
    async def _handle_state_operations(self, workspace: TerraformWorkspace, config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Terraform state operations."""
        try:
            state_operation = config.get('state_operation', 'list')
            
            if state_operation == 'list':
                result = await workspace._run_terraform_command(['terraform', 'state', 'list'])
                return {
                    'success': result['success'],
                    'operation': 'state_operations',
                    'state_operation': 'list',
                    'resources': result.get('output', '').split('\n') if result.get('output') else [],
                    'error': result.get('error')
                }
            elif state_operation == 'show':
                resource_address = config.get('resource_address')
                if not resource_address:
                    return {
                        'success': False,
                        'operation': 'state_operations',
                        'error': 'resource_address required for state show operation'
                    }
                
                result = await workspace._run_terraform_command(['terraform', 'state', 'show', resource_address])
                return {
                    'success': result['success'],
                    'operation': 'state_operations',
                    'state_operation': 'show',
                    'resource_address': resource_address,
                    'resource_details': result.get('output', ''),
                    'error': result.get('error')
                }
            else:
                return {
                    'success': False,
                    'operation': 'state_operations',
                    'error': f'Unsupported state operation: {state_operation}'
                }
        
        except Exception as e:
            return {'success': False, 'operation': 'state_operations', 'error': str(e)}
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Terraform plugin health."""
        try:
            # Check if Terraform is available
            result = await asyncio.create_subprocess_exec(
                'terraform', 'version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            terraform_available = result.returncode == 0
            terraform_version = stdout.decode().strip() if terraform_available else None
            
            return {
                'healthy': terraform_available,
                'terraform_available': terraform_available,
                'terraform_version': terraform_version,
                'plugin_id': self.plugin_id,
                'workspaces_count': len(self.workspaces),
                'operations_count': self.operations_count,
                'uptime': str(datetime.now() - self.created_at),
                'supported_operations': self.supported_operations
            }
        
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e),
                'plugin_id': self.plugin_id
            }


# Plugin metadata
plug_metadata = {
    "name": "terraform",
    "version": "1.0.0",
    "owner": "PlugPipe Core Team",
    "status": "stable",
    "description": "Enterprise Terraform plugin for universal infrastructure as code management with multi-cloud support, state management, and security analysis",
    "capabilities": [
        "terraform_operations",
        "multi_cloud_infrastructure",
        "state_management",
        "plan_analysis", 
        "workspace_management",
        "module_operations",
        "security_analysis",
        "enterprise_features"
    ]
}

async def process_async(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Async process function for Terraform Plugin."""
    try:
        terraform_plugin = TerraformPlugin(config)
        
        operation = config.get('operation', 'plan')
        
        if operation == 'health_check':
            health_status = await terraform_plugin.health_check()
            return {
                'success': True,
                'operation_completed': 'health_check',
                'health_status': health_status
            }
        
        else:
            # Handle Terraform operations
            result = await terraform_plugin.process(ctx, config)
            return {
                'success': result.get('success', False),
                'operation_completed': operation,
                'result': result
            }
    
    except Exception as e:
        logger.error(f"Terraform Plugin error: {e}")
        return {
            'success': False,
            'error': str(e),
            'plugin_type': 'terraform'
        }

def process(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous wrapper for the async process function."""
    return asyncio.run(process_async(ctx, config))

if __name__ == "__main__":
    # Test the Terraform Plugin
    test_config = {
        'terraform': {
            'default_workspace': 'test',
            'auto_approve': False,
            'state_backend': 'local'
        },
        'operation': 'health_check'
    }
    
    result = process({}, test_config)
    print(json.dumps(result, indent=2))