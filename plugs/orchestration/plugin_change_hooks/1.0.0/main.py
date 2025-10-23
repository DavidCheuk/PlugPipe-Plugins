#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Plugin Change Hooks System
==========================

Auto-triggering hook system for plugin change validation that monitors plugin 
directory changes and automatically triggers the validation pipeline with 
issue tracking integration.

Features:
- Filesystem monitoring with configurable patterns
- Git hooks integration (pre-commit, post-commit, pre-push)
- Automatic validation pipeline triggering
- Issue tracker integration for results storage
- Configurable debouncing and validation scope
- Background async validation execution

Following PlugPipe principles:
- "Reuse everything, reinvent nothing" - leverages existing validation pipeline and issue tracker
- "Everything is a plugin" - integrates through plugin discovery system
- "Convention over configuration" - smart defaults with extensive configurability
"""

import os
import sys
import json
import time
import asyncio
import logging
import threading
import subprocess
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import fnmatch
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
sys.path.insert(0, PROJECT_ROOT)

try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
except ImportError:
    # Fallback for standalone execution
    def pp(plugin_name):
        return None
    def get_llm_config(primary=True):
        return {}

# Optional filesystem monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("⚠️ Watchdog not available - filesystem monitoring disabled. Install with: pip install watchdog")
    
    # Mock classes for when watchdog is not available
    class FileSystemEventHandler:
        def __init__(self):
            self.logger = logging.getLogger(__name__ + ".FallbackEventHandler")
            self.logger.warning("Using fallback event handler - install watchdog for real-time monitoring")

        def on_any_event(self, event):
            """Handle any filesystem event (fallback: log only)."""
            self.logger.info(f"File system event (fallback): {getattr(event, 'event_type', 'unknown')} on {getattr(event, 'src_path', 'unknown')}")
    
    class Observer:
        def __init__(self):
            self.running = False
        def schedule(self, handler, path, recursive=True):
            """Schedule handler for path (fallback mode - no real monitoring)."""
            logger = logging.getLogger(__name__ + ".FallbackObserver")
            logger.info(f"Scheduled fallback monitoring for: {path} (recursive={recursive})")
            logger.warning("Fallback mode: no real-time file monitoring - install watchdog for full functionality")
        def start(self):
            self.running = True
        def stop(self):
            self.running = False
        def join(self):
            """Join observer thread (fallback: log status)."""
            logger = logging.getLogger(__name__ + ".FallbackObserver")
            logger.debug(f"Observer join() called - running: {self.running}")

@dataclass
class ValidationTrigger:
    """Represents a validation trigger event."""
    trigger_id: str
    timestamp: datetime
    trigger_type: str  # filesystem_change, git_hook, manual
    target_plugin: str
    file_paths: List[str]
    change_type: str
    validation_id: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None

class PluginChangeHandler(FileSystemEventHandler):
    """File system event handler for plugin changes."""
    
    def __init__(self, hook_system):
        self.hook_system = hook_system
        
    def on_any_event(self, event):
        """Handle any filesystem event."""
        if event.is_directory:
            return
            
        # Check if file matches watch patterns
        file_path = event.src_path
        if self.hook_system._should_monitor_file(file_path):
            change_type = self._get_change_type(event)
            plugin_name = self.hook_system._extract_plugin_name(file_path)
            
            # Add to debounced changes
            self.hook_system._add_debounced_change(file_path, plugin_name, change_type)
    
    def _get_change_type(self, event) -> str:
        """Determine change type from event."""
        if isinstance(event, FileCreatedEvent):
            return "created"
        elif isinstance(event, FileDeletedEvent):
            return "deleted"
        elif isinstance(event, FileModifiedEvent):
            return "modified"
        else:
            return "unknown"

class PluginChangeHooks:
    """
    Plugin change hooks system for auto-triggering validation.
    
    Monitors plugin directory changes and automatically triggers validation
    pipeline with configurable debouncing and scope.
    """
    
    def __init__(self):
        self.session_id = str(uuid.uuid4())
        self.monitoring_active = False
        self.filesystem_observer = None
        self.git_hooks_installed = []
        
        # Monitoring state
        self.watch_paths = []
        self.watch_patterns = []
        self.ignore_patterns = []
        self.debounce_seconds = 5
        
        # Validation state
        self.validation_triggers = deque(maxlen=100)  # Keep last 100 triggers
        self.active_validations = {}
        self.debounced_changes = {}  # file_path -> (plugin, change_type, timestamp)
        self.debounce_timer = None
        
        # Configuration
        self.validation_config = {}
        self.git_hooks_config = {}
        
    async def process_operation(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for hook system operations."""
        try:
            operation = config.get('operation', 'start_monitoring')
            
            # Route to appropriate operation handler
            if operation == 'start_monitoring':
                return await self._start_monitoring(context, config)
            elif operation == 'stop_monitoring':
                return await self._stop_monitoring(context, config)
            elif operation == 'get_status':
                return await self._get_status(context, config)
            elif operation == 'setup_git_hooks':
                return await self._setup_git_hooks(context, config)
            elif operation == 'setup_filesystem_watch':
                return await self._setup_filesystem_watch(context, config)
            elif operation == 'trigger_validation':
                return await self._trigger_validation(context, config)
            elif operation == 'list_hooks':
                return await self._list_hooks(context, config)
            elif operation == 'remove_hooks':
                return await self._remove_hooks(context, config)
            else:
                return self._error_response(f"Unknown operation: {operation}")
                
        except Exception as e:
            return self._error_response(f"Hook system operation failed: {str(e)}")
    
    async def _start_monitoring(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Start the plugin change monitoring system."""
        try:
            # Load configuration
            monitoring_config = config.get('monitoring_config', {})
            self.validation_config = config.get('validation_config', {})
            self.git_hooks_config = config.get('git_hooks_config', {})
            
            # Configure monitoring parameters
            self.watch_paths = monitoring_config.get('watch_paths', ['plugs'])
            self.watch_patterns = monitoring_config.get('watch_patterns', ['*.py', '*.yaml', '*.yml', '*.json'])
            self.ignore_patterns = monitoring_config.get('ignore_patterns', ['__pycache__', '*.pyc', '.git', '*.tmp'])
            self.debounce_seconds = monitoring_config.get('debounce_seconds', 5)
            
            results = []
            
            # Setup filesystem watching if enabled
            if monitoring_config.get('enable_filesystem_watch', True):
                fs_result = await self._setup_filesystem_watch(context, {'monitoring_config': monitoring_config})
                results.append(('filesystem_watch', fs_result))
            
            # Setup git hooks if enabled
            if monitoring_config.get('enable_git_hooks', True):
                git_result = await self._setup_git_hooks(context, {'git_hooks_config': self.git_hooks_config})
                results.append(('git_hooks', git_result))
            
            # Run startup validation if enabled
            if monitoring_config.get('validation_on_startup', False):
                startup_result = await self._trigger_startup_validation(context)
                results.append(('startup_validation', startup_result))
            
            self.monitoring_active = True
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'start_monitoring',
                    'timestamp': datetime.utcnow().isoformat(),
                    'session_id': self.session_id,
                    'hooks_active': True
                },
                'monitoring_status': {
                    'filesystem_watch_active': self.filesystem_observer is not None and self.filesystem_observer.running if WATCHDOG_AVAILABLE else False,
                    'git_hooks_installed': self.git_hooks_installed,
                    'watch_paths': self.watch_paths,
                    'files_monitored': self._count_monitored_files(),
                    'triggers_executed': len(self.validation_triggers)
                },
                'setup_results': dict(results)
            }
            
        except Exception as e:
            return self._error_response(f"Failed to start monitoring: {str(e)}")
    
    async def _setup_filesystem_watch(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Setup filesystem monitoring for plugin changes."""
        if not WATCHDOG_AVAILABLE:
            return {
                'success': False,
                'error': 'Filesystem watching not available - install watchdog package',
                'watchdog_available': False
            }
        
        try:
            # Stop existing observer if running
            if self.filesystem_observer and self.filesystem_observer.running:
                self.filesystem_observer.stop()
                self.filesystem_observer.join()
            
            # Create new observer
            self.filesystem_observer = Observer()
            handler = PluginChangeHandler(self)
            
            # Schedule watching for each path
            paths_scheduled = []
            for watch_path in self.watch_paths:
                if os.path.exists(watch_path):
                    self.filesystem_observer.schedule(handler, watch_path, recursive=True)
                    paths_scheduled.append(watch_path)
                else:
                    print(f"Warning: Watch path does not exist: {watch_path}")
            
            # Start observer
            self.filesystem_observer.start()
            
            return {
                'success': True,
                'filesystem_watch_active': True,
                'paths_monitored': paths_scheduled,
                'files_monitored': self._count_monitored_files()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Failed to setup filesystem watch: {str(e)}",
                'filesystem_watch_active': False
            }
    
    async def _setup_git_hooks(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Setup git hooks for plugin change validation."""
        try:
            git_config = config.get('git_hooks_config', self.git_hooks_config)
            hooks_installed = []
            hooks_failed = []
            
            # Check if we're in a git repository
            if not os.path.exists('.git'):
                return {
                    'success': False,
                    'error': 'Not in a git repository - git hooks cannot be installed'
                }
            
            # Create hooks directory if it doesn't exist
            hooks_dir = Path('.git/hooks')
            hooks_dir.mkdir(exist_ok=True)
            
            # Install pre-commit hook
            if git_config.get('install_pre_commit', True):
                try:
                    self._install_git_hook('pre-commit', git_config)
                    hooks_installed.append('pre-commit')
                except Exception as e:
                    hooks_failed.append(f'pre-commit: {str(e)}')
            
            # Install post-commit hook
            if git_config.get('install_post_commit', False):
                try:
                    self._install_git_hook('post-commit', git_config)
                    hooks_installed.append('post-commit')
                except Exception as e:
                    hooks_failed.append(f'post-commit: {str(e)}')
            
            # Install pre-push hook
            if git_config.get('install_pre_push', True):
                try:
                    self._install_git_hook('pre-push', git_config)
                    hooks_installed.append('pre-push')
                except Exception as e:
                    hooks_failed.append(f'pre-push: {str(e)}')
            
            self.git_hooks_installed = hooks_installed
            
            return {
                'success': len(hooks_installed) > 0,
                'git_hooks_installed': hooks_installed,
                'git_hooks_failed': hooks_failed,
                'hooks_directory': str(hooks_dir)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Failed to setup git hooks: {str(e)}"
            }
    
    def _install_git_hook(self, hook_name: str, git_config: Dict[str, Any]):
        """Install a specific git hook."""
        hooks_dir = Path('.git/hooks')
        hook_path = hooks_dir / hook_name
        
        # Generate hook script
        hook_script = self._generate_hook_script(hook_name, git_config)
        
        # Write hook script
        with open(hook_path, 'w') as f:
            f.write(hook_script)
        
        # Make executable
        os.chmod(hook_path, 0o755)
    
    def _generate_hook_script(self, hook_name: str, git_config: Dict[str, Any]) -> str:
        """Generate git hook script content."""
        fail_on_error = git_config.get('fail_on_validation_error', False)
        
        # Use custom template if provided
        if 'hook_script_template' in git_config:
            return git_config['hook_script_template'].format(
                hook_name=hook_name,
                fail_on_error=fail_on_error
            )
        
        # Default hook script template
        script = f'''#!/bin/bash
# PlugPipe Plugin Change Hook - {hook_name}
# Auto-generated by plugin_change_hooks plugin

echo "🔍 PlugPipe: Running plugin validation ({hook_name})..."

# Run validation through plugin change hooks
cd "$(git rev-parse --show-toplevel)"

# Trigger validation via PlugPipe CLI
if command -v ./pp &> /dev/null; then
    ./pp run plugin_change_hooks --input '{{"operation": "trigger_validation", "trigger_options": {{"change_type": "git_{hook_name}", "validation_categories": ["all"]}}}}'
    exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo "✅ PlugPipe: Validation passed"
        exit 0
    else
        echo "❌ PlugPipe: Validation failed"
        {'exit $exit_code' if fail_on_error else 'echo "⚠️  PlugPipe: Continuing despite validation failure"'}
    fi
else
    echo "⚠️  PlugPipe: ./pp command not found, skipping validation"
fi

exit 0
'''
        return script
    
    async def _trigger_validation(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Manually trigger validation for specified plugins."""
        try:
            trigger_options = config.get('trigger_options', {})
            target_plugin = trigger_options.get('target_plugin', 'all')
            change_type = trigger_options.get('change_type', 'manual')
            force_validation = trigger_options.get('force_validation', False)
            
            # Create validation trigger
            trigger = ValidationTrigger(
                trigger_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                trigger_type='manual',
                target_plugin=target_plugin,
                file_paths=[],
                change_type=change_type
            )
            
            # Execute validation
            validation_result = await self._execute_validation(trigger, force_validation)
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'trigger_validation',
                    'timestamp': datetime.utcnow().isoformat(),
                    'trigger_id': trigger.trigger_id,
                    'validation_triggered': True
                },
                'validation_result': validation_result
            }
            
        except Exception as e:
            return self._error_response(f"Failed to trigger validation: {str(e)}")
    
    async def _execute_validation(self, trigger: ValidationTrigger, force: bool = False) -> Dict[str, Any]:
        """Execute validation pipeline for a trigger."""
        try:
            # Mark trigger as running
            trigger.status = "running"
            trigger.validation_id = str(uuid.uuid4())
            self.validation_triggers.append(trigger)
            self.active_validations[trigger.validation_id] = trigger
            
            start_time = time.time()
            
            # Get validation pipeline plugin
            validation_pipeline = pp('plugin_change_validation_pipeline')
            if not validation_pipeline:
                raise Exception("Validation pipeline plugin not available")

            # DEPENDENCY MANAGEMENT INTEGRATION: Run dependency analysis
            dependency_results = await self._run_dependency_analysis(trigger)

            # Report dependency analysis results
            if dependency_results.get('status') == 'success':
                issues_count = dependency_results.get('dependency_issues_found', 0)
                plugins_count = dependency_results.get('plugins_analyzed', 0)
                print(f"🔍 Dependency Analysis: {plugins_count} plugins analyzed, {issues_count} issues found")
            elif dependency_results.get('status') == 'script_not_found':
                print("⚠️  Dependency analysis script not available")
            else:
                print(f"⚠️  Dependency analysis status: {dependency_results.get('status', 'unknown')}")

            # Prepare validation configuration
            validation_config = {
                'operation': 'full_validation',
                'target_plugin': trigger.target_plugin,
                'change_type': trigger.change_type,
                'dependency_analysis': dependency_results
            }
            
            # Execute validation
            if self.validation_config.get('async_validation', True):
                # Run asynchronously
                result = await self._safe_plugin_call(validation_pipeline, {}, validation_config)
            else:
                # Run synchronously
                result = await self._safe_plugin_call(validation_pipeline, {}, validation_config)
            
            # Calculate duration
            duration = time.time() - start_time
            trigger.duration_seconds = duration
            
            # Update trigger status
            if result.get('success'):
                trigger.status = "completed"
                
                # Store results in issue tracker if enabled
                if self.validation_config.get('trigger_issue_tracker', True):
                    await self._store_validation_results(trigger, result)
            else:
                trigger.status = "failed"
                trigger.error_message = result.get('error', 'Unknown validation error')
            
            # Remove from active validations
            if trigger.validation_id in self.active_validations:
                del self.active_validations[trigger.validation_id]
            
            return {
                'validation_success': result.get('success', False),
                'validation_id': trigger.validation_id,
                'duration_seconds': duration,
                'validation_details': result
            }
            
        except Exception as e:
            trigger.status = "failed"
            trigger.error_message = str(e)
            if trigger.validation_id in self.active_validations:
                del self.active_validations[trigger.validation_id]
            
            return {
                'validation_success': False,
                'validation_id': trigger.validation_id,
                'error': str(e)
            }
    
    async def _store_validation_results(self, trigger: ValidationTrigger, validation_result: Dict[str, Any]):
        """Store validation results in the issue tracker."""
        try:
            issue_tracker = pp('issue_tracker')
            if not issue_tracker:
                print("Warning: Issue tracker plugin not available")
                return
            
            # Extract issue data from validation result
            issue_aggregation = validation_result.get('issue_aggregation', {})
            issue_summary = issue_aggregation.get('issue_summary', {})
            
            # Prepare issues for storage
            tracker_config = {
                'operation': 'store_issues',
                'issues': {
                    'validation_run_id': trigger.validation_id,
                    'timestamp': trigger.timestamp.isoformat(),
                    'target_plugin': trigger.target_plugin,
                    'change_type': trigger.change_type,
                    'pipeline_score': validation_result.get('pipeline_execution', {}).get('overall_score', 0),
                    'issues_list': issue_summary.get('all_issues', []),
                    'metadata': {
                        'trigger_type': trigger.trigger_type,
                        'trigger_id': trigger.trigger_id,
                        'file_paths': trigger.file_paths,
                        'duration_seconds': trigger.duration_seconds
                    }
                },
                'storage_backend': 'auto'
            }
            
            # Store in issue tracker
            await self._safe_plugin_call(issue_tracker, {}, tracker_config)
            
        except Exception as e:
            print(f"Warning: Failed to store validation results in issue tracker: {e}")

    async def _run_dependency_analysis(self, trigger: ValidationTrigger) -> Dict[str, Any]:
        """Run dependency analysis using the dependency management automation script."""
        try:
            dependency_script = os.path.join(PROJECT_ROOT, "scripts", "dependency_management_automation.py")

            if not os.path.exists(dependency_script):
                return {"status": "script_not_found", "dependencies_checked": 0}

            # Run dependency analysis
            if trigger.target_plugin and trigger.target_plugin != 'all':
                # Analyze specific plugin
                result = subprocess.run([
                    sys.executable, dependency_script, "--scan", "--plugin", trigger.target_plugin
                ], capture_output=True, text=True, timeout=30)
            else:
                # Analyze all plugins
                result = subprocess.run([
                    sys.executable, dependency_script, "--scan"
                ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse output for dependency issues
                output_lines = result.stdout.split('\n')
                issues_found = 0
                plugins_analyzed = 0

                for line in output_lines:
                    if "Plugins with issues:" in line:
                        issues_found = int(line.split(':')[1].strip())
                    elif "Total plugins:" in line:
                        plugins_analyzed = int(line.split(':')[1].strip())

                return {
                    "status": "success",
                    "plugins_analyzed": plugins_analyzed,
                    "dependency_issues_found": issues_found,
                    "analysis_output": result.stdout,
                    "auto_fix_available": True
                }
            else:
                return {
                    "status": "error",
                    "error_message": result.stderr,
                    "dependencies_checked": 0
                }

        except subprocess.TimeoutExpired:
            return {"status": "timeout", "dependencies_checked": 0}
        except Exception as e:
            return {"status": "error", "error_message": str(e), "dependencies_checked": 0}

    def _should_monitor_file(self, file_path: str) -> bool:
        """Check if a file should be monitored based on patterns."""
        path = Path(file_path)
        
        # Check ignore patterns first
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(str(path), pattern) or fnmatch.fnmatch(path.name, pattern):
                return False
        
        # Check if file matches watch patterns
        for pattern in self.watch_patterns:
            if fnmatch.fnmatch(str(path), pattern) or fnmatch.fnmatch(path.name, pattern):
                # Check if it's in a monitored path
                for watch_path in self.watch_paths:
                    if str(path).startswith(watch_path):
                        return True
        
        return False
    
    def _extract_plugin_name(self, file_path: str) -> str:
        """Extract plugin name from file path."""
        try:
            path_parts = Path(file_path).parts
            
            # Look for plugin directory structure: plugs/{category}/{plugin_name}/{version}/
            if 'plugs' in path_parts:
                plugs_index = path_parts.index('plugs')
                if len(path_parts) > plugs_index + 2:
                    return path_parts[plugs_index + 2]  # plugin_name
            
            return 'unknown'
        except Exception:
            return 'unknown'
    
    def _add_debounced_change(self, file_path: str, plugin_name: str, change_type: str):
        """Add a file change to the debounced changes queue."""
        self.debounced_changes[file_path] = (plugin_name, change_type, datetime.utcnow())
        
        # Reset debounce timer
        if self.debounce_timer:
            self.debounce_timer.cancel()
        
        self.debounce_timer = threading.Timer(self.debounce_seconds, self._process_debounced_changes)
        self.debounce_timer.start()
    
    def _process_debounced_changes(self):
        """Process accumulated debounced changes."""
        if not self.debounced_changes:
            return
        
        # Group changes by plugin
        plugins_changed = defaultdict(lambda: {'files': [], 'change_types': set()})
        
        for file_path, (plugin_name, change_type, timestamp) in self.debounced_changes.items():
            plugins_changed[plugin_name]['files'].append(file_path)
            plugins_changed[plugin_name]['change_types'].add(change_type)
        
        # Create validation triggers for each changed plugin
        for plugin_name, changes in plugins_changed.items():
            trigger = ValidationTrigger(
                trigger_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                trigger_type='filesystem_change',
                target_plugin=plugin_name,
                file_paths=changes['files'],
                change_type='modified' if 'modified' in changes['change_types'] else list(changes['change_types'])[0]
            )
            
            # Execute validation asynchronously
            asyncio.create_task(self._execute_validation(trigger))
        
        # Clear debounced changes
        self.debounced_changes.clear()
    
    def _count_monitored_files(self) -> int:
        """Count the number of files being monitored."""
        count = 0
        for watch_path in self.watch_paths:
            if os.path.exists(watch_path):
                for root, dirs, files in os.walk(watch_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self._should_monitor_file(file_path):
                            count += 1
        return count
    
    async def _get_status(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Get current status of the hook system."""
        recent_triggers = [
            {
                'timestamp': trigger.timestamp.isoformat(),
                'trigger_type': trigger.trigger_type,
                'target_plugin': trigger.target_plugin,
                'validation_id': trigger.validation_id,
                'status': trigger.status,
                'duration_seconds': trigger.duration_seconds
            }
            for trigger in list(self.validation_triggers)[-10:]  # Last 10 triggers
        ]
        
        return {
            'success': True,
            'operation_result': {
                'operation': 'get_status',
                'timestamp': datetime.utcnow().isoformat(),
                'session_id': self.session_id,
                'hooks_active': self.monitoring_active
            },
            'monitoring_status': {
                'filesystem_watch_active': self.filesystem_observer is not None and getattr(self.filesystem_observer, 'running', False) if WATCHDOG_AVAILABLE else False,
                'git_hooks_installed': self.git_hooks_installed,
                'watch_paths': self.watch_paths,
                'files_monitored': self._count_monitored_files(),
                'triggers_executed': len(self.validation_triggers)
            },
            'validation_triggers': {
                'recent_triggers': recent_triggers,
                'active_validations': len(self.active_validations),
                'failed_validations': len([t for t in self.validation_triggers if t.status == 'failed'])
            }
        }
    
    async def _stop_monitoring(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Stop the monitoring system."""
        try:
            # Stop filesystem observer
            if self.filesystem_observer and getattr(self.filesystem_observer, 'running', False):
                self.filesystem_observer.stop()
                self.filesystem_observer.join()
            
            # Cancel debounce timer
            if self.debounce_timer:
                self.debounce_timer.cancel()
            
            self.monitoring_active = False
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'stop_monitoring',
                    'timestamp': datetime.utcnow().isoformat(),
                    'session_id': self.session_id,
                    'hooks_active': False
                },
                'final_status': {
                    'triggers_executed': len(self.validation_triggers),
                    'active_validations_cancelled': len(self.active_validations)
                }
            }
            
        except Exception as e:
            return self._error_response(f"Failed to stop monitoring: {str(e)}")
    
    async def _safe_plugin_call(self, plugin, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Safely call a plugin, handling both sync and async returns."""
        try:
            result = plugin.process(context, config)
            
            # Handle async plugins
            if asyncio.iscoroutine(result):
                result = await result
                
            return result if isinstance(result, dict) else {'success': False, 'error': 'Invalid plugin response'}
            
        except Exception as e:
            return {'success': False, 'error': f'Plugin call failed: {str(e)}'}
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Generate standardized error response."""
        return {
            'success': False,
            'error': error_message,
            'operation_result': {
                'operation': 'error',
                'timestamp': datetime.utcnow().isoformat(),
                'session_id': self.session_id,
                'hooks_active': self.monitoring_active
            }
        }
    
    # Placeholder methods for remaining operations
    async def _list_hooks(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """List installed hooks."""
        return {
            'success': True,
            'git_hooks_installed': self.git_hooks_installed,
            'filesystem_watch_active': getattr(self.filesystem_observer, 'running', False) if self.filesystem_observer else False
        }
    
    async def _remove_hooks(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Remove installed hooks."""
        return self._error_response("remove_hooks operation not yet implemented")
    
    async def _trigger_startup_validation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger validation for all plugins on startup."""
        return self._error_response("startup_validation not yet implemented")

# Main plugin entry point
async def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point for the hook system."""
    hooks = PluginChangeHooks()
    return await hooks.process_operation(context, config)

# Plugin metadata
plug_metadata = {
    "name": "plugin_change_hooks",
    "version": "1.0.0",
    "description": "Auto-triggering hook system for plugin change validation with filesystem monitoring and git hooks integration",
    "author": "PlugPipe Core Team",
    "license": "MIT",
    "category": "orchestration",
    "tags": ["hooks", "monitoring", "validation", "automation", "git", "filesystem"],
    "requirements": ["watchdog>=2.1.0 (optional, for filesystem monitoring)"],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["start_monitoring", "stop_monitoring", "get_status", "setup_git_hooks", "setup_filesystem_watch", "trigger_validation"],
                "default": "start_monitoring",
                "description": "Hook system operation to perform"
            }
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "monitoring_status": {
                "type": "object",
                "properties": {
                    "hooks_active": {"type": "boolean"},
                    "triggers_executed": {"type": "integer"}
                }
            }
        }
    },
    "sbom": "sbom/"
}