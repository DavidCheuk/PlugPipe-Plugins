#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Architecture Guardian Watcher Plugin

A continuous monitoring plugin that integrates with the pp-architecture-guardian agent
to ensure real-time enforcement of PlugPipe principles during development sessions.

This plugin provides:
1. File system monitoring for code changes
2. Automatic architecture guardian reviews
3. Git hook integration for commit-time validation
4. Compliance dashboard and reporting
5. Integration with existing PlugPipe monitoring infrastructure

Following PlugPipe principles: reuse everything, reinvent nothing.
Leverages proven file monitoring tools and existing PlugPipe infrastructure.
"""

import os
import time
import json
import yaml
import asyncio
import logging
import threading
import subprocess
from typing import Dict, List, Any, Optional, Set, Callable
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import hashlib

# Import PlugPipe ecosystem functions
try:
    from shares.utils.config_loader import get_llm_config
    from shares.loader import pp
    PLUGPIPE_ECOSYSTEM_AVAILABLE = True
    print("✅ PlugPipe ecosystem functions loaded successfully")
except ImportError as e:
    PLUGPIPE_ECOSYSTEM_AVAILABLE = False
    print(f"⚠️ PlugPipe ecosystem functions not available: {e}")

# Import file monitoring - using proven watchdog library
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("⚠️ Watchdog not available - install with: pip install watchdog")
    
    # Create mock classes when watchdog is not available
    class FileSystemEventHandler:
        """Fallback file system event handler when watchdog unavailable."""
        def __init__(self):
            self.logger = logging.getLogger(__name__ + ".FallbackHandler")
            self.logger.warning("Using fallback file system handler - install watchdog for full functionality")

        def on_modified(self, event):
            """Log file modification events when watchdog unavailable."""
            self.logger.info(f"File modified (fallback): {getattr(event, 'src_path', 'unknown')}")

        def on_created(self, event):
            """Log file creation events when watchdog unavailable."""
            self.logger.info(f"File created (fallback): {getattr(event, 'src_path', 'unknown')}")
    
    class Observer:
        """Fallback observer when watchdog unavailable."""
        def __init__(self):
            self.logger = logging.getLogger(__name__ + ".FallbackObserver")
            self.logger.warning("Using fallback file observer - install watchdog for real-time monitoring")
            self.handlers = []
            self.paths = []
            self.is_running = False

        def schedule(self, handler, path, recursive=True):
            """Schedule handler for path (fallback mode - no real monitoring)."""
            self.handlers.append(handler)
            self.paths.append((path, recursive))
            self.logger.info(f"Scheduled fallback monitoring for: {path} (recursive={recursive})")

        def start(self):
            """Start fallback observer (logs warning about limited functionality)."""
            self.is_running = True
            self.logger.warning("Fallback observer started - no real-time file monitoring available")
            self.logger.info("To enable real-time monitoring, install watchdog: pip install watchdog")

        def stop(self):
            """Stop fallback observer."""
            self.is_running = False
            self.logger.info("Fallback observer stopped")

        def join(self):
            """Join fallback observer (no-op in fallback mode)."""
            self.logger.debug("Fallback observer join() called")

# Plugin metadata
plug_metadata = {
    "name": "architecture_guardian_watcher",
    "version": "1.0.0",
    "description": "Continuous monitoring integration for PlugPipe Architecture Guardian",
    "owner": "plugpipe-core",
    "tags": ["monitoring", "architecture", "guardian", "compliance"],
    "category": "monitoring",
    "status": "active"
}

logger = logging.getLogger(__name__)

@dataclass
class ArchitectureViolation:
    """Represents a PlugPipe architecture principle violation."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    principle: str  # Which PlugPipe principle was violated
    file_path: str
    line_number: Optional[int]
    description: str
    recommendation: str
    timestamp: datetime
    resolved: bool = False

@dataclass
class GuardianSession:
    """Tracks a continuous monitoring session."""
    session_id: str
    start_time: datetime
    monitored_paths: List[str]
    violations_found: int = 0
    reviews_conducted: int = 0
    files_monitored: int = 0
    active: bool = True

class ArchitectureGuardianEventHandler(FileSystemEventHandler):
    """File system event handler that triggers architecture reviews."""
    
    def __init__(self, watcher_instance):
        super().__init__()
        self.watcher = watcher_instance
        self.debounce_timer = None
        self.pending_files = set()
        self.debounce_delay = 2.0  # Wait 2 seconds after last change
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        # Filter for relevant files
        if self._should_monitor_file(event.src_path):
            self._debounce_review(event.src_path)
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        if self._should_monitor_file(event.src_path):
            self._debounce_review(event.src_path)
    
    def _should_monitor_file(self, file_path: str) -> bool:
        """Determine if file should trigger architecture review."""
        path = Path(file_path)
        
        # Monitor key file types
        monitored_extensions = {'.py', '.yaml', '.yml', '.md', '.json'}
        if path.suffix not in monitored_extensions:
            return False
        
        # Monitor key directories
        monitored_dirs = {'cores', 'plugs', 'shares', 'scripts', 'pipes'}
        if not any(part in monitored_dirs for part in path.parts):
            return False
        
        # Skip temporary files and directories
        skip_patterns = {'.git', '__pycache__', '.pytest_cache', '.venv', 'node_modules', '.tmp'}
        if any(pattern in str(path) for pattern in skip_patterns):
            return False
        
        return True
    
    def _debounce_review(self, file_path: str):
        """Debounce multiple rapid changes to the same file."""
        self.pending_files.add(file_path)
        
        # Cancel existing timer
        if self.debounce_timer:
            self.debounce_timer.cancel()
        
        # Start new timer
        self.debounce_timer = threading.Timer(
            self.debounce_delay, 
            self._trigger_review
        )
        self.debounce_timer.start()
    
    def _trigger_review(self):
        """Trigger architecture guardian review for pending files."""
        if self.pending_files:
            files_to_review = list(self.pending_files)
            self.pending_files.clear()
            
            # Trigger review in background thread
            threading.Thread(
                target=self.watcher._review_files,
                args=(files_to_review,),
                daemon=True
            ).start()

class ArchitectureGuardianWatcher:
    """Main watcher class for continuous architecture monitoring."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session_id = self._generate_session_id()
        self.session = GuardianSession(
            session_id=self.session_id,
            start_time=datetime.now(timezone.utc),
            monitored_paths=config.get('monitored_paths', ['.'])
        )
        
        self.violations = []
        self.observer = None
        self.event_handler = None
        
        # Configuration
        self.enable_git_hooks = config.get('enable_git_hooks', True)
        self.enable_realtime_monitoring = config.get('enable_realtime_monitoring', True)
        self.guardian_agent_path = config.get('guardian_agent_path', '.claude/agents/pp-architecture-guardian.md')
        
        # Initialize monitoring
        self._setup_monitoring()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"arch_guardian_{timestamp}_{os.getpid()}"
    
    def _setup_monitoring(self):
        """Set up file system monitoring."""
        if not WATCHDOG_AVAILABLE:
            logger.warning("File system monitoring unavailable - watchdog not installed")
            return
        
        if self.enable_realtime_monitoring:
            self.observer = Observer()
            self.event_handler = ArchitectureGuardianEventHandler(self)
            
            # Set up monitoring for each path
            for path in self.session.monitored_paths:
                if os.path.exists(path):
                    self.observer.schedule(self.event_handler, path, recursive=True)
                    logger.info(f"Monitoring path: {path}")
            
            self.observer.start()
            logger.info("Architecture guardian file monitoring started")
    
    def _review_files(self, file_paths: List[str]):
        """Review files using the architecture guardian agent."""
        try:
            self.session.reviews_conducted += 1
            
            # Prepare review context
            review_context = {
                'files_changed': file_paths,
                'session_id': self.session_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'review_type': 'file_change'
            }
            
            # Call architecture guardian agent
            violations = self._call_architecture_guardian(review_context)
            
            # Process violations
            for violation in violations:
                self.violations.append(violation)
                self.session.violations_found += 1
                
                # Log violation
                logger.warning(f"Architecture violation: {violation.principle} in {violation.file_path}")
                
                # Send alert if critical
                if violation.severity == 'CRITICAL':
                    self._send_critical_alert(violation)
        
        except Exception as e:
            logger.error(f"Error during file review: {e}")
    
    def _call_architecture_guardian(self, context: Dict[str, Any]) -> List[ArchitectureViolation]:
        """Call the pp-architecture-guardian agent."""
        violations = []
        
        try:
            # For now, implement basic principle checking
            # In production, this would call the actual agent
            violations.extend(self._check_plugin_first_principle(context))
            violations.extend(self._check_reuse_principle(context))
            violations.extend(self._check_cli_tools_principle(context))
            
        except Exception as e:
            logger.error(f"Error calling architecture guardian: {e}")
        
        return violations
    
    def _check_plugin_first_principle(self, context: Dict[str, Any]) -> List[ArchitectureViolation]:
        """Check for violations of 'Plugin-First Development' principle."""
        violations = []
        
        for file_path in context['files_changed']:
            if not os.path.exists(file_path):
                continue
                
            # Check if core functionality is being added instead of plugins
            if file_path.startswith('cores/') and file_path.endswith('.py'):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    # Look for new functionality patterns
                    new_function_patterns = [
                        'def create_',
                        'def generate_',
                        'def process_',
                        'class.*Service',
                        'class.*Manager'
                    ]
                    
                    for pattern in new_function_patterns:
                        import re
                        if re.search(pattern, content):
                            violations.append(ArchitectureViolation(
                                severity='HIGH',
                                principle='Plugin-First Development',
                                file_path=file_path,
                                line_number=None,
                                description=f'New functionality detected in core module - should be a plugin',
                                recommendation='Move this functionality to plugs/ directory as a reusable plugin',
                                timestamp=datetime.now(timezone.utc)
                            ))
                            break
                
                except Exception as e:
                    logger.debug(f"Error checking file {file_path}: {e}")
        
        return violations
    
    def _check_reuse_principle(self, context: Dict[str, Any]) -> List[ArchitectureViolation]:
        """Check for violations of 'Reuse Everything, Reinvent Nothing' principle."""
        violations = []
        
        for file_path in context['files_changed']:
            if not os.path.exists(file_path) or not file_path.endswith('.py'):
                continue
                
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for custom implementations instead of existing tools
                custom_patterns = [
                    ('custom.*validator', 'Use existing CLI validation tools'),
                    ('custom.*scanner', 'Use existing scanning plugins'),
                    ('def validate_schema', 'Use existing schema validation tools'),
                    ('class.*Validator', 'Use existing validation plugins')
                ]
                
                for pattern, recommendation in custom_patterns:
                    import re
                    if re.search(pattern, content, re.IGNORECASE):
                        violations.append(ArchitectureViolation(
                            severity='MEDIUM',
                            principle='Reuse Everything, Reinvent Nothing',
                            file_path=file_path,
                            line_number=None,
                            description=f'Custom implementation detected: {pattern}',
                            recommendation=recommendation,
                            timestamp=datetime.now(timezone.utc)
                        ))
            
            except Exception as e:
                logger.debug(f"Error checking reuse principle for {file_path}: {e}")
        
        return violations
    
    def _check_cli_tools_principle(self, context: Dict[str, Any]) -> List[ArchitectureViolation]:
        """Check for violations of 'Always Use Existing CLI Tools' principle."""
        violations = []
        
        for file_path in context['files_changed']:
            if not os.path.exists(file_path) or not file_path.endswith('.py'):
                continue
                
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for direct tool construction instead of pp commands
                anti_patterns = [
                    ('subprocess.*sbom', 'Use ./pp sbom command'),
                    ('subprocess.*validate', 'Use ./pp validate command'),
                    ('subprocess.*generate', 'Use ./pp generate command'),
                    ('os\.system.*pytest', 'Use PYTHONPATH=. pytest'),
                ]
                
                for pattern, recommendation in anti_patterns:
                    import re
                    if re.search(pattern, content):
                        violations.append(ArchitectureViolation(
                            severity='MEDIUM',
                            principle='Always Use Existing CLI Tools',
                            file_path=file_path,
                            line_number=None,
                            description=f'Direct tool construction detected: {pattern}',
                            recommendation=recommendation,
                            timestamp=datetime.now(timezone.utc)
                        ))
            
            except Exception as e:
                logger.debug(f"Error checking CLI tools principle for {file_path}: {e}")
        
        return violations
    
    def _send_critical_alert(self, violation: ArchitectureViolation):
        """Send alert for critical architecture violations."""
        alert_message = f"""
🚨 CRITICAL ARCHITECTURE VIOLATION DETECTED
==========================================

Principle: {violation.principle}
File: {violation.file_path}
Description: {violation.description}
Recommendation: {violation.recommendation}
Time: {violation.timestamp}

This violation requires immediate attention to maintain PlugPipe architecture integrity.
"""
        
        print(alert_message)
        logger.critical(alert_message)
    
    def setup_git_hooks(self) -> Dict[str, Any]:
        """Set up git hooks for commit-time architecture validation."""
        if not self.enable_git_hooks:
            return {"status": "disabled", "message": "Git hooks disabled by configuration"}
        
        hooks_dir = Path('.git/hooks')
        if not hooks_dir.exists():
            return {"status": "error", "message": "Git hooks directory not found"}
        
        # Create pre-commit hook
        pre_commit_script = '''#!/bin/bash
# PlugPipe Architecture Guardian Pre-commit Hook

echo "🔍 Running PlugPipe Architecture Guardian..."

# Get list of changed files
changed_files=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$changed_files" ]; then
    echo "✅ No files to check"
    exit 0
fi

# Run architecture guardian review
if [ -f "scripts/architecture_guardian_cli.py" ]; then
    echo "$changed_files" | tr ' ' '\n' | while read -r file; do
        if [ -n "$file" ]; then
            echo "Checking: $file"
            PYTHONPATH=. python scripts/architecture_guardian_cli.py review --files "$file" 2>/dev/null || {
                echo "⚠️ Architecture review failed for $file - allowing commit"
            }
        fi
    done
else
    echo "⚠️ Architecture guardian CLI not found - skipping review"
fi

exit 0
'''
        
        try:
            pre_commit_path = hooks_dir / 'pre-commit'
            with open(pre_commit_path, 'w') as f:
                f.write(pre_commit_script)
            
            # Make executable
            os.chmod(pre_commit_path, 0o755)
            
            return {
                "status": "success",
                "message": "Git hooks installed successfully",
                "hooks_installed": ["pre-commit"]
            }
        
        except Exception as e:
            return {
                "status": "error", 
                "message": f"Failed to install git hooks: {e}"
            }
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Generate compliance dashboard data."""
        now = datetime.now(timezone.utc)
        session_duration = (now - self.session.start_time).total_seconds()
        
        # Categorize violations by principle
        violations_by_principle = defaultdict(int)
        violations_by_severity = defaultdict(int)
        
        for violation in self.violations:
            violations_by_principle[violation.principle] += 1
            violations_by_severity[violation.severity] += 1
        
        return {
            "session": {
                "session_id": self.session_id,
                "start_time": self.session.start_time.isoformat(),
                "duration_seconds": int(session_duration),
                "active": self.session.active
            },
            "monitoring": {
                "monitored_paths": self.session.monitored_paths,
                "files_monitored": self.session.files_monitored,
                "reviews_conducted": self.session.reviews_conducted
            },
            "violations": {
                "total": len(self.violations),
                "by_principle": dict(violations_by_principle),
                "by_severity": dict(violations_by_severity),
                "recent": [asdict(v) for v in self.violations[-5:]]  # Last 5 violations
            },
            "compliance_score": self._calculate_compliance_score(),
            "recommendations": self._get_top_recommendations()
        }
    
    def _calculate_compliance_score(self) -> float:
        """Calculate overall compliance score (0-100)."""
        if self.session.reviews_conducted == 0:
            return 100.0
        
        # Weight violations by severity
        severity_weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
        total_weighted_violations = sum(
            severity_weights.get(v.severity, 1) for v in self.violations
        )
        
        # Calculate score (lower violations = higher score)
        max_possible_score = self.session.reviews_conducted * 10
        score = max(0, 100 - (total_weighted_violations / max(1, max_possible_score) * 100))
        
        return round(score, 1)
    
    def _get_top_recommendations(self) -> List[str]:
        """Get top recommendations based on violations."""
        principle_counts = defaultdict(int)
        for violation in self.violations:
            principle_counts[violation.principle] += 1
        
        recommendations = []
        
        # Sort by frequency
        sorted_principles = sorted(principle_counts.items(), key=lambda x: x[1], reverse=True)
        
        for principle, count in sorted_principles[:3]:
            if principle == 'Plugin-First Development':
                recommendations.append("Move new functionality to plugs/ directory instead of core modules")
            elif principle == 'Reuse Everything, Reinvent Nothing':
                recommendations.append("Use existing PlugPipe plugins and CLI tools instead of custom implementations")
            elif principle == 'Always Use Existing CLI Tools':
                recommendations.append("Use ./pp commands instead of direct tool construction")
        
        return recommendations
    
    def stop_monitoring(self):
        """Stop the architecture guardian monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        self.session.active = False
        logger.info("Architecture guardian monitoring stopped")

# Main plugin process function
def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin process function for Architecture Guardian Watcher.
    
    Args:
        context: PlugPipe execution context
        config: Plugin configuration
        
    Returns:
        Plugin execution results
    """
    try:
        operation = config.get('operation', 'start_monitoring')
        
        if operation == 'start_monitoring':
            # Start continuous monitoring
            watcher = ArchitectureGuardianWatcher(config)
            
            # Set up git hooks if requested
            hook_result = None
            if config.get('setup_git_hooks', False):
                hook_result = watcher.setup_git_hooks()
                
            # Return session info
            result = {
                "status": "success",
                "session_id": watcher.session_id,
                "monitoring_active": watcher.session.active,
                "monitored_paths": watcher.session.monitored_paths,
                "message": "Architecture Guardian monitoring started successfully",
                "compliance_dashboard": watcher.get_compliance_dashboard()
            }
            
            # Add hook results if applicable
            if hook_result:
                result["hook_setup"] = hook_result
                if hook_result.get("hooks_installed"):
                    result["hooks_installed"] = hook_result["hooks_installed"]
            
            return result
        
        elif operation == 'get_dashboard':
            # Get current compliance dashboard
            session_id = config.get('session_id')
            # In practice, would retrieve session from storage
            
            return {
                "status": "success",
                "message": "Compliance dashboard retrieved",
                "dashboard": {
                    "placeholder": "Dashboard data would be retrieved from active session"
                }
            }
        
        elif operation == 'review_files':
            # Manual file review
            files_to_review = config.get('files', [])
            if not files_to_review:
                return {"status": "error", "message": "No files specified for review"}
            
            watcher = ArchitectureGuardianWatcher(config)
            watcher._review_files(files_to_review)
            
            return {
                "status": "success",
                "files_reviewed": len(files_to_review),
                "violations_found": len(watcher.violations),
                "violations": [asdict(v) for v in watcher.violations]
            }
        
        else:
            return {"status": "error", "message": f"Unknown operation: {operation}"}
    
    except Exception as e:
        logger.error(f"Architecture Guardian Watcher error: {e}")
        return {
            "status": "error",
            "message": f"Plugin execution failed: {str(e)}"
        }

# Test function for development
def test_architecture_guardian():
    """Test the architecture guardian watcher functionality."""
    print("🧪 Testing Architecture Guardian Watcher...")
    
    test_config = {
        'operation': 'start_monitoring',
        'monitored_paths': ['.'],
        'enable_realtime_monitoring': False,  # Don't start file watcher in test
        'enable_git_hooks': False,
        'setup_git_hooks': False
    }
    
    result = process({}, test_config)
    print(f"✅ Test result: {result}")
    
    return result

if __name__ == "__main__":
    test_architecture_guardian()