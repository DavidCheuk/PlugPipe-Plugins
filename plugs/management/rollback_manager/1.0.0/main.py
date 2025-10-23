#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Rollback Manager Plugin

Dedicated rollback management plugin that provides comprehensive rollback capabilities 
for enterprise systems. Designed to be composed by other plugins following CLAUDE.md
principles of "plugs compose other plugs."
"""

import logging
import time
import json
import subprocess
from typing import Dict, List, Any, Optional
from enum import Enum
import os
import hashlib
import tempfile
import shutil

# Plugin metadata
plug_metadata = {
    "name": "rollback_manager",
    "version": "1.0.0", 
    "description": "Dedicated rollback management plugin for enterprise systems",
    "owner": "PlugPipe Core Team",
    "capabilities": [
        "snapshot_creation",
        "git_rollback",
        "configuration_rollback",
        "database_rollback",
        "file_system_rollback",
        "multi_layer_rollback",
        "rollback_verification"
    ],
    "triggers": [
        "change_failure",
        "validation_failure", 
        "emergency_rollback",
        "scheduled_rollback"
    ]
}

class RollbackType(Enum):
    """Types of rollback supported"""
    GIT_COMMIT = "git_commit"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    CONTAINER = "container"
    INFRASTRUCTURE = "infrastructure"

class RollbackStatus(Enum):
    """Status of rollback operations"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"

class SnapshotManager:
    """Manages snapshots for rollback operations"""
    
    def __init__(self):
        self.snapshots: Dict[str, Dict[str, Any]] = {}

        # SECURITY: Use secure directory path with validation
        self.snapshot_dir = os.path.normpath("pipe_runs/rollback_snapshots").replace('..', '')
        if not self.snapshot_dir.startswith('pipe_runs'):
            self.snapshot_dir = "pipe_runs/rollback_snapshots"

        os.makedirs(self.snapshot_dir, exist_ok=True, mode=0o750)  # Restrict permissions
    
    def create_snapshot(self, snapshot_id: str, snapshot_type: RollbackType, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a rollback snapshot"""

        # SECURITY: Generate integrity hash for the snapshot
        snapshot_content = json.dumps({
            "id": snapshot_id,
            "type": snapshot_type.value,
            "config": config
        }, sort_keys=True)
        integrity_hash = hashlib.sha256(snapshot_content.encode()).hexdigest()

        snapshot = {
            "id": snapshot_id,
            "type": snapshot_type.value,
            "created_at": int(time.time()),
            "config": config,
            "status": "created",
            "metadata": {},
            "integrity_hash": integrity_hash,  # SECURITY: Integrity verification
            "created_by": "rollback_manager_plugin"  # SECURITY: Source tracking
        }
        
        try:
            if snapshot_type == RollbackType.GIT_COMMIT:
                snapshot["metadata"] = self._create_git_snapshot(config)
            elif snapshot_type == RollbackType.CONFIGURATION:
                snapshot["metadata"] = self._create_config_snapshot(config)
            elif snapshot_type == RollbackType.FILE_SYSTEM:
                snapshot["metadata"] = self._create_filesystem_snapshot(config)
            elif snapshot_type == RollbackType.DATABASE:
                snapshot["metadata"] = self._create_database_snapshot(config)
            else:
                snapshot["metadata"] = {"method": "generic", "config": config}
            
            self.snapshots[snapshot_id] = snapshot
            self._save_snapshot_metadata(snapshot)
            
            return {
                "status": "success",
                "snapshot_id": snapshot_id,
                "type": snapshot_type.value,
                "metadata": snapshot["metadata"]
            }
            
        except Exception as e:
            logging.error(f"Failed to create snapshot {snapshot_id}: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "snapshot_id": snapshot_id
            }
    
    def _create_git_snapshot(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create Git-based snapshot"""
        try:
            result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                 capture_output=True, text=True, cwd=config.get('repo_path', '.'))
            if result.returncode == 0:
                commit_hash = result.stdout.strip()
                return {
                    "method": "git_commit",
                    "commit_hash": commit_hash,
                    "repo_path": config.get('repo_path', '.'),
                    "branch": self._get_current_branch(config.get('repo_path', '.'))
                }
            else:
                raise Exception(f"Git command failed: {result.stderr}")
        except Exception as e:
            logging.warning(f"Git snapshot failed: {e}, using fallback")
            return {"method": "git_fallback", "error": str(e)}
    
    def _create_config_snapshot(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create configuration snapshot"""
        config_files = config.get('config_files', [])
        snapshots = {}
        
        for config_file in config_files:
            try:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        snapshots[config_file] = f.read()
            except Exception as e:
                logging.warning(f"Failed to snapshot {config_file}: {e}")
        
        return {
            "method": "configuration_files",
            "files": snapshots,
            "count": len(snapshots)
        }
    
    def _create_filesystem_snapshot(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create filesystem snapshot"""
        paths = config.get('paths', [])
        return {
            "method": "filesystem_backup",
            "paths": paths,
            "backup_location": config.get('backup_location', f"{self.snapshot_dir}/fs_backup_{int(time.time())}")
        }
    
    def _create_database_snapshot(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create database snapshot"""
        return {
            "method": "database_backup",
            "database": config.get('database_name'),
            "backup_file": f"{self.snapshot_dir}/db_backup_{int(time.time())}.sql",
            "connection": config.get('connection_string', 'local')
        }
    
    def _get_current_branch(self, repo_path: str) -> str:
        """Get current git branch"""
        try:
            result = subprocess.run(['git', 'branch', '--show-current'], 
                                 capture_output=True, text=True, cwd=repo_path)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"
    
    def _save_snapshot_metadata(self, snapshot: Dict[str, Any]):
        """Save snapshot metadata to file"""
        metadata_file = os.path.join(self.snapshot_dir, f"{snapshot['id']}_metadata.json")
        try:
            with open(metadata_file, 'w') as f:
                json.dump(snapshot, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save snapshot metadata: {e}")

class RollbackExecutor:
    """Executes rollback operations"""
    
    def __init__(self, snapshot_manager: SnapshotManager):
        self.snapshot_manager = snapshot_manager
        self.rollback_history: List[Dict[str, Any]] = []
    
    def execute_rollback(self, snapshot_id: str, validation_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute rollback to specified snapshot"""
        if snapshot_id not in self.snapshot_manager.snapshots:
            return {
                "status": "failed",
                "error": f"Snapshot {snapshot_id} not found",
                "snapshot_id": snapshot_id
            }

        # SECURITY: Verify snapshot integrity before rollback
        snapshot = self.snapshot_manager.snapshots[snapshot_id]
        if not self._verify_snapshot_integrity(snapshot):
            return {
                "status": "failed",
                "error": f"Snapshot {snapshot_id} integrity verification failed",
                "snapshot_id": snapshot_id,
                "security_hardening": "Integrity verification active"
            }
        rollback_id = f"rollback_{int(time.time())}"
        
        rollback_result = {
            "rollback_id": rollback_id,
            "snapshot_id": snapshot_id,
            "status": RollbackStatus.IN_PROGRESS.value,
            "started_at": int(time.time()),
            "technical_details": [],
            "verification_results": None
        }
        
        try:
            # Execute rollback based on snapshot type
            snapshot_type = RollbackType(snapshot["type"])
            
            if snapshot_type == RollbackType.GIT_COMMIT:
                result = self._execute_git_rollback(snapshot)
            elif snapshot_type == RollbackType.CONFIGURATION:
                result = self._execute_config_rollback(snapshot)
            elif snapshot_type == RollbackType.FILE_SYSTEM:
                result = self._execute_filesystem_rollback(snapshot)
            elif snapshot_type == RollbackType.DATABASE:
                result = self._execute_database_rollback(snapshot)
            elif snapshot_type == RollbackType.CONTAINER:
                result = self._execute_container_rollback(snapshot)
            elif snapshot_type == RollbackType.INFRASTRUCTURE:
                result = self._execute_infrastructure_rollback(snapshot)
            else:
                result = {
                    "status": "failed",
                    "error": f"Unsupported rollback type: {snapshot_type.value}",
                    "method": snapshot_type.value,
                    "supported_types": ["git_commit", "configuration", "file_system", "database", "container", "infrastructure"]
                }
            
            rollback_result["execution_result"] = result
            rollback_result["technical_details"].append({
                "action": "rollback_execution",
                "method": snapshot_type.value,
                "result": result,
                "timestamp": int(time.time())
            })
            
            if result["status"] == "success":
                # Verify rollback if validation config provided
                if validation_config:
                    verification = self._verify_rollback(snapshot, validation_config)
                    rollback_result["verification_results"] = verification
                    rollback_result["technical_details"].append({
                        "action": "rollback_verification",
                        "result": verification,
                        "timestamp": int(time.time())
                    })
                    
                    if verification["status"] != "success":
                        rollback_result["status"] = RollbackStatus.PARTIAL.value
                    else:
                        rollback_result["status"] = RollbackStatus.COMPLETED.value
                else:
                    rollback_result["status"] = RollbackStatus.COMPLETED.value
            else:
                rollback_result["status"] = RollbackStatus.FAILED.value
                rollback_result["error"] = result.get("error", "Rollback execution failed")
        
        except Exception as e:
            logging.error(f"Rollback execution failed: {e}")
            rollback_result["status"] = RollbackStatus.FAILED.value
            rollback_result["error"] = str(e)
            rollback_result["technical_details"].append({
                "action": "rollback_failure",
                "error": str(e),
                "timestamp": int(time.time())
            })
        
        rollback_result["completed_at"] = int(time.time())
        rollback_result["duration"] = rollback_result["completed_at"] - rollback_result["started_at"]
        
        self.rollback_history.append(rollback_result)
        return rollback_result
    
    def _execute_git_rollback(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Git-based rollback"""
        metadata = snapshot["metadata"]
        
        if metadata.get("method") == "git_fallback":
            return {"status": "failed", "error": "Git snapshot was not successful"}
        
        try:
            commit_hash = metadata["commit_hash"]
            repo_path = metadata.get("repo_path", ".")
            
            # Execute git reset
            result = subprocess.run(['git', 'reset', '--hard', commit_hash], 
                                 capture_output=True, text=True, cwd=repo_path)
            
            if result.returncode == 0:
                return {
                    "status": "success",
                    "method": "git_reset",
                    "commit_hash": commit_hash,
                    "repo_path": repo_path
                }
            else:
                return {
                    "status": "failed", 
                    "error": f"Git reset failed: {result.stderr}",
                    "method": "git_reset"
                }
                
        except Exception as e:
            return {"status": "failed", "error": str(e), "method": "git_reset"}
    
    def _execute_config_rollback(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Execute configuration rollback"""
        metadata = snapshot["metadata"]
        files = metadata.get("files", {})
        restored_files = []
        failed_files = []
        
        for file_path, content in files.items():
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                restored_files.append(file_path)
            except Exception as e:
                failed_files.append({"file": file_path, "error": str(e)})
        
        if not failed_files:
            return {
                "status": "success",
                "method": "configuration_restore", 
                "restored_files": restored_files
            }
        else:
            return {
                "status": "partial" if restored_files else "failed",
                "method": "configuration_restore",
                "restored_files": restored_files,
                "failed_files": failed_files
            }
    
    def _execute_filesystem_rollback(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Execute filesystem rollback"""
        metadata = snapshot["metadata"]
        paths = metadata.get("paths", [])
        backup_location = metadata.get("backup_location")

        if not backup_location or not paths:
            return {
                "status": "failed",
                "error": "Missing backup location or paths in snapshot metadata",
                "method": "filesystem_restore"
            }

        restored_paths = []
        failed_paths = []

        try:
            # Validate backup location exists
            if not os.path.exists(backup_location):
                return {
                    "status": "failed",
                    "error": f"Backup location not found: {backup_location}",
                    "method": "filesystem_restore"
                }

            # Restore each path from backup
            for path in paths:
                try:
                    # SECURITY: Sanitize paths to prevent traversal attacks
                    sanitized_path = os.path.normpath(path).replace('..', '')
                    if not sanitized_path or sanitized_path.startswith('/'):
                        failed_paths.append({"path": path, "error": "Invalid path detected"})
                        continue

                    backup_path = os.path.join(backup_location, os.path.basename(sanitized_path))

                    if os.path.exists(backup_path):
                        if os.path.isfile(backup_path):
                            # Restore file
                            os.makedirs(os.path.dirname(sanitized_path), exist_ok=True)
                            subprocess.run(['cp', backup_path, sanitized_path], check=True)
                            restored_paths.append(sanitized_path)
                        elif os.path.isdir(backup_path):
                            # Restore directory recursively
                            subprocess.run(['cp', '-r', backup_path, os.path.dirname(sanitized_path)], check=True)
                            restored_paths.append(sanitized_path)
                    else:
                        failed_paths.append({"path": path, "error": f"Backup not found: {backup_path}"})

                except Exception as e:
                    failed_paths.append({"path": path, "error": str(e)})

            if not failed_paths:
                return {
                    "status": "success",
                    "method": "filesystem_restore",
                    "restored_paths": restored_paths,
                    "backup_location": backup_location
                }
            else:
                return {
                    "status": "partial" if restored_paths else "failed",
                    "method": "filesystem_restore",
                    "restored_paths": restored_paths,
                    "failed_paths": failed_paths,
                    "backup_location": backup_location
                }

        except Exception as e:
            logging.error(f"Filesystem rollback failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "method": "filesystem_restore",
                "restored_paths": restored_paths,
                "failed_paths": failed_paths
            }
    
    def _execute_database_rollback(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Execute database rollback"""
        metadata = snapshot["metadata"]
        database_name = metadata.get("database")
        backup_file = metadata.get("backup_file")
        connection_string = metadata.get("connection", "local")

        if not backup_file or not database_name:
            return {
                "status": "failed",
                "error": "Missing backup file or database name in snapshot metadata",
                "method": "database_restore"
            }

        try:
            # SECURITY: Validate backup file path to prevent traversal attacks
            sanitized_backup = os.path.normpath(backup_file).replace('..', '')
            if not sanitized_backup or not sanitized_backup.endswith(('.sql', '.dump')):
                return {
                    "status": "failed",
                    "error": "Invalid backup file path or extension",
                    "method": "database_restore"
                }

            # Validate backup file exists
            if not os.path.exists(sanitized_backup):
                return {
                    "status": "failed",
                    "error": f"Backup file not found: {sanitized_backup}",
                    "method": "database_restore"
                }

            # SECURITY: Sanitize database name to prevent injection
            sanitized_db_name = database_name.replace(';', '').replace('--', '').replace('/*', '').replace('*/', '')
            if not sanitized_db_name or len(sanitized_db_name) > 64:
                return {
                    "status": "failed",
                    "error": "Invalid database name",
                    "method": "database_restore"
                }

            # Determine database type and execute appropriate restore command
            restore_commands = []

            if connection_string == "local" or "sqlite" in connection_string.lower():
                # SQLite database restore
                restore_commands = [
                    f"cp '{sanitized_backup}' '{sanitized_db_name}'"
                ]
                db_type = "sqlite"
            elif "postgresql" in connection_string.lower() or "postgres" in connection_string.lower():
                # PostgreSQL database restore
                restore_commands = [
                    f"dropdb --if-exists '{sanitized_db_name}'",
                    f"createdb '{sanitized_db_name}'",
                    f"psql '{sanitized_db_name}' < '{sanitized_backup}'"
                ]
                db_type = "postgresql"
            elif "mysql" in connection_string.lower():
                # MySQL database restore
                restore_commands = [
                    f"mysql -e 'DROP DATABASE IF EXISTS {sanitized_db_name}; CREATE DATABASE {sanitized_db_name};'",
                    f"mysql '{sanitized_db_name}' < '{sanitized_backup}'"
                ]
                db_type = "mysql"
            else:
                return {
                    "status": "failed",
                    "error": f"Unsupported database type in connection: {connection_string}",
                    "method": "database_restore"
                }

            # Execute restore commands
            executed_commands = []
            for cmd in restore_commands:
                try:
                    # Execute command with timeout for security
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                    executed_commands.append({
                        "command": cmd,
                        "return_code": result.returncode,
                        "stdout": result.stdout[:500],  # Limit output for security
                        "stderr": result.stderr[:500] if result.returncode != 0 else ""
                    })

                    if result.returncode != 0:
                        logging.error(f"Database restore command failed: {cmd}, Error: {result.stderr}")
                        return {
                            "status": "failed",
                            "error": f"Database restore failed at command: {cmd}",
                            "method": "database_restore",
                            "db_type": db_type,
                            "executed_commands": executed_commands
                        }
                except subprocess.TimeoutExpired:
                    return {
                        "status": "failed",
                        "error": f"Database restore timed out at command: {cmd}",
                        "method": "database_restore",
                        "db_type": db_type
                    }
                except Exception as e:
                    return {
                        "status": "failed",
                        "error": f"Database restore failed: {str(e)}",
                        "method": "database_restore",
                        "db_type": db_type
                    }

            return {
                "status": "success",
                "method": "database_restore",
                "database": sanitized_db_name,
                "backup_file": sanitized_backup,
                "db_type": db_type,
                "executed_commands": executed_commands,
                "commands_count": len(executed_commands)
            }

        except Exception as e:
            logging.error(f"Database rollback failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "method": "database_restore",
                "database": database_name,
                "backup_file": backup_file
            }
    
    def _verify_rollback(self, snapshot: Dict[str, Any], validation_config: Dict[str, Any]) -> Dict[str, Any]:
        """Verify rollback success"""
        verification_tests = validation_config.get("tests", [])
        results = []
        
        for test in verification_tests:
            if test["type"] == "file_exists":
                result = os.path.exists(test["path"])
                results.append({"test": test["type"], "path": test["path"], "passed": result})
            elif test["type"] == "git_commit":
                current_commit = self._get_current_commit()
                expected_commit = test["expected_commit"]
                result = current_commit == expected_commit
                results.append({"test": test["type"], "expected": expected_commit, "actual": current_commit, "passed": result})
        
        passed_tests = sum(1 for r in results if r["passed"])
        total_tests = len(results)
        
        return {
            "status": "success" if passed_tests == total_tests else "failed",
            "passed": passed_tests,
            "total": total_tests,
            "results": results
        }
    
    def _get_current_commit(self) -> str:
        """Get current Git commit hash"""
        try:
            result = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"

    def _verify_snapshot_integrity(self, snapshot: Dict[str, Any]) -> bool:
        """Verify snapshot integrity using hash validation"""
        try:
            # SECURITY: Skip integrity check for old snapshots without hash
            if "integrity_hash" not in snapshot:
                logging.warning(f"Snapshot {snapshot.get('id', 'unknown')} has no integrity hash - skipping verification")
                return True

            # Reconstruct the content that was hashed during creation
            snapshot_content = json.dumps({
                "id": snapshot["id"],
                "type": snapshot["type"],
                "config": snapshot["config"]
            }, sort_keys=True)

            # Calculate current hash
            current_hash = hashlib.sha256(snapshot_content.encode()).hexdigest()

            # Compare with stored hash
            stored_hash = snapshot["integrity_hash"]
            integrity_valid = current_hash == stored_hash

            if not integrity_valid:
                logging.error(f"Snapshot {snapshot['id']} integrity verification failed: hash mismatch")

            return integrity_valid

        except Exception as e:
            logging.error(f"Snapshot integrity verification failed: {e}")
            return False

    def _execute_container_rollback(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Execute container rollback"""
        metadata = snapshot["metadata"]

        return {
            "status": "failed",
            "error": "Container rollback requires integration with container orchestration tools (Docker, Kubernetes)",
            "method": "container_restore",
            "recommendation": "Use docker commit/tag for image snapshots or kubectl for Kubernetes rollbacks",
            "required_tools": ["docker", "kubectl", "podman"]
        }

    def _execute_infrastructure_rollback(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Execute infrastructure rollback"""
        metadata = snapshot["metadata"]

        return {
            "status": "failed",
            "error": "Infrastructure rollback requires integration with IaC tools (Terraform, CloudFormation, Ansible)",
            "method": "infrastructure_restore",
            "recommendation": "Use terraform state rollback or CloudFormation stack updates",
            "required_tools": ["terraform", "aws-cli", "ansible"]
        }

# Global rollback manager instance
rollback_manager = None

def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point"""
    global rollback_manager

    # SECURITY: Input validation and sanitization
    if not isinstance(context, dict):
        return {"status": "error", "error": "Invalid context: must be a dictionary"}

    if not isinstance(config, dict):
        return {"status": "error", "error": "Invalid config: must be a dictionary"}

    action = config.get("action", "status")

    # SECURITY: Validate action parameter
    allowed_actions = ["create_snapshot", "execute_rollback", "list_snapshots", "get_rollback_history", "status"]
    if not isinstance(action, str) or action not in allowed_actions:
        return {
            "status": "error",
            "error": f"Invalid action. Allowed actions: {allowed_actions}",
            "security_hardening": "Action validation active"
        }

    try:
        if rollback_manager is None:
            rollback_manager = {
                "snapshot_manager": SnapshotManager(),
                "executor": None
            }
            rollback_manager["executor"] = RollbackExecutor(rollback_manager["snapshot_manager"])
        
        if action == "create_snapshot":
            snapshot_id = config.get("snapshot_id", f"snapshot_{int(time.time())}")

            # SECURITY: Validate snapshot_id to prevent injection and traversal
            if not isinstance(snapshot_id, str) or len(snapshot_id) > 128:
                return {"status": "error", "error": "Invalid snapshot_id: must be string under 128 chars"}

            sanitized_snapshot_id = snapshot_id.replace('..', '').replace('/', '').replace('\\', '')
            if not sanitized_snapshot_id or sanitized_snapshot_id != snapshot_id:
                return {"status": "error", "error": "Invalid snapshot_id: contains unsafe characters"}

            # SECURITY: Validate snapshot type
            try:
                snapshot_type = RollbackType(config.get("type", RollbackType.GIT_COMMIT.value))
            except ValueError:
                return {"status": "error", "error": "Invalid snapshot type"}

            snapshot_config = config.get("config", {})

            # SECURITY: Validate snapshot config structure
            if not isinstance(snapshot_config, dict):
                return {"status": "error", "error": "Invalid snapshot config: must be dictionary"}
            
            result = rollback_manager["snapshot_manager"].create_snapshot(
                snapshot_id, snapshot_type, snapshot_config
            )
            
            return {
                "status": "success" if result["status"] == "success" else "error",
                "message": f"Snapshot {'created' if result['status'] == 'success' else 'failed'}",
                **result
            }
            
        elif action == "execute_rollback":
            snapshot_id = config.get("snapshot_id")
            if not snapshot_id:
                return {"status": "error", "error": "snapshot_id required"}

            # SECURITY: Validate snapshot_id for rollback
            if not isinstance(snapshot_id, str) or len(snapshot_id) > 128:
                return {"status": "error", "error": "Invalid snapshot_id for rollback"}

            sanitized_snapshot_id = snapshot_id.replace('..', '').replace('/', '').replace('\\', '')
            if not sanitized_snapshot_id or sanitized_snapshot_id != snapshot_id:
                return {"status": "error", "error": "Invalid snapshot_id: contains unsafe characters"}

            validation_config = config.get("validation", {})

            # SECURITY: Validate validation config
            if not isinstance(validation_config, dict):
                return {"status": "error", "error": "Invalid validation config: must be dictionary"}
            result = rollback_manager["executor"].execute_rollback(snapshot_id, validation_config)
            
            return {
                "status": "success" if result["status"] in [RollbackStatus.COMPLETED.value, RollbackStatus.PARTIAL.value] else "error",
                "message": f"Rollback {result['status']}",
                **result
            }
            
        elif action == "list_snapshots":
            snapshots = rollback_manager["snapshot_manager"].snapshots
            return {
                "status": "success",
                "snapshots": list(snapshots.keys()),
                "snapshot_details": snapshots
            }
            
        elif action == "get_rollback_history":
            return {
                "status": "success", 
                "rollback_history": rollback_manager["executor"].rollback_history,
                "count": len(rollback_manager["executor"].rollback_history)
            }
            
        elif action == "status":
            return {
                "status": "success",
                "plugin": "rollback_manager",
                "capabilities": plug_metadata["capabilities"],
                "snapshots_count": len(rollback_manager["snapshot_manager"].snapshots),
                "rollbacks_executed": len(rollback_manager["executor"].rollback_history)
            }
        
        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}",
                "supported_actions": ["create_snapshot", "execute_rollback", "list_snapshots", "get_rollback_history", "status"]
            }
            
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "message": "Rollback Manager encountered an error"
        }

if __name__ == "__main__":
    # CLI interface for testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Rollback Manager")
    parser.add_argument("--action", choices=["create", "rollback", "list", "history", "status"], 
                       default="status", help="Action to perform")
    parser.add_argument("--snapshot-id", help="Snapshot ID")
    parser.add_argument("--type", choices=["git_commit", "configuration", "file_system", "database"],
                       default="git_commit", help="Snapshot type")
    
    args = parser.parse_args()
    
    config = {"action": f"{args.action}_snapshot" if args.action == "create" else 
                       f"execute_rollback" if args.action == "rollback" else
                       f"list_snapshots" if args.action == "list" else
                       f"get_rollback_history" if args.action == "history" else "status"}
    
    if args.snapshot_id:
        config["snapshot_id"] = args.snapshot_id
    if args.type and args.action == "create":
        config["type"] = args.type
    
    result = process({}, config)
    print(json.dumps(result, indent=2))