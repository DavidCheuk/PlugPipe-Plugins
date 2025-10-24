# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
PlugPipe Plugin Registry Scanner
Provides accurate plugin counts and metadata by scanning the file system directly
"""

import os
import sys
import json
import glob
import yaml
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class PlugPipeRegistryScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_path = Path(get_plugpipe_root())
        
    def scan_all_plugins(self, include_metadata: bool = True, format: str = "json") -> Dict[str, Any]:
        """Scan all plugins and pipes for accurate registry data"""
        
        # Use recursive pattern to catch all plug.yaml files
        plug_files = glob.glob(str(self.base_path / 'plugs' / '**' / 'plug.yaml'), recursive=True)
        
        # Use recursive pattern to catch all pipe.yaml files  
        pipe_files = glob.glob(str(self.base_path / 'pipes' / '**' / 'pipe.yaml'), recursive=True)
        
        plugs_data = []
        pipes_data = []
        
        # Process plugs
        for manifest_path in plug_files:
            plugin_data = self._process_manifest(manifest_path, 'plug', include_metadata)
            if plugin_data:
                plugs_data.append(plugin_data)
                
        # Process pipes
        for manifest_path in pipe_files:
            pipe_data = self._process_manifest(manifest_path, 'pipe', include_metadata)
            if pipe_data:
                pipes_data.append(pipe_data)
        
        # Get pp list data for comparison
        pp_list_data = self._get_pp_list_data()
        
        result = {
            "scan_timestamp": datetime.now().isoformat(),
            "summary": {
                "total_plugins": len(plugs_data) + len(pipes_data),
                "plugs_count": len(plugs_data),
                "pipes_count": len(pipes_data),
                "pp_list_shows": len(pp_list_data),
                "discrepancy": (len(plugs_data) + len(pipes_data)) - len(pp_list_data)
            },
            "plugs": plugs_data,
            "pipes": pipes_data,
            "pp_list_comparison": {
                "visible_in_pp_list": len(pp_list_data),
                "missing_from_pp_list": [],
                "categories_breakdown": self._get_category_breakdown(plugs_data + pipes_data)
            }
        }
        
        # Find plugins missing from pp list
        pp_list_names = {item.get('name') for item in pp_list_data}
        for plugin in plugs_data + pipes_data:
            if plugin['name'] not in pp_list_names:
                result["pp_list_comparison"]["missing_from_pp_list"].append({
                    "name": plugin['name'],
                    "type": plugin['type'],
                    "category": plugin.get('category', 'unknown')
                })
        
        if format == "summary":
            return result["summary"]
        elif format == "detailed":
            return result
        else:  # json
            return result
    
    def count_only(self, breakdown: bool = True) -> Dict[str, Any]:
        """Get accurate plugin and pipe counts only"""
        
        # Use recursive patterns to catch all files
        plug_files = glob.glob(str(self.base_path / 'plugs' / '**' / 'plug.yaml'), recursive=True)
        pipe_files = glob.glob(str(self.base_path / 'pipes' / '**' / 'pipe.yaml'), recursive=True)
        
        result = {
            "total": len(plug_files) + len(pipe_files),
            "plugs": len(plug_files),
            "pipes": len(pipe_files),
            "scan_timestamp": datetime.now().isoformat()
        }
        
        if breakdown:
            # Get category breakdown
            categories = {}
            
            for manifest_path in plug_files + pipe_files:
                try:
                    with open(manifest_path, 'r') as f:
                        manifest = yaml.safe_load(f)
                    category = manifest.get('category', 'unknown')
                    categories[category] = categories.get(category, 0) + 1
                except Exception:
                    categories['unknown'] = categories.get('unknown', 0) + 1
            
            result["categories"] = categories
        
        return result
    
    def verify_pp_list(self, show_missing: bool = True) -> Dict[str, Any]:
        """Compare file system scan with pp list output"""
        
        filesystem_data = self.scan_all_plugins()
        pp_list_data = self._get_pp_list_data()
        
        filesystem_names = {item['name'] for item in filesystem_data['plugs'] + filesystem_data['pipes']}
        pp_list_names = {item.get('name') for item in pp_list_data}
        
        missing_from_pp_list = filesystem_names - pp_list_names
        only_in_pp_list = pp_list_names - filesystem_names
        
        result = {
            "verification_timestamp": datetime.now().isoformat(),
            "filesystem_count": len(filesystem_names),
            "pp_list_count": len(pp_list_names),
            "discrepancy": len(filesystem_names) - len(pp_list_names),
            "missing_from_pp_list_count": len(missing_from_pp_list),
            "only_in_pp_list_count": len(only_in_pp_list)
        }
        
        if show_missing:
            result["missing_from_pp_list"] = sorted(list(missing_from_pp_list))
            result["only_in_pp_list"] = sorted(list(only_in_pp_list))
        
        return result
    
    def _process_manifest(self, manifest_path: str, plugin_type: str, include_metadata: bool) -> Optional[Dict[str, Any]]:
        """Process a single manifest file"""
        try:
            with open(manifest_path, 'r') as f:
                manifest = yaml.safe_load(f)
            
            plugin_data = {
                "name": manifest.get('name', 'unknown'),
                "type": plugin_type,
                "manifest_path": manifest_path
            }
            
            if include_metadata:
                plugin_data.update({
                    "version": manifest.get('version', '1.0.0'),
                    "category": manifest.get('category', 'unknown'),
                    "description": manifest.get('description', 'No description available'),
                    "author": manifest.get('author', 'Unknown'),
                    "license": manifest.get('license', 'Unknown')
                })
            
            return plugin_data
            
        except Exception as e:
            self.logger.warning(f"Failed to process manifest {manifest_path}: {str(e)}")
            return None
    
    def _get_pp_list_data(self) -> List[Dict[str, Any]]:
        """Get data from pp list command for comparison"""
        try:
            result = subprocess.run(['./pp', 'list'], 
                                  capture_output=True, text=True, 
                                  cwd=str(self.base_path))
            
            if result.returncode != 0:
                return []
            
            import re
            plugins = []
            
            for line in result.stdout.splitlines():
                line = line.strip()
                
                # Skip headers and empty lines
                if (not line or line.startswith('📋 Available') or 
                    line.startswith('=========================') or 
                    line.startswith('📊 Total:')):
                    continue
                
                # Match plugin line format
                match = re.match(r'\s*([✅📦🔧⚠️❌🚀])\s+(.+?)\s+v([\d.]+)\s+\[([^\]]+)\]\s*(.*)', line)
                if match:
                    plugins.append({
                        "name": match.group(2),
                        "version": match.group(3),
                        "category": match.group(4).strip(),
                        "description": match.group(5).strip(),
                        "status_icon": match.group(1)
                    })
            
            return plugins
            
        except Exception as e:
            self.logger.error(f"Failed to get pp list data: {str(e)}")
            return []
    
    def _get_category_breakdown(self, plugins: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get breakdown by category"""
        categories = {}
        for plugin in plugins:
            category = plugin.get('category', 'unknown')
            categories[category] = categories.get(category, 0) + 1
        return categories

def process(ctx, cfg):
    """Standard PlugPipe process function"""
    scanner = PlugPipeRegistryScanner()
    
    # Get input data from context
    input_data = ctx.get("input") or ctx.get("with") or ctx
    if not isinstance(input_data, dict):
        input_data = {"operation": "count_only"}
    
    operation = input_data.get('operation', 'count_only')
    
    try:
        if operation == "scan_all":
            include_metadata = input_data.get('include_metadata', True)
            format_arg = input_data.get('format', 'json')
            result = scanner.scan_all_plugins(include_metadata, format_arg)
            
        elif operation == "count_only":
            breakdown = input_data.get('breakdown', True)
            result = scanner.count_only(breakdown)
            
        elif operation == "verify_pp_list":
            show_missing = input_data.get('show_missing', True)
            result = scanner.verify_pp_list(show_missing)
            
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "available_operations": ["scan_all", "count_only", "verify_pp_list"]
            }
        
        return {
            "success": True,
            "operation": operation,
            "data": result
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "operation": operation
        }

def main():
    """Main entry point for the plugin"""
    if len(sys.argv) < 2:
        print("Usage: python main.py <operation> [options]")
        print("Operations: scan_all, count_only, verify_pp_list")
        return
    
    operation = sys.argv[1]
    scanner = PlugPipeRegistryScanner()
    
    try:
        if operation == "scan_all":
            include_metadata = "--no-metadata" not in sys.argv
            format_arg = "json"
            if "--format=summary" in sys.argv:
                format_arg = "summary"
            elif "--format=detailed" in sys.argv:
                format_arg = "detailed"
            
            result = scanner.scan_all_plugins(include_metadata, format_arg)
            
        elif operation == "count_only":
            breakdown = "--no-breakdown" not in sys.argv
            result = scanner.count_only(breakdown)
            
        elif operation == "verify_pp_list":
            show_missing = "--no-missing" not in sys.argv
            result = scanner.verify_pp_list(show_missing)
            
        else:
            print(f"Unknown operation: {operation}")
            return
        
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()