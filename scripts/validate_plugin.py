#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright 2025 PlugPipe Team
# https://github.com/DavidCheuk/PlugPipe-Plugins

"""
PlugPipe Plugin Validation Toolkit (Standalone)

Validates plugins for common issues before PR submission:
- YAML syntax and required manifest fields
- SPDX copyright headers in Python files
- Semantic versioning
- A2A protocol compliance (execute function, stateless)
- Basic security checks

Usage:
    python3 scripts/validate_plugin.py plugs/category/my_plugin/1.0.0/
    python3 scripts/validate_plugin.py plugs/category/my_plugin/1.0.0/ --strict
    python3 scripts/validate_plugin.py --all  # Validate all plugins
"""

import os
import sys
import re
import yaml
import ast
from pathlib import Path
from typing import Dict, List, Any, Tuple
import argparse

# Validation results
class ValidationResult:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info = []
        self.passed = 0
        self.failed = 0

    def add_error(self, message: str):
        self.errors.append(f"❌ ERROR: {message}")
        self.failed += 1

    def add_warning(self, message: str):
        self.warnings.append(f"⚠️  WARNING: {message}")

    def add_info(self, message: str):
        self.info.append(f"ℹ️  INFO: {message}")

    def add_pass(self, message: str):
        self.passed += 1

    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def print_summary(self):
        print("\n" + "="*70)
        print("VALIDATION SUMMARY")
        print("="*70)

        if self.errors:
            print(f"\n🔴 ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  {error}")

        if self.warnings:
            print(f"\n🟡 WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  {warning}")

        if self.info:
            print(f"\n🔵 INFO ({len(self.info)}):")
            for info in self.info:
                print(f"  {info}")

        print(f"\n📊 Results: {self.passed} passed, {self.failed} failed")

        if self.is_valid():
            print("\n✅ VALIDATION PASSED - Plugin is ready for submission!")
            return 0
        else:
            print("\n❌ VALIDATION FAILED - Fix errors before submitting PR")
            return 1


def validate_yaml_syntax(manifest_path: Path, result: ValidationResult) -> Dict:
    """Validate YAML syntax and load manifest."""
    try:
        with open(manifest_path, 'r') as f:
            manifest = yaml.safe_load(f)
        result.add_pass("YAML syntax valid")
        return manifest
    except yaml.YAMLError as e:
        result.add_error(f"Invalid YAML syntax in {manifest_path}: {e}")
        return None
    except FileNotFoundError:
        result.add_error(f"Manifest not found: {manifest_path}")
        return None


def validate_required_fields(manifest: Dict, result: ValidationResult):
    """Validate required manifest fields."""
    required_fields = {
        'name': 'Plugin name',
        'version': 'Version number',
        'description': 'Plugin description',
        'category': 'Plugin category',
        'author': 'Author name',
        'copyright': 'Copyright notice',
        'license': 'License identifier'
    }

    for field, description in required_fields.items():
        if field not in manifest:
            result.add_error(f"Missing required field: '{field}' ({description})")
        elif not manifest[field]:
            result.add_error(f"Empty required field: '{field}'")
        else:
            result.add_pass(f"Field '{field}' present")


def validate_semantic_versioning(version: str, result: ValidationResult):
    """Validate semantic versioning format (X.Y.Z)."""
    pattern = re.compile(r'^\d+\.\d+\.\d+$')
    if pattern.match(version):
        result.add_pass(f"Version '{version}' follows semantic versioning")
    else:
        result.add_error(f"Invalid version format: '{version}'. Use semantic versioning (e.g., 1.0.0)")


def validate_copyright_headers(plugin_dir: Path, result: ValidationResult):
    """Validate SPDX copyright headers in Python files."""
    python_files = list(plugin_dir.glob('**/*.py'))

    if not python_files:
        result.add_warning("No Python files found")
        return

    for py_file in python_files:
        with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Check for SPDX identifier
        if 'SPDX-License-Identifier:' not in content:
            result.add_error(f"Missing SPDX header in {py_file.name}")
        else:
            result.add_pass(f"SPDX header found in {py_file.name}")

        # Check for Copyright notice
        if 'Copyright' not in content:
            result.add_warning(f"No copyright notice in {py_file.name}")


def validate_a2a_compliance(plugin_dir: Path, manifest: Dict, result: ValidationResult):
    """Validate A2A protocol compliance."""
    main_py = plugin_dir / 'main.py'

    if not main_py.exists():
        result.add_error("main.py not found")
        return

    with open(main_py, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Check for execute() function
    if 'def execute(' in content:
        result.add_pass("A2A execute() function found")
    else:
        result.add_error("A2A execute() function not found (required for A2A compliance)")

    # Check manifest for a2a_enabled flag
    if manifest and manifest.get('a2a_enabled') is True:
        result.add_pass("Manifest declares a2a_enabled: true")
    else:
        result.add_warning("Manifest should include 'a2a_enabled: true' for A2A compliance")

    # Check for stateless design (no instance variables in execute)
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'execute':
                # Look for self assignments (indicates instance state)
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                                if target.value.id == 'self':
                                    result.add_warning(f"Possible instance state in execute(): {ast.unparse(child)}")
        result.add_pass("Stateless design check passed")
    except:
        result.add_info("Could not parse main.py for stateless check")


def validate_naming_convention(name: str, result: ValidationResult):
    """Validate plugin name follows naming conventions."""
    pattern = re.compile(r'^[a-z0-9_]+$')
    if pattern.match(name):
        result.add_pass(f"Name '{name}' follows naming convention")
    else:
        result.add_error(f"Invalid name: '{name}'. Use only lowercase letters, numbers, and underscores")


def validate_directory_structure(plugin_dir: Path, result: ValidationResult):
    """Validate expected directory structure."""
    required_files = ['plug.yaml', 'main.py']
    recommended_files = ['README.md']

    for file in required_files:
        file_path = plugin_dir / file
        if file_path.exists():
            result.add_pass(f"Required file found: {file}")
        else:
            result.add_error(f"Missing required file: {file}")

    for file in recommended_files:
        file_path = plugin_dir / file
        if not file_path.exists():
            result.add_warning(f"Missing recommended file: {file}")


def validate_security_basics(plugin_dir: Path, result: ValidationResult):
    """Basic security checks."""
    python_files = list(plugin_dir.glob('**/*.py'))

    dangerous_patterns = [
        (r'eval\(', 'eval() usage detected (security risk)'),
        (r'exec\(', 'exec() usage detected (security risk)'),
        (r'__import__\(', '__import__() usage detected (potential security risk)'),
        (r'os\.system\(', 'os.system() usage detected (use subprocess instead)'),
    ]

    for py_file in python_files:
        with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        for pattern, message in dangerous_patterns:
            if re.search(pattern, content):
                result.add_warning(f"{py_file.name}: {message}")


def validate_plugin(plugin_dir: Path, strict: bool = False) -> ValidationResult:
    """Validate a single plugin directory."""
    result = ValidationResult()

    print(f"\n{'='*70}")
    print(f"Validating: {plugin_dir}")
    print(f"{'='*70}\n")

    # 1. Check directory structure
    print("📁 Checking directory structure...")
    validate_directory_structure(plugin_dir, result)

    # 2. Validate manifest
    print("\n📋 Validating manifest...")
    manifest_path = plugin_dir / 'plug.yaml'
    if not manifest_path.exists():
        manifest_path = plugin_dir / 'pipe.yaml'

    manifest = validate_yaml_syntax(manifest_path, result)
    if manifest:
        validate_required_fields(manifest, result)

        # Validate version
        if 'version' in manifest:
            validate_semantic_versioning(manifest['version'], result)

        # Validate name
        if 'name' in manifest:
            validate_naming_convention(manifest['name'], result)

    # 3. Validate copyright headers
    print("\n©️  Validating copyright headers...")
    validate_copyright_headers(plugin_dir, result)

    # 4. Validate A2A compliance
    print("\n🔗 Validating A2A protocol compliance...")
    validate_a2a_compliance(plugin_dir, manifest, result)

    # 5. Basic security checks
    if strict:
        print("\n🔒 Running security checks...")
        validate_security_basics(plugin_dir, result)

    return result


def find_all_plugins(base_dir: Path = Path('.')) -> List[Path]:
    """Find all plugin directories in the repository."""
    plugins = []

    for plug_type in ['plugs', 'pipes', 'glues']:
        type_dir = base_dir / plug_type
        if not type_dir.exists():
            continue

        # Find version directories (e.g., plugs/category/name/1.0.0/)
        for category_dir in type_dir.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith('.'):
                continue

            for name_dir in category_dir.iterdir():
                if not name_dir.is_dir() or name_dir.name.startswith('.'):
                    continue

                for version_dir in name_dir.iterdir():
                    if version_dir.is_dir() and not version_dir.name.startswith('.'):
                        # Check if it has plug.yaml or pipe.yaml
                        if (version_dir / 'plug.yaml').exists() or (version_dir / 'pipe.yaml').exists():
                            plugins.append(version_dir)

    return plugins


def main():
    parser = argparse.ArgumentParser(
        description='PlugPipe Plugin Validation Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate single plugin
  python3 scripts/validate_plugin.py plugs/integration/my_plugin/1.0.0/

  # Validate with strict security checks
  python3 scripts/validate_plugin.py plugs/integration/my_plugin/1.0.0/ --strict

  # Validate all plugins in repository
  python3 scripts/validate_plugin.py --all

  # Validate all plugins with strict mode
  python3 scripts/validate_plugin.py --all --strict
        """
    )

    parser.add_argument('plugin_path', nargs='?', help='Path to plugin directory')
    parser.add_argument('--all', action='store_true', help='Validate all plugins in repository')
    parser.add_argument('--strict', action='store_true', help='Enable strict validation (security checks)')

    args = parser.parse_args()

    if args.all:
        print("🔍 Discovering all plugins...")
        plugins = find_all_plugins()
        print(f"Found {len(plugins)} plugins\n")

        total_passed = 0
        total_failed = 0
        failed_plugins = []

        for plugin_dir in plugins:
            result = validate_plugin(plugin_dir, args.strict)
            if result.is_valid():
                total_passed += 1
            else:
                total_failed += 1
                failed_plugins.append(str(plugin_dir))
            result.print_summary()

        print(f"\n{'='*70}")
        print("OVERALL SUMMARY")
        print(f"{'='*70}")
        print(f"Total plugins validated: {len(plugins)}")
        print(f"✅ Passed: {total_passed}")
        print(f"❌ Failed: {total_failed}")

        if failed_plugins:
            print(f"\nFailed plugins:")
            for plugin in failed_plugins:
                print(f"  - {plugin}")
            return 1
        else:
            print("\n✅ All plugins passed validation!")
            return 0

    elif args.plugin_path:
        plugin_dir = Path(args.plugin_path)

        if not plugin_dir.exists():
            print(f"❌ Error: Plugin directory not found: {plugin_dir}")
            return 1

        if not plugin_dir.is_dir():
            print(f"❌ Error: Not a directory: {plugin_dir}")
            return 1

        result = validate_plugin(plugin_dir, args.strict)
        return result.print_summary()

    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
