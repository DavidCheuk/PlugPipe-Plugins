#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Copyright Validator Plugin

Validates and enforces copyright headers across the entire PlugPipe ecosystem.
Ensures all source files have proper SPDX-License-Identifier headers and all
plugin manifests have copyright fields.

Following PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Uses standard SPDX format
- SIMPLICITY BY TRADITION: 3-line header format (industry standard)
- GRACEFUL DEGRADATION: Reports violations without breaking builds
- DEFAULT TO CREATING PLUGINS: Copyright protection as a plugin
"""

import os
import sys
import re
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime

# Standard SPDX header template
SPDX_HEADER_TEMPLATE = """# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe
"""

# Shebang-aware header (for executable scripts)
SPDX_HEADER_WITH_SHEBANG = """#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe
"""

# Copyright fields for plug.yaml
COPYRIGHT_MANIFEST_FIELDS = {
    "copyright": {
        "owner": "PlugPipe Team",
        "year": 2025,
        "notice": "Copyright © 2025 PlugPipe Team. All rights reserved."
    },
    "license": "MIT",
    "license_url": "https://opensource.org/licenses/MIT",
    "spdx_license_identifier": "MIT"
}

@dataclass
class ValidationResult:
    """Result of copyright validation"""
    file_path: str
    has_spdx: bool = False
    has_copyright: bool = False
    has_proper_format: bool = False
    line_number: Optional[int] = None
    issue: Optional[str] = None

    @property
    def is_compliant(self) -> bool:
        """Check if file is fully compliant"""
        return self.has_spdx and self.has_copyright and self.has_proper_format


@dataclass
class ComplianceReport:
    """Compliance statistics"""
    total_files: int = 0
    files_with_headers: int = 0
    files_missing_headers: int = 0
    violations: List[Dict[str, Any]] = field(default_factory=list)
    by_category: Dict[str, Dict[str, int]] = field(default_factory=dict)

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage"""
        if self.total_files == 0:
            return 100.0
        return (self.files_with_headers / self.total_files) * 100.0


class CopyrightValidator:
    """Main copyright validation and enforcement engine"""

    def __init__(self, root_path: Optional[Path] = None):
        """Initialize validator"""
        self.root_path = root_path or Path("/mnt/c/Project/PlugPipe")
        self.report = ComplianceReport()

        # Scope definitions
        self.scopes = {
            "all": [
                "plugs", "pipes", "glues", "cores", "shares",
                "tests", "utils", "scripts", "pp_hub"
            ],
            "plugs": ["plugs"],
            "cores": ["cores"],
            "shares": ["shares"],
            "tests": ["tests"],
            "utils": ["utils"],
            "scripts": ["scripts"]
        }

        # Patterns to identify SPDX headers
        self.spdx_pattern = re.compile(
            r'^\s*#\s*SPDX-License-Identifier:\s*MIT',
            re.MULTILINE | re.IGNORECASE
        )

        self.copyright_pattern = re.compile(
            r'^\s*#\s*Copyright\s*\(c\)\s*202[45].*PlugPipe',
            re.MULTILINE | re.IGNORECASE
        )

        self.shebang_pattern = re.compile(r'^#!/usr/bin/env python3')

    def find_python_files(self, scope: str = "all", limit: Optional[int] = None) -> List[Path]:
        """Find all Python files in scope"""
        python_files = []
        directories = self.scopes.get(scope, self.scopes["all"])

        for directory in directories:
            dir_path = self.root_path / directory
            if not dir_path.exists():
                continue

            # Find all .py files
            for py_file in dir_path.rglob("*.py"):
                # Skip virtual environment
                if ".venv" in str(py_file) or "venv" in str(py_file):
                    continue
                # Skip __pycache__
                if "__pycache__" in str(py_file):
                    continue

                python_files.append(py_file)

                if limit and len(python_files) >= limit:
                    break

            if limit and len(python_files) >= limit:
                break

        # Also check root pp executable
        pp_executable = self.root_path / "pp"
        if pp_executable.exists() and pp_executable not in python_files:
            python_files.append(pp_executable)

        return sorted(python_files)

    def find_plugin_manifests(self, limit: Optional[int] = None) -> List[Path]:
        """Find all plug.yaml manifest files"""
        manifests = []

        for directory in ["plugs", "pipes", "glues"]:
            dir_path = self.root_path / directory
            if not dir_path.exists():
                continue

            for manifest in dir_path.rglob("plug.yaml"):
                manifests.append(manifest)

                if limit and len(manifests) >= limit:
                    break

        # Also check for pipe.yaml files
        for directory in ["pipes"]:
            dir_path = self.root_path / directory
            if dir_path.exists():
                for manifest in dir_path.rglob("pipe.yaml"):
                    manifests.append(manifest)

                    if limit and len(manifests) >= limit:
                        break

        return sorted(manifests)

    def validate_file(self, file_path: Path) -> ValidationResult:
        """Validate a single Python file for copyright headers"""
        result = ValidationResult(file_path=str(file_path.relative_to(self.root_path)))

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                first_10_lines = '\n'.join(content.split('\n')[:10])

            # Check for SPDX identifier
            if self.spdx_pattern.search(first_10_lines):
                result.has_spdx = True
            else:
                result.issue = "Missing SPDX-License-Identifier"

            # Check for copyright notice
            if self.copyright_pattern.search(first_10_lines):
                result.has_copyright = True
            else:
                if not result.issue:
                    result.issue = "Missing Copyright notice"
                else:
                    result.issue += " and Copyright notice"

            # Check format (both should be in first 10 lines)
            if result.has_spdx and result.has_copyright:
                result.has_proper_format = True

            # Find line number if issue exists
            if result.issue:
                result.line_number = 1

        except Exception as e:
            result.issue = f"Error reading file: {str(e)}"

        return result

    def validate_manifest(self, manifest_path: Path) -> ValidationResult:
        """Validate a plugin manifest for copyright fields"""
        result = ValidationResult(
            file_path=str(manifest_path.relative_to(self.root_path))
        )

        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = yaml.safe_load(f)

            # Check for copyright field
            if "copyright" in manifest:
                result.has_copyright = True
            else:
                result.issue = "Missing 'copyright' field"

            # Check for license field
            if "license" in manifest:
                result.has_spdx = True
            else:
                if result.issue:
                    result.issue += " and 'license' field"
                else:
                    result.issue = "Missing 'license' field"

            # Check for spdx_license_identifier
            if "spdx_license_identifier" in manifest:
                result.has_proper_format = True
            else:
                if result.issue:
                    result.issue += " and 'spdx_license_identifier' field"
                else:
                    result.issue = "Missing 'spdx_license_identifier' field"

        except Exception as e:
            result.issue = f"Error reading manifest: {str(e)}"

        return result

    def scan_all_files(self, scope: str = "all", limit: Optional[int] = None) -> ComplianceReport:
        """Scan all Python files and generate compliance report"""
        python_files = self.find_python_files(scope, limit)

        self.report = ComplianceReport()
        self.report.total_files = len(python_files)

        category_stats = {}

        for file_path in python_files:
            result = self.validate_file(file_path)

            # Determine category
            relative_path = file_path.relative_to(self.root_path)
            category = str(relative_path).split('/')[0] if '/' in str(relative_path) else "root"

            # Initialize category stats
            if category not in category_stats:
                category_stats[category] = {
                    "total": 0,
                    "compliant": 0,
                    "percentage": 0.0
                }

            category_stats[category]["total"] += 1

            if result.is_compliant:
                self.report.files_with_headers += 1
                category_stats[category]["compliant"] += 1
            else:
                self.report.files_missing_headers += 1
                self.report.violations.append({
                    "file_path": result.file_path,
                    "issue": result.issue,
                    "line_number": result.line_number
                })

        # Calculate percentages
        for category in category_stats:
            total = category_stats[category]["total"]
            compliant = category_stats[category]["compliant"]
            category_stats[category]["percentage"] = (
                (compliant / total * 100.0) if total > 0 else 100.0
            )

        self.report.by_category = category_stats

        return self.report

    def fix_file(self, file_path: Path, dry_run: bool = False) -> bool:
        """Add copyright header to a file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if already has header
            if self.spdx_pattern.search(content[:500]):
                return False  # Already has header

            # Determine if file has shebang
            has_shebang = self.shebang_pattern.match(content)

            if has_shebang:
                # Insert header after shebang
                lines = content.split('\n')
                shebang_line = lines[0]
                rest_of_file = '\n'.join(lines[1:])

                # Remove leading blank lines
                rest_of_file = rest_of_file.lstrip('\n')

                new_content = (
                    f"{shebang_line}\n"
                    f"# SPDX-License-Identifier: MIT\n"
                    f"# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk\n"
                    f"# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe\n"
                    f"\n"
                    f"{rest_of_file}"
                )
            else:
                # Add header at the beginning
                new_content = SPDX_HEADER_TEMPLATE.lstrip() + "\n" + content.lstrip()

            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)

            return True

        except Exception as e:
            print(f"Error fixing {file_path}: {e}")
            return False

    def fix_manifest(self, manifest_path: Path, dry_run: bool = False) -> bool:
        """Add copyright fields to a manifest file"""
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = yaml.safe_load(f) or {}

            # Check if already has copyright fields
            if all(key in manifest for key in COPYRIGHT_MANIFEST_FIELDS.keys()):
                return False  # Already has all fields

            # Add missing fields (preserve order by inserting after version)
            updated = False
            for key, value in COPYRIGHT_MANIFEST_FIELDS.items():
                if key not in manifest:
                    manifest[key] = value
                    updated = True

            if updated and not dry_run:
                # Write back to file (maintaining YAML formatting)
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    yaml.dump(manifest, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

            return updated

        except Exception as e:
            print(f"Error fixing manifest {manifest_path}: {e}")
            return False

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        trend = "📊 Initial scan - no trend data available"

        if self.report.compliance_percentage == 100.0:
            trend = "✅ Maintaining 100% compliance"
        elif self.report.compliance_percentage >= 90.0:
            trend = "⚠️ High compliance but requires attention"
        elif self.report.compliance_percentage >= 70.0:
            trend = "🔴 Moderate compliance - action required"
        else:
            trend = "🚨 Critical compliance gap - immediate action required"

        recommendations = []

        if self.report.compliance_percentage < 100.0:
            recommendations.append(
                f"Run auto-fix to update {self.report.files_missing_headers} files"
            )
            recommendations.append(
                "Install pre-commit hook to prevent future violations"
            )
            recommendations.append(
                "Review and update plugin manifests with copyright fields"
            )

        return {
            "report_date": datetime.now().isoformat(),
            "compliance": asdict(self.report),
            "trend": trend,
            "recommendations": recommendations
        }


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point"""
    action = cfg.get("action", "scan")
    scope = cfg.get("scope", "all")
    auto_approve = cfg.get("auto_approve", False)
    dry_run = cfg.get("dry_run", False)
    limit = cfg.get("limit")

    validator = CopyrightValidator()

    result = {
        "success": True,
        "action": action,
        "compliance": {},
        "violations": [],
        "fixes_applied": [],
        "report": {}
    }

    try:
        if action == "scan":
            # Scan all files and report violations
            report = validator.scan_all_files(scope, limit)
            result["compliance"] = {
                "total_files": report.total_files,
                "files_with_headers": report.files_with_headers,
                "files_missing_headers": report.files_missing_headers,
                "compliance_percentage": round(report.compliance_percentage, 2)
            }
            result["violations"] = report.violations[:100]  # Limit to first 100

            print(f"\n{'='*60}")
            print(f"📋 Copyright Compliance Scan Results")
            print(f"{'='*60}")
            print(f"Total files scanned: {report.total_files}")
            print(f"Files with headers: {report.files_with_headers}")
            print(f"Files missing headers: {report.files_missing_headers}")
            print(f"Compliance: {report.compliance_percentage:.1f}%")
            print(f"{'='*60}\n")

            if report.violations:
                print(f"⚠️  Found {len(report.violations)} violations")
                print(f"Run with action='fix' to auto-fix violations\n")

        elif action == "validate":
            # Quick validation check (pass/fail)
            report = validator.scan_all_files(scope, limit)
            result["compliance"] = {
                "total_files": report.total_files,
                "files_with_headers": report.files_with_headers,
                "files_missing_headers": report.files_missing_headers,
                "compliance_percentage": round(report.compliance_percentage, 2)
            }

            if report.compliance_percentage < 100.0:
                result["success"] = False
                print(f"❌ Compliance validation FAILED: {report.compliance_percentage:.1f}%")
                print(f"   {report.files_missing_headers} files missing headers")
            else:
                print(f"✅ Compliance validation PASSED: 100%")

        elif action == "report":
            # Generate comprehensive report
            report = validator.scan_all_files(scope, limit)
            result["report"] = validator.generate_report()
            result["compliance"] = {
                "total_files": report.total_files,
                "files_with_headers": report.files_with_headers,
                "files_missing_headers": report.files_missing_headers,
                "compliance_percentage": round(report.compliance_percentage, 2)
            }

            print(json.dumps(result["report"], indent=2))

        elif action == "fix":
            # Auto-fix missing headers
            if not auto_approve and not dry_run:
                print("⚠️  This will modify source files. Use auto_approve=true to proceed.")
                result["success"] = False
                return result

            python_files = validator.find_python_files(scope, limit)
            fixes_applied = []

            mode_str = "(DRY RUN)" if dry_run else ""
            print(f"\n{'='*60}")
            print(f"🔧 Auto-Fixing Copyright Headers {mode_str}")
            print(f"{'='*60}")

            for file_path in python_files:
                validation = validator.validate_file(file_path)
                if not validation.is_compliant:
                    fixed = validator.fix_file(file_path, dry_run)
                    if fixed:
                        fixes_applied.append({
                            "file_path": str(file_path.relative_to(validator.root_path)),
                            "action": "added_header"
                        })
                        print(f"✅ Fixed: {file_path.relative_to(validator.root_path)}")

            result["fixes_applied"] = fixes_applied
            print(f"\n{'='*60}")
            print(f"{'DRY RUN: Would fix' if dry_run else 'Fixed'} {len(fixes_applied)} files")
            print(f"{'='*60}\n")

        elif action == "fix_manifests":
            # Fix plugin manifests
            if not auto_approve and not dry_run:
                print("⚠️  This will modify manifest files. Use auto_approve=true to proceed.")
                result["success"] = False
                return result

            manifests = validator.find_plugin_manifests(limit)
            fixes_applied = []

            mode_str = "(DRY RUN)" if dry_run else ""
            print(f"\n{'='*60}")
            print(f"🔧 Auto-Fixing Plugin Manifests {mode_str}")
            print(f"{'='*60}")

            for manifest_path in manifests:
                fixed = validator.fix_manifest(manifest_path, dry_run)
                if fixed:
                    fixes_applied.append({
                        "file_path": str(manifest_path.relative_to(validator.root_path)),
                        "action": "added_copyright_fields"
                    })
                    print(f"✅ Fixed: {manifest_path.relative_to(validator.root_path)}")

            result["fixes_applied"] = fixes_applied
            print(f"\n{'='*60}")
            print(f"{'DRY RUN: Would fix' if dry_run else 'Fixed'} {len(fixes_applied)} manifests")
            print(f"{'='*60}\n")

        elif action == "install_hook":
            # Install pre-commit hook
            hook_script = """#!/bin/bash
# Copyright Pre-Commit Hook
# Validates all Python files have SPDX headers before commit

echo "🔒 Checking copyright headers..."

STAGED_PY_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\\.py$')

if [ -z "$STAGED_PY_FILES" ]; then
    echo "✅ No Python files to check"
    exit 0
fi

MISSING_HEADERS=0

for file in $STAGED_PY_FILES; do
    if ! head -10 "$file" | grep -q "SPDX-License-Identifier"; then
        echo "❌ Missing copyright header: $file"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done

if [ $MISSING_HEADERS -gt 0 ]; then
    echo ""
    echo "🚨 COMMIT BLOCKED: $MISSING_HEADERS file(s) missing copyright headers"
    echo ""
    echo "Required header format:"
    echo "  # SPDX-License-Identifier: MIT"
    echo "  # Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk"
    echo "  # This file is part of PlugPipe"
    echo ""
    echo "Fix with: ./pp run copyright_validator --input '{\"action\": \"fix\", \"auto_approve\": true}'"
    exit 1
fi

echo "✅ All files have copyright headers"
exit 0
"""

            hook_path = validator.root_path / ".git" / "hooks" / "pre-commit"

            if not dry_run:
                hook_path.parent.mkdir(parents=True, exist_ok=True)
                with open(hook_path, 'w') as f:
                    f.write(hook_script)
                hook_path.chmod(0o755)
                print(f"✅ Installed pre-commit hook at: {hook_path}")
            else:
                print(f"DRY RUN: Would install pre-commit hook at: {hook_path}")

            result["fixes_applied"] = [{"file_path": str(hook_path), "action": "installed_hook"}]

        else:
            result["success"] = False
            result["error"] = f"Unknown action: {action}"

    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
        print(f"❌ Error: {e}")

    return result


if __name__ == "__main__":
    # CLI interface for direct execution
    import sys

    if len(sys.argv) < 2:
        print("Usage: python main.py <action> [--scope=<scope>] [--dry-run] [--auto-approve] [--limit=N]")
        print("Actions: scan, validate, report, fix, fix_manifests, install_hook")
        sys.exit(1)

    cfg = {"action": sys.argv[1]}

    # Parse additional arguments
    for arg in sys.argv[2:]:
        if arg.startswith("--scope="):
            cfg["scope"] = arg.split("=")[1]
        elif arg == "--dry-run":
            cfg["dry_run"] = True
        elif arg == "--auto-approve":
            cfg["auto_approve"] = True
        elif arg.startswith("--limit="):
            cfg["limit"] = int(arg.split("=")[1])

    result = process({}, cfg)

    if not result["success"]:
        sys.exit(1)
