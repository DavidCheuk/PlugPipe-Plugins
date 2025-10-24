#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Automated Test Generator CLI

Provides pp command integration for flexible test generation and execution.
Supports selective test patterns, interactive mode, and comprehensive test management.

Usage:
  pp test-gen generate --plugin my_plugin --types unit,integration
  pp test-gen run --pattern "test_*_performance" --plugin my_plugin
  pp test-gen list --plugin my_plugin --show-patterns
  pp test-gen interactive --plugin my_plugin
"""

import argparse
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
import importlib.util

# Add PlugPipe paths for ecosystem access
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

try:
    from shares.loader import pp
    PLUGPIPE_AVAILABLE = True
except ImportError:
    PLUGPIPE_AVAILABLE = False

class TestGeneratorCLI:
    """CLI interface for PlugPipe Automated Test Generator"""
    
    def __init__(self):
        self.test_generator = None
        if PLUGPIPE_AVAILABLE:
            try:
                self.test_generator = pp('automated_test_generator')
            except Exception as e:
                print(f"Warning: Could not load automated_test_generator plugin: {e}")
    
    def generate_tests(self, args):
        """Generate tests for specified plugin with selective patterns"""
        if not self.test_generator:
            print("❌ Automated test generator plugin not available")
            return 1
        
        # Parse test types
        test_types = []
        if args.types:
            test_types = [t.strip() for t in args.types.split(',')]
        
        # Parse test patterns
        test_patterns = []
        if args.patterns:
            test_patterns = [p.strip() for p in args.patterns.split(',')]
        
        # Build configuration
        config = {
            'action': 'generate_full_test_suite' if not test_types else 'run_selective_tests',
            'target_plugin': {
                'name': args.plugin,
                'path': args.plugin_path or f'plugs/{args.category or "unknown"}/{args.plugin}/1.0.0',
                'category': args.category or 'unknown'
            },
            'test_configuration': {
                'test_types': test_types or ['unit', 'integration', 'security'],
                'test_framework': args.framework or 'pytest',
                'coverage_target': args.coverage_target or 0.90,
                'enable_mock_generation': not args.no_mocks,
                'enable_fixture_generation': not args.no_fixtures,
                'enable_parametrized_tests': not args.no_parametrized,
                'include_error_scenarios': not args.no_error_scenarios
            },
            'test_selection': {
                'test_patterns': test_patterns,
                'exclude_patterns': args.exclude_patterns.split(',') if args.exclude_patterns else [],
                'test_categories': test_types,
                'max_execution_time': args.max_time or 300,
                'parallel_execution': args.parallel
            },
            'cli_options': {
                'verbose': args.verbose,
                'dry_run': args.dry_run,
                'output_format': args.output_format or 'table',
                'save_results': not args.no_save,
                'interactive_mode': args.interactive
            },
            'ecosystem_integration': {
                'llm_service_config': {'enabled': not args.no_llm},
                'context_analyzer_config': {'enabled': not args.no_context},
                'agent_factory_config': {'enabled': not args.no_agents},
                'enable_performance_testing': not args.no_performance,
                'enable_security_testing': not args.no_security,
                'enable_integrity_validation': not args.no_validation
            }
        }
        
        if args.dry_run:
            print("🔍 DRY RUN - Test Generation Configuration:")
            print(yaml.dump(config, default_flow_style=False, indent=2))
            return 0
        
        print(f"🧪 Generating tests for plugin: {args.plugin}")
        if test_types:
            print(f"📋 Test types: {', '.join(test_types)}")
        if test_patterns:
            print(f"🎯 Patterns: {', '.join(test_patterns)}")
        
        try:
            result = self.test_generator.process({}, config)
            
            if result.get('success'):
                self._display_generation_results(result, args.output_format or 'table')
                return 0
            else:
                print(f"❌ Test generation failed: {result.get('error', 'Unknown error')}")
                return 1
                
        except Exception as e:
            print(f"❌ Test generation error: {e}")
            return 1
    
    def run_tests(self, args):
        """Run existing tests with pattern filtering"""
        import subprocess
        import os
        
        plugin_path = args.plugin_path or f"plugs/{args.category or 'unknown'}/{args.plugin}/1.0.0"
        test_dir = Path(plugin_path) / "tests"
        
        if not test_dir.exists():
            print(f"❌ No tests directory found at: {test_dir}")
            print("💡 Generate tests first with: pp test-gen generate --plugin {args.plugin}")
            return 1
        
        # Build pytest command
        pytest_args = ['pytest']
        
        if args.verbose:
            pytest_args.append('-v')
        
        if args.pattern:
            pytest_args.extend(['-k', args.pattern])
        
        if args.parallel and args.parallel > 1:
            pytest_args.extend(['-n', str(args.parallel)])
        
        if args.coverage:
            pytest_args.extend(['--cov=main', '--cov-report=term-missing'])
        
        if args.markers:
            for marker in args.markers.split(','):
                pytest_args.extend(['-m', marker.strip()])
        
        if args.max_time:
            pytest_args.extend(['--timeout', str(args.max_time)])
        
        # Add test directory
        pytest_args.append(str(test_dir))
        
        if args.dry_run:
            print("🔍 DRY RUN - Would execute:")
            print(f"  {' '.join(pytest_args)}")
            print(f"  Working directory: {plugin_path}")
            return 0
        
        print(f"🏃 Running tests for plugin: {args.plugin}")
        print(f"📁 Test directory: {test_dir}")
        print(f"⚡ Command: {' '.join(pytest_args)}")
        
        # Change to plugin directory and run tests
        original_cwd = os.getcwd()
        try:
            os.chdir(plugin_path)
            result = subprocess.run(pytest_args, capture_output=args.output_format == 'json')
            
            if args.output_format == 'json' and result.stdout:
                try:
                    # Parse pytest JSON output if available
                    print(json.dumps({'stdout': result.stdout.decode(), 'stderr': result.stderr.decode(), 'returncode': result.returncode}, indent=2))
                except:
                    print(result.stdout.decode())
            
            return result.returncode
            
        except FileNotFoundError:
            print("❌ pytest not found. Install with: pip install pytest")
            return 1
        finally:
            os.chdir(original_cwd)
    
    def list_patterns(self, args):
        """List available test patterns for a plugin"""
        plugin_path = args.plugin_path or f"plugs/{args.category or 'unknown'}/{args.plugin}/1.0.0"
        test_dir = Path(plugin_path) / "tests"
        
        if not test_dir.exists():
            print(f"❌ No tests directory found at: {test_dir}")
            return 1
        
        print(f"📋 Available test patterns for plugin: {args.plugin}")
        print(f"📁 Test directory: {test_dir}")
        print()
        
        # Find all test files
        test_files = list(test_dir.glob("test_*.py"))
        
        if not test_files:
            print("❌ No test files found")
            return 1
        
        patterns = {
            'Test Files': [],
            'Test Categories': set(),
            'Test Functions': [],
            'Test Classes': []
        }
        
        for test_file in test_files:
            patterns['Test Files'].append(test_file.name)
            
            # Extract category from filename
            if '_performance' in test_file.name:
                patterns['Test Categories'].add('performance')
            elif '_security' in test_file.name:
                patterns['Test Categories'].add('security')
            elif '_integration' in test_file.name:
                patterns['Test Categories'].add('integration')
            else:
                patterns['Test Categories'].add('unit')
            
            # Parse test file for function and class names
            try:
                with open(test_file, 'r') as f:
                    content = f.read()
                    
                import re
                # Find test functions
                test_functions = re.findall(r'def (test_[a-zA-Z0-9_]+)', content)
                patterns['Test Functions'].extend([f"{test_file.stem}.{func}" for func in test_functions])
                
                # Find test classes
                test_classes = re.findall(r'class (Test[a-zA-Z0-9_]+)', content)
                patterns['Test Classes'].extend([f"{test_file.stem}.{cls}" for cls in test_classes])
                
            except Exception as e:
                print(f"Warning: Could not parse {test_file}: {e}")
        
        # Display patterns
        for category, items in patterns.items():
            if items:
                print(f"🏷️  {category}:")
                if isinstance(items, set):
                    items = sorted(list(items))
                for item in sorted(items)[:10]:  # Show first 10
                    print(f"   • {item}")
                if len(items) > 10:
                    print(f"   ... and {len(items) - 10} more")
                print()
        
        # Suggest common patterns
        print("💡 Common pattern examples:")
        print("   • test_*_performance     - All performance tests")
        print("   • test_*_security        - All security tests") 
        print("   • test_*_integration     - All integration tests")
        print("   • test_baseline_*        - All baseline tests")
        print("   • test_*_stress          - All stress tests")
        print("   • *redundancy*           - All redundancy tests")
        
        return 0
    
    def interactive_mode(self, args):
        """Interactive test selection and execution"""
        print("🎯 PlugPipe Interactive Test Generator")
        print("=" * 40)
        
        # Get plugin information
        plugin_name = args.plugin or input("Plugin name: ").strip()
        if not plugin_name:
            print("❌ Plugin name required")
            return 1
        
        plugin_path = args.plugin_path or input(f"Plugin path [plugs/unknown/{plugin_name}/1.0.0]: ").strip()
        if not plugin_path:
            plugin_path = f"plugs/unknown/{plugin_name}/1.0.0"
        
        # Check if tests exist
        test_dir = Path(plugin_path) / "tests"
        tests_exist = test_dir.exists() and any(test_dir.glob("test_*.py"))
        
        if tests_exist:
            print(f"✅ Existing tests found at: {test_dir}")
            action = input("Action [generate/run/both]: ").strip().lower()
        else:
            print(f"ℹ️  No tests found at: {test_dir}")
            action = "generate"
        
        if action in ['generate', 'both', '']:
            print("\n📝 Test Generation Options")
            print("-" * 25)
            
            # Select test types
            all_types = ['unit', 'integration', 'performance', 'security', 'compliance', 'api', 'e2e']
            print("Available test types:", ', '.join(all_types))
            selected_types = input("Select test types [unit,integration,security]: ").strip()
            if not selected_types:
                selected_types = "unit,integration,security"
            
            # Configure options
            performance_tests = 'performance' in selected_types
            if performance_tests:
                is_critical = input("Is this a mission-critical plugin? [y/N]: ").strip().lower()
                if is_critical == 'y':
                    print("✅ Enhanced performance testing will be generated")
            
            # Generate tests
            generate_args = argparse.Namespace(
                plugin=plugin_name,
                plugin_path=plugin_path,
                category=None,
                types=selected_types,
                patterns=None,
                exclude_patterns=None,
                framework='pytest',
                coverage_target=0.90,
                max_time=300,
                parallel=False,
                verbose=True,
                dry_run=False,
                output_format='table',
                no_save=False,
                interactive=True,
                no_mocks=False,
                no_fixtures=False,
                no_parametrized=False,
                no_error_scenarios=False,
                no_llm=False,
                no_context=False,
                no_agents=False,
                no_performance=not performance_tests,
                no_security='security' not in selected_types,
                no_validation=False
            )
            
            print("\n🧪 Generating tests...")
            result = self.generate_tests(generate_args)
            if result != 0:
                return result
        
        if action in ['run', 'both']:
            if not tests_exist and action != 'both':
                print("❌ No tests to run. Generate tests first.")
                return 1
            
            print("\n🏃 Test Execution Options")
            print("-" * 23)
            
            pattern = input("Test pattern [press enter for all tests]: ").strip()
            verbose = input("Verbose output? [y/N]: ").strip().lower() == 'y'
            coverage = input("Show coverage report? [y/N]: ").strip().lower() == 'y'
            
            # Run tests
            run_args = argparse.Namespace(
                plugin=plugin_name,
                plugin_path=plugin_path,
                category=None,
                pattern=pattern or None,
                markers=None,
                max_time=300,
                parallel=1,
                coverage=coverage,
                verbose=verbose,
                dry_run=False,
                output_format='table'
            )
            
            print("\n🏃 Running tests...")
            return self.run_tests(run_args)
        
        return 0
    
    def _display_generation_results(self, result: Dict[str, Any], output_format: str):
        """Display test generation results in specified format"""
        if output_format == 'json':
            print(json.dumps(result, indent=2, default=str))
            return
        
        if output_format == 'yaml':
            print(yaml.dump(result, default_flow_style=False, indent=2))
            return
        
        # Table format (default)
        print("\n📊 Test Generation Results")
        print("=" * 40)
        
        test_results = result.get('test_generation_results', {})
        
        print(f"✅ Success: {result.get('success', False)}")
        print(f"📋 Operation: {result.get('operation_completed', 'unknown')}")
        print(f"🧪 Tests Generated: {test_results.get('tests_generated', 0)}")
        
        # Test categories
        categories = test_results.get('test_categories', {})
        if categories:
            print("\n📑 Test Categories:")
            for category, count in categories.items():
                if count > 0:
                    print(f"   • {category.replace('_', ' ').title()}: {count} tests")
        
        # Coverage analysis
        coverage = test_results.get('coverage_analysis', {})
        if coverage:
            print(f"\n📈 Coverage Analysis:")
            print(f"   • Estimated Coverage: {coverage.get('estimated_coverage', 0):.1%}")
            print(f"   • Functions Covered: {coverage.get('functions_covered', 0)}/{coverage.get('functions_total', 0)}")
            print(f"   • Lines Covered: {coverage.get('lines_covered', 0)}/{coverage.get('lines_total', 0)}")
        
        # Test files created
        test_files = test_results.get('test_files_created', [])
        if test_files:
            print(f"\n📄 Generated Test Files:")
            for test_file in test_files:
                file_path = test_file.get('file_path', 'unknown')
                test_type = test_file.get('test_type', 'unknown')
                test_count = test_file.get('tests_count', 0)
                print(f"   • {Path(file_path).name} ({test_type}): {test_count} tests")
        
        # Recommendations
        recommendations = result.get('recommendations', [])
        if recommendations:
            print(f"\n💡 Recommendations:")
            for rec in recommendations:
                print(f"   • {rec}")
        
        # Quality metrics
        quality = test_results.get('quality_metrics', {})
        if quality:
            print(f"\n⭐ Quality Metrics:")
            for metric, value in quality.items():
                if isinstance(value, float):
                    print(f"   • {metric.replace('_', ' ').title()}: {value:.2f}")
                else:
                    print(f"   • {metric.replace('_', ' ').title()}: {value}")


def create_parser():
    """Create argument parser for CLI"""
    parser = argparse.ArgumentParser(
        description="PlugPipe Automated Test Generator CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all tests for a plugin
  pp test-gen generate --plugin my_plugin --category core
  
  # Generate only unit and integration tests
  pp test-gen generate --plugin my_plugin --types unit,integration
  
  # Run performance tests with pattern matching
  pp test-gen run --plugin my_plugin --pattern "*performance*"
  
  # Interactive mode
  pp test-gen interactive --plugin my_plugin
  
  # List available test patterns
  pp test-gen list --plugin my_plugin --show-patterns
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate tests for plugin')
    gen_parser.add_argument('--plugin', required=True, help='Plugin name')
    gen_parser.add_argument('--plugin-path', help='Plugin directory path')
    gen_parser.add_argument('--category', help='Plugin category (e.g., core, security, testing)')
    gen_parser.add_argument('--types', help='Test types (comma-separated): unit,integration,performance,security')
    gen_parser.add_argument('--patterns', help='Test patterns to generate (comma-separated)')
    gen_parser.add_argument('--exclude-patterns', help='Test patterns to exclude (comma-separated)')
    gen_parser.add_argument('--framework', default='pytest', help='Test framework (default: pytest)')
    gen_parser.add_argument('--coverage-target', type=float, help='Coverage target (0.0-1.0)')
    gen_parser.add_argument('--max-time', type=int, help='Max execution time in seconds')
    gen_parser.add_argument('--parallel', action='store_true', help='Enable parallel execution')
    gen_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    gen_parser.add_argument('--dry-run', action='store_true', help='Show configuration without generating')
    gen_parser.add_argument('--output-format', choices=['table', 'json', 'yaml'], help='Output format')
    gen_parser.add_argument('--no-save', action='store_true', help='Do not save results to file')
    gen_parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    gen_parser.add_argument('--no-mocks', action='store_true', help='Disable mock generation')
    gen_parser.add_argument('--no-fixtures', action='store_true', help='Disable fixture generation')
    gen_parser.add_argument('--no-parametrized', action='store_true', help='Disable parametrized tests')
    gen_parser.add_argument('--no-error-scenarios', action='store_true', help='Disable error scenario tests')
    gen_parser.add_argument('--no-llm', action='store_true', help='Disable LLM analysis')
    gen_parser.add_argument('--no-context', action='store_true', help='Disable context analysis')
    gen_parser.add_argument('--no-agents', action='store_true', help='Disable agent factory')
    gen_parser.add_argument('--no-performance', action='store_true', help='Disable performance tests')
    gen_parser.add_argument('--no-security', action='store_true', help='Disable security tests')
    gen_parser.add_argument('--no-validation', action='store_true', help='Disable validation')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Run existing tests with filtering')
    run_parser.add_argument('--plugin', required=True, help='Plugin name')
    run_parser.add_argument('--plugin-path', help='Plugin directory path')
    run_parser.add_argument('--category', help='Plugin category')
    run_parser.add_argument('--pattern', '-k', help='Test pattern to run')
    run_parser.add_argument('--markers', '-m', help='Pytest markers to run (comma-separated)')
    run_parser.add_argument('--max-time', type=int, help='Max execution time in seconds')
    run_parser.add_argument('--parallel', '-n', type=int, help='Number of parallel workers')
    run_parser.add_argument('--coverage', action='store_true', help='Show coverage report')
    run_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    run_parser.add_argument('--dry-run', action='store_true', help='Show command without executing')
    run_parser.add_argument('--output-format', choices=['table', 'json'], help='Output format')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available test patterns')
    list_parser.add_argument('--plugin', required=True, help='Plugin name')
    list_parser.add_argument('--plugin-path', help='Plugin directory path')
    list_parser.add_argument('--category', help='Plugin category')
    list_parser.add_argument('--show-patterns', action='store_true', help='Show detailed patterns')
    
    # Interactive command
    int_parser = subparsers.add_parser('interactive', help='Interactive test generation and execution')
    int_parser.add_argument('--plugin', help='Plugin name (will prompt if not provided)')
    int_parser.add_argument('--plugin-path', help='Plugin directory path')
    
    return parser


def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    cli = TestGeneratorCLI()
    
    if args.command == 'generate':
        return cli.generate_tests(args)
    elif args.command == 'run':
        return cli.run_tests(args)
    elif args.command == 'list':
        return cli.list_patterns(args)
    elif args.command == 'interactive':
        return cli.interactive_mode(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == '__main__':
    sys.exit(main())