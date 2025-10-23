#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Unified Attack Database CLI

Provides pp command integration for attack case generation and database management.
Supports direct CLI parameters without JSON input files.

Usage:
  pp db generate --cases 100 --github --unique --categories sql_injection,xss
  pp db stats
  pp db query --category sql_injection --limit 10
  pp db clear --confirm
  pp db export --format json --output /tmp/attacks.json
"""

import argparse
import sys
import json
import yaml
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import importlib.util

# Add PlugPipe paths for ecosystem access
PROJECT_ROOT = str(Path(__file__).parent.parent.parent.parent.parent)
sys.path.insert(0, PROJECT_ROOT)

try:
    from shares.loader import pp
    PLUGPIPE_AVAILABLE = True
    print("Debug: PlugPipe pp() loader available")
except ImportError as e:
    PLUGPIPE_AVAILABLE = False
    print(f"Debug: PlugPipe pp() loader not available: {e}")

class AttackDatabaseCLI:
    """CLI interface for PlugPipe Unified Attack Database"""
    
    def __init__(self):
        self.attack_db = None
        # Try to load plugin using pp() loader if available
        if PLUGPIPE_AVAILABLE:
            try:
                self.attack_db = pp('unified_attack_database')
                print("Info: Using PlugPipe pp() loader")
            except Exception as e:
                print(f"Info: pp() loader failed, trying direct import: {e}")
        
        # If pp() loader not available or failed, try direct import
        if not self.attack_db:
            try:
                plugin_path = Path(__file__).parent.parent / "main.py"
                if not plugin_path.exists():
                    raise FileNotFoundError(f"Plugin main.py not found at {plugin_path}")
                
                # Add plugin directory to path for imports
                plugin_dir = str(plugin_path.parent)
                if plugin_dir not in sys.path:
                    sys.path.insert(0, plugin_dir)
                
                # Add shares path for shared utilities
                shares_path = str(Path(PROJECT_ROOT) / "shares")
                if shares_path not in sys.path:
                    sys.path.insert(0, shares_path)
                
                spec = importlib.util.spec_from_file_location("unified_attack_database", plugin_path)
                plugin_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(plugin_module)
                self.attack_db_direct = plugin_module
                self.attack_db = True  # Flag that we have access
                print("Info: Using direct plugin import")
            except Exception as e2:
                print(f"Error: Could not load unified_attack_database plugin: {e2}")
                import traceback
                traceback.print_exc()
    
    def _execute_plugin(self, context, config):
        """Execute plugin using available method (pp loader or direct import)"""
        if hasattr(self, 'attack_db_direct'):
            return self.attack_db_direct.process(context, config)
        else:
            return self.attack_db.process(context, config)
    
    def generate_cases(self, args):
        """Generate attack cases with specified parameters"""
        if not self.attack_db:
            print("❌ Unified attack database plugin not available")
            return 1
        
        # Parse categories
        categories = ['all']
        if args.categories:
            categories = [c.strip() for c in args.categories.split(',')]
        
        # Build configuration
        config = {
            'operation': 'generate_unified_database',
            'test_cases': args.cases or 50,
            'include_github_payloads': args.github,
            'unique_only': args.unique,
            'exclude_previous': args.exclude_previous,
            'randomize': args.randomize,
            'categories': categories,
            'protocol_format': args.format or 'raw',
            'github_rate_limit_delay': args.delay or 0.0,
            'github_max_delay': args.max_delay or 0.5
        }
        
        if args.dry_run:
            print("🔍 DRY RUN - Attack Case Generation Configuration:")
            print(yaml.dump(config, default_flow_style=False, indent=2))
            return 0
        
        print(f"🗃️  Generating {config['test_cases']} attack cases")
        if args.github:
            print("🔍 Including GitHub payload analysis")
        if args.unique:
            print("✨ Unique cases only (deduplication enabled)")
        if categories != ['all']:
            print(f"🏷️  Categories: {', '.join(categories)}")
        
        try:
            result = self._execute_plugin({}, config)
            
            if result.get('success'):
                self._display_generation_results(result, args.output_format or 'table')
                return 0
            else:
                print(f"❌ Attack case generation failed: {result.get('error', 'Unknown error')}")
                return 1
                
        except Exception as e:
            print(f"❌ Attack case generation error: {e}")
            return 1
    
    def get_stats(self, args):
        """Get database statistics"""
        if not self.attack_db:
            print("❌ Unified attack database plugin not available")
            return 1
        
        config = {
            'operation': 'get_database_stats'
        }
        
        try:
            result = self._execute_plugin({}, config)
            
            if result.get('success'):
                self._display_stats_results(result, args.output_format or 'table')
                return 0
            else:
                print(f"❌ Failed to get database stats: {result.get('error', 'Unknown error')}")
                return 1
                
        except Exception as e:
            print(f"❌ Database stats error: {e}")
            return 1
    
    def query_database(self, args):
        """Query attack cases from database"""
        if not self.attack_db:
            print("❌ Unified attack database plugin not available")
            return 1
        
        config = {
            'operation': 'query_database',
            'category': args.category,
            'limit': args.limit or 10,
            'severity': args.severity,
            'protocol_format': args.protocol,
            'source': args.source
        }
        
        try:
            result = self._execute_plugin({}, config)
            
            if result.get('success'):
                self._display_query_results(result, args.output_format or 'table')
                return 0
            else:
                print(f"❌ Database query failed: {result.get('error', 'Unknown error')}")
                return 1
                
        except Exception as e:
            print(f"❌ Database query error: {e}")
            return 1
    
    def clear_database(self, args):
        """Clear database with confirmation"""
        if not self.attack_db:
            print("❌ Unified attack database plugin not available")
            return 1
        
        if not args.confirm and not args.force:
            print("❌ Database clearing requires --confirm or --force flag for safety")
            print("   Use: pp db clear --confirm")
            return 1
        
        if not args.force:
            confirm = input("⚠️  Are you sure you want to clear the attack database? [y/N]: ").strip().lower()
            if confirm != 'y':
                print("❌ Database clearing cancelled")
                return 1
        
        config = {
            'operation': 'clear_database'
        }
        
        try:
            result = self._execute_plugin({}, config)
            
            if result.get('success'):
                print("✅ Database cleared successfully")
                return 0
            else:
                print(f"❌ Database clearing failed: {result.get('error', 'Unknown error')}")
                return 1
                
        except Exception as e:
            print(f"❌ Database clearing error: {e}")
            return 1
    
    def export_database(self, args):
        """Export database to file"""
        if not self.attack_db:
            print("❌ Unified attack database plugin not available")
            return 1
        
        config = {
            'operation': 'export_database',
            'output_file': args.output or '/tmp/attack_database_export.json',
            'export_format': args.format or 'json',
            'category': args.category,
            'limit': args.limit
        }
        
        try:
            result = self._execute_plugin({}, config)
            
            if result.get('success'):
                output_file = result.get('export_file', args.output)
                print(f"✅ Database exported to: {output_file}")
                print(f"📊 Records exported: {result.get('records_exported', 0)}")
                return 0
            else:
                print(f"❌ Database export failed: {result.get('error', 'Unknown error')}")
                return 1
                
        except Exception as e:
            print(f"❌ Database export error: {e}")
            return 1
    
    def _display_generation_results(self, result: Dict[str, Any], output_format: str):
        """Display attack case generation results in specified format"""
        if output_format == 'json':
            print(json.dumps(result, indent=2, default=str))
            return
        
        if output_format == 'yaml':
            print(yaml.dump(result, default_flow_style=False, indent=2))
            return
        
        # Table format (default)
        print("\n🗃️  Attack Case Generation Results")
        print("=" * 40)
        
        generation_stats = result.get('generation_stats', {})
        
        print(f"✅ Success: {result.get('success', False)}")
        print(f"📊 Cases Generated: {generation_stats.get('cases_generated', 0)}")
        print(f"📈 Database Total: {generation_stats.get('database_total', 0)}")
        print(f"⏱️  Generation Time: {generation_stats.get('generation_time', 0):.2f}s")
        
        # Category breakdown
        category_stats = generation_stats.get('category_breakdown', {})
        if category_stats:
            print("\n📑 Category Breakdown:")
            for category, count in category_stats.items():
                if count > 0:
                    print(f"   • {category.replace('_', ' ').title()}: {count} cases")
        
        # Source breakdown
        source_stats = generation_stats.get('source_breakdown', {})
        if source_stats:
            print("\n📍 Source Breakdown:")
            for source, count in source_stats.items():
                if count > 0:
                    print(f"   • {source.title()}: {count} cases")
        
        # Performance metrics
        perf_metrics = generation_stats.get('performance_metrics', {})
        if perf_metrics:
            print(f"\n⚡ Performance Metrics:")
            print(f"   • Cases per Minute: {perf_metrics.get('cases_per_minute', 0):.1f}")
            print(f"   • Average Case Time: {perf_metrics.get('avg_case_time', 0):.2f}s")
    
    def _display_stats_results(self, result: Dict[str, Any], output_format: str):
        """Display database statistics in specified format"""
        if output_format == 'json':
            print(json.dumps(result, indent=2, default=str))
            return
        
        if output_format == 'yaml':
            print(yaml.dump(result, default_flow_style=False, indent=2))
            return
        
        # Table format (default)
        print("\n📊 Attack Database Statistics")
        print("=" * 32)
        
        stats = result.get('database_stats', {})
        
        print(f"📈 Total Cases: {stats.get('total_cases', 0)}")
        print(f"📅 Last Updated: {stats.get('last_updated', 'Never')}")
        
        # Category distribution
        category_dist = stats.get('category_distribution', {})
        if category_dist:
            print("\n🏷️  Category Distribution:")
            for category, count in sorted(category_dist.items()):
                if count > 0:
                    print(f"   • {category.replace('_', ' ').title()}: {count}")
        
        # Severity distribution
        severity_dist = stats.get('severity_distribution', {})
        if severity_dist:
            print("\n⚠️  Severity Distribution:")
            for severity, count in sorted(severity_dist.items()):
                if count > 0:
                    print(f"   • {severity.title()}: {count}")
        
        # Source distribution
        source_dist = stats.get('source_distribution', {})
        if source_dist:
            print("\n📍 Source Distribution:")
            for source, count in sorted(source_dist.items()):
                if count > 0:
                    print(f"   • {source.title()}: {count}")
        
        # Database health
        health = stats.get('health', {})
        if health:
            print(f"\n💚 Database Health:")
            print(f"   • Unique Ratio: {health.get('unique_ratio', 0):.1%}")
            print(f"   • Data Quality: {health.get('data_quality_score', 0):.1f}/10")
    
    def _display_query_results(self, result: Dict[str, Any], output_format: str):
        """Display query results in specified format"""
        if output_format == 'json':
            print(json.dumps(result, indent=2, default=str))
            return
        
        if output_format == 'yaml':
            print(yaml.dump(result, default_flow_style=False, indent=2))
            return
        
        # Table format (default)
        attack_cases = result.get('attack_cases', [])
        
        print(f"\n🔍 Query Results ({len(attack_cases)} cases)")
        print("=" * 30)
        
        if not attack_cases:
            print("   No matching attack cases found")
            return
        
        for i, case in enumerate(attack_cases, 1):
            print(f"\n{i}. {case.get('id', 'Unknown ID')}")
            print(f"   Category: {case.get('category', 'Unknown')}")
            print(f"   Severity: {case.get('severity', 'Unknown')}")
            print(f"   Source: {case.get('source', 'Unknown')}")
            print(f"   Payload: {case.get('payload', 'No payload')[:100]}{'...' if len(case.get('payload', '')) > 100 else ''}")
            if case.get('description'):
                print(f"   Description: {case.get('description')[:100]}{'...' if len(case.get('description', '')) > 100 else ''}")


def create_parser():
    """Create argument parser for CLI"""
    parser = argparse.ArgumentParser(
        description="PlugPipe Unified Attack Database CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 100 unique GitHub-sourced attack cases
  pp db generate --cases 100 --github --unique
  
  # Generate SQL injection cases only
  pp db generate --cases 50 --categories sql_injection --github
  
  # Get database statistics
  pp db stats
  
  # Query XSS attacks
  pp db query --category xss --limit 5
  
  # Export database to JSON
  pp db export --format json --output /tmp/attacks.json
  
  # Clear database (requires confirmation)
  pp db clear --confirm
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate attack cases')
    gen_parser.add_argument('--cases', type=int, default=50, help='Number of cases to generate (default: 50)')
    gen_parser.add_argument('--github', action='store_true', help='Include GitHub payload analysis')
    gen_parser.add_argument('--unique', action='store_true', help='Generate unique cases only (deduplication)')
    gen_parser.add_argument('--exclude-previous', action='store_true', help='Exclude previously generated cases')
    gen_parser.add_argument('--randomize', action='store_true', help='Randomize case generation')
    gen_parser.add_argument('--categories', help='Attack categories (comma-separated): sql_injection,xss,rce,etc.')
    gen_parser.add_argument('--format', choices=['raw', 'mcp', 'http'], default='raw', help='Protocol format (default: raw)')
    gen_parser.add_argument('--delay', type=float, help='GitHub API rate limit delay in seconds (default: 0.0)')
    gen_parser.add_argument('--max-delay', type=float, help='Maximum GitHub API delay in seconds (default: 0.5)')
    gen_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    gen_parser.add_argument('--dry-run', action='store_true', help='Show configuration without generating')
    gen_parser.add_argument('--output-format', choices=['table', 'json', 'yaml'], default='table', help='Output format')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    stats_parser.add_argument('--output-format', choices=['table', 'json', 'yaml'], default='table', help='Output format')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Query attack cases from database')
    query_parser.add_argument('--category', help='Attack category to filter by')
    query_parser.add_argument('--severity', help='Severity level to filter by')
    query_parser.add_argument('--protocol', help='Protocol format to filter by')
    query_parser.add_argument('--source', help='Source to filter by (github, internal, etc.)')
    query_parser.add_argument('--limit', type=int, default=10, help='Maximum number of results (default: 10)')
    query_parser.add_argument('--output-format', choices=['table', 'json', 'yaml'], default='table', help='Output format')
    
    # Clear command
    clear_parser = subparsers.add_parser('clear', help='Clear attack database')
    clear_parser.add_argument('--confirm', action='store_true', help='Confirm database clearing')
    clear_parser.add_argument('--force', action='store_true', help='Force clear without confirmation prompt')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export attack database')
    export_parser.add_argument('--output', default='/tmp/attack_database_export.json', help='Output file path')
    export_parser.add_argument('--format', choices=['json', 'csv', 'yaml'], default='json', help='Export format')
    export_parser.add_argument('--category', help='Category to export (exports all if not specified)')
    export_parser.add_argument('--limit', type=int, help='Limit number of records to export')
    
    return parser


def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    cli = AttackDatabaseCLI()
    
    if args.command == 'generate':
        return cli.generate_cases(args)
    elif args.command == 'stats':
        return cli.get_stats(args)
    elif args.command == 'query':
        return cli.query_database(args)
    elif args.command == 'clear':
        return cli.clear_database(args)
    elif args.command == 'export':
        return cli.export_database(args)
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == '__main__':
    sys.exit(main())