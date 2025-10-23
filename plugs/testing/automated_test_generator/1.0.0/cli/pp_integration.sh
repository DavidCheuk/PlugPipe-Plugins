#!/bin/bash
"""
PlugPipe CLI Integration for Automated Test Generator

This script provides pp command integration for the automated test generator.
It should be integrated into the main pp CLI command structure.

Usage:
  pp test-gen <subcommand> [options]

Available subcommands:
  generate    - Generate tests for a plugin
  run         - Run existing tests with filtering
  list        - List available test patterns
  interactive - Interactive test selection
"""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_SCRIPT="$SCRIPT_DIR/pp_test_gen.py"

# Check if the CLI script exists
if [[ ! -f "$CLI_SCRIPT" ]]; then
    echo "❌ Error: CLI script not found at $CLI_SCRIPT"
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 is required but not installed"
    exit 1
fi

# Execute the CLI script with all arguments
exec python3 "$CLI_SCRIPT" "$@"