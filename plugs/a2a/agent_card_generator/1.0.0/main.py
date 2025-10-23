#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Agent Card Generator - PlugPipe to A2A Protocol Converter

Converts PlugPipe plug.yaml manifests to A2A Protocol agent-card.json format.
Implements A2A specification from https://a2a-protocol.org/dev/specification/
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import yaml
import jsonschema
from datetime import datetime

# A2A Agent Card JSON Schema (from specification)
A2A_AGENT_CARD_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["agentCard"],
    "properties": {
        "agentCard": {
            "type": "object",
            "required": ["id", "name", "description", "version", "serviceUrl", "skills"],
            "properties": {
                "id": {
                    "type": "string",
                    "pattern": "^urn:agent:",
                    "description": "Unique agent identifier in URN format"
                },
                "name": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Human-readable agent name"
                },
                "description": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Agent description and capabilities"
                },
                "version": {
                    "type": "string",
                    "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$",
                    "description": "Semantic version"
                },
                "serviceUrl": {
                    "type": "string",
                    "format": "uri",
                    "description": "A2A service endpoint URL"
                },
                "skills": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["id", "name", "description"],
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Unique skill identifier"
                            },
                            "name": {
                                "type": "string",
                                "description": "Human-readable skill name"
                            },
                            "description": {
                                "type": "string",
                                "description": "Skill description"
                            },
                            "inputModes": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "enum": ["text", "structured", "binary", "multimodal"]
                                }
                            },
                            "outputModes": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "enum": ["text", "json", "artifact", "binary"]
                                }
                            }
                        }
                    }
                },
                "signature": {
                    "type": "object",
                    "description": "Optional JWS signature for verification",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["JWS"]
                        },
                        "value": {
                            "type": "string",
                            "description": "JWS compact serialization"
                        }
                    }
                }
            }
        }
    }
}


class AgentCardGenerator:
    """Converts PlugPipe plug.yaml to A2A agent-card.json"""

    def __init__(self, service_url: str = "http://localhost:8000/a2a"):
        self.service_url = service_url
        self.validator = jsonschema.Draft7Validator(A2A_AGENT_CARD_SCHEMA)

    def load_plug_manifest(self, plug_yaml_path: str) -> Dict[str, Any]:
        """Load and parse plug.yaml file"""
        try:
            with open(plug_yaml_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Failed to load plug.yaml: {e}")

    def convert_to_agent_card(self, plug_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert plug.yaml data to A2A agent card format"""

        # Extract basic plugin information
        plugin_name = plug_data.get('name', 'unknown')
        plugin_version = plug_data.get('version', '1.0.0')
        plugin_category = plug_data.get('category', 'general')
        plugin_subcategory = plug_data.get('subcategory', '')

        # Generate unique agent ID (URN format)
        agent_id = f"urn:agent:plugpipe:{plugin_category}"
        if plugin_subcategory:
            agent_id += f":{plugin_subcategory}"
        agent_id += f":{plugin_name}"

        # Extract description
        description = plug_data.get('description', '').strip()
        if not description:
            description = f"PlugPipe plugin: {plugin_name}"

        # Convert parameters to skills
        skills = self._convert_parameters_to_skills(plug_data)

        # Build agent card
        agent_card = {
            "agentCard": {
                "id": agent_id,
                "name": f"{plugin_name.replace('_', ' ').title()} Agent",
                "description": description,
                "version": plugin_version,
                "serviceUrl": f"{self.service_url}/{plugin_name}",
                "skills": skills,
                "metadata": {
                    "plugpipe": {
                        "originalPlugin": plugin_name,
                        "category": plugin_category,
                        "subcategory": plugin_subcategory,
                        "tags": plug_data.get('tags', []),
                        "author": plug_data.get('author', 'Unknown'),
                        "license": plug_data.get('license', 'Unknown')
                    },
                    "generatedAt": datetime.utcnow().isoformat() + "Z",
                    "generator": "PlugPipe Agent Card Generator v1.0.0"
                }
            }
        }

        return agent_card

    def _convert_parameters_to_skills(self, plug_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert PlugPipe parameters to A2A skills"""

        plugin_name = plug_data.get('name', 'unknown')
        parameters = plug_data.get('parameters', [])

        # Primary skill based on plugin functionality
        primary_skill = {
            "id": f"{plugin_name}-primary",
            "name": f"{plugin_name.replace('_', ' ').title()}",
            "description": plug_data.get('description', '').split('\n')[0].strip(),
            "inputModes": self._determine_input_modes(parameters),
            "outputModes": self._determine_output_modes(plug_data)
        }

        skills = [primary_skill]

        # Add additional skills based on examples if available
        examples = plug_data.get('examples', [])
        if examples:
            # Handle examples as either dict or list
            if isinstance(examples, dict):
                # Convert dict to list of examples
                example_list = []
                for key, value in list(examples.items())[:3]:  # Limit to 3
                    if isinstance(value, dict):
                        example_list.append(value)
                examples = example_list
            elif isinstance(examples, list):
                examples = examples[:3]  # Limit to 3
            else:
                examples = []

            for idx, example in enumerate(examples):
                if not isinstance(example, dict):
                    continue

                skill = {
                    "id": f"{plugin_name}-example-{idx+1}",
                    "name": example.get('description', f'Example {idx+1}'),
                    "description": example.get('description', ''),
                    "inputModes": ["text", "structured"],
                    "outputModes": ["text", "json"]
                }
                skills.append(skill)

        return skills

    def _determine_input_modes(self, parameters: List[Dict[str, Any]]) -> List[str]:
        """Determine A2A input modes from PlugPipe parameters"""
        modes = []

        # Handle case where parameters might not be a list
        if not isinstance(parameters, list):
            parameters = []

        try:
            for param in parameters:
                # Skip non-dict parameters
                if not isinstance(param, dict):
                    continue

                param_type = param.get('type', 'string')

                # Convert param_type to string if it's not already
                if not isinstance(param_type, str):
                    continue

                if param_type in ['string', 'text']:
                    if 'text' not in modes:
                        modes.append('text')
                elif param_type in ['dict', 'object', 'json']:
                    if 'structured' not in modes:
                        modes.append('structured')
                elif param_type in ['file', 'binary']:
                    if 'binary' not in modes:
                        modes.append('binary')

        except (TypeError, AttributeError) as e:
            # If there's any error processing parameters, use defaults
            pass

        # Default to text and structured if no specific modes found
        if not modes:
            modes = ['text', 'structured']

        return sorted(modes)

    def _determine_output_modes(self, plug_data: Dict[str, Any]) -> List[str]:
        """Determine A2A output modes from PlugPipe output config"""
        modes = set()

        output_config = plug_data.get('output', {})
        output_type = output_config.get('type', 'text')

        if output_type == 'json':
            modes.add('json')
            modes.add('artifact')
        elif output_type in ['text', 'string']:
            modes.add('text')
        elif output_type in ['file', 'binary']:
            modes.add('binary')

        # Default to text and json if no specific modes found
        if not modes:
            modes = {'text', 'json'}

        return sorted(list(modes))

    def validate_agent_card(self, agent_card: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate agent card against A2A specification"""
        try:
            self.validator.validate(agent_card)
            return True, None
        except jsonschema.exceptions.ValidationError as e:
            return False, str(e)

    def generate_agent_card(
        self,
        plug_yaml_path: str,
        output_path: Optional[str] = None,
        validate: bool = True
    ) -> Dict[str, Any]:
        """
        Generate A2A agent card from plug.yaml

        Args:
            plug_yaml_path: Path to plug.yaml file
            output_path: Optional output path for agent-card.json
            validate: Whether to validate against A2A specification

        Returns:
            Generated agent card dictionary
        """
        # Load plug manifest
        plug_data = self.load_plug_manifest(plug_yaml_path)

        # Convert to agent card
        agent_card = self.convert_to_agent_card(plug_data)

        # Validate if requested
        if validate:
            is_valid, error = self.validate_agent_card(agent_card)
            if not is_valid:
                raise ValueError(f"Generated agent card is invalid: {error}")

        # Save to file if output path provided
        if output_path:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(agent_card, f, indent=2)

        return agent_card

    def batch_generate(
        self,
        input_dir: str,
        output_dir: str = "/tmp/agent_cards",
        validate: bool = True,
        save_in_plugin_dir: bool = False
    ) -> Dict[str, Any]:
        """
        Batch generate agent cards for all plugins in directory

        Args:
            input_dir: Directory containing plugin subdirectories
            output_dir: Output directory for generated agent cards (used if save_in_plugin_dir=False)
            validate: Whether to validate each agent card
            save_in_plugin_dir: If True, save agent-card.json in each plugin's directory

        Returns:
            Summary of generation results
        """
        results = {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "errors": [],
            "generated_cards": []
        }

        # Find all plug.yaml files
        plug_files = list(Path(input_dir).rglob("plug.yaml"))
        results["total"] = len(plug_files)

        for plug_file in plug_files:
            try:
                # Generate agent card
                plugin_name = plug_file.parent.parent.name

                # Determine output path
                if save_in_plugin_dir:
                    # Save as agent-card.json in plugin directory
                    output_path = os.path.join(plug_file.parent, "agent-card.json")
                else:
                    # Save in centralized output directory
                    output_path = os.path.join(output_dir, f"{plugin_name}-agent-card.json")

                agent_card = self.generate_agent_card(
                    str(plug_file),
                    output_path,
                    validate=validate
                )

                results["successful"] += 1
                results["generated_cards"].append({
                    "plugin": plugin_name,
                    "agent_id": agent_card["agentCard"]["id"],
                    "output": output_path
                })

            except Exception as e:
                results["failed"] += 1
                results["errors"].append({
                    "plugin": str(plug_file),
                    "error": str(e)
                })

        return results


def main():
    """Main entry point for agent card generator"""
    import argparse

    parser = argparse.ArgumentParser(description="Convert PlugPipe plugins to A2A agent cards")
    parser.add_argument('--input', required=True, help='Path to plug.yaml or directory')
    parser.add_argument('--output', default='/tmp/agent_cards', help='Output directory (ignored if --save-in-plugin-dir)')
    parser.add_argument('--service-url', default='http://localhost:8000/a2a', help='A2A service URL')
    parser.add_argument('--validate', type=bool, default=True, help='Validate agent cards')
    parser.add_argument('--batch', type=bool, default=False, help='Batch process directory')
    parser.add_argument('--save-in-plugin-dir', action='store_true', help='Save agent-card.json in each plugin directory')

    args = parser.parse_args()

    # Initialize generator
    generator = AgentCardGenerator(service_url=args.service_url)

    try:
        if args.batch or os.path.isdir(args.input):
            # Batch processing
            print(f"🔄 Batch processing plugins in: {args.input}")
            if args.save_in_plugin_dir:
                print(f"📂 Saving agent-card.json in each plugin directory")
            else:
                print(f"📂 Saving to output directory: {args.output}")

            results = generator.batch_generate(
                args.input,
                args.output,
                validate=args.validate,
                save_in_plugin_dir=args.save_in_plugin_dir
            )

            # Print summary
            print(f"\n📊 Batch Generation Summary:")
            print(f"   Total plugins: {results['total']}")
            print(f"   ✅ Successful: {results['successful']}")
            print(f"   ❌ Failed: {results['failed']}")

            if results['errors']:
                print(f"\n❌ Errors:")
                for error in results['errors']:
                    print(f"   - {error['plugin']}: {error['error']}")

            # Output results as JSON
            print(f"\n{json.dumps(results, indent=2)}")

        else:
            # Single file processing
            print(f"🔄 Converting: {args.input}")

            # Generate output path
            plugin_name = Path(args.input).parent.parent.name
            output_path = os.path.join(args.output, f"{plugin_name}-agent-card.json")

            agent_card = generator.generate_agent_card(
                args.input,
                output_path,
                validate=args.validate
            )

            print(f"✅ Agent card generated: {output_path}")
            print(f"   Agent ID: {agent_card['agentCard']['id']}")
            print(f"   Skills: {len(agent_card['agentCard']['skills'])}")

            # Output agent card as JSON
            print(f"\n{json.dumps(agent_card, indent=2)}")

    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
