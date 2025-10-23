# SPDX-License-Identifier: MIT
# Copyright 2025 PlugPipe Team
# https://github.com/DavidCheuk/PlugPipe-Plugins

"""
Template Plugin - Reference Implementation

This plugin demonstrates PlugPipe best practices:
- Proper SPDX copyright headers
- Standard execute() function signature
- Comprehensive error handling
- Input validation
- Clear documentation
- A2A protocol compliance
"""

from typing import Dict, Any, List, Optional
import logging

# Configure logging
logger = logging.getLogger(__name__)


class TemplatePluginError(Exception):
    """Custom exception for template plugin errors."""
    pass


def execute(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Standard PlugPipe execution function (A2A protocol compliant).

    This is the main entry point for all plugin operations. It should:
    - Accept a dictionary of parameters
    - Return a dictionary with success status and results
    - Handle errors gracefully
    - Be stateless (no instance variables)

    Args:
        params: Dictionary containing:
            - action (str): Action to perform (example, validate, process)
            - data (any): Optional data to process
            - options (dict): Optional configuration options

    Returns:
        Dictionary containing:
            - success (bool): Whether operation succeeded
            - result (any): Operation result
            - message (str): Human-readable message
            - error (str): Error message if success=False

    Examples:
        >>> execute({'action': 'example', 'data': 'test'})
        {'success': True, 'result': 'Processed: test', 'message': 'Operation completed'}

        >>> execute({'action': 'unknown'})
        {'success': False, 'error': 'Unknown action: unknown'}
    """
    try:
        # Extract parameters with defaults
        action = params.get('action', 'example')
        data = params.get('data')
        options = params.get('options', {})

        # Log execution (helps with debugging)
        logger.info(f"Executing template_plugin with action={action}")

        # Route to appropriate handler
        if action == 'example':
            return _handle_example(data, options)
        elif action == 'validate':
            return _handle_validate(data, options)
        elif action == 'process':
            return _handle_process(data, options)
        elif action == 'batch':
            return _handle_batch(data, options)
        else:
            return {
                'success': False,
                'error': f'Unknown action: {action}',
                'available_actions': ['example', 'validate', 'process', 'batch']
            }

    except TemplatePluginError as e:
        # Custom plugin errors
        logger.error(f"Plugin error: {e}")
        return {
            'success': False,
            'error': str(e),
            'error_type': 'TemplatePluginError'
        }
    except Exception as e:
        # Unexpected errors
        logger.exception(f"Unexpected error: {e}")
        return {
            'success': False,
            'error': f'Internal error: {str(e)}',
            'error_type': type(e).__name__
        }


def _handle_example(data: Any, options: Dict) -> Dict:
    """
    Handle example action.

    Args:
        data: Input data
        options: Configuration options

    Returns:
        Result dictionary
    """
    return {
        'success': True,
        'result': f'Processed: {data}' if data else 'Example executed',
        'message': 'Example action completed successfully',
        'metadata': {
            'action': 'example',
            'data_type': type(data).__name__,
            'options_provided': len(options)
        }
    }


def _handle_validate(data: Any, options: Dict) -> Dict:
    """
    Handle validation action.

    Args:
        data: Data to validate
        options: Validation options

    Returns:
        Validation result
    """
    if data is None:
        return {
            'success': False,
            'error': 'No data provided for validation',
            'validation_errors': ['data is required']
        }

    # Example validation logic
    validation_errors = []

    if isinstance(data, dict):
        required_fields = options.get('required_fields', [])
        for field in required_fields:
            if field not in data:
                validation_errors.append(f'Missing required field: {field}')

    if validation_errors:
        return {
            'success': False,
            'valid': False,
            'validation_errors': validation_errors,
            'message': f'Validation failed with {len(validation_errors)} errors'
        }

    return {
        'success': True,
        'valid': True,
        'message': 'Validation passed',
        'validated_data': data
    }


def _handle_process(data: Any, options: Dict) -> Dict:
    """
    Handle process action.

    Args:
        data: Data to process
        options: Processing options

    Returns:
        Processing result
    """
    if data is None:
        raise TemplatePluginError('No data provided for processing')

    # Example processing logic
    transform = options.get('transform', 'uppercase')

    if isinstance(data, str):
        if transform == 'uppercase':
            result = data.upper()
        elif transform == 'lowercase':
            result = data.lower()
        elif transform == 'reverse':
            result = data[::-1]
        else:
            result = data
    else:
        result = str(data)

    return {
        'success': True,
        'result': result,
        'message': f'Processed with transform={transform}',
        'metadata': {
            'original_type': type(data).__name__,
            'result_type': type(result).__name__,
            'transform_applied': transform
        }
    }


def _handle_batch(data: Any, options: Dict) -> Dict:
    """
    Handle batch processing action.

    Args:
        data: List of items to process
        options: Batch processing options

    Returns:
        Batch processing results
    """
    if not isinstance(data, list):
        return {
            'success': False,
            'error': 'Batch processing requires a list of items'
        }

    results = []
    errors = []

    for idx, item in enumerate(data):
        try:
            # Process each item
            processed = _handle_process(item, options)
            results.append({
                'index': idx,
                'item': item,
                'result': processed.get('result'),
                'success': True
            })
        except Exception as e:
            errors.append({
                'index': idx,
                'item': item,
                'error': str(e)
            })

    return {
        'success': len(errors) == 0,
        'results': results,
        'errors': errors,
        'total': len(data),
        'successful': len(results),
        'failed': len(errors),
        'message': f'Batch processed {len(results)}/{len(data)} items successfully'
    }


# Plugin metadata for discovery (A2A protocol)
plug_metadata = {
    'name': 'template_plugin',
    'version': '1.0.0',
    'description': 'Reference implementation for PlugPipe plugin development',
    'category': 'examples',
    'author': 'PlugPipe Team',
    'a2a_enabled': True,
    'capabilities': ['execute', 'validate', 'batch'],
    'stateless': True  # Important for A2A compliance
}


# Optional: Health check function
def health_check() -> Dict[str, Any]:
    """
    Health check for plugin monitoring.

    Returns:
        Health status dictionary
    """
    return {
        'healthy': True,
        'plugin': 'template_plugin',
        'version': '1.0.0',
        'status': 'operational'
    }


# Optional: Plugin initialization
def initialize(config: Optional[Dict] = None) -> bool:
    """
    Initialize plugin with configuration.

    Args:
        config: Optional configuration dictionary

    Returns:
        True if initialization successful
    """
    logger.info("Template plugin initialized")
    return True


# Optional: Plugin cleanup
def cleanup() -> None:
    """
    Cleanup plugin resources before shutdown.
    """
    logger.info("Template plugin cleanup complete")
