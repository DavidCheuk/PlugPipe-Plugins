#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Basic Usage Examples for Automatic Pipe Creation Agent

This file demonstrates common usage patterns for the Automatic Pipe Creation Agent,
showing how to generate workflows for different industries and use cases.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

def example_ecommerce_order_processing():
    """Example: Generate e-commerce order processing workflow"""

    print("🛒 Generating E-commerce Order Processing Workflow")
    print("=" * 50)

    # Configuration for e-commerce order processing
    config = {
        'action': 'research_and_create',
        'workflow_name': 'order_processing',
        'industry': 'ecommerce',
        'workflow_description': 'Complete order lifecycle from validation to delivery tracking'
    }

    # Plugin context
    plugin_ctx = {
        'logger': None,
        'action': config['action'],
        'workflow_name': config['workflow_name'],
        'industry': config['industry'],
        'workflow_description': config['workflow_description']
    }

    # User configuration
    user_ctx = {
        'config': {
            'pipe_category': 'ecommerce',
            'complexity_preference': 'standard',
            'include_testing': True,
            'include_documentation': True
        }
    }

    print(f"Input Configuration:")
    print(f"  Workflow: {config['workflow_name']}")
    print(f"  Industry: {config['industry']}")
    print(f"  Description: {config['workflow_description']}")
    print()

    # In a real scenario, you would call:
    # from main import process
    # result = process(plugin_ctx, user_ctx)

    # Mock result for demonstration
    result = {
        'success': True,
        'pipe_created': True,
        'pipe_details': {
            'name': 'order_processing',
            'path': 'pipes/ecommerce/order_processing',
            'complexity': 'standard',
            'steps': 6,
            'estimated_duration': '20-45 minutes',
            'plugins_used': ['payment_gateway', 'inventory_management', 'shipping_provider', 'notification_service']
        },
        'research_results': {
            'patterns_found': 3,
            'industry_best_practices': ['payment_validation', 'inventory_check', 'real_time_tracking'],
            'optimization_suggestions': ['parallel_processing', 'cache_inventory_data', 'batch_notifications']
        }
    }

    print("Generated Workflow Result:")
    print(json.dumps(result, indent=2))
    print()

    return result

def example_marketing_lead_nurturing():
    """Example: Generate marketing lead nurturing workflow"""

    print("📧 Generating Marketing Lead Nurturing Workflow")
    print("=" * 50)

    config = {
        'action': 'research_and_create',
        'workflow_name': 'lead_nurturing',
        'industry': 'marketing',
        'workflow_description': 'Automated lead scoring, segmentation, and email campaign delivery'
    }

    plugin_ctx = {
        'logger': None,
        'action': config['action'],
        'workflow_name': config['workflow_name'],
        'industry': config['industry'],
        'workflow_description': config['workflow_description']
    }

    user_ctx = {
        'config': {
            'pipe_category': 'marketing',
            'complexity_preference': 'standard',
            'include_testing': True,
            'include_documentation': True,
            'marketing_automation_provider': 'mailchimp',
            'crm_integration': 'salesforce'
        }
    }

    print(f"Input Configuration:")
    print(f"  Workflow: {config['workflow_name']}")
    print(f"  Industry: {config['industry']}")
    print(f"  CRM Integration: {user_ctx['config']['crm_integration']}")
    print(f"  Email Provider: {user_ctx['config']['marketing_automation_provider']}")
    print()

    # Mock result
    result = {
        'success': True,
        'pipe_created': True,
        'pipe_details': {
            'name': 'lead_nurturing',
            'path': 'pipes/marketing/lead_nurturing',
            'complexity': 'standard',
            'steps': 5,
            'estimated_duration': '15-30 minutes',
            'plugins_used': ['crm_integration', 'email_marketing', 'analytics', 'lead_scoring']
        },
        'research_results': {
            'patterns_found': 4,
            'industry_best_practices': ['progressive_profiling', 'behavioral_triggers', 'a_b_testing'],
            'optimization_suggestions': ['personalization_engine', 'predictive_scoring', 'multi_channel_delivery']
        }
    }

    print("Generated Workflow Result:")
    print(json.dumps(result, indent=2))
    print()

    return result

def example_hr_employee_onboarding():
    """Example: Generate HR employee onboarding workflow"""

    print("👥 Generating HR Employee Onboarding Workflow")
    print("=" * 50)

    config = {
        'action': 'research_and_create',
        'workflow_name': 'employee_onboarding',
        'industry': 'hr',
        'workflow_description': 'Complete new hire process from application to first day training'
    }

    plugin_ctx = {
        'logger': None,
        'action': config['action'],
        'workflow_name': config['workflow_name'],
        'industry': config['industry'],
        'workflow_description': config['workflow_description']
    }

    user_ctx = {
        'config': {
            'pipe_category': 'hr',
            'complexity_preference': 'standard',
            'include_testing': True,
            'include_documentation': True,
            'hr_system': 'workday',
            'background_check_provider': 'sterling',
            'learning_platform': 'cornerstone'
        }
    }

    print(f"Input Configuration:")
    print(f"  Workflow: {config['workflow_name']}")
    print(f"  Industry: {config['industry']}")
    print(f"  HR System: {user_ctx['config']['hr_system']}")
    print(f"  Background Check: {user_ctx['config']['background_check_provider']}")
    print()

    # Mock result
    result = {
        'success': True,
        'pipe_created': True,
        'pipe_details': {
            'name': 'employee_onboarding',
            'path': 'pipes/hr/employee_onboarding',
            'complexity': 'standard',
            'steps': 8,
            'estimated_duration': '2-5 days',
            'plugins_used': ['hr_management', 'background_check', 'document_management', 'training_platform']
        },
        'research_results': {
            'patterns_found': 5,
            'industry_best_practices': ['digital_document_signing', 'automated_training_assignment', 'buddy_system'],
            'optimization_suggestions': ['mobile_friendly_forms', 'progress_tracking', 'feedback_collection']
        }
    }

    print("Generated Workflow Result:")
    print(json.dumps(result, indent=2))
    print()

    return result

def example_healthcare_patient_scheduling():
    """Example: Generate healthcare patient scheduling workflow"""

    print("🏥 Generating Healthcare Patient Scheduling Workflow")
    print("=" * 50)

    config = {
        'action': 'research_and_create',
        'workflow_name': 'patient_scheduling',
        'industry': 'healthcare',
        'workflow_description': 'HIPAA-compliant patient appointment scheduling with automated reminders'
    }

    plugin_ctx = {
        'logger': None,
        'action': config['action'],
        'workflow_name': config['workflow_name'],
        'industry': config['industry'],
        'workflow_description': config['workflow_description']
    }

    user_ctx = {
        'config': {
            'pipe_category': 'healthcare',
            'complexity_preference': 'simple',
            'include_testing': True,
            'include_documentation': True,
            'compliance_requirements': ['hipaa', 'gdpr'],
            'ehr_system': 'epic',
            'notification_methods': ['sms', 'email', 'voice']
        }
    }

    print(f"Input Configuration:")
    print(f"  Workflow: {config['workflow_name']}")
    print(f"  Industry: {config['industry']}")
    print(f"  Compliance: {user_ctx['config']['compliance_requirements']}")
    print(f"  EHR System: {user_ctx['config']['ehr_system']}")
    print()

    # Mock result
    result = {
        'success': True,
        'pipe_created': True,
        'pipe_details': {
            'name': 'patient_scheduling',
            'path': 'pipes/healthcare/patient_scheduling',
            'complexity': 'simple',
            'steps': 4,
            'estimated_duration': '5-15 minutes',
            'plugins_used': ['scheduling_system', 'notification_service', 'patient_management', 'calendar_integration'],
            'compliance_features': ['data_encryption', 'audit_logging', 'access_controls']
        },
        'research_results': {
            'patterns_found': 6,
            'industry_best_practices': ['appointment_confirmation', 'automated_reminders', 'waitlist_management'],
            'compliance_notes': ['all_communications_encrypted', 'audit_trail_maintained', 'patient_consent_required']
        }
    }

    print("Generated Workflow Result:")
    print(json.dumps(result, indent=2))
    print()

    return result

def example_batch_workflow_creation():
    """Example: Generate multiple workflows in batch"""

    print("🚀 Generating Multiple Workflows in Batch")
    print("=" * 50)

    workflow_patterns = [
        {
            'name': 'invoice_processing',
            'industry': 'finance',
            'description': 'Automated invoice validation, approval, and payment processing'
        },
        {
            'name': 'content_publishing',
            'industry': 'marketing',
            'description': 'Content creation, review, approval, and multi-channel publishing'
        },
        {
            'name': 'inventory_management',
            'industry': 'ecommerce',
            'description': 'Stock monitoring, reorder processing, and supplier coordination'
        }
    ]

    plugin_ctx = {
        'logger': None,
        'action': 'batch_create',
        'workflow_patterns': workflow_patterns
    }

    user_ctx = {
        'config': {
            'batch_processing': True,
            'parallel_execution': True,
            'max_concurrent': 3,
            'include_testing': True,
            'include_documentation': True
        }
    }

    print("Batch Configuration:")
    for i, pattern in enumerate(workflow_patterns, 1):
        print(f"  {i}. {pattern['name']} ({pattern['industry']})")
    print()

    # Mock result
    result = {
        'success': True,
        'total_workflows': 3,
        'successful': 3,
        'failed': 0,
        'processing_time': 45.2,
        'results': [
            {
                'name': 'invoice_processing',
                'success': True,
                'path': 'pipes/finance/invoice_processing',
                'generation_time': 12.1
            },
            {
                'name': 'content_publishing',
                'success': True,
                'path': 'pipes/marketing/content_publishing',
                'generation_time': 15.8
            },
            {
                'name': 'inventory_management',
                'success': True,
                'path': 'pipes/ecommerce/inventory_management',
                'generation_time': 17.3
            }
        ]
    }

    print("Batch Processing Result:")
    print(json.dumps(result, indent=2))
    print()

    return result

def example_custom_workflow_creation():
    """Example: Create a custom workflow not in predefined patterns"""

    print("🔧 Generating Custom Workflow")
    print("=" * 50)

    config = {
        'action': 'research_and_create',
        'workflow_name': 'compliance_reporting',
        'industry': 'finance',
        'workflow_description': '''
        Quarterly compliance reporting workflow for financial services:
        1. Gather data from multiple financial systems
        2. Validate data completeness and accuracy
        3. Generate preliminary compliance reports
        4. Review by compliance team with approval workflow
        5. Submit to regulatory agencies with tracking
        6. Archive reports and maintain audit trail
        '''
    }

    plugin_ctx = {
        'logger': None,
        'action': config['action'],
        'workflow_name': config['workflow_name'],
        'industry': config['industry'],
        'workflow_description': config['workflow_description']
    }

    user_ctx = {
        'config': {
            'pipe_category': 'compliance',
            'complexity_preference': 'complex',
            'include_testing': True,
            'include_documentation': True,
            'regulatory_requirements': ['sox', 'dodd_frank', 'mifid_ii'],
            'data_sources': ['core_banking', 'trading_systems', 'risk_management'],
            'approval_levels': 3
        }
    }

    print(f"Custom Workflow Configuration:")
    print(f"  Workflow: {config['workflow_name']}")
    print(f"  Industry: {config['industry']}")
    print(f"  Complexity: {user_ctx['config']['complexity_preference']}")
    print(f"  Regulatory Requirements: {user_ctx['config']['regulatory_requirements']}")
    print()

    # Mock result
    result = {
        'success': True,
        'pipe_created': True,
        'pipe_details': {
            'name': 'compliance_reporting',
            'path': 'pipes/finance/compliance_reporting',
            'complexity': 'complex',
            'steps': 12,
            'estimated_duration': '2-6 hours',
            'plugins_used': [
                'data_aggregation', 'data_validation', 'reporting_engine',
                'approval_workflow', 'regulatory_submission', 'audit_trail'
            ],
            'custom_generated': True
        },
        'research_results': {
            'patterns_found': 0,
            'custom_pattern_created': True,
            'industry_analysis': 'Leveraged financial services best practices',
            'compliance_features': ['data_lineage', 'digital_signatures', 'immutable_audit_trail']
        }
    }

    print("Custom Workflow Result:")
    print(json.dumps(result, indent=2))
    print()

    return result

def example_error_handling():
    """Example: Error handling and validation"""

    print("⚠️  Error Handling Examples")
    print("=" * 50)

    # Example 1: Invalid workflow name
    print("Example 1: Invalid workflow name")
    try:
        config = {
            'action': 'research_and_create',
            'workflow_name': '',  # Invalid: empty name
            'industry': 'ecommerce'
        }

        # This would result in an error
        error_result = {
            'success': False,
            'error': 'workflow_name is required for research_and_create action',
            'error_code': 'INVALID_WORKFLOW_NAME'
        }

        print("  Result:", json.dumps(error_result, indent=4))
        print()

    except Exception as e:
        print(f"  Caught exception: {e}")
        print()

    # Example 2: Unknown industry with fallback
    print("Example 2: Unknown industry with custom description")
    config = {
        'action': 'research_and_create',
        'workflow_name': 'data_processing',
        'industry': 'biotechnology',  # Not in predefined patterns
        'workflow_description': 'Laboratory data analysis and reporting workflow'
    }

    # This would succeed by creating a custom pattern
    success_result = {
        'success': True,
        'pipe_created': True,
        'pipe_details': {
            'name': 'data_processing',
            'path': 'pipes/biotechnology/data_processing',
            'complexity': 'standard',
            'custom_pattern': True
        },
        'warnings': ['Industry "biotechnology" not in predefined patterns, created custom pattern']
    }

    print("  Result:", json.dumps(success_result, indent=4))
    print()

    # Example 3: Missing description for unknown industry
    print("Example 3: Unknown industry without description")
    error_config = {
        'action': 'research_and_create',
        'workflow_name': 'unknown_workflow',
        'industry': 'unknown_industry'
        # Missing workflow_description
    }

    error_result = {
        'success': False,
        'error': 'No workflow patterns found and no description provided',
        'suggestions': [
            'Provide a workflow_description parameter',
            'Use a supported industry: ecommerce, marketing, hr, finance, healthcare'
        ]
    }

    print("  Result:", json.dumps(error_result, indent=4))
    print()

def main():
    """Run all usage examples"""

    print("🤖 Automatic Pipe Creation Agent - Usage Examples")
    print("=" * 60)
    print()

    examples = [
        example_ecommerce_order_processing,
        example_marketing_lead_nurturing,
        example_hr_employee_onboarding,
        example_healthcare_patient_scheduling,
        example_batch_workflow_creation,
        example_custom_workflow_creation,
        example_error_handling
    ]

    for i, example_func in enumerate(examples, 1):
        print(f"Example {i}:")
        try:
            example_func()
        except Exception as e:
            print(f"Error in example {i}: {e}")

        print("\n" + "-" * 60 + "\n")

    print("✅ All examples completed!")
    print()
    print("Next steps:")
    print("1. Copy these examples and modify for your use case")
    print("2. Refer to the README.md for detailed configuration options")
    print("3. Check the developer guide for advanced customization")

if __name__ == "__main__":
    main()