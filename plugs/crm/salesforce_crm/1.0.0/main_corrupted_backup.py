# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Salesforce CRM Plug - Enterprise-grade integration
Provides full CRUD operations for Salesforce objects with authentication and error handling.
"""

import requests
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import re

logger = logging.getLogger(__name__)

# SECURITY FIX: Import Universal Input Sanitizer for SOQL injection prevention
try:
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '../../..'))
    from shares.loader import pp
    
    # Use pp() function to discover Universal Input Sanitizer plugin
    universal_sanitizer = pp('security/universal_input_sanitizer')
    logger.info("Universal Input Sanitizer plugin loaded for SOQL security")
except Exception as e:
    logger.warning(f"Could not load Universal Input Sanitizer plugin: {e}")
    universal_sanitizer = None

def process(ctx: dict, cfg: dict) -> dict:
    """
    Main plugin entry point for Salesforce CRM operations.
    
    Args:
        ctx: Pipe context containing operation parameters
        cfg: Plug configuration including authentication
        
    Returns:
        Updated context with operation results
    """
    try:
        # Initialize Salesforce client
        client = SalesforceClient(cfg)
        
        # Get operation from context
        operation = ctx.get('operation', 'list')
        sobject = ctx.get('sobject', 'Account')
        
        result = None
        
        if operation == 'list':
            result = client.list_records(sobject, ctx.get('fields'), ctx.get('filters'), ctx.get('limit', 50))
        elif operation == 'get':
            result = client.get_record(sobject, ctx.get('record_id'), ctx.get('fields'))
        elif operation == 'create':
            result = client.create_record(sobject, ctx.get('data'))
        elif operation == 'update':
            result = client.update_record(sobject, ctx.get('record_id'), ctx.get('data'))
        elif operation == 'delete':
            result = client.delete_record(sobject, ctx.get('record_id'))
        elif operation == 'search':
            result = client.search_records(ctx.get('query'))
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        
        # Store results in context
        ctx['salesforce_result'] = result
        ctx['salesforce_status'] = 'success'
        
        logger.info(f"Salesforce {operation} operation completed successfully")
        return ctx
        
    except Exception as e:
        logger.error(f"Salesforce operation failed: {str(e)}")
        ctx['salesforce_result'] = None
        ctx['salesforce_status'] = 'error'
        ctx['salesforce_error'] = str(e)
        return ctx


class SalesforceClient:
    """
    Enterprise Salesforce API client with authentication and error handling.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.instance_url = config.get('instance_url')
        self.access_token = None
        self.session = requests.Session()
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with Salesforce using OAuth2 or JWT."""
        auth_method = self.config.get('auth_method', 'oauth2')
        
        if auth_method == 'oauth2':
            self._oauth2_authenticate()
        elif auth_method == 'jwt':
            self._jwt_authenticate()
        else:
            raise ValueError(f"Unsupported auth method: {auth_method}")
    
    def _oauth2_authenticate(self):
        """OAuth2 Username-Password flow authentication."""
        auth_url = f"{self.instance_url}/services/oauth2/token"
        
        auth_data = {
            'grant_type': 'password',
            'client_id': self.config['client_id'],
            'client_secret': self.config['client_secret'],
            'username': self.config['username'],
            'password': self.config['password'] + self.config.get('security_token', '')
        }
        
        response = requests.post(auth_url, data=auth_data)
        response.raise_for_status()
        
        auth_result = response.json()
        self.access_token = auth_result['access_token']
        self.instance_url = auth_result['instance_url']
        
        # Set default headers
        self.session.headers.update({
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def _jwt_authenticate(self):
        """JWT Bearer token authentication (for server-to-server)."""
        import jwt
        import time
        
        # Create JWT assertion
        payload = {
            'iss': self.config['client_id'],
            'sub': self.config['username'],
            'aud': self.instance_url,
            'exp': int(time.time()) + 300  # 5 minutes
        }
        
        private_key = self.config['private_key']
        assertion = jwt.encode(payload, private_key, algorithm='RS256')
        
        auth_url = f"{self.instance_url}/services/oauth2/token"
        auth_data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion
        }
        
        response = requests.post(auth_url, data=auth_data)
        response.raise_for_status()
        
        auth_result = response.json()
        self.access_token = auth_result['access_token']
        
        self.session.headers.update({
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def list_records(self, sobject: str, fields: Optional[List[str]] = None, 
                    filters: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        """
        List records from a Salesforce object with SOQL injection prevention.
        SECURITY FIX: Validates all parameters using Universal Input Sanitizer.
        """
        # SECURITY FIX: Validate parameters to prevent SOQL injection
        validation_result = self._validate_soql_parameters(sobject, fields, filters, limit)
        if not validation_result['is_safe']:
            logger.error(f"SOQL injection attempt blocked: {validation_result['threats_detected']}")
            return {
                'success': False,
                'error': 'Invalid parameters detected - potential SOQL injection blocked',
                'security_warning': validation_result['threats_detected']
            }
        
        # Use validated parameters
        safe_fields = validation_result['sanitized_fields']
        safe_sobject = validation_result['sanitized_sobject']
        safe_filters = validation_result['sanitized_filters']
        safe_limit = validation_result['sanitized_limit']
        
        fields_str = ','.join(safe_fields) if safe_fields else 'Id,Name'
        query = f"SELECT {fields_str} FROM {safe_sobject}"
        
        if safe_filters:
            query += f" WHERE {safe_filters}"
        
        query += f" LIMIT {safe_limit}"
        
        logger.info(f"Executing validated SOQL query: {query}")
        return self._execute_soql(query)
    
    def get_record(self, sobject: str, record_id: str, 
                  fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get a specific record by ID."""
        url = f"{self.instance_url}/services/data/v57.0/sobjects/{sobject}/{record_id}"
        
        params = {}
        if fields:
            params['fields'] = ','.join(fields)
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()
    
    def create_record(self, sobject: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new record."""
        url = f"{self.instance_url}/services/data/v57.0/sobjects/{sobject}"
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
        return response.json()
    
    def update_record(self, sobject: str, record_id: str, 
                     data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing record."""
        url = f"{self.instance_url}/services/data/v57.0/sobjects/{sobject}/{record_id}"
        
        response = self.session.patch(url, json=data)
        response.raise_for_status()
        
        # PATCH returns 204 No Content on success
        return {"success": True, "id": record_id}
    
    def delete_record(self, sobject: str, record_id: str) -> Dict[str, Any]:
        """Delete a record."""
        url = f"{self.instance_url}/services/data/v57.0/sobjects/{sobject}/{record_id}"
        
        response = self.session.delete(url)
        response.raise_for_status()
        
        return {"success": True, "id": record_id}
    
    def search_records(self, sosl_query: str) -> Dict[str, Any]:
        """
        Execute a SOSL search query with injection prevention.
        SECURITY FIX: Validates SOSL query using Universal Input Sanitizer.
        """
        # SECURITY FIX: Validate SOSL query to prevent injection
        validation_result = self._validate_sosl_query(sosl_query)
        if not validation_result['is_safe']:
            logger.error(f"SOSL injection attempt blocked: {validation_result['threats_detected']}")
            return {
                'success': False,
                'error': 'Invalid SOSL query detected - potential injection blocked',
                'security_warning': validation_result['threats_detected']
            }
        
        url = f"{self.instance_url}/services/data/v57.0/search"
        
        # Use validated query
        safe_query = validation_result['sanitized_query']
        params = {'q': safe_query}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        logger.info(f"Executed validated SOSL query: {safe_query}")
        return response.json()
    
    def _validate_sosl_query(self, sosl_query: str) -> Dict[str, Any]:
        """
        SECURITY FIX: Validate SOSL query to prevent injection attacks.
        Uses Universal Input Sanitizer for comprehensive security analysis.
        """
        if not sosl_query or not isinstance(sosl_query, str):
            return {
                'is_safe': False,
                'threats_detected': ['Invalid SOSL query: empty or non-string value'],
                'sanitized_query': None
            }
        
        # Use Universal Input Sanitizer if available
        if universal_sanitizer:
            try:
                sanitizer_result = universal_sanitizer.process({
                    'input_data': sosl_query,
                    'sanitization_types': ['sql_injection']
                })
                
                if not sanitizer_result.get('overall_assessment', {}).get('is_safe', False):
                    return {
                        'is_safe': False,
                        'threats_detected': sanitizer_result.get('threats_detected', ['Malicious SOSL query detected']),
                        'sanitized_query': None
                    }
                
                # Get sanitized output from Universal Input Sanitizer
                sanitized_results = sanitizer_result.get('sanitization_results', [])
                sanitized_query = sosl_query
                for result in sanitized_results:
                    if result.get('injection_type') == 'sql_injection' and result.get('sanitized_output'):
                        sanitized_query = result.get('sanitized_output')
                        break
                
                return {
                    'is_safe': True,
                    'threats_detected': [],
                    'sanitized_query': sanitized_query
                }
                
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error for SOSL query: {e}")
        
        # Fallback validation: Basic SOSL injection patterns
        dangerous_patterns = [
            r'\b(UNION|union)\s+(SELECT|select)\b',
            r'\b(DROP|drop)\s+(TABLE|table|DATABASE|database)\b',
            r'\b(DELETE|delete)\s+(FROM|from)\b',
            r'\b(UPDATE|update)\s+\w+\s+(SET|set)\b',
            r'\b(INSERT|insert)\s+(INTO|into)\b',
            r'[\'";].*[\'";]',  # Multiple quote patterns
            r'--.*$',  # SQL comments
            r'/\*.*\*/',  # Block comments
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, sosl_query, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'threats_detected': [f'Potential SOSL injection pattern detected: {pattern}'],
                    'sanitized_query': None
                }
        
        # SOSL query length validation
        if len(sosl_query) > 2000:
            return {
                'is_safe': False,
                'threats_detected': ['SOSL query too long - potential injection attempt'],
                'sanitized_query': None
            }
        
        # Ensure SOSL query starts with FIND
        if not re.match(r'^\s*FIND\s+', sosl_query, re.IGNORECASE):
            return {
                'is_safe': False,
                'threats_detected': ['Invalid SOSL query format - must start with FIND'],
                'sanitized_query': None
            }
        
        return {
            'is_safe': True,
            'threats_detected': [],
            'sanitized_query': sosl_query
        }
    
    def _validate_soql_parameters(self, sobject: str, fields: Optional[List[str]], 
                                filters: Optional[str], limit: int) -> Dict[str, Any]:
        """
        SECURITY FIX: Comprehensive SOQL parameter validation using Universal Input Sanitizer.
        Prevents SOQL injection attacks through parameter validation.
        """
        try:
            # Validate sobject name
            sobject_result = self._validate_salesforce_identifier(sobject, 'sobject')
            if not sobject_result['is_safe']:
                return {
                    'is_safe': False,
                    'threats_detected': sobject_result['threats_detected'],
                    'sanitized_sobject': None,
                    'sanitized_fields': None,
                    'sanitized_filters': None,
                    'sanitized_limit': None
                }
            
            # Validate field names
            sanitized_fields = []
            if fields:
                for field in fields:
                    field_result = self._validate_salesforce_identifier(field, 'field')
                    if not field_result['is_safe']:
                        return {
                            'is_safe': False,
                            'threats_detected': field_result['threats_detected'],
                            'sanitized_sobject': None,
                            'sanitized_fields': None,
                            'sanitized_filters': None,
                            'sanitized_limit': None
                        }
                    sanitized_fields.append(field_result['sanitized_identifier'])
            else:
                sanitized_fields = ['Id', 'Name']  # Default safe fields
            
            # Validate filters
            sanitized_filters = None
            if filters:
                filter_result = self._validate_soql_filter(filters)
                if not filter_result['is_safe']:
                    return {
                        'is_safe': False,
                        'threats_detected': filter_result['threats_detected'],
                        'sanitized_sobject': None,
                        'sanitized_fields': None,
                        'sanitized_filters': None,
                        'sanitized_limit': None
                    }
                sanitized_filters = filter_result['sanitized_filter']
            
            # Validate limit
            try:
                sanitized_limit = int(limit)
                if sanitized_limit < 1 or sanitized_limit > 2000:
                    return {
                        'is_safe': False,
                        'threats_detected': ['Limit must be between 1 and 2000'],
                        'sanitized_sobject': None,
                        'sanitized_fields': None,
                        'sanitized_filters': None,
                        'sanitized_limit': None
                    }
            except (ValueError, TypeError):
                return {
                    'is_safe': False,
                    'threats_detected': ['Invalid limit value - must be integer'],
                    'sanitized_sobject': None,
                    'sanitized_fields': None,
                    'sanitized_filters': None,
                    'sanitized_limit': None
                }
            
            return {
                'is_safe': True,
                'threats_detected': [],
                'sanitized_sobject': sobject_result['sanitized_identifier'],
                'sanitized_fields': sanitized_fields,
                'sanitized_filters': sanitized_filters,
                'sanitized_limit': sanitized_limit
            }
            
        except Exception as e:
            logger.error(f"SOQL parameter validation error: {e}")
            return {
                'is_safe': False,
                'threats_detected': ['Internal validation error'],
                'sanitized_sobject': None,
                'sanitized_fields': None,
                'sanitized_filters': None,
                'sanitized_limit': None
            }
    
    def _validate_salesforce_identifier(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        """
        SECURITY FIX: Validate Salesforce identifiers (sobject names, field names) using Universal Input Sanitizer.
        Prevents SOQL injection through malicious identifier names.
        """
        if not identifier or not isinstance(identifier, str):
            return {
                'is_safe': False,
                'threats_detected': [f'Invalid {identifier_type} identifier - must be non-empty string'],
                'sanitized_identifier': None
            }
        
        # Use Universal Input Sanitizer if available
        if self.universal_sanitizer:
            try:
                sanitizer_result = self.universal_sanitizer.process({
                    'input_data': identifier,
                    'sanitization_types': ['sql_injection', 'code_injection']
                })
                
                if not sanitizer_result.get('overall_assessment', {}).get('is_safe', False):
                    return {
                        'is_safe': False,
                        'threats_detected': sanitizer_result.get('threats_detected', [f'Malicious {identifier_type} identifier detected']),
                        'sanitized_identifier': None
                    }
                
                # Get sanitized output from Universal Input Sanitizer
                sanitized_results = sanitizer_result.get('sanitization_results', [])
                sanitized_identifier = identifier
                for result in sanitized_results:
                    if result.get('injection_type') in ['sql_injection', 'code_injection'] and result.get('sanitized_output'):
                        sanitized_identifier = result.get('sanitized_output')
                        break
                
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error for {identifier_type}: {e}")
                sanitized_identifier = identifier
        else:
            sanitized_identifier = identifier
        
        # Fallback validation: Salesforce identifier patterns
        # Valid Salesforce identifiers: letters, numbers, underscores, no SQL keywords
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', sanitized_identifier):
            return {
                'is_safe': False,
                'threats_detected': [f'Invalid {identifier_type} format - must start with letter and contain only alphanumeric characters and underscores'],
                'sanitized_identifier': None
            }
        
        # Check for SQL keywords that could be used for injection
        sql_keywords = [
            'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
            'UNION', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'ON', 'AS', 'TABLE', 'DATABASE',
            'SCHEMA', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION', 'TRIGGER', 'GRANT', 'REVOKE'
        ]
        
        if sanitized_identifier.upper() in sql_keywords:
            return {
                'is_safe': False,
                'threats_detected': [f'Reserved SQL keyword detected in {identifier_type}: {sanitized_identifier}'],
                'sanitized_identifier': None
            }
        
        # Length validation
        if len(sanitized_identifier) > 80:  # Salesforce field name limit
            return {
                'is_safe': False,
                'threats_detected': [f'{identifier_type} name too long - maximum 80 characters'],
                'sanitized_identifier': None
            }
        
        return {
            'is_safe': True,
            'threats_detected': [],
            'sanitized_identifier': sanitized_identifier
        }
    
    def _validate_soql_filter(self, filter_clause: str) -> Dict[str, Any]:
        """
        SECURITY FIX: Validate SOQL WHERE filter clauses using Universal Input Sanitizer.
        Prevents SOQL injection through malicious filter conditions.
        """
        if not filter_clause or not isinstance(filter_clause, str):
            return {
                'is_safe': False,
                'threats_detected': ['Invalid filter clause - must be non-empty string'],
                'sanitized_filter': None
            }
        
        # Use Universal Input Sanitizer if available
        if self.universal_sanitizer:
            try:
                sanitizer_result = self.universal_sanitizer.process({
                    'input_data': filter_clause,
                    'sanitization_types': ['sql_injection']
                })
                
                if not sanitizer_result.get('overall_assessment', {}).get('is_safe', False):
                    return {
                        'is_safe': False,
                        'threats_detected': sanitizer_result.get('threats_detected', ['Malicious SOQL filter detected']),
                        'sanitized_filter': None
                    }
                
                # Get sanitized output from Universal Input Sanitizer
                sanitized_results = sanitizer_result.get('sanitization_results', [])
                sanitized_filter = filter_clause
                for result in sanitized_results:
                    if result.get('injection_type') == 'sql_injection' and result.get('sanitized_output'):
                        sanitized_filter = result.get('sanitized_output')
                        break
                
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error for filter: {e}")
                sanitized_filter = filter_clause
        else:
            sanitized_filter = filter_clause
        
        # Fallback validation: Dangerous SOQL injection patterns
        dangerous_patterns = [
            r'\b(UNION|union)\s+(SELECT|select)\b',
            r'\b(DROP|drop)\s+(TABLE|table|DATABASE|database)\b',
            r'\b(DELETE|delete)\s+(FROM|from)\b',
            r'\b(UPDATE|update)\s+\w+\s+(SET|set)\b',
            r'\b(INSERT|insert)\s+(INTO|into)\b',
            r'[\'";].*[\'";]',  # Multiple quote patterns
            r'--.*$',  # SQL comments
            r'/\*.*\*/',  # Block comments
            r'\bEXEC\b|\bEXECUTE\b',  # Execute statements
            r'\bxp_cmdshell\b',  # Command execution
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, sanitized_filter, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'threats_detected': [f'Potential SOQL injection pattern in filter: {pattern}'],
                    'sanitized_filter': None
                }
        
        # Filter length validation
        if len(sanitized_filter) > 1000:
            return {
                'is_safe': False,
                'threats_detected': ['Filter clause too long - potential injection attempt'],
                'sanitized_filter': None
            }
        
        # Validate balanced quotes and parentheses
        single_quotes = sanitized_filter.count("'") 
        double_quotes = sanitized_filter.count('"')
        open_parens = sanitized_filter.count('(')
        close_parens = sanitized_filter.count(')')
        
        if single_quotes % 2 != 0 or double_quotes % 2 != 0 or open_parens != close_parens:
            return {
                'is_safe': False,
                'threats_detected': ['Unbalanced quotes or parentheses in filter - potential injection'],
                'sanitized_filter': None
            }
        
        return {
            'is_safe': True,
            'threats_detected': [],
            'sanitized_filter': sanitized_filter
        }
                            'sanitized_fields': None,
                            'sanitized_filters': None,
                            'sanitized_limit': None
                        }
                    sanitized_fields.append(field_result['sanitized_value'])
            
            # Validate SOQL filters
            sanitized_filters = None
            if filters:
                filter_result = self._validate_soql_filter(filters)
                if not filter_result['is_safe']:
                    return {
                        'is_safe': False,
                        'threats_detected': filter_result['threats_detected'],
                        'sanitized_sobject': None,
                        'sanitized_fields': None,
                        'sanitized_filters': None,
                        'sanitized_limit': None
                    }
                sanitized_filters = filter_result['sanitized_value']
            
            # Validate limit
            if not isinstance(limit, int) or limit < 1 or limit > 2000:
                return {
                    'is_safe': False,
                    'threats_detected': [f'Invalid limit value: {limit}. Must be integer between 1-2000'],
                    'sanitized_sobject': None,
                    'sanitized_fields': None,
                    'sanitized_filters': None,
                    'sanitized_limit': None
                }
            
            return {
                'is_safe': True,
                'threats_detected': [],
                'sanitized_sobject': sobject_result['sanitized_value'],
                'sanitized_fields': sanitized_fields if sanitized_fields else None,
                'sanitized_filters': sanitized_filters,
                'sanitized_limit': limit
            }
            
        except Exception as e:
            logger.error(f"SOQL validation error: {e}")
            return {
                'is_safe': False,
                'threats_detected': [f'Validation system error: {str(e)}'],
                'sanitized_sobject': None,
                'sanitized_fields': None,
                'sanitized_filters': None,
                'sanitized_limit': None
            }
    
    def _validate_salesforce_identifier(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        """
        SECURITY FIX: Validate Salesforce object and field identifiers.
        Prevents injection through malformed identifiers.
        """
        if not identifier or not isinstance(identifier, str):
            return {
                'is_safe': False,
                'threats_detected': [f'Invalid {identifier_type}: empty or non-string value'],
                'sanitized_value': None
            }
        
        # Use Universal Input Sanitizer if available
        if universal_sanitizer:
            try:
                sanitizer_result = universal_sanitizer.process({
                    'input_data': identifier,
                    'sanitization_types': ['sql_injection']
                })
                
                if not sanitizer_result.get('overall_assessment', {}).get('is_safe', False):
                    return {
                        'is_safe': False,
                        'threats_detected': sanitizer_result.get('threats_detected', [f'Malicious {identifier_type} detected']),
                        'sanitized_value': None
                    }
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error for {identifier_type}: {e}")
        
        # Fallback validation: Salesforce identifier pattern
        # Valid Salesforce identifiers: alphanumeric, underscore, start with letter/underscore
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
            return {
                'is_safe': False,
                'threats_detected': [f'Invalid {identifier_type} format: {identifier}. Must contain only alphanumeric characters and underscores, start with letter or underscore'],
                'sanitized_value': None
            }
        
        # Additional security: Check length limits
        if len(identifier) > 80:  # Salesforce identifier length limit
            return {
                'is_safe': False,
                'threats_detected': [f'{identifier_type} too long: {len(identifier)} characters. Maximum 80 characters allowed'],
                'sanitized_value': None
            }
        
        return {
            'is_safe': True,
            'threats_detected': [],
            'sanitized_value': identifier
        }
    
    def _validate_soql_filter(self, filter_clause: str) -> Dict[str, Any]:
        """
        SECURITY FIX: Validate SOQL WHERE clause to prevent injection attacks.
        Uses Universal Input Sanitizer for comprehensive security analysis.
        """
        if not filter_clause or not isinstance(filter_clause, str):
            return {
                'is_safe': True,
                'threats_detected': [],
                'sanitized_value': None
            }
        
        # Use Universal Input Sanitizer if available
        if universal_sanitizer:
            try:
                sanitizer_result = universal_sanitizer.process({
                    'input_data': filter_clause,
                    'sanitization_types': ['sql_injection']
                })
                
                if not sanitizer_result.get('overall_assessment', {}).get('is_safe', False):
                    return {
                        'is_safe': False,
                        'threats_detected': sanitizer_result.get('threats_detected', ['Malicious SOQL filter detected']),
                        'sanitized_value': None
                    }
                
                # Get sanitized output from Universal Input Sanitizer
                sanitized_results = sanitizer_result.get('sanitization_results', [])
                sanitized_filter = filter_clause
                for result in sanitized_results:
                    if result.get('injection_type') == 'sql_injection' and result.get('sanitized_output'):
                        sanitized_filter = result.get('sanitized_output')
                        break
                
                return {
                    'is_safe': True,
                    'threats_detected': [],
                    'sanitized_value': sanitized_filter
                }
                
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error for SOQL filter: {e}")
        
        # Fallback validation: Basic SOQL injection patterns
        dangerous_patterns = [
            r'\b(UNION|union)\s+(SELECT|select)\b',
            r'\b(DROP|drop)\s+(TABLE|table|DATABASE|database)\b',
            r'\b(DELETE|delete)\s+(FROM|from)\b',
            r'\b(UPDATE|update)\s+\w+\s+(SET|set)\b',
            r'\b(INSERT|insert)\s+(INTO|into)\b',
            r'[\'";].*[\'";]',  # Multiple quote patterns
            r'--.*$',  # SQL comments
            r'/\*.*\*/',  # Block comments
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, filter_clause, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'threats_detected': [f'Potential SOQL injection pattern detected: {pattern}'],
                    'sanitized_value': None
                }
        
        # Basic length validation
        if len(filter_clause) > 1000:
            return {
                'is_safe': False,
                'threats_detected': ['SOQL filter too long - potential injection attempt'],
                'sanitized_value': None
            }
        
        return {
            'is_safe': True,
            'threats_detected': [],
            'sanitized_value': filter_clause
        }
    
    def _execute_soql(self, query: str) -> Dict[str, Any]:
        """Execute a SOQL query."""
        url = f"{self.instance_url}/services/data/v57.0/query"
        
        params = {'q': query}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()


# Plug metadata and schemas
plug_metadata = {
    "name": "salesforce_crm",
    "version": "1.0.0",
    "description": "Enterprise Salesforce CRM integration with full CRUD operations, authentication, and error handling",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "crm",
    "tags": ["salesforce", "crm", "enterprise", "oauth2", "jwt"],
    "requirements": ["requests", "PyJWT"],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["list", "get", "create", "update", "delete", "search"],
                "description": "CRM operation to perform"
            },
            "sobject": {
                "type": "string",
                "description": "Salesforce object name (e.g., Account, Contact, Lead)",
                "default": "Account"
            },
            "record_id": {
                "type": "string",
                "description": "Record ID for get, update, delete operations"
            },
            "fields": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Fields to retrieve"
            },
            "data": {
                "type": "object",
                "description": "Data for create/update operations"
            },
            "filters": {
                "type": "string",
                "description": "WHERE clause for list operations"
            },
            "query": {
                "type": "string",
                "description": "SOSL search query"
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2000,
                "default": 50,
                "description": "Maximum number of records to return"
            }
        },
        "required": ["operation"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "salesforce_result": {
                "type": ["object", "null"],
                "description": "Operation result data"
            },
            "salesforce_status": {
                "type": "string",
                "enum": ["success", "error"],
                "description": "Operation status"
            },
            "salesforce_error": {
                "type": "string",
                "description": "Error message if operation failed"
            }
        }
    },
    "config_schema": {
        "type": "object",
        "properties": {
            "instance_url": {
                "type": "string",
                "description": "Salesforce instance URL (e.g., https://mycompany.salesforce.com)"
            },
            "auth_method": {
                "type": "string",
                "enum": ["oauth2", "jwt"],
                "default": "oauth2",
                "description": "Authentication method"
            },
            "client_id": {
                "type": "string",
                "description": "Connected App Client ID"
            },
            "client_secret": {
                "type": "string",
                "description": "Connected App Client Secret (for OAuth2)"
            },
            "username": {
                "type": "string",
                "description": "Salesforce username"
            },
            "password": {
                "type": "string",
                "description": "Salesforce password (for OAuth2)"
            },
            "security_token": {
                "type": "string",
                "description": "Security token (for OAuth2, optional if IP is trusted)"
            },
            "private_key": {
                "type": "string",
                "description": "Private key for JWT authentication"
            }
        },
        "required": ["instance_url", "client_id", "username"],
        "oneOf": [
            {
                "properties": {"auth_method": {"const": "oauth2"}},
                "required": ["client_secret", "password"]
            },
            {
                "properties": {"auth_method": {"const": "jwt"}},
                "required": ["private_key"]
            }
        ]
    }
}