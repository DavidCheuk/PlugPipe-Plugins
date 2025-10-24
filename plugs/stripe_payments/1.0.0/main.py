# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Stripe Payments Plug - Enterprise payment processing
Provides comprehensive Stripe API integration for payments, subscriptions, and financial operations.
"""

import requests
import json
import base64
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

def process(ctx: dict, cfg: dict) -> dict:
    """
    Main plugin entry point for Stripe operations.
    
    Args:
        ctx: Pipe context containing operation parameters
        cfg: Plug configuration including API keys
        
    Returns:
        Updated context with operation results
    """
    try:
        # Initialize Stripe client
        client = StripeClient(cfg)
        
        # Get operation from context
        operation = ctx.get('operation', 'list_customers')
        
        result = None
        
        # Customer operations
        if operation == 'list_customers':
            result = client.list_customers(ctx.get('limit', 10), ctx.get('starting_after'))
        elif operation == 'create_customer':
            result = client.create_customer(ctx.get('customer_data'))
        elif operation == 'get_customer':
            result = client.get_customer(ctx.get('customer_id'))
        elif operation == 'update_customer':
            result = client.update_customer(ctx.get('customer_id'), ctx.get('customer_data'))
        elif operation == 'delete_customer':
            result = client.delete_customer(ctx.get('customer_id'))
            
        # Payment Intent operations
        elif operation == 'create_payment_intent':
            result = client.create_payment_intent(ctx.get('payment_data'))
        elif operation == 'get_payment_intent':
            result = client.get_payment_intent(ctx.get('payment_intent_id'))
        elif operation == 'confirm_payment_intent':
            result = client.confirm_payment_intent(ctx.get('payment_intent_id'), ctx.get('confirmation_data'))
        elif operation == 'cancel_payment_intent':
            result = client.cancel_payment_intent(ctx.get('payment_intent_id'))
            
        # Subscription operations
        elif operation == 'list_subscriptions':
            result = client.list_subscriptions(ctx.get('customer_id'), ctx.get('status'), ctx.get('limit', 10))
        elif operation == 'create_subscription':
            result = client.create_subscription(ctx.get('subscription_data'))
        elif operation == 'get_subscription':
            result = client.get_subscription(ctx.get('subscription_id'))
        elif operation == 'update_subscription':
            result = client.update_subscription(ctx.get('subscription_id'), ctx.get('subscription_data'))
        elif operation == 'cancel_subscription':
            result = client.cancel_subscription(ctx.get('subscription_id'), ctx.get('cancel_immediately', False))
            
        # Product operations
        elif operation == 'list_products':
            result = client.list_products(ctx.get('active'), ctx.get('limit', 10))
        elif operation == 'create_product':
            result = client.create_product(ctx.get('product_data'))
        elif operation == 'get_product':
            result = client.get_product(ctx.get('product_id'))
        elif operation == 'update_product':
            result = client.update_product(ctx.get('product_id'), ctx.get('product_data'))
            
        # Price operations
        elif operation == 'list_prices':
            result = client.list_prices(ctx.get('product_id'), ctx.get('active'), ctx.get('limit', 10))
        elif operation == 'create_price':
            result = client.create_price(ctx.get('price_data'))
        elif operation == 'get_price':
            result = client.get_price(ctx.get('price_id'))
            
        # Invoice operations
        elif operation == 'list_invoices':
            result = client.list_invoices(ctx.get('customer_id'), ctx.get('status'), ctx.get('limit', 10))
        elif operation == 'create_invoice':
            result = client.create_invoice(ctx.get('invoice_data'))
        elif operation == 'get_invoice':
            result = client.get_invoice(ctx.get('invoice_id'))
        elif operation == 'pay_invoice':
            result = client.pay_invoice(ctx.get('invoice_id'))
            
        # Webhook operations
        elif operation == 'construct_event':
            result = client.construct_webhook_event(ctx.get('payload'), ctx.get('signature'), ctx.get('endpoint_secret'))
            
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        
        # Store results in context
        ctx['stripe_result'] = result
        ctx['stripe_status'] = 'success'
        
        logger.info(f"Stripe {operation} operation completed successfully")
        return ctx
        
    except Exception as e:
        logger.error(f"Stripe operation failed: {str(e)}")
        ctx['stripe_result'] = None
        ctx['stripe_status'] = 'error'
        ctx['stripe_error'] = str(e)
        return ctx


class StripeClient:
    """
    Enterprise Stripe API client with authentication and error handling.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.api_key = config.get('secret_key') or config.get('api_key')
        self.base_url = "https://api.stripe.com/v1"
        self.session = requests.Session()
        
        if not self.api_key:
            raise ValueError("Stripe API key is required")
        
        # Set authentication header
        auth_string = base64.b64encode(f"{self.api_key}:".encode()).decode()
        self.session.headers.update({
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Stripe-Version': '2023-10-16'
        })
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make authenticated request to Stripe API."""
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=data)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, data=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            error_data = e.response.json() if e.response.content else {}
            error_message = error_data.get('error', {}).get('message', str(e))
            raise Exception(f"Stripe API error: {error_message}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
    
    # Customer operations
    def list_customers(self, limit: int = 10, starting_after: Optional[str] = None) -> Dict[str, Any]:
        """List customers."""
        params = {'limit': limit}
        if starting_after:
            params['starting_after'] = starting_after
        
        return self._make_request('GET', 'customers', params)
    
    def create_customer(self, customer_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new customer."""
        return self._make_request('POST', 'customers', customer_data)
    
    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        """Get customer details."""
        return self._make_request('GET', f'customers/{customer_id}')
    
    def update_customer(self, customer_id: str, customer_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update customer information."""
        return self._make_request('POST', f'customers/{customer_id}', customer_data)
    
    def delete_customer(self, customer_id: str) -> Dict[str, Any]:
        """Delete a customer."""
        return self._make_request('DELETE', f'customers/{customer_id}')
    
    # Payment Intent operations
    def create_payment_intent(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a payment intent."""
        return self._make_request('POST', 'payment_intents', payment_data)
    
    def get_payment_intent(self, payment_intent_id: str) -> Dict[str, Any]:
        """Get payment intent details."""
        return self._make_request('GET', f'payment_intents/{payment_intent_id}')
    
    def confirm_payment_intent(self, payment_intent_id: str, confirmation_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Confirm a payment intent."""
        return self._make_request('POST', f'payment_intents/{payment_intent_id}/confirm', confirmation_data or {})
    
    def cancel_payment_intent(self, payment_intent_id: str) -> Dict[str, Any]:
        """Cancel a payment intent."""
        return self._make_request('POST', f'payment_intents/{payment_intent_id}/cancel')
    
    # Subscription operations
    def list_subscriptions(self, customer_id: Optional[str] = None, status: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
        """List subscriptions."""
        params = {'limit': limit}
        if customer_id:
            params['customer'] = customer_id
        if status:
            params['status'] = status
        
        return self._make_request('GET', 'subscriptions', params)
    
    def create_subscription(self, subscription_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new subscription."""
        return self._make_request('POST', 'subscriptions', subscription_data)
    
    def get_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Get subscription details."""
        return self._make_request('GET', f'subscriptions/{subscription_id}')
    
    def update_subscription(self, subscription_id: str, subscription_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update subscription."""
        return self._make_request('POST', f'subscriptions/{subscription_id}', subscription_data)
    
    def cancel_subscription(self, subscription_id: str, cancel_immediately: bool = False) -> Dict[str, Any]:
        """Cancel a subscription."""
        data = {}
        if cancel_immediately:
            data['prorate'] = 'false'
        
        return self._make_request('DELETE', f'subscriptions/{subscription_id}', data)
    
    # Product operations
    def list_products(self, active: Optional[bool] = None, limit: int = 10) -> Dict[str, Any]:
        """List products."""
        params = {'limit': limit}
        if active is not None:
            params['active'] = str(active).lower()
        
        return self._make_request('GET', 'products', params)
    
    def create_product(self, product_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new product."""
        return self._make_request('POST', 'products', product_data)
    
    def get_product(self, product_id: str) -> Dict[str, Any]:
        """Get product details."""
        return self._make_request('GET', f'products/{product_id}')
    
    def update_product(self, product_id: str, product_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update product information."""
        return self._make_request('POST', f'products/{product_id}', product_data)
    
    # Price operations
    def list_prices(self, product_id: Optional[str] = None, active: Optional[bool] = None, limit: int = 10) -> Dict[str, Any]:
        """List prices."""
        params = {'limit': limit}
        if product_id:
            params['product'] = product_id
        if active is not None:
            params['active'] = str(active).lower()
        
        return self._make_request('GET', 'prices', params)
    
    def create_price(self, price_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new price."""
        return self._make_request('POST', 'prices', price_data)
    
    def get_price(self, price_id: str) -> Dict[str, Any]:
        """Get price details."""
        return self._make_request('GET', f'prices/{price_id}')
    
    # Invoice operations
    def list_invoices(self, customer_id: Optional[str] = None, status: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
        """List invoices."""
        params = {'limit': limit}
        if customer_id:
            params['customer'] = customer_id
        if status:
            params['status'] = status
        
        return self._make_request('GET', 'invoices', params)
    
    def create_invoice(self, invoice_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new invoice."""
        return self._make_request('POST', 'invoices', invoice_data)
    
    def get_invoice(self, invoice_id: str) -> Dict[str, Any]:
        """Get invoice details."""
        return self._make_request('GET', f'invoices/{invoice_id}')
    
    def pay_invoice(self, invoice_id: str) -> Dict[str, Any]:
        """Pay an invoice."""
        return self._make_request('POST', f'invoices/{invoice_id}/pay')
    
    # Webhook operations
    def construct_webhook_event(self, payload: str, signature: str, endpoint_secret: str) -> Dict[str, Any]:
        """Construct and verify webhook event."""
        import hmac
        import hashlib
        import time
        
        # Extract timestamp and signatures from header
        elements = signature.split(',')
        timestamp = None
        signatures = []
        
        for element in elements:
            key, value = element.split('=', 1)
            if key == 't':
                timestamp = int(value)
            elif key.startswith('v'):
                signatures.append(value)
        
        if not timestamp or not signatures:
            raise ValueError("Invalid signature header")
        
        # Check timestamp tolerance (5 minutes)
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:
            raise ValueError("Timestamp outside tolerance")
        
        # Verify signature
        expected_sig = hmac.new(
            endpoint_secret.encode(),
            f"{timestamp}.{payload}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not any(hmac.compare_digest(expected_sig, sig) for sig in signatures):
            raise ValueError("Invalid signature")
        
        # Parse and return event
        try:
            event = json.loads(payload)
            return event
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON payload")


# Plug metadata
plug_metadata = {
    "name": "stripe_payments",
    "version": "1.0.0",
    "description": "Enterprise Stripe payment processing integration with comprehensive financial operations",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "payments",
    "tags": ["stripe", "payments", "billing", "subscriptions", "ecommerce", "fintech"],
    "requirements": ["requests"]
}