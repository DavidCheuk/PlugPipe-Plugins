# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Slack Messaging Plug - Enterprise team communication
Provides comprehensive Slack API integration for messaging, channel management, and workflows.
"""

import requests
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def process(ctx: dict, cfg: dict) -> dict:
    """
    Main plugin entry point for Slack operations.
    
    Args:
        ctx: Pipe context containing operation parameters
        cfg: Plug configuration including authentication
        
    Returns:
        Updated context with operation results
    """
    try:
        # Initialize Slack client
        client = SlackClient(cfg)
        
        # Get operation from context
        operation = ctx.get('operation', 'send_message')
        
        result = None
        
        # Message operations
        if operation == 'send_message':
            result = client.send_message(
                ctx.get('channel'),
                ctx.get('text'),
                ctx.get('blocks'),
                ctx.get('attachments'),
                ctx.get('thread_ts')
            )
        elif operation == 'update_message':
            result = client.update_message(
                ctx.get('channel'),
                ctx.get('ts'),
                ctx.get('text'),
                ctx.get('blocks'),
                ctx.get('attachments')
            )
        elif operation == 'delete_message':
            result = client.delete_message(ctx.get('channel'), ctx.get('ts'))
        elif operation == 'get_message_history':
            result = client.get_message_history(
                ctx.get('channel'),
                ctx.get('limit', 100),
                ctx.get('oldest'),
                ctx.get('latest')
            )
            
        # Channel operations
        elif operation == 'list_channels':
            result = client.list_channels(ctx.get('types', 'public_channel,private_channel'), ctx.get('limit', 100))
        elif operation == 'create_channel':
            result = client.create_channel(ctx.get('name'), ctx.get('is_private', False))
        elif operation == 'join_channel':
            result = client.join_channel(ctx.get('channel'))
        elif operation == 'leave_channel':
            result = client.leave_channel(ctx.get('channel'))
        elif operation == 'invite_to_channel':
            result = client.invite_to_channel(ctx.get('channel'), ctx.get('users'))
        elif operation == 'kick_from_channel':
            result = client.kick_from_channel(ctx.get('channel'), ctx.get('user'))
            
        # User operations
        elif operation == 'get_user_info':
            result = client.get_user_info(ctx.get('user'))
        elif operation == 'list_users':
            result = client.list_users(ctx.get('limit', 100))
        elif operation == 'set_user_status':
            result = client.set_user_status(ctx.get('status_text'), ctx.get('status_emoji'), ctx.get('status_expiration'))
            
        # File operations
        elif operation == 'upload_file':
            result = client.upload_file(
                ctx.get('file_path'),
                ctx.get('channels'),
                ctx.get('filename'),
                ctx.get('title'),
                ctx.get('initial_comment')
            )
        elif operation == 'get_file_info':
            result = client.get_file_info(ctx.get('file_id'))
        elif operation == 'delete_file':
            result = client.delete_file(ctx.get('file_id'))
            
        # Workflow operations
        elif operation == 'trigger_workflow':
            result = client.trigger_workflow(ctx.get('trigger_id'), ctx.get('inputs'))
            
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        
        # Store results in context
        ctx['slack_result'] = result
        ctx['slack_status'] = 'success'
        
        logger.info(f"Slack {operation} operation completed successfully")
        return ctx
        
    except Exception as e:
        logger.error(f"Slack operation failed: {str(e)}")
        ctx['slack_result'] = None
        ctx['slack_status'] = 'error'
        ctx['slack_error'] = str(e)
        return ctx


class SlackClient:
    """
    Enterprise Slack API client with authentication and error handling.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.base_url = "https://slack.com/api"
        self.session = requests.Session()
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with Slack API."""
        auth_method = self.config.get('auth_method', 'bot_token')
        
        if auth_method == 'bot_token':
            token = self.config.get('bot_token')
            self.session.headers.update({
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            })
        elif auth_method == 'oauth':
            # For OAuth apps, token would be obtained through OAuth flow
            token = self.config.get('access_token')
            self.session.headers.update({
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            })
        else:
            raise ValueError(f"Unsupported auth method: {auth_method}")
    
    def _make_request(self, endpoint: str, method: str = 'POST', **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Slack API."""
        url = f"{self.base_url}/{endpoint}"
        
        if method.upper() == 'GET':
            response = self.session.get(url, params=kwargs)
        else:
            response = self.session.post(url, json=kwargs)
        
        response.raise_for_status()
        result = response.json()
        
        if not result.get('ok'):
            raise Exception(f"Slack API error: {result.get('error', 'Unknown error')}")
        
        return result
    
    # Message operations
    def send_message(self, channel: str, text: Optional[str] = None, 
                    blocks: Optional[List[Dict]] = None, 
                    attachments: Optional[List[Dict]] = None,
                    thread_ts: Optional[str] = None) -> Dict[str, Any]:
        """Send a message to a channel."""
        params = {'channel': channel}
        
        if text:
            params['text'] = text
        if blocks:
            params['blocks'] = blocks
        if attachments:
            params['attachments'] = attachments
        if thread_ts:
            params['thread_ts'] = thread_ts
        
        return self._make_request('chat.postMessage', **params)
    
    def update_message(self, channel: str, ts: str, text: Optional[str] = None,
                      blocks: Optional[List[Dict]] = None,
                      attachments: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """Update an existing message."""
        params = {'channel': channel, 'ts': ts}
        
        if text:
            params['text'] = text
        if blocks:
            params['blocks'] = blocks
        if attachments:
            params['attachments'] = attachments
        
        return self._make_request('chat.update', **params)
    
    def delete_message(self, channel: str, ts: str) -> Dict[str, Any]:
        """Delete a message."""
        return self._make_request('chat.delete', channel=channel, ts=ts)
    
    def get_message_history(self, channel: str, limit: int = 100,
                           oldest: Optional[str] = None,
                           latest: Optional[str] = None) -> Dict[str, Any]:
        """Get message history from a channel."""
        params = {'channel': channel, 'limit': limit}
        
        if oldest:
            params['oldest'] = oldest
        if latest:
            params['latest'] = latest
        
        return self._make_request('conversations.history', method='GET', **params)
    
    # Channel operations
    def list_channels(self, types: str = 'public_channel,private_channel', 
                     limit: int = 100) -> Dict[str, Any]:
        """List channels."""
        return self._make_request('conversations.list', method='GET', 
                                types=types, limit=limit)
    
    def create_channel(self, name: str, is_private: bool = False) -> Dict[str, Any]:
        """Create a new channel."""
        return self._make_request('conversations.create', name=name, is_private=is_private)
    
    def join_channel(self, channel: str) -> Dict[str, Any]:
        """Join a channel."""
        return self._make_request('conversations.join', channel=channel)
    
    def leave_channel(self, channel: str) -> Dict[str, Any]:
        """Leave a channel."""
        return self._make_request('conversations.leave', channel=channel)
    
    def invite_to_channel(self, channel: str, users: List[str]) -> Dict[str, Any]:
        """Invite users to a channel."""
        return self._make_request('conversations.invite', channel=channel, users=','.join(users))
    
    def kick_from_channel(self, channel: str, user: str) -> Dict[str, Any]:
        """Remove a user from a channel."""
        return self._make_request('conversations.kick', channel=channel, user=user)
    
    # User operations
    def get_user_info(self, user: str) -> Dict[str, Any]:
        """Get user information."""
        return self._make_request('users.info', method='GET', user=user)
    
    def list_users(self, limit: int = 100) -> Dict[str, Any]:
        """List workspace users."""
        return self._make_request('users.list', method='GET', limit=limit)
    
    def set_user_status(self, status_text: str, status_emoji: Optional[str] = None,
                       status_expiration: Optional[int] = None) -> Dict[str, Any]:
        """Set user status."""
        profile = {'status_text': status_text}
        
        if status_emoji:
            profile['status_emoji'] = status_emoji
        if status_expiration:
            profile['status_expiration'] = status_expiration
        
        return self._make_request('users.profile.set', profile=profile)
    
    # File operations
    def upload_file(self, file_path: str, channels: Optional[List[str]] = None,
                   filename: Optional[str] = None, title: Optional[str] = None,
                   initial_comment: Optional[str] = None) -> Dict[str, Any]:
        """Upload a file to Slack."""
        import os
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Prepare upload URL
        upload_url = f"{self.base_url}/files.upload"
        
        # Prepare files and data for multipart/form-data
        files = {'file': open(file_path, 'rb')}
        data = {}
        
        if channels:
            data['channels'] = ','.join(channels)
        if filename:
            data['filename'] = filename
        else:
            data['filename'] = os.path.basename(file_path)
        if title:
            data['title'] = title
        if initial_comment:
            data['initial_comment'] = initial_comment
        
        try:
            # Make real multipart file upload request
            response = self.session.post(upload_url, files=files, data=data)
            response.raise_for_status()
            result = response.json()
            
            if not result.get('ok'):
                raise Exception(f"Slack API error: {result.get('error', 'Unknown error')}")
            
            return result
            
        finally:
            # Ensure file is closed
            files['file'].close()
    
    def get_file_info(self, file_id: str) -> Dict[str, Any]:
        """Get file information."""
        return self._make_request('files.info', method='GET', file=file_id)
    
    def delete_file(self, file_id: str) -> Dict[str, Any]:
        """Delete a file."""
        return self._make_request('files.delete', file=file_id)
    
    # Workflow operations
    def trigger_workflow(self, trigger_id: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger a workflow."""
        return self._make_request('workflows.stepCompleted', 
                                workflow_step_execute_id=trigger_id, 
                                outputs=inputs)


# Plug metadata
plug_metadata = {
    "name": "slack_messaging",
    "version": "1.0.0",
    "description": "Enterprise Slack messaging and team communication integration",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "communication",
    "tags": ["slack", "messaging", "team", "communication", "workflow"],
    "requirements": ["requests"]
}