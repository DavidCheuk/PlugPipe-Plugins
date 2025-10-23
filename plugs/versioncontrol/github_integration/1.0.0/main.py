# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
GitHub Integration Plug - Enterprise repository management
Provides comprehensive GitHub API integration for repository, issue, and PR management.
"""

import requests
import json
import base64
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def process(ctx: dict, cfg: dict) -> dict:
    """
    Main plugin entry point for GitHub operations.
    
    Args:
        ctx: Pipe context containing operation parameters
        cfg: Plug configuration including authentication
        
    Returns:
        Updated context with operation results
    """
    try:
        # Initialize GitHub client
        client = GitHubClient(cfg)
        
        # Get operation from context
        operation = ctx.get('operation', 'list_repos')
        
        result = None
        
        # Repository operations
        if operation == 'list_repos':
            result = client.list_repositories(ctx.get('org'), ctx.get('type', 'all'), ctx.get('limit', 30))
        elif operation == 'get_repo':
            result = client.get_repository(ctx.get('owner'), ctx.get('repo'))
        elif operation == 'create_repo':
            result = client.create_repository(ctx.get('repo_data'))
        elif operation == 'update_repo':
            result = client.update_repository(ctx.get('owner'), ctx.get('repo'), ctx.get('repo_data'))
        elif operation == 'delete_repo':
            result = client.delete_repository(ctx.get('owner'), ctx.get('repo'))
            
        # Issue operations
        elif operation == 'list_issues':
            result = client.list_issues(ctx.get('owner'), ctx.get('repo'), ctx.get('state', 'open'), ctx.get('limit', 30))
        elif operation == 'get_issue':
            result = client.get_issue(ctx.get('owner'), ctx.get('repo'), ctx.get('issue_number'))
        elif operation == 'create_issue':
            result = client.create_issue(ctx.get('owner'), ctx.get('repo'), ctx.get('issue_data'))
        elif operation == 'update_issue':
            result = client.update_issue(ctx.get('owner'), ctx.get('repo'), ctx.get('issue_number'), ctx.get('issue_data'))
        elif operation == 'close_issue':
            result = client.close_issue(ctx.get('owner'), ctx.get('repo'), ctx.get('issue_number'))
            
        # Pull Request operations
        elif operation == 'list_prs':
            result = client.list_pull_requests(ctx.get('owner'), ctx.get('repo'), ctx.get('state', 'open'), ctx.get('limit', 30))
        elif operation == 'get_pr':
            result = client.get_pull_request(ctx.get('owner'), ctx.get('repo'), ctx.get('pr_number'))
        elif operation == 'create_pr':
            result = client.create_pull_request(ctx.get('owner'), ctx.get('repo'), ctx.get('pr_data'))
        elif operation == 'merge_pr':
            result = client.merge_pull_request(ctx.get('owner'), ctx.get('repo'), ctx.get('pr_number'), ctx.get('merge_data'))
            
        # File operations
        elif operation == 'get_file':
            result = client.get_file_content(ctx.get('owner'), ctx.get('repo'), ctx.get('path'), ctx.get('ref', 'main'))
        elif operation == 'create_file':
            result = client.create_file(ctx.get('owner'), ctx.get('repo'), ctx.get('path'), ctx.get('content'), ctx.get('commit_data'))
        elif operation == 'update_file':
            result = client.update_file(ctx.get('owner'), ctx.get('repo'), ctx.get('path'), ctx.get('content'), ctx.get('sha'), ctx.get('commit_data'))
        elif operation == 'delete_file':
            result = client.delete_file(ctx.get('owner'), ctx.get('repo'), ctx.get('path'), ctx.get('sha'), ctx.get('commit_data'))
            
        # Webhook operations
        elif operation == 'list_webhooks':
            result = client.list_webhooks(ctx.get('owner'), ctx.get('repo'))
        elif operation == 'create_webhook':
            result = client.create_webhook(ctx.get('owner'), ctx.get('repo'), ctx.get('webhook_data'))
        elif operation == 'delete_webhook':
            result = client.delete_webhook(ctx.get('owner'), ctx.get('repo'), ctx.get('webhook_id'))
            
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        
        # Store results in context
        ctx['github_result'] = result
        ctx['github_status'] = 'success'
        
        logger.info(f"GitHub {operation} operation completed successfully")
        return ctx
        
    except Exception as e:
        logger.error(f"GitHub operation failed: {str(e)}")
        ctx['github_result'] = None
        ctx['github_status'] = 'error'
        ctx['github_error'] = str(e)
        return ctx


class GitHubClient:
    """
    Enterprise GitHub API client with authentication and error handling.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.base_url = config.get('base_url', 'https://api.github.com')
        self.session = requests.Session()
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with GitHub API."""
        auth_method = self.config.get('auth_method', 'token')
        
        if auth_method == 'token':
            token = self.config.get('token')
            self.session.headers.update({
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'PlugPipe-GitHub-Integration/1.0.0'
            })
        elif auth_method == 'app':
            self._authenticate_as_app()
        else:
            raise ValueError(f"Unsupported auth method: {auth_method}")
    
    def _authenticate_as_app(self):
        """Authenticate as GitHub App."""
        import jwt
        import time
        
        # Create JWT for GitHub App
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 600,  # 10 minutes
            'iss': self.config['app_id']
        }
        
        private_key = self.config['private_key']
        jwt_token = jwt.encode(payload, private_key, algorithm='RS256')
        
        # Get installation access token
        installation_id = self.config['installation_id']
        
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        response = requests.post(
            f"{self.base_url}/app/installations/{installation_id}/access_tokens",
            headers=headers
        )
        response.raise_for_status()
        
        access_token = response.json()['token']
        
        self.session.headers.update({
            'Authorization': f'token {access_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'PlugPipe-GitHub-Integration/1.0.0'
        })
    
    # Repository operations
    def list_repositories(self, org: Optional[str] = None, type_filter: str = 'all', limit: int = 30) -> Dict[str, Any]:
        """List repositories."""
        if org:
            url = f"{self.base_url}/orgs/{org}/repos"
        else:
            url = f"{self.base_url}/user/repos"
        
        params = {'type': type_filter, 'per_page': min(limit, 100), 'sort': 'updated'}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return {
            'repositories': response.json(),
            'total_count': len(response.json())
        }
    
    def get_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        """Get repository details."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def create_repository(self, repo_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new repository."""
        org = repo_data.get('org')
        if org:
            url = f"{self.base_url}/orgs/{org}/repos"
        else:
            url = f"{self.base_url}/user/repos"
        
        response = self.session.post(url, json=repo_data)
        response.raise_for_status()
        return response.json()
    
    def update_repository(self, owner: str, repo: str, repo_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update repository settings."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        response = self.session.patch(url, json=repo_data)
        response.raise_for_status()
        return response.json()
    
    def delete_repository(self, owner: str, repo: str) -> Dict[str, Any]:
        """Delete a repository."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        response = self.session.delete(url)
        response.raise_for_status()
        return {"success": True, "message": "Repository deleted"}
    
    # Issue operations
    def list_issues(self, owner: str, repo: str, state: str = 'open', limit: int = 30) -> Dict[str, Any]:
        """List repository issues."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues"
        params = {'state': state, 'per_page': min(limit, 100)}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return {
            'issues': response.json(),
            'total_count': len(response.json())
        }
    
    def get_issue(self, owner: str, repo: str, issue_number: int) -> Dict[str, Any]:
        """Get issue details."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def create_issue(self, owner: str, repo: str, issue_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new issue."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues"
        response = self.session.post(url, json=issue_data)
        response.raise_for_status()
        return response.json()
    
    def update_issue(self, owner: str, repo: str, issue_number: int, issue_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an issue."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}"
        response = self.session.patch(url, json=issue_data)
        response.raise_for_status()
        return response.json()
    
    def close_issue(self, owner: str, repo: str, issue_number: int) -> Dict[str, Any]:
        """Close an issue."""
        return self.update_issue(owner, repo, issue_number, {"state": "closed"})
    
    # Pull Request operations
    def list_pull_requests(self, owner: str, repo: str, state: str = 'open', limit: int = 30) -> Dict[str, Any]:
        """List pull requests."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls"
        params = {'state': state, 'per_page': min(limit, 100)}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return {
            'pull_requests': response.json(),
            'total_count': len(response.json())
        }
    
    def get_pull_request(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        """Get pull request details."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def create_pull_request(self, owner: str, repo: str, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a pull request."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls"
        response = self.session.post(url, json=pr_data)
        response.raise_for_status()
        return response.json()
    
    def merge_pull_request(self, owner: str, repo: str, pr_number: int, merge_data: Dict[str, Any]) -> Dict[str, Any]:
        """Merge a pull request."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/merge"
        response = self.session.put(url, json=merge_data)
        response.raise_for_status()
        return response.json()
    
    # File operations
    def get_file_content(self, owner: str, repo: str, path: str, ref: str = 'main') -> Dict[str, Any]:
        """Get file content from repository."""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        params = {'ref': ref}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        file_data = response.json()
        if file_data.get('content'):
            file_data['decoded_content'] = base64.b64decode(file_data['content']).decode('utf-8')
        
        return file_data
    
    def create_file(self, owner: str, repo: str, path: str, content: str, commit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new file in repository."""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        data = {
            'message': commit_data.get('message', f'Create {path}'),
            'content': base64.b64encode(content.encode('utf-8')).decode('utf-8'),
            'branch': commit_data.get('branch', 'main')
        }
        
        if 'committer' in commit_data:
            data['committer'] = commit_data['committer']
        
        response = self.session.put(url, json=data)
        response.raise_for_status()
        return response.json()
    
    def update_file(self, owner: str, repo: str, path: str, content: str, sha: str, commit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing file."""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        data = {
            'message': commit_data.get('message', f'Update {path}'),
            'content': base64.b64encode(content.encode('utf-8')).decode('utf-8'),
            'sha': sha,
            'branch': commit_data.get('branch', 'main')
        }
        
        if 'committer' in commit_data:
            data['committer'] = commit_data['committer']
        
        response = self.session.put(url, json=data)
        response.raise_for_status()
        return response.json()
    
    def delete_file(self, owner: str, repo: str, path: str, sha: str, commit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a file from repository."""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        data = {
            'message': commit_data.get('message', f'Delete {path}'),
            'sha': sha,
            'branch': commit_data.get('branch', 'main')
        }
        
        if 'committer' in commit_data:
            data['committer'] = commit_data['committer']
        
        response = self.session.delete(url, json=data)
        response.raise_for_status()
        return response.json()
    
    # Webhook operations
    def list_webhooks(self, owner: str, repo: str) -> Dict[str, Any]:
        """List repository webhooks."""
        url = f"{self.base_url}/repos/{owner}/{repo}/hooks"
        response = self.session.get(url)
        response.raise_for_status()
        
        return {
            'webhooks': response.json(),
            'total_count': len(response.json())
        }
    
    def create_webhook(self, owner: str, repo: str, webhook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a repository webhook."""
        url = f"{self.base_url}/repos/{owner}/{repo}/hooks"
        response = self.session.post(url, json=webhook_data)
        response.raise_for_status()
        return response.json()
    
    def delete_webhook(self, owner: str, repo: str, webhook_id: int) -> Dict[str, Any]:
        """Delete a repository webhook."""
        url = f"{self.base_url}/repos/{owner}/{repo}/hooks/{webhook_id}"
        response = self.session.delete(url)
        response.raise_for_status()
        return {"success": True, "message": "Webhook deleted"}


# Plug metadata
plug_metadata = {
    "name": "github_integration",
    "version": "1.0.0",
    "description": "Enterprise GitHub integration for repository, issue, and PR management",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "version_control",
    "tags": ["github", "git", "repository", "issue", "pull_request", "api"],
    "requirements": ["requests", "PyJWT"]
}