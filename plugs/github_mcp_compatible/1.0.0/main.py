# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
GitHub MCP-Compatible Plug - Full GitHub API compatibility with MCP server features
Based on GitHub's official MCP server capabilities with PlugPipe enhancements.
"""

import requests
import json
import base64
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import os

logger = logging.getLogger(__name__)

def process(ctx: dict, cfg: dict) -> dict:
    """
    Main plugin entry point for GitHub MCP-compatible operations.
    
    Args:
        ctx: Pipe context containing operation parameters
        cfg: Plug configuration including authentication and toolsets
        
    Returns:
        Updated context with operation results
    """
    try:
        # Initialize GitHub MCP client
        client = GitHubMCPClient(cfg)
        
        # Get operation from context
        operation = ctx.get('operation', 'list_repositories')
        
        result = None
        
        # Repository operations
        if operation == 'list_repositories':
            result = client.list_repositories(
                org=ctx.get('org'),
                type=ctx.get('type', 'all'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'search_repositories':
            result = client.search_repositories(
                query=ctx.get('query'),
                sort=ctx.get('sort', 'stars'),
                order=ctx.get('order', 'desc'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'get_repository':
            result = client.get_repository(ctx.get('owner'), ctx.get('repo'))
        elif operation == 'create_repository':
            result = client.create_repository(ctx.get('repo_data'))
            
        # File operations (MCP-compatible)
        elif operation == 'create_or_update_file':
            result = client.create_or_update_file(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                path=ctx.get('path'),
                content=ctx.get('content'),
                message=ctx.get('message'),
                branch=ctx.get('branch'),
                sha=ctx.get('sha')  # For updates
            )
        elif operation == 'push_files':
            result = client.push_files(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                files=ctx.get('files'),
                message=ctx.get('message'),
                branch=ctx.get('branch')
            )
        elif operation == 'get_file_content':
            result = client.get_file_content(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                path=ctx.get('path'),
                ref=ctx.get('ref', 'main')
            )
            
        # Search operations  
        elif operation == 'search_code':
            result = client.search_code(
                query=ctx.get('query'),
                repo=ctx.get('repo'),
                owner=ctx.get('owner'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'search_users':
            result = client.search_users(
                query=ctx.get('query'),
                limit=ctx.get('limit', 30)
            )
            
        # Issue operations (MCP-compatible)
        elif operation == 'list_issues':
            result = client.list_issues(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                state=ctx.get('state', 'open'),
                labels=ctx.get('labels'),
                assignee=ctx.get('assignee'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'create_issue':
            result = client.create_issue(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                title=ctx.get('title'),
                body=ctx.get('body'),
                labels=ctx.get('labels'),
                assignees=ctx.get('assignees')
            )
        elif operation == 'update_issue':
            result = client.update_issue(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                issue_number=ctx.get('issue_number'),
                issue_data=ctx.get('issue_data')
            )
            
        # Pull Request operations (MCP-compatible)
        elif operation == 'list_pull_requests':
            result = client.list_pull_requests(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                state=ctx.get('state', 'open'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'create_pull_request':
            result = client.create_pull_request(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                title=ctx.get('title'),
                body=ctx.get('body'),
                head=ctx.get('head'),
                base=ctx.get('base', 'main'),
                draft=ctx.get('draft', False)
            )
        elif operation == 'merge_pull_request':
            result = client.merge_pull_request(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                pr_number=ctx.get('pr_number'),
                merge_method=ctx.get('merge_method', 'merge')
            )
            
        # Actions/CI-CD operations (NEW)
        elif operation == 'list_workflow_runs':
            result = client.list_workflow_runs(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                workflow_id=ctx.get('workflow_id'),
                status=ctx.get('status'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'get_workflow_run':
            result = client.get_workflow_run(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                run_id=ctx.get('run_id')
            )
        elif operation == 'rerun_workflow':
            result = client.rerun_workflow(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                run_id=ctx.get('run_id')
            )
            
        # Security operations (NEW)
        elif operation == 'list_code_scanning_alerts':
            result = client.list_code_scanning_alerts(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                state=ctx.get('state', 'open'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'list_dependabot_alerts':
            result = client.list_dependabot_alerts(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                state=ctx.get('state', 'open'),
                limit=ctx.get('limit', 30)
            )
        elif operation == 'dismiss_dependabot_alert':
            result = client.dismiss_dependabot_alert(
                owner=ctx.get('owner'),
                repo=ctx.get('repo'),
                alert_number=ctx.get('alert_number'),
                reason=ctx.get('reason', 'no_bandwidth')
            )
            
        # User/Organization operations (NEW)
        elif operation == 'get_me':
            result = client.get_authenticated_user()
        elif operation == 'get_user':
            result = client.get_user(ctx.get('username'))
        elif operation == 'get_organization':
            result = client.get_organization(ctx.get('org'))
            
        else:
            raise ValueError(f"Unsupported GitHub MCP operation: {operation}")
        
        # Store results in context
        ctx['github_mcp_result'] = result
        ctx['github_mcp_status'] = 'success'
        ctx['operation_performed'] = operation
        
        logger.info(f"GitHub MCP {operation} operation completed successfully")
        return ctx
        
    except Exception as e:
        logger.error(f"GitHub MCP operation failed: {str(e)}")
        ctx['github_mcp_result'] = None
        ctx['github_mcp_status'] = 'error'
        ctx['github_mcp_error'] = str(e)
        return ctx


class GitHubMCPClient:
    """
    GitHub MCP-compatible client implementing official MCP server capabilities.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.github_config = config.get('github', {})
        self.toolsets = set(config.get('toolsets', ['repos', 'issues', 'pull_requests', 'actions', 'code_security']))
        self.read_only = config.get('read_only', False)
        
        # Setup authentication
        self.token = self.github_config.get('token') or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GitHub token is required")
            
        self.base_url = self.github_config.get('base_url', 'https://api.github.com')
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'PlugPipe-GitHub-MCP/1.0.0'
        }
        
    def _check_toolset(self, toolset: str):
        """Check if toolset is enabled."""
        if toolset not in self.toolsets:
            raise ValueError(f"Toolset '{toolset}' is not enabled. Available: {list(self.toolsets)}")
    
    def _check_write_operation(self, operation: str):
        """Check if write operations are allowed."""
        if self.read_only:
            raise ValueError(f"Write operation '{operation}' not allowed in read-only mode")
    
    def _make_request(self, method: str, endpoint: str, data: dict = None, params: dict = None) -> dict:
        """Make authenticated GitHub API request."""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=self.headers, params=params)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=self.headers, json=data, params=params)
            elif method.upper() == 'PUT':
                response = requests.put(url, headers=self.headers, json=data, params=params)
            elif method.upper() == 'PATCH':
                response = requests.patch(url, headers=self.headers, json=data, params=params)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=self.headers, params=params)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
                
            response.raise_for_status()
            
            # Handle empty responses
            if response.status_code == 204:
                return {'status': 'success', 'message': 'Operation completed'}
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    raise Exception(f"GitHub API error: {error_detail.get('message', str(e))}")
                except:
                    pass
            raise Exception(f"GitHub API request failed: {str(e)}")
    
    # Repository operations
    def list_repositories(self, org: str = None, type: str = 'all', limit: int = 30) -> dict:
        """List repositories."""
        self._check_toolset('repos')
        
        if org:
            endpoint = f"/orgs/{org}/repos"
            params = {'type': type, 'per_page': min(limit, 100)}
        else:
            endpoint = "/user/repos"
            params = {'type': type, 'per_page': min(limit, 100)}
            
        response = self._make_request('GET', endpoint, params=params)
        return {'repositories': response[:limit]}
    
    def search_repositories(self, query: str, sort: str = 'stars', order: str = 'desc', limit: int = 30) -> dict:
        """Search repositories (MCP-compatible)."""
        self._check_toolset('repos')
        
        params = {
            'q': query,
            'sort': sort,
            'order': order,
            'per_page': min(limit, 100)
        }
        
        response = self._make_request('GET', '/search/repositories', params=params)
        return {
            'repositories': response.get('items', [])[:limit],
            'total_count': response.get('total_count', 0)
        }
    
    def get_repository(self, owner: str, repo: str) -> dict:
        """Get repository details."""
        self._check_toolset('repos')
        return self._make_request('GET', f'/repos/{owner}/{repo}')
    
    def create_repository(self, repo_data: dict) -> dict:
        """Create repository (write operation)."""
        self._check_toolset('repos')
        self._check_write_operation('create_repository')
        
        if 'org' in repo_data:
            endpoint = f"/orgs/{repo_data['org']}/repos"
        else:
            endpoint = "/user/repos"
            
        return self._make_request('POST', endpoint, data=repo_data)
    
    # File operations (MCP-compatible)
    def create_or_update_file(self, owner: str, repo: str, path: str, content: str, 
                             message: str, branch: str = None, sha: str = None) -> dict:
        """Create or update file with automatic branch creation (MCP-compatible)."""
        self._check_toolset('repos')
        self._check_write_operation('create_or_update_file')
        
        # Encode content to base64
        encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        # Prepare data
        file_data = {
            'message': message,
            'content': encoded_content
        }
        
        if branch:
            file_data['branch'] = branch
            # Ensure branch exists
            self._ensure_branch_exists(owner, repo, branch)
            
        if sha:  # Update operation
            file_data['sha'] = sha
        
        endpoint = f'/repos/{owner}/{repo}/contents/{path}'
        return self._make_request('PUT', endpoint, data=file_data)
    
    def push_files(self, owner: str, repo: str, files: List[dict], message: str, branch: str = None) -> dict:
        """Push multiple files in a single operation (MCP-compatible)."""
        self._check_toolset('repos')
        self._check_write_operation('push_files')
        
        if branch:
            self._ensure_branch_exists(owner, repo, branch)
        
        results = []
        for file_info in files:
            try:
                result = self.create_or_update_file(
                    owner=owner,
                    repo=repo,
                    path=file_info['path'],
                    content=file_info['content'],
                    message=f"{message} - {file_info['path']}",
                    branch=branch,
                    sha=file_info.get('sha')
                )
                results.append({
                    'path': file_info['path'],
                    'status': 'success',
                    'result': result
                })
            except Exception as e:
                results.append({
                    'path': file_info['path'],
                    'status': 'error',
                    'error': str(e)
                })
        
        return {
            'operation': 'push_files',
            'total_files': len(files),
            'successful': len([r for r in results if r['status'] == 'success']),
            'failed': len([r for r in results if r['status'] == 'error']),
            'results': results
        }
    
    def get_file_content(self, owner: str, repo: str, path: str, ref: str = 'main') -> dict:
        """Get file content."""
        self._check_toolset('repos')
        
        params = {'ref': ref}
        response = self._make_request('GET', f'/repos/{owner}/{repo}/contents/{path}', params=params)
        
        # Decode content if it's base64 encoded
        if response.get('encoding') == 'base64':
            content = base64.b64decode(response['content']).decode('utf-8')
            response['decoded_content'] = content
            
        return response
    
    def _ensure_branch_exists(self, owner: str, repo: str, branch: str):
        """Ensure branch exists, create if it doesn't (MCP feature)."""
        try:
            # Check if branch exists
            self._make_request('GET', f'/repos/{owner}/{repo}/branches/{branch}')
        except:
            # Branch doesn't exist, create it from main
            try:
                # Get main branch SHA
                main_branch = self._make_request('GET', f'/repos/{owner}/{repo}/branches/main')
                main_sha = main_branch['commit']['sha']
                
                # Create new branch
                branch_data = {
                    'ref': f'refs/heads/{branch}',
                    'sha': main_sha
                }
                self._make_request('POST', f'/repos/{owner}/{repo}/git/refs', data=branch_data)
                logger.info(f"Created branch '{branch}' from main")
            except Exception as e:
                logger.warning(f"Could not create branch '{branch}': {str(e)}")
    
    # Search operations (MCP-compatible)
    def search_code(self, query: str, repo: str = None, owner: str = None, limit: int = 30) -> dict:
        """Search code in repositories."""
        self._check_toolset('repos')
        
        search_query = query
        if repo and owner:
            search_query += f" repo:{owner}/{repo}"
        elif repo:
            search_query += f" repo:{repo}"
            
        params = {
            'q': search_query,
            'per_page': min(limit, 100)
        }
        
        response = self._make_request('GET', '/search/code', params=params)
        return {
            'code_results': response.get('items', [])[:limit],
            'total_count': response.get('total_count', 0)
        }
    
    def search_users(self, query: str, limit: int = 30) -> dict:
        """Search users."""
        params = {
            'q': query,
            'per_page': min(limit, 100)
        }
        
        response = self._make_request('GET', '/search/users', params=params)
        return {
            'users': response.get('items', [])[:limit],
            'total_count': response.get('total_count', 0)
        }
    
    # Issue operations
    def list_issues(self, owner: str, repo: str, state: str = 'open', labels: List[str] = None, 
                   assignee: str = None, limit: int = 30) -> dict:
        """List issues with enhanced filtering."""
        self._check_toolset('issues')
        
        params = {
            'state': state,
            'per_page': min(limit, 100)
        }
        
        if labels:
            params['labels'] = ','.join(labels)
        if assignee:
            params['assignee'] = assignee
            
        response = self._make_request('GET', f'/repos/{owner}/{repo}/issues', params=params)
        return {'issues': response[:limit]}
    
    def create_issue(self, owner: str, repo: str, title: str, body: str = '', 
                    labels: List[str] = None, assignees: List[str] = None) -> dict:
        """Create issue (MCP-compatible)."""
        self._check_toolset('issues')
        self._check_write_operation('create_issue')
        
        issue_data = {
            'title': title,
            'body': body
        }
        
        if labels:
            issue_data['labels'] = labels
        if assignees:
            issue_data['assignees'] = assignees
            
        return self._make_request('POST', f'/repos/{owner}/{repo}/issues', data=issue_data)
    
    def update_issue(self, owner: str, repo: str, issue_number: int, issue_data: dict) -> dict:
        """Update issue."""
        self._check_toolset('issues')
        self._check_write_operation('update_issue')
        
        return self._make_request('PATCH', f'/repos/{owner}/{repo}/issues/{issue_number}', data=issue_data)
    
    # Pull Request operations  
    def list_pull_requests(self, owner: str, repo: str, state: str = 'open', limit: int = 30) -> dict:
        """List pull requests."""
        self._check_toolset('pull_requests')
        
        params = {
            'state': state,
            'per_page': min(limit, 100)
        }
        
        response = self._make_request('GET', f'/repos/{owner}/{repo}/pulls', params=params)
        return {'pull_requests': response[:limit]}
    
    def create_pull_request(self, owner: str, repo: str, title: str, body: str, 
                           head: str, base: str = 'main', draft: bool = False) -> dict:
        """Create pull request (MCP-compatible)."""
        self._check_toolset('pull_requests')
        self._check_write_operation('create_pull_request')
        
        pr_data = {
            'title': title,
            'body': body,
            'head': head,
            'base': base,
            'draft': draft
        }
        
        return self._make_request('POST', f'/repos/{owner}/{repo}/pulls', data=pr_data)
    
    def merge_pull_request(self, owner: str, repo: str, pr_number: int, merge_method: str = 'merge') -> dict:
        """Merge pull request."""
        self._check_toolset('pull_requests')
        self._check_write_operation('merge_pull_request')
        
        merge_data = {
            'merge_method': merge_method
        }
        
        return self._make_request('PUT', f'/repos/{owner}/{repo}/pulls/{pr_number}/merge', data=merge_data)
    
    # Actions/Workflow operations (NEW)
    def list_workflow_runs(self, owner: str, repo: str, workflow_id: str = None, 
                          status: str = None, limit: int = 30) -> dict:
        """List workflow runs."""
        self._check_toolset('actions')
        
        if workflow_id:
            endpoint = f'/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs'
        else:
            endpoint = f'/repos/{owner}/{repo}/actions/runs'
            
        params = {'per_page': min(limit, 100)}
        if status:
            params['status'] = status
            
        response = self._make_request('GET', endpoint, params=params)
        return {
            'workflow_runs': response.get('workflow_runs', [])[:limit],
            'total_count': response.get('total_count', 0)
        }
    
    def get_workflow_run(self, owner: str, repo: str, run_id: int) -> dict:
        """Get workflow run details."""
        self._check_toolset('actions')
        return self._make_request('GET', f'/repos/{owner}/{repo}/actions/runs/{run_id}')
    
    def rerun_workflow(self, owner: str, repo: str, run_id: int) -> dict:
        """Rerun workflow."""
        self._check_toolset('actions')
        self._check_write_operation('rerun_workflow')
        
        return self._make_request('POST', f'/repos/{owner}/{repo}/actions/runs/{run_id}/rerun')
    
    # Security operations (NEW)
    def list_code_scanning_alerts(self, owner: str, repo: str, state: str = 'open', limit: int = 30) -> dict:
        """List code scanning alerts."""
        self._check_toolset('code_security')
        
        params = {
            'state': state,
            'per_page': min(limit, 100)
        }
        
        response = self._make_request('GET', f'/repos/{owner}/{repo}/code-scanning/alerts', params=params)
        return {'code_scanning_alerts': response[:limit]}
    
    def list_dependabot_alerts(self, owner: str, repo: str, state: str = 'open', limit: int = 30) -> dict:
        """List Dependabot alerts."""
        self._check_toolset('code_security')
        
        params = {
            'state': state,
            'per_page': min(limit, 100)
        }
        
        response = self._make_request('GET', f'/repos/{owner}/{repo}/dependabot/alerts', params=params)
        return {'dependabot_alerts': response[:limit]}
    
    def dismiss_dependabot_alert(self, owner: str, repo: str, alert_number: int, reason: str = 'no_bandwidth') -> dict:
        """Dismiss Dependabot alert."""
        self._check_toolset('code_security')
        self._check_write_operation('dismiss_dependabot_alert')
        
        dismiss_data = {
            'state': 'dismissed',
            'dismissed_reason': reason
        }
        
        return self._make_request('PATCH', f'/repos/{owner}/{repo}/dependabot/alerts/{alert_number}', data=dismiss_data)
    
    # User operations (NEW)
    def get_authenticated_user(self) -> dict:
        """Get authenticated user info (get_me)."""
        return self._make_request('GET', '/user')
    
    def get_user(self, username: str) -> dict:
        """Get user info."""
        return self._make_request('GET', f'/users/{username}')
    
    def get_organization(self, org: str) -> dict:
        """Get organization info."""
        return self._make_request('GET', f'/orgs/{org}')


# Plugin metadata for MCP compatibility
plug_metadata = {
    'name': 'github_mcp_compatible',
    'version': '1.0.0',
    'description': 'GitHub MCP-compatible plug with full GitHub API access',
    'author': 'PlugPipe Team',
    'mcp_compatible': True,
    'github_mcp_server_compatible': True
}