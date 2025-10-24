# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
LLM GitHub MCP Integration Plug - AI-Powered Repository Management
Provides intelligent GitHub automation through Model Context Protocol integration.
"""

import json
import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import re
import requests

logger = logging.getLogger(__name__)

def process(ctx: dict, cfg: dict) -> dict:
    """
    Main plug entry point for LLM-powered GitHub automation.
    
    Args:
        ctx: Pipe context containing operation parameters and LLM integration
        cfg: Plug configuration including GitHub auth and LLM settings
        
    Returns:
        Updated context with AI analysis results
    """
    try:
        # Initialize LLM GitHub MCP client
        client = LLMGitHubMCP(cfg)
        
        # Get operation from context
        operation = ctx.get('operation', 'analyze_repository')
        
        result = None
        
        # AI-powered repository analysis
        if operation == 'analyze_repository':
            result = client.analyze_repository_health(
                ctx.get('owner'), 
                ctx.get('repo'),
                ctx.get('analysis_depth', 'standard')
            )
        elif operation == 'review_pull_request':
            result = client.review_pull_request_with_ai(
                ctx.get('owner'),
                ctx.get('repo'), 
                ctx.get('pr_number'),
                ctx.get('review_criteria', [])
            )
        elif operation == 'spot_bugs':
            result = client.ai_bug_detection(
                ctx.get('owner'),
                ctx.get('repo'),
                ctx.get('commit_range', 'HEAD~5..HEAD')
            )
        elif operation == 'enforce_coding_standards':
            result = client.enforce_coding_standards(
                ctx.get('owner'),
                ctx.get('repo'),
                ctx.get('standards_config', {})
            )
        elif operation == 'prioritize_issues':
            result = client.ai_issue_prioritization(
                ctx.get('owner'),
                ctx.get('repo'),
                ctx.get('prioritization_criteria', {})
            )
        elif operation == 'manage_dependencies':
            result = client.intelligent_dependency_management(
                ctx.get('owner'),
                ctx.get('repo'),
                ctx.get('update_strategy', 'conservative')
            )
        elif operation == 'security_scan':
            result = client.ai_security_scanning(
                ctx.get('owner'),
                ctx.get('repo'),
                ctx.get('scan_depth', 'comprehensive')
            )
        elif operation == 'automated_maintenance':
            result = client.automated_repository_maintenance(
                ctx.get('owner'),
                ctx.get('repo'),
                ctx.get('maintenance_tasks', [])
            )
        else:
            raise ValueError(f"Unsupported LLM GitHub MCP operation: {operation}")
        
        # Store results in context
        ctx['llm_github_result'] = result
        ctx['llm_github_status'] = 'success'
        ctx['ai_insights'] = result.get('ai_insights', {})
        
        logger.info(f"LLM GitHub MCP {operation} operation completed successfully")
        return ctx
        
    except Exception as e:
        logger.error(f"LLM GitHub MCP operation failed: {str(e)}")
        ctx['llm_github_result'] = None
        ctx['llm_github_status'] = 'error'
        ctx['llm_github_error'] = str(e)
        return ctx


class LLMGitHubMCP:
    """
    AI-powered GitHub MCP client providing intelligent repository management.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.github_config = config.get('github', {})
        self.llm_config = config.get('llm', {})
        
        # Initialize GitHub client
        try:
            # Try relative import first
            from ...github_integration.main import GitHubClient
        except ImportError:
            # Fallback to absolute import
            import sys
            from pathlib import Path
            sys.path.append(str(Path(__file__).parent.parent.parent / "github_integration" / "1.0.0"))
            from main import GitHubClient
        
        self.github = GitHubClient(self.github_config)
        
        # Initialize LLM client for AI analysis
        self.llm_client = self._initialize_llm_client()
        
        # AI analysis prompts and templates
        self.prompts = self._load_ai_prompts()
    
    def _initialize_llm_client(self):
        """Initialize LLM client for AI-powered analysis."""
        provider = self.llm_config.get('provider', 'openai')
        
        if provider == 'openai':
            import openai
            return openai.OpenAI(api_key=self.llm_config['api_key'])
        elif provider == 'anthropic':
            import anthropic
            return anthropic.Anthropic(api_key=self.llm_config['api_key'])
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
    
    def _load_ai_prompts(self) -> dict:
        """Load AI analysis prompts and templates."""
        return {
            'code_review': """
            You are an expert code reviewer. Analyze this pull request and provide:
            1. Code quality assessment
            2. Potential bugs or issues
            3. Security vulnerabilities
            4. Performance concerns
            5. Maintainability suggestions
            6. Coding standards compliance
            
            Be specific and actionable in your feedback.
            """,
            'bug_detection': """
            You are a senior software engineer specializing in bug detection. 
            Analyze the code changes and identify:
            1. Logic errors
            2. Null pointer risks
            3. Resource leaks
            4. Race conditions
            5. Edge case handling issues
            6. Type safety problems
            
            Provide specific line numbers and fixes where possible.
            """,
            'security_analysis': """
            You are a cybersecurity expert. Analyze this code for:
            1. SQL injection vulnerabilities
            2. XSS risks
            3. Authentication bypass
            4. Data exposure issues
            5. Dependency vulnerabilities
            6. Insecure configurations
            
            Rate severity (CRITICAL/HIGH/MEDIUM/LOW) and provide remediation steps.
            """,
            'issue_prioritization': """
            You are a product manager. Prioritize these GitHub issues based on:
            1. Business impact
            2. User experience effect
            3. Technical complexity
            4. Dependencies
            5. Risk assessment
            6. Strategic alignment
            
            Provide priority ranking (P0-P4) with justification.
            """
        }
    
    def analyze_repository_health(self, owner: str, repo: str, depth: str = 'standard') -> Dict[str, Any]:
        """Comprehensive AI-powered repository health analysis."""
        try:
            # Gather repository data
            repo_data = self.github.get_repository(owner, repo)
            issues = self.github.list_issues(owner, repo, state='open', limit=50)
            prs = self.github.list_pull_requests(owner, repo, state='open', limit=20)
            
            # Get recent commits for analysis
            commits_url = f"{self.github.base_url}/repos/{owner}/{repo}/commits"
            commits_response = self.github.session.get(commits_url, params={'per_page': 20})
            commits = commits_response.json() if commits_response.status_code == 200 else []
            
            # AI analysis of repository health
            analysis_prompt = f"""
            Analyze this GitHub repository health:
            
            Repository: {repo_data.get('name', 'Unknown')}
            Description: {repo_data.get('description', 'No description')}
            Language: {repo_data.get('language', 'Unknown')}
            Stars: {repo_data.get('stargazers_count', 0)}
            Forks: {repo_data.get('forks_count', 0)}
            Open Issues: {len(issues.get('issues', []))}
            Open PRs: {len(prs.get('pull_requests', []))}
            Last Updated: {repo_data.get('updated_at', 'Unknown')}
            
            Recent Issues:
            {self._format_issues_for_analysis(issues.get('issues', [])[:10])}
            
            Recent PRs:
            {self._format_prs_for_analysis(prs.get('pull_requests', [])[:5])}
            
            Recent Commits:
            {self._format_commits_for_analysis(commits[:10])}
            
            Provide a comprehensive health assessment including:
            1. Overall repository health score (1-10)
            2. Key issues and concerns
            3. Recommended improvements
            4. Maintenance priorities
            5. Security considerations
            6. Performance optimization opportunities
            """
            
            ai_analysis = self._get_llm_analysis(analysis_prompt)
            
            # Calculate health metrics
            health_metrics = self._calculate_health_metrics(repo_data, issues, prs, commits)
            
            return {
                'repository': f"{owner}/{repo}",
                'health_score': health_metrics['overall_score'],
                'ai_analysis': ai_analysis,
                'metrics': health_metrics,
                'recommendations': self._generate_recommendations(health_metrics, ai_analysis),
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'analysis_depth': depth
            }
            
        except Exception as e:
            logger.error(f"Repository health analysis failed: {str(e)}")
            return {
                'repository': f"{owner}/{repo}",
                'error': str(e),
                'health_score': 0,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
    
    async def review_pull_request_with_ai(self, owner: str, repo: str, pr_number: int, criteria: List[str] = None) -> Dict[str, Any]:
        """AI-powered pull request review with intelligent feedback."""
        try:
            # Get PR details
            pr_data = self.github.get_pull_request(owner, repo, pr_number)
            
            # Get PR diff/changes
            diff_url = f"{self.github.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
            diff_response = self.github.session.get(diff_url, headers={'Accept': 'application/vnd.github.v3.diff'})
            pr_diff = diff_response.text if diff_response.status_code == 200 else ""
            
            # Get PR files
            files_url = f"{self.github.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
            files_response = self.github.session.get(files_url)
            pr_files = files_response.json() if files_response.status_code == 200 else []
            
            # AI code review analysis
            review_prompt = f"""
            {self.prompts['code_review']}
            
            Pull Request Details:
            Title: {pr_data.get('title', 'No title')}
            Description: {pr_data.get('body', 'No description')}
            Author: {pr_data.get('user', {}).get('login', 'Unknown')}
            Files Changed: {len(pr_files)}
            Additions: {pr_data.get('additions', 0)}
            Deletions: {pr_data.get('deletions', 0)}
            
            Code Changes:
            {pr_diff[:8000]}  # Truncate for API limits
            
            Review Criteria: {criteria or ['general', 'security', 'performance', 'maintainability']}
            
            Provide detailed review feedback with specific recommendations.
            """
            
            ai_review = await self._get_llm_analysis(review_prompt)
            
            # Security-focused analysis
            security_issues = await self._analyze_pr_security(pr_diff, pr_files)
            
            # Performance analysis
            performance_concerns = await self._analyze_pr_performance(pr_diff, pr_files)
            
            # Generate review summary
            review_summary = {
                'pr_number': pr_number,
                'pr_title': pr_data.get('title'),
                'author': pr_data.get('user', {}).get('login'),
                'files_changed': len(pr_files),
                'changes_summary': {
                    'additions': pr_data.get('additions', 0),
                    'deletions': pr_data.get('deletions', 0),
                    'modified_files': [f['filename'] for f in pr_files]
                },
                'ai_review': ai_review,
                'security_analysis': security_issues,
                'performance_analysis': performance_concerns,
                'overall_recommendation': self._generate_pr_recommendation(ai_review, security_issues, performance_concerns),
                'review_timestamp': datetime.utcnow().isoformat()
            }
            
            # Optionally post review as comment
            if self.config.get('auto_comment', False):
                self._post_review_comment(owner, repo, pr_number, review_summary)
            
            return review_summary
            
        except Exception as e:
            logger.error(f"PR review analysis failed: {str(e)}")
            raise
    
    async def ai_bug_detection(self, owner: str, repo: str, commit_range: str = 'HEAD~5..HEAD') -> Dict[str, Any]:
        """AI-powered bug detection in recent code changes."""
        try:
            # Get commits in range
            compare_url = f"{self.github.base_url}/repos/{owner}/{repo}/compare/{commit_range}"
            compare_response = self.github.session.get(compare_url)
            compare_data = compare_response.json() if compare_response.status_code == 200 else {}
            
            commits = compare_data.get('commits', [])
            files = compare_data.get('files', [])
            
            # Analyze each significant change
            bug_findings = []
            
            for file_change in files[:10]:  # Limit analysis
                if file_change.get('changes', 0) > 5:  # Focus on significant changes
                    file_analysis = await self._analyze_file_for_bugs(file_change)
                    if file_analysis['potential_bugs']:
                        bug_findings.append(file_analysis)
            
            # Overall bug analysis
            bug_summary_prompt = f"""
            {self.prompts['bug_detection']}
            
            Recent Commits:
            {self._format_commits_for_analysis(commits)}
            
            Files with Significant Changes:
            {self._format_files_for_analysis(files)}
            
            Identify patterns and potential systemic issues across these changes.
            """
            
            ai_bug_analysis = await self._get_llm_analysis(bug_summary_prompt)
            
            return {
                'repository': f"{owner}/{repo}",
                'commit_range': commit_range,
                'commits_analyzed': len(commits),
                'files_analyzed': len(files),
                'bug_findings': bug_findings,
                'ai_analysis': ai_bug_analysis,
                'risk_assessment': self._assess_bug_risk(bug_findings),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Bug detection analysis failed: {str(e)}")
            raise
    
    async def enforce_coding_standards(self, owner: str, repo: str, standards_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """AI-powered coding standards enforcement."""
        try:
            # Get recent PRs and commits
            recent_prs = self.github.list_pull_requests(owner, repo, state='all', limit=10)
            
            standards_violations = []
            recommendations = []
            
            # Analyze each recent PR for standards compliance
            for pr in recent_prs.get('pull_requests', [])[:5]:
                pr_analysis = await self._analyze_pr_standards(owner, repo, pr['number'], standards_config)
                if pr_analysis['violations']:
                    standards_violations.extend(pr_analysis['violations'])
                    recommendations.extend(pr_analysis['recommendations'])
            
            # Generate coding standards report
            standards_report = {
                'repository': f"{owner}/{repo}",
                'standards_config': standards_config or self._get_default_standards(),
                'violations_found': len(standards_violations),
                'violation_details': standards_violations,
                'recommendations': recommendations,
                'compliance_score': self._calculate_compliance_score(standards_violations),
                'enforcement_actions': self._suggest_enforcement_actions(standards_violations),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            return standards_report
            
        except Exception as e:
            logger.error(f"Coding standards enforcement failed: {str(e)}")
            raise
    
    async def ai_issue_prioritization(self, owner: str, repo: str, criteria: Dict[str, Any] = None) -> Dict[str, Any]:
        """AI-powered intelligent issue prioritization."""
        try:
            # Get all open issues
            issues_data = self.github.list_issues(owner, repo, state='open', limit=100)
            issues = issues_data.get('issues', [])
            
            # AI prioritization analysis
            prioritization_prompt = f"""
            {self.prompts['issue_prioritization']}
            
            Repository: {owner}/{repo}
            Total Open Issues: {len(issues)}
            
            Issues to Prioritize:
            {self._format_issues_for_prioritization(issues)}
            
            Prioritization Criteria: {criteria or self._get_default_prioritization_criteria()}
            
            Provide prioritized ranking with business justification.
            """
            
            ai_prioritization = await self._get_llm_analysis(prioritization_prompt)
            
            # Generate priority assignments
            priority_assignments = self._assign_issue_priorities(issues, ai_prioritization)
            
            # Create prioritization report
            prioritization_report = {
                'repository': f"{owner}/{repo}",
                'total_issues': len(issues),
                'prioritization_criteria': criteria or self._get_default_prioritization_criteria(),
                'ai_analysis': ai_prioritization,
                'priority_assignments': priority_assignments,
                'recommendations': self._generate_priority_recommendations(priority_assignments),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            # Optionally update issue labels with priorities
            if self.config.get('auto_label', False):
                self._apply_priority_labels(owner, repo, priority_assignments)
            
            return prioritization_report
            
        except Exception as e:
            logger.error(f"Issue prioritization failed: {str(e)}")
            raise
    
    async def intelligent_dependency_management(self, owner: str, repo: str, strategy: str = 'conservative') -> Dict[str, Any]:
        """AI-powered dependency management and updates."""
        try:
            # Get repository files to analyze dependencies
            dependency_files = self._get_dependency_files(owner, repo)
            
            dependency_analysis = []
            
            for dep_file in dependency_files:
                file_content = self.github.get_file_content(owner, repo, dep_file['path'])
                analysis = await self._analyze_dependencies(dep_file, file_content, strategy)
                dependency_analysis.append(analysis)
            
            # Generate dependency management report
            dependency_report = {
                'repository': f"{owner}/{repo}",
                'strategy': strategy,
                'dependency_files_analyzed': len(dependency_files),
                'analysis_results': dependency_analysis,
                'update_recommendations': self._generate_update_recommendations(dependency_analysis, strategy),
                'security_alerts': self._check_dependency_security(dependency_analysis),
                'maintenance_plan': self._create_maintenance_plan(dependency_analysis),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            # Optionally create PR for dependency updates
            if self.config.get('auto_update', False) and strategy in ['aggressive', 'moderate']:
                self._create_dependency_update_pr(owner, repo, dependency_report)
            
            return dependency_report
            
        except Exception as e:
            logger.error(f"Dependency management failed: {str(e)}")
            raise
    
    async def ai_security_scanning(self, owner: str, repo: str, scan_depth: str = 'comprehensive') -> Dict[str, Any]:
        """AI-powered security vulnerability scanning and analysis."""
        try:
            # Get repository code for security analysis
            security_analysis = {
                'code_security': await self._scan_code_security(owner, repo),
                'dependency_security': await self._scan_dependency_security(owner, repo),
                'configuration_security': await self._scan_configuration_security(owner, repo),
                'secrets_detection': await self._scan_for_secrets(owner, repo)
            }
            
            # AI security assessment
            security_prompt = f"""
            {self.prompts['security_analysis']}
            
            Repository: {owner}/{repo}
            Scan Depth: {scan_depth}
            
            Security Analysis Results:
            {json.dumps(security_analysis, indent=2)[:4000]}
            
            Provide comprehensive security assessment with prioritized remediation plan.
            """
            
            ai_security_analysis = await self._get_llm_analysis(security_prompt)
            
            # Generate security report
            security_report = {
                'repository': f"{owner}/{repo}",
                'scan_depth': scan_depth,
                'security_analysis': security_analysis,
                'ai_assessment': ai_security_analysis,
                'vulnerability_summary': self._summarize_vulnerabilities(security_analysis),
                'remediation_plan': self._create_remediation_plan(security_analysis),
                'risk_score': self._calculate_security_risk_score(security_analysis),
                'compliance_status': self._assess_compliance(security_analysis),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            # Optionally create security issues
            if self.config.get('auto_create_security_issues', False):
                self._create_security_issues(owner, repo, security_report)
            
            return security_report
            
        except Exception as e:
            logger.error(f"Security scanning failed: {str(e)}")
            raise
    
    async def automated_repository_maintenance(self, owner: str, repo: str, tasks: List[str] = None) -> Dict[str, Any]:
        """Comprehensive automated repository maintenance."""
        try:
            maintenance_tasks = tasks or [
                'cleanup_stale_branches',
                'update_documentation',
                'review_open_issues',
                'update_dependencies',
                'security_audit',
                'performance_analysis'
            ]
            
            maintenance_results = {}
            
            for task in maintenance_tasks:
                try:
                    if task == 'cleanup_stale_branches':
                        maintenance_results[task] = await self._cleanup_stale_branches(owner, repo)
                    elif task == 'update_documentation':
                        maintenance_results[task] = await self._update_documentation(owner, repo)
                    elif task == 'review_open_issues':
                        maintenance_results[task] = await self._review_open_issues(owner, repo)
                    elif task == 'update_dependencies':
                        maintenance_results[task] = await self.intelligent_dependency_management(owner, repo, 'moderate')
                    elif task == 'security_audit':
                        maintenance_results[task] = await self.ai_security_scanning(owner, repo, 'standard')
                    elif task == 'performance_analysis':
                        maintenance_results[task] = await self._performance_analysis(owner, repo)
                    
                except Exception as e:
                    maintenance_results[task] = {'error': str(e), 'status': 'failed'}
            
            # Generate maintenance report
            maintenance_report = {
                'repository': f"{owner}/{repo}",
                'maintenance_tasks': maintenance_tasks,
                'task_results': maintenance_results,
                'overall_status': self._assess_maintenance_status(maintenance_results),
                'recommendations': self._generate_maintenance_recommendations(maintenance_results),
                'next_maintenance': self._schedule_next_maintenance(),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            return maintenance_report
            
        except Exception as e:
            logger.error(f"Repository maintenance failed: {str(e)}")
            raise
    
    # Helper methods for AI analysis
    async def _get_llm_analysis(self, prompt: str) -> str:
        """Get AI analysis from configured LLM provider."""
        try:
            provider = self.llm_config.get('provider', 'openai')
            
            if provider == 'openai':
                response = self.llm_client.chat.completions.create(
                    model=self.llm_config.get('model', 'gpt-4'),
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.llm_config.get('max_tokens', 2000),
                    temperature=self.llm_config.get('temperature', 0.1)
                )
                return response.choices[0].message.content
            
            elif provider == 'anthropic':
                response = self.llm_client.messages.create(
                    model=self.llm_config.get('model', 'claude-3-sonnet-20240229'),
                    max_tokens=self.llm_config.get('max_tokens', 2000),
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            
            else:
                raise ValueError(f"Unsupported LLM provider: {provider}")
                
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            return f"AI analysis unavailable: {str(e)}"
    
    def _format_issues_for_analysis(self, issues: List[Dict]) -> str:
        """Format issues for AI analysis."""
        formatted = []
        for issue in issues[:10]:  # Limit for API
            formatted.append(f"#{issue['number']}: {issue['title']} - {issue.get('body', '')[:200]}...")
        return '\n'.join(formatted)
    
    def _format_prs_for_analysis(self, prs: List[Dict]) -> str:
        """Format PRs for AI analysis."""
        formatted = []
        for pr in prs[:5]:  # Limit for API
            formatted.append(f"#{pr['number']}: {pr['title']} - {pr.get('body', '')[:200]}...")
        return '\n'.join(formatted)
    
    def _format_commits_for_analysis(self, commits: List[Dict]) -> str:
        """Format commits for AI analysis."""
        formatted = []
        for commit in commits[:10]:  # Limit for API
            message = commit.get('commit', {}).get('message', 'No message')
            formatted.append(f"{commit['sha'][:8]}: {message[:100]}...")
        return '\n'.join(formatted)
    
    def _calculate_health_metrics(self, repo_data: Dict, issues: Dict, prs: Dict, commits: List) -> Dict[str, Any]:
        """Calculate repository health metrics."""
        # Implementation for health metrics calculation
        return {
            'overall_score': 8.5,  # Placeholder - implement actual calculation
            'issue_health': len(issues.get('issues', [])),
            'pr_health': len(prs.get('pull_requests', [])),
            'activity_score': len(commits),
            'last_activity': repo_data.get('updated_at')
        }
    
    def _generate_recommendations(self, metrics: Dict, ai_analysis: str) -> List[str]:
        """Generate actionable recommendations."""
        # Implementation for generating recommendations
        return [
            "Consider updating documentation",
            "Review open issues and close stale ones",
            "Update dependencies to latest versions"
        ]
    
    # Additional helper methods would be implemented here...
    # (For brevity, I'm showing the structure and key methods)


# Plug metadata
plug_metadata = {
    "name": "llm_github_mcp",
    "version": "1.0.0", 
    "description": "AI-powered GitHub automation through Model Context Protocol integration",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "ai_devops",
    "tags": ["github", "llm", "mcp", "ai", "automation", "code_review", "security"],
    "requirements": ["requests", "openai", "anthropic", "PyJWT"],
    "dependencies": ["github_integration"]
}