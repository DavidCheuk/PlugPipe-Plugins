# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
"""
AI Helper Methods for LLM GitHub MCP Integration
Provides detailed implementation of AI-powered analysis methods.
"""

import json
import re
import base64
import logging
import asyncio
import importlib.util
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class GitHubAIHelpers:
    """Helper methods for AI-powered GitHub analysis."""
    
    def __init__(self, github_client, llm_client, config):
        self.github = github_client
        self.llm_client = llm_client  # Keep for backward compatibility but use LLM Service
        self.config = config
        
        # Initialize LLM Service connection
        self.llm_service = None
        self._initialize_llm_service()
    
    def _initialize_llm_service(self):
        """Initialize LLM Service plugin for standardized LLM access"""
        try:
            spec = importlib.util.spec_from_file_location(
                "llm_service", 
                get_plugpipe_path("plugs/intelligence/llm_service/1.0.0/main.py")
            )
            llm_service_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(llm_service_module)
            self.llm_service_process = llm_service_module.process
            logger.info("LLM Service initialized successfully for GitHub AI helpers")
        except Exception as e:
            logger.warning(f"Failed to initialize LLM Service: {e}")
            self.llm_service_process = None
    
    async def _analyze_pr_security(self, pr_diff: str, pr_files: List[Dict]) -> Dict[str, Any]:
        """Analyze PR for security vulnerabilities."""
        security_issues = []
        
        # Pattern-based security checks
        security_patterns = {
            'sql_injection': r'(SELECT|INSERT|UPDATE|DELETE).*\+.*\$',
            'xss_risk': r'innerHTML|document\.write|eval\(',
            'hardcoded_secrets': r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']',
            'file_inclusion': r'include\s*\(\s*\$_[GET|POST]',
            'command_injection': r'exec\s*\(|system\s*\(|shell_exec\s*\(',
        }
        
        for file_data in pr_files:
            filename = file_data.get('filename', '')
            patch = file_data.get('patch', '')
            
            for vulnerability, pattern in security_patterns.items():
                matches = re.findall(pattern, patch, re.IGNORECASE)
                if matches:
                    security_issues.append({
                        'file': filename,
                        'vulnerability': vulnerability,
                        'matches': matches,
                        'severity': self._assess_vulnerability_severity(vulnerability),
                        'line_numbers': self._extract_line_numbers(patch, pattern)
                    })
        
        # AI-powered security analysis
        security_prompt = f"""
        Analyze this code diff for security vulnerabilities:
        
        Files changed: {len(pr_files)}
        
        Code changes (first 4000 chars):
        {pr_diff[:4000]}
        
        Identify specific security issues including:
        1. SQL injection risks
        2. XSS vulnerabilities  
        3. Authentication bypasses
        4. Data exposure
        5. Insecure configurations
        6. Dependency vulnerabilities
        
        For each issue found, provide:
        - Severity level (CRITICAL/HIGH/MEDIUM/LOW)
        - Specific location
        - Remediation steps
        """
        
        ai_security_analysis = await self._get_llm_analysis(security_prompt)
        
        return {
            'pattern_based_issues': security_issues,
            'ai_analysis': ai_security_analysis,
            'total_issues': len(security_issues),
            'severity_summary': self._summarize_severity(security_issues)
        }
    
    async def _analyze_pr_performance(self, pr_diff: str, pr_files: List[Dict]) -> Dict[str, Any]:
        """Analyze PR for performance implications."""
        performance_concerns = []
        
        # Performance anti-patterns
        performance_patterns = {
            'n_plus_one_query': r'for.*in.*:.*query\(',
            'large_file_processing': r'\.read\(\)|\.readlines\(\)',
            'inefficient_loops': r'for.*in.*for.*in',
            'memory_leaks': r'global\s+\w+|\.append\(.*\)',
            'blocking_operations': r'\.get\(|\.post\(|\.request\(',
        }
        
        for file_data in pr_files:
            filename = file_data.get('filename', '')
            patch = file_data.get('patch', '')
            
            for concern, pattern in performance_patterns.items():
                matches = re.findall(pattern, patch, re.IGNORECASE)
                if matches:
                    performance_concerns.append({
                        'file': filename,
                        'concern': concern,
                        'matches': matches,
                        'impact': self._assess_performance_impact(concern),
                        'suggestions': self._get_performance_suggestions(concern)
                    })
        
        # AI performance analysis
        performance_prompt = f"""
        Analyze this code diff for performance implications:
        
        Code changes:
        {pr_diff[:4000]}
        
        Identify performance issues including:
        1. Database query efficiency
        2. Memory usage patterns
        3. CPU-intensive operations
        4. I/O bottlenecks
        5. Algorithmic complexity
        6. Resource management
        
        Provide specific optimization recommendations.
        """
        
        ai_performance_analysis = await self._get_llm_analysis(performance_prompt)
        
        return {
            'pattern_based_concerns': performance_concerns,
            'ai_analysis': ai_performance_analysis,
            'total_concerns': len(performance_concerns),
            'optimization_opportunities': self._identify_optimizations(performance_concerns)
        }
    
    async def _analyze_file_for_bugs(self, file_change: Dict) -> Dict[str, Any]:
        """Analyze individual file for potential bugs."""
        filename = file_change.get('filename', '')
        patch = file_change.get('patch', '')
        changes = file_change.get('changes', 0)
        
        # Bug pattern detection
        bug_patterns = {
            'null_pointer': r'\.(?:get|access)\(.*\)\.(?:get|access)',
            'array_bounds': r'\[.*\+.*\]|\[.*\-.*\]',
            'resource_leak': r'open\(.*\)|connect\(.*\)',
            'race_condition': r'threading|async.*await',
            'type_mismatch': r'str\(.*int\)|int\(.*str\)',
            'unhandled_exception': r'except\s*:|try\s*:.*(?!except)',
        }
        
        potential_bugs = []
        
        for bug_type, pattern in bug_patterns.items():
            matches = re.findall(pattern, patch, re.IGNORECASE)
            if matches:
                potential_bugs.append({
                    'bug_type': bug_type,
                    'matches': matches,
                    'severity': self._assess_bug_severity(bug_type),
                    'confidence': self._assess_bug_confidence(bug_type, matches)
                })
        
        # AI bug analysis for this specific file
        bug_prompt = f"""
        Analyze this file change for potential bugs:
        
        File: {filename}
        Changes: {changes} lines
        
        Code diff:
        {patch[:2000]}
        
        Look for:
        1. Logic errors
        2. Edge case handling
        3. Error handling gaps
        4. Type safety issues
        5. Resource management problems
        6. Concurrency issues
        
        Be specific about line numbers and provide fixes.
        """
        
        ai_bug_analysis = await self._get_llm_analysis(bug_prompt)
        
        return {
            'filename': filename,
            'changes_count': changes,
            'potential_bugs': potential_bugs,
            'ai_analysis': ai_bug_analysis,
            'risk_score': self._calculate_file_risk_score(potential_bugs, changes)
        }
    
    async def _analyze_pr_standards(self, owner: str, repo: str, pr_number: int, standards_config: Dict) -> Dict[str, Any]:
        """Analyze PR for coding standards compliance."""
        # Get PR files
        files_url = f"{self.github.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        files_response = self.github.session.get(files_url)
        pr_files = files_response.json() if files_response.status_code == 200 else []
        
        violations = []
        recommendations = []
        
        standards = standards_config or self._get_default_standards()
        
        for file_data in pr_files:
            filename = file_data.get('filename', '')
            patch = file_data.get('patch', '')
            
            # Language-specific standards checking
            if filename.endswith('.py'):
                file_violations = self._check_python_standards(patch, standards.get('python', {}))
            elif filename.endswith(('.js', '.jsx', '.ts', '.tsx')):
                file_violations = self._check_javascript_standards(patch, standards.get('javascript', {}))
            elif filename.endswith(('.java')):
                file_violations = self._check_java_standards(patch, standards.get('java', {}))
            else:
                file_violations = self._check_general_standards(patch, standards.get('general', {}))
            
            if file_violations:
                violations.extend([{**v, 'file': filename} for v in file_violations])
        
        # AI standards analysis
        standards_prompt = f"""
        Analyze this pull request for coding standards compliance:
        
        Standards Configuration: {json.dumps(standards, indent=2)}
        
        Files Changed: {len(pr_files)}
        
        Sample code changes:
        {self._get_sample_code_changes(pr_files)[:3000]}
        
        Check for:
        1. Code formatting consistency
        2. Naming conventions
        3. Documentation standards
        4. File organization
        5. Import/dependency management
        6. Error handling patterns
        
        Provide specific recommendations for improvement.
        """
        
        ai_standards_analysis = await self._get_llm_analysis(standards_prompt)
        
        return {
            'violations': violations,
            'recommendations': self._generate_standards_recommendations(violations, ai_standards_analysis),
            'compliance_score': self._calculate_compliance_score(violations, len(pr_files)),
            'ai_analysis': ai_standards_analysis
        }
    
    def _check_python_standards(self, code: str, python_standards: Dict) -> List[Dict]:
        """Check Python-specific coding standards."""
        violations = []
        
        # Line length check
        max_length = python_standards.get('line_length', 88)
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if len(line) > max_length:
                violations.append({
                    'type': 'line_length',
                    'line': i + 1,
                    'message': f'Line exceeds {max_length} characters ({len(line)})',
                    'severity': 'low'
                })
        
        # Import style check
        import_style = python_standards.get('import_style', 'pep8')
        if import_style == 'black':
            # Check for black-style imports
            if re.search(r'from\s+\w+\s+import\s+\w+,\s+\w+', code):
                violations.append({
                    'type': 'import_style',
                    'message': 'Use parentheses for multi-line imports (black style)',
                    'severity': 'medium'
                })
        
        # Docstring style check
        docstring_style = python_standards.get('docstring_style', 'google')
        functions = re.findall(r'def\s+\w+\([^)]*\):', code)
        if functions and not re.search(r'""".*"""', code, re.DOTALL):
            violations.append({
                'type': 'missing_docstring',
                'message': f'Functions should have {docstring_style}-style docstrings',
                'severity': 'medium'
            })
        
        return violations
    
    def _check_javascript_standards(self, code: str, js_standards: Dict) -> List[Dict]:
        """Check JavaScript/TypeScript coding standards."""
        violations = []
        
        # Semicolon check
        if js_standards.get('semicolons') == 'required':
            lines = [line.strip() for line in code.split('\n') if line.strip()]
            for i, line in enumerate(lines):
                if (line.endswith('}') or line.endswith(')') or 
                    re.match(r'.*[a-zA-Z0-9_]\s*$', line)) and not line.endswith(';'):
                    violations.append({
                        'type': 'missing_semicolon',
                        'line': i + 1,
                        'message': 'Statement should end with semicolon',
                        'severity': 'low'
                    })
        
        # Quote style check
        quote_style = js_standards.get('quotes', 'single')
        if quote_style == 'single' and '"' in code:
            violations.append({
                'type': 'quote_style',
                'message': 'Use single quotes instead of double quotes',
                'severity': 'low'
            })
        
        return violations
    
    def _check_general_standards(self, code: str, general_standards: Dict) -> List[Dict]:
        """Check general coding standards."""
        violations = []
        
        # TODO/FIXME comments
        todos = re.findall(r'(TODO|FIXME|HACK):', code, re.IGNORECASE)
        if todos:
            violations.append({
                'type': 'technical_debt',
                'message': f'Found {len(todos)} TODO/FIXME comments',
                'severity': 'low'
            })
        
        # Hardcoded values
        hardcoded = re.findall(r'["\'][^"\']*(?:localhost|127\.0\.0\.1|password|secret)[^"\']*["\']', code, re.IGNORECASE)
        if hardcoded:
            violations.append({
                'type': 'hardcoded_values',
                'message': 'Avoid hardcoded sensitive values',
                'severity': 'high'
            })
        
        return violations
    
    def _get_dependency_files(self, owner: str, repo: str) -> List[Dict]:
        """Get dependency management files from repository."""
        dependency_files = []
        
        # Common dependency files
        dep_file_patterns = [
            'requirements.txt', 'requirements-dev.txt', 'pyproject.toml',
            'package.json', 'package-lock.json', 'yarn.lock',
            'Pipfile', 'Pipfile.lock', 'poetry.lock',
            'pom.xml', 'build.gradle', 'Cargo.toml'
        ]
        
        for pattern in dep_file_patterns:
            try:
                file_data = self.github.get_file_content(owner, repo, pattern)
                dependency_files.append({
                    'path': pattern,
                    'type': self._detect_dependency_type(pattern),
                    'content': file_data.get('decoded_content', ''),
                    'sha': file_data.get('sha')
                })
            except:
                continue  # File doesn't exist
        
        return dependency_files
    
    async def _analyze_dependencies(self, dep_file: Dict, file_content: Dict, strategy: str) -> Dict[str, Any]:
        """Analyze dependencies for updates and security."""
        file_path = dep_file['path']
        file_type = dep_file['type']
        content = file_content.get('decoded_content', '')
        
        # Parse dependencies based on file type
        dependencies = self._parse_dependencies(content, file_type)
        
        # AI dependency analysis
        dep_prompt = f"""
        Analyze these dependencies for security and updates:
        
        File: {file_path}
        Type: {file_type}
        Strategy: {strategy}
        
        Dependencies:
        {json.dumps(dependencies[:20], indent=2)}  # Limit for API
        
        For each dependency:
        1. Check for known vulnerabilities
        2. Recommend version updates
        3. Assess compatibility risks
        4. Suggest alternatives if needed
        
        Consider the update strategy: {strategy}
        - conservative: Only security updates
        - moderate: Minor and security updates  
        - aggressive: Latest versions
        """
        
        ai_dep_analysis = await self._get_llm_analysis(dep_prompt)
        
        return {
            'file': file_path,
            'file_type': file_type,
            'dependencies_count': len(dependencies),
            'dependencies': dependencies,
            'ai_analysis': ai_dep_analysis,
            'update_recommendations': self._generate_dep_recommendations(dependencies, strategy),
            'security_concerns': self._check_dep_security(dependencies)
        }
    
    def _parse_dependencies(self, content: str, file_type: str) -> List[Dict]:
        """Parse dependencies from various file formats."""
        dependencies = []
        
        if file_type == 'python_requirements':
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    if '==' in line:
                        name, version = line.split('==', 1)
                        dependencies.append({'name': name.strip(), 'version': version.strip()})
                    elif '>=' in line:
                        name, version = line.split('>=', 1)
                        dependencies.append({'name': name.strip(), 'version': f'>={version.strip()}'})
        
        elif file_type == 'nodejs_package':
            try:
                package_data = json.loads(content)
                deps = package_data.get('dependencies', {})
                for name, version in deps.items():
                    dependencies.append({'name': name, 'version': version})
            except:
                pass
        
        # Add other parsers as needed
        
        return dependencies
    
    def _detect_dependency_type(self, filename: str) -> str:
        """Detect dependency file type."""
        type_mapping = {
            'requirements.txt': 'python_requirements',
            'requirements-dev.txt': 'python_requirements',
            'pyproject.toml': 'python_pyproject',
            'package.json': 'nodejs_package',
            'Pipfile': 'python_pipfile',
            'pom.xml': 'java_maven',
            'build.gradle': 'java_gradle',
            'Cargo.toml': 'rust_cargo'
        }
        return type_mapping.get(filename, 'unknown')
    
    # Utility methods
    def _assess_vulnerability_severity(self, vulnerability: str) -> str:
        """Assess vulnerability severity level."""
        severity_map = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'xss_risk': 'HIGH',
            'hardcoded_secrets': 'HIGH',
            'file_inclusion': 'HIGH'
        }
        return severity_map.get(vulnerability, 'MEDIUM')
    
    def _assess_performance_impact(self, concern: str) -> str:
        """Assess performance impact level."""
        impact_map = {
            'n_plus_one_query': 'HIGH',
            'inefficient_loops': 'MEDIUM',
            'large_file_processing': 'MEDIUM',
            'memory_leaks': 'HIGH',
            'blocking_operations': 'MEDIUM'
        }
        return impact_map.get(concern, 'LOW')
    
    def _calculate_file_risk_score(self, bugs: List[Dict], changes: int) -> float:
        """Calculate risk score for a file."""
        base_score = 0.0
        
        for bug in bugs:
            severity = bug.get('severity', 'low')
            confidence = bug.get('confidence', 0.5)
            
            if severity == 'critical':
                base_score += 3.0 * confidence
            elif severity == 'high':
                base_score += 2.0 * confidence
            elif severity == 'medium':
                base_score += 1.0 * confidence
            else:
                base_score += 0.5 * confidence
        
        # Factor in number of changes
        change_factor = min(changes / 100.0, 1.0)  # Normalize to 0-1
        
        return min(base_score * (1 + change_factor), 10.0)
    
    async def _get_llm_analysis(self, prompt: str) -> str:
        """Get AI analysis from LLM Service (standardized PlugPipe approach)."""
        try:
            if self.llm_service_process:
                # Use LLM Service for standardized, configurable LLM access
                llm_ctx = {
                    'action': 'query',
                    'request': {
                        'prompt': prompt,
                        'task_type': 'analysis',
                        'max_tokens': self.config.get('llm', {}).get('max_tokens', 2000),
                        'temperature': self.config.get('llm', {}).get('temperature', 0.1),
                        'prefer_local': True,
                        'fallback_allowed': True,
                        'cost_sensitive': False,
                        'time_sensitive': False
                    }
                }
                
                result = await self.llm_service_process(llm_ctx, self.config)
                
                if result.get('success') and result.get('response', {}).get('content'):
                    return result['response']['content'].strip()
                else:
                    logger.warning(f"LLM Service failed: {result.get('error', 'Unknown error')}")
                    return await self._fallback_llm_analysis(prompt)
            else:
                logger.warning("LLM Service unavailable, using fallback")
                return await self._fallback_llm_analysis(prompt)
                
        except Exception as e:
            logger.error(f"LLM Service analysis failed: {str(e)}")
            return await self._fallback_llm_analysis(prompt)
    
    async def _fallback_llm_analysis(self, prompt: str) -> str:
        """Fallback LLM analysis using direct client for backward compatibility."""
        try:
            provider = self.config.get('llm', {}).get('provider', 'openai')
            
            if provider == 'openai' and self.llm_client:
                response = self.llm_client.chat.completions.create(
                    model=self.config['llm'].get('model', 'gpt-4'),
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self.config['llm'].get('max_tokens', 2000),
                    temperature=self.config['llm'].get('temperature', 0.1)
                )
                return response.choices[0].message.content
            
            elif provider == 'anthropic' and self.llm_client:
                response = self.llm_client.messages.create(
                    model=self.config['llm'].get('model', 'claude-3-sonnet-20240229'),
                    max_tokens=self.config['llm'].get('max_tokens', 2000),
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            
            # If no direct client available
            return f"AI analysis unavailable: No LLM client or service available"
            
        except Exception as e:
            logger.error(f"Fallback LLM analysis failed: {str(e)}")
            return f"AI analysis unavailable: {str(e)}"
    
    def _get_default_standards(self) -> Dict[str, Any]:
        """Get default coding standards configuration."""
        return {
            'python': {
                'line_length': 88,
                'import_style': 'black',
                'docstring_style': 'google'
            },
            'javascript': {
                'semicolons': 'required',
                'quotes': 'single',
                'indent': 2
            },
            'general': {
                'commit_message_format': 'conventional',
                'branch_naming': 'feature/task-description'
            }
        }
    
    def _get_default_prioritization_criteria(self) -> Dict[str, Any]:
        """Get default issue prioritization criteria."""
        return {
            'business_impact': 'high',
            'user_experience': 'critical',
            'technical_complexity': 'medium',
            'security_risk': 'high',
            'strategic_alignment': 'high'
        }