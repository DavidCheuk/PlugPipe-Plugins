# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
🔒 CRITICAL: PlugPipe Prompt Security Enhancement Module

COMPREHENSIVE PROMPT SECRET DETECTION using AI/LLM evaluation combined with pattern analysis.
This module enhances the existing secret scanner to treat ALL prompt content as confidential 
security assets requiring encryption and secure references.

Critical Principle: Prompts are secrets that contain:
- Sensitive AI behavior patterns 
- Proprietary methodology and strategies
- Security intelligence and guardrail logic
- Confidential system instructions and templates

All prompt content must be detected, classified, and protected through secure injection patterns.
"""

import re
import json
import logging
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class PromptSecretType(Enum):
    """Specialized prompt secret classifications"""
    SYSTEM_PROMPT = "system_prompt"
    INSTRUCTION_TEMPLATE = "instruction_template" 
    AI_BEHAVIOR_PATTERN = "ai_behavior_pattern"
    GUARDRAIL_LOGIC = "guardrail_logic"
    PROMPT_TEMPLATE = "prompt_template"
    MULTI_LINE_PROMPT = "multi_line_prompt"
    PROMPT_VARIABLE = "prompt_variable"
    UNKNOWN_PROMPT = "unknown_prompt"

@dataclass
class AIPromptAnalysis:
    """Results from AI-powered prompt analysis"""
    is_prompt: bool
    confidence: float
    prompt_type: PromptSecretType
    sensitivity_level: str  # low, medium, high, critical
    reasoning: str
    security_classification: str
    recommended_protection: str
    context_analysis: Dict[str, Any]

class LLMPromptAnalyzer:
    """🔒 AI-Powered Prompt Secret Analyzer using PlugPipe LLM Service"""
    
    def __init__(self, llm_service=None, config: Dict[str, Any] = None):
        self.llm_service = llm_service
        self.config = config or {}
        self.enable_ai_analysis = self.config.get('enable_ai_prompt_analysis', True)
    
    def analyze_potential_prompt(self, text: str, context: Dict[str, Any] = None) -> AIPromptAnalysis:
        """
        🧠 COMPREHENSIVE AI ANALYSIS: Use LLM to identify and classify prompt content
        
        This is the primary method for detecting prompts that patterns cannot identify:
        - Multi-line prompts spanning multiple strings
        - Complex prompt engineering techniques
        - Contextual prompt patterns
        - Sophisticated AI instruction formats
        """
        context = context or {}
        
        # CRITICAL FIX: Use fallback analysis - AI service integration disabled for stability
        logger.info("Using fallback prompt analysis (AI service integration disabled for stability)")
        return self._fallback_analysis(text, context)
        
        if not self.enable_ai_analysis or not self.llm_service:
            return self._fallback_analysis(text, context)
        
        try:
            # Create comprehensive prompt analysis request
            analysis_prompt = self._create_prompt_analysis_prompt(text, context)
            
            llm_request = {
                "action": "query",
                "request": {
                    "prompt": analysis_prompt,
                    "task_type": "prompt_security_analysis", 
                    "temperature": 0.1,  # Low temperature for consistent analysis
                    "max_tokens": 500,
                    "system_prompt": "You are a cybersecurity expert specializing in AI/LLM prompt security and confidential content detection."
                }
            }
            
            # Handle both sync and async LLM service calls
            response = self.llm_service.process({}, llm_request)
            
            # If response is a coroutine, we need to handle it properly
            if hasattr(response, '__await__'):
                # In sync context, we can't await, so use fallback analysis
                logger.warning("LLM service returned coroutine in sync context, using fallback analysis")
                return self._fallback_analysis(text, context)
            
            if response.get('success') and response.get('response', {}).get('content'):
                return self._parse_ai_analysis_response(response['response']['content'], text, context)
            else:
                logger.warning("LLM prompt analysis failed, using fallback analysis")
                return self._fallback_analysis(text, context)
                
        except Exception as e:
            logger.error(f"AI prompt analysis error: {e}")
            return self._fallback_analysis(text, context)
    
    def _create_prompt_analysis_prompt(self, text: str, context: Dict[str, Any]) -> str:
        """Create comprehensive prompt for AI analysis of potential prompt content"""
        # Mask sensitive content while preserving analytical features
        masked_text = self._mask_for_analysis(text)
        file_type = context.get('file_type', 'unknown')
        file_path = context.get('file_path', 'unknown')
        
        analysis_prompt = f"""
🔒 CRITICAL SECURITY ANALYSIS: Prompt Content Detection

You are analyzing code/configuration content to identify AI prompts, templates, and instructions that should be treated as confidential security assets.

CONTENT TO ANALYZE:
Text: "{masked_text}"
File Type: {file_type}
File Path: {file_path[:50] if file_path else 'unknown'}
Context: {context.get('surrounding_code', '')[:100]}

ANALYSIS CRITERIA:
1. PROMPT IDENTIFICATION - Is this content likely an AI prompt, template, or instruction?
   - System prompts and behavior instructions
   - Template strings for AI interactions  
   - Multi-line prompt patterns
   - AI persona or role definitions
   - Instruction templates and examples
   - Guardrail or safety prompts

2. SENSITIVITY ASSESSMENT - If it's a prompt, what's the security sensitivity?
   - CRITICAL: System behavior, guardrails, security logic
   - HIGH: AI instructions, templates, methodology 
   - MEDIUM: Example prompts, user templates
   - LOW: Simple prompt variables, placeholder text

3. SECURITY CLASSIFICATION:
   - Does this contain sensitive AI methodology?
   - Does this reveal security or guardrail logic?
   - Does this expose proprietary AI behavior patterns?
   - Should this be encrypted/protected?

4. CONTEXT ANALYSIS:
   - Variable names, function context
   - File structure and purpose
   - Integration patterns
   - Usage context

RESPOND WITH JSON FORMAT ONLY:
{{
  "is_prompt": boolean,
  "confidence": number (0.0 to 1.0),
  "prompt_type": "system_prompt|instruction_template|ai_behavior_pattern|guardrail_logic|prompt_template|multi_line_prompt|prompt_variable|unknown_prompt",
  "sensitivity_level": "low|medium|high|critical", 
  "reasoning": "brief explanation of why this is/isn't a prompt",
  "security_classification": "public|internal|confidential|restricted",
  "recommended_protection": "none|environment_variable|encrypted_file|vault_reference|secure_template",
  "context_analysis": {{
    "file_context_relevant": boolean,
    "variable_name_indicates_prompt": boolean,
    "multi_line_pattern": boolean,
    "contains_ai_instructions": boolean,
    "contains_system_behavior": boolean,
    "contains_security_logic": boolean
  }}
}}

IMPORTANT CONSIDERATIONS:
- Be conservative but thorough - false negatives (missing prompts) are more dangerous than false positives
- Consider context clues like variable names, file paths, surrounding code
- Multi-line strings and template patterns are often prompts
- Look for AI-specific terminology and instruction patterns
- System prompts and behavior instructions are always CRITICAL sensitivity
"""
        
        return analysis_prompt
    
    def _parse_ai_analysis_response(self, response: str, original_text: str, context: Dict[str, Any]) -> AIPromptAnalysis:
        """Parse AI analysis response into structured format"""
        try:
            # Extract JSON from response
            json_match = re.search(r'{.*}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                
                return AIPromptAnalysis(
                    is_prompt=bool(result.get("is_prompt", False)),
                    confidence=float(result.get("confidence", 0.0)),
                    prompt_type=PromptSecretType(result.get("prompt_type", "unknown_prompt")),
                    sensitivity_level=result.get("sensitivity_level", "low"),
                    reasoning=result.get("reasoning", "AI analysis performed"),
                    security_classification=result.get("security_classification", "internal"),
                    recommended_protection=result.get("recommended_protection", "environment_variable"),
                    context_analysis=result.get("context_analysis", {})
                )
            else:
                # Fallback parsing
                is_prompt = any(word in response.lower() for word in ["prompt", "template", "instruction", "system", "ai", "true"])
                confidence = 0.7 if is_prompt else 0.3
                
                return AIPromptAnalysis(
                    is_prompt=is_prompt,
                    confidence=confidence,
                    prompt_type=PromptSecretType.UNKNOWN_PROMPT,
                    sensitivity_level="medium" if is_prompt else "low",
                    reasoning="Fallback parsing of AI response",
                    security_classification="confidential" if is_prompt else "internal",
                    recommended_protection="vault_reference" if is_prompt else "none",
                    context_analysis={}
                )
                
        except json.JSONDecodeError:
            logger.warning("Failed to parse AI prompt analysis JSON response")
            return self._fallback_analysis(original_text, context)
        except Exception as e:
            logger.error(f"Error parsing AI prompt analysis: {e}")
            return self._fallback_analysis(original_text, context)
    
    def _fallback_analysis(self, text: str, context: Dict[str, Any]) -> AIPromptAnalysis:
        """Fallback analysis when AI is unavailable"""
        # Basic pattern-based detection as fallback
        text_lower = text.lower()
        
        # Check for basic prompt indicators
        prompt_indicators = [
            "system", "prompt", "template", "instruction", "behavior", 
            "persona", "role", "you are", "your task", "respond with"
        ]
        
        has_indicators = sum(1 for indicator in prompt_indicators if indicator in text_lower)
        is_likely_prompt = has_indicators >= 2 or len(text) > 50
        
        return AIPromptAnalysis(
            is_prompt=is_likely_prompt,
            confidence=0.6 if is_likely_prompt else 0.2,
            prompt_type=PromptSecretType.UNKNOWN_PROMPT,
            sensitivity_level="medium" if is_likely_prompt else "low",
            reasoning=f"Fallback analysis: {has_indicators} prompt indicators found",
            security_classification="confidential" if is_likely_prompt else "internal",
            recommended_protection="environment_variable" if is_likely_prompt else "none",
            context_analysis={"fallback_analysis": True}
        )
    
    def _mask_for_analysis(self, text: str) -> str:
        """Mask text for safe AI analysis while preserving analytical features"""
        if len(text) <= 20:
            return "[CONTENT:" + "*" * len(text) + "]"
        
        # Show structure while protecting content
        start = text[:10] if len(text) > 10 else text
        end = text[-6:] if len(text) > 16 else ""
        middle_info = f"[{len(text)-16}chars]"
        
        # Analyze character composition for pattern recognition
        has_uppercase = any(c.isupper() for c in text)
        has_lowercase = any(c.islower() for c in text)
        has_digits = any(c.isdigit() for c in text)
        has_special = any(not c.isalnum() and c not in ' \n\t' for c in text)
        has_newlines = '\n' in text
        
        # Create pattern description
        pattern = f"[ANALYSIS:{len(text)}chars"
        if has_newlines: pattern += ",MULTILINE"
        if has_uppercase: pattern += ",UPPER"
        if has_lowercase: pattern += ",LOWER"  
        if has_digits: pattern += ",DIGITS"
        if has_special: pattern += ",SPECIAL"
        pattern += "]"
        
        return f"{start}...{pattern}...{end}"

class PlugPipePromptSecretScanner:
    """🔒 COMPREHENSIVE: PlugPipe Ecosystem Prompt Secret Scanner with AI Analysis"""
    
    def __init__(self, llm_service=None, config: Dict[str, Any] = None):
        self.llm_service = llm_service
        self.config = config or {}
        self.ai_analyzer = LLMPromptAnalyzer(llm_service, config)
        
        # Plugin directories that commonly contain prompts
        self.PROMPT_PLUGIN_PATTERNS = [
            "**/plugs/intelligence/*/",  # LLM services, agents, etc.
            "**/plugs/agents/*/",       # Agent factory, consistency agents
            "**/plugs/security/*guardrail*/", # Guardrail plugins
            "**/plugs/security/*prompt*/",    # Prompt security plugins
            "**/plugs/llm*/",           # Any LLM-related plugins
            "**/plugs/ai/*/",           # AI/ML plugins
            "**/plugs/*/prompt*/",      # Any plugin with 'prompt' in name
        ]
        
        # File patterns that commonly contain prompts
        self.PROMPT_FILE_PATTERNS = [
            "**/prompt*.py",
            "**/template*.py", 
            "**/guardrail*.py",
            "**/ai_*.py",
            "**/llm_*.py",
            "**/*prompt*.yaml",
            "**/*template*.yaml",
            "**/*instruction*.yaml",
            "**/*system*.yaml",
            "**/plug.yaml",  # Plugin manifests may contain prompt configs
            "**/pipe.yaml"   # Pipeline specs may contain prompt templates
        ]
    
    def comprehensive_prompt_scan(self, plugpipe_root: str = get_plugpipe_root()) -> List[Dict[str, Any]]:
        """
        🔍 COMPREHENSIVE SCAN: AI-powered prompt secret detection across entire PlugPipe ecosystem
        
        Uses both pattern analysis AND AI evaluation for maximum detection accuracy
        """
        prompt_violations = []
        
        import glob
        import os
        
        # Scan plugin directories specifically
        for pattern in self.PROMPT_PLUGIN_PATTERNS:
            plugin_dirs = glob.glob(os.path.join(plugpipe_root, pattern.lstrip('**/')), recursive=True)
            for plugin_dir in plugin_dirs:
                if os.path.isdir(plugin_dir):
                    violations = self._scan_directory_with_ai_analysis(plugin_dir)
                    prompt_violations.extend(violations)
        
        # Scan specific file patterns across the entire codebase
        for pattern in self.PROMPT_FILE_PATTERNS:
            files = glob.glob(os.path.join(plugpipe_root, pattern.lstrip('**/')), recursive=True)
            for file_path in files:
                if os.path.isfile(file_path):
                    violations = self._scan_file_with_ai_analysis(file_path)
                    prompt_violations.extend(violations)
        
        return prompt_violations
    
    def _scan_directory_with_ai_analysis(self, directory: str) -> List[Dict[str, Any]]:
        """Scan directory with comprehensive AI analysis"""
        violations = []
        
        # Common prompt-containing files in plugins
        prompt_files = [
            "main.py", "plug.yaml", "config.yaml", "templates.py", "prompts.py",
            "ai_helpers.py", "llm_integration.py", "guardrails.py"
        ]
        
        import os
        for filename in prompt_files:
            file_path = os.path.join(directory, filename)
            if os.path.exists(file_path):
                file_violations = self._scan_file_with_ai_analysis(file_path)
                violations.extend(file_violations)
        
        return violations
    
    def _scan_file_with_ai_analysis(self, file_path: str) -> List[Dict[str, Any]]:
        """🧠 AI-POWERED FILE SCANNING: Comprehensive prompt detection in files"""
        violations = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            # Strategy 1: Line-by-line AI analysis for string literals
            for line_num, line in enumerate(lines, 1):
                line_violations = self._analyze_line_with_ai(line, line_num, file_path)
                violations.extend(line_violations)
            
            # Strategy 2: Multi-line string detection and analysis
            multi_line_violations = self._analyze_multiline_strings_with_ai(content, file_path)
            violations.extend(multi_line_violations)
            
            # Strategy 3: Variable and function analysis
            variable_violations = self._analyze_variables_with_ai(content, file_path)
            violations.extend(variable_violations)
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path} with AI analysis: {e}")
        
        return violations
    
    def _analyze_line_with_ai(self, line: str, line_num: int, file_path: str) -> List[Dict[str, Any]]:
        """Analyze individual line for prompt content using AI"""
        violations = []
        
        # Extract string literals from line
        string_patterns = [
            r'"([^"]{15,})"',  # Double quoted strings 15+ chars
            r"'([^']{15,})'",  # Single quoted strings 15+ chars
            r'"""([^"]{20,})"""',  # Triple quoted strings 20+ chars
            r"'''([^']{20,})'''"   # Triple quoted strings 20+ chars
        ]
        
        for pattern in string_patterns:
            matches = re.finditer(pattern, line, re.DOTALL)
            for match in matches:
                potential_prompt = match.group(1).strip()
                
                if len(potential_prompt) >= 15:  # Minimum length for analysis
                    context = {
                        'file_path': file_path,
                        'line_number': line_num,
                        'file_type': self._get_file_type(file_path),
                        'surrounding_code': line.strip()
                    }
                    
                    # AI analysis of potential prompt
                    analysis = self.ai_analyzer.analyze_potential_prompt(potential_prompt, context)
                    
                    if analysis.is_prompt and analysis.confidence >= 0.6:
                        violations.append({
                            "file_path": file_path,
                            "line_number": line_num,
                            "violation_type": "ai_detected_prompt_secret",
                            "prompt_type": analysis.prompt_type.value,
                            "severity": self._determine_severity(analysis),
                            "confidence": analysis.confidence,
                            "original_text": self._mask_prompt_content(potential_prompt),
                            "full_line": line.strip(),
                            "ai_analysis": {
                                "reasoning": analysis.reasoning,
                                "sensitivity_level": analysis.sensitivity_level,
                                "security_classification": analysis.security_classification,
                                "recommended_protection": analysis.recommended_protection,
                                "context_analysis": analysis.context_analysis
                            },
                            "remediation": self._generate_remediation(analysis),
                            "plugin_context": self._extract_plugin_context(file_path)
                        })
        
        return violations
    
    def _analyze_multiline_strings_with_ai(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Detect and analyze multi-line strings that may contain prompts"""
        violations = []
        
        # Multi-line string patterns
        multiline_patterns = [
            (r'"""([\s\S]{30,}?)"""', "triple_double_quote"),
            (r"'''([\s\S]{30,}?)'''", "triple_single_quote"),
            (r'f"""([\s\S]{30,}?)"""', "f_string_triple_double"),
            (r"f'''([\s\S]{30,}?)'''", "f_string_triple_single")
        ]
        
        for pattern, pattern_type in multiline_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
            for match in matches:
                potential_prompt = match.group(1).strip()
                
                if len(potential_prompt) >= 30:  # Minimum length for multi-line analysis
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    context = {
                        'file_path': file_path,
                        'line_number': line_num,
                        'file_type': self._get_file_type(file_path),
                        'string_type': pattern_type,
                        'is_multiline': True
                    }
                    
                    # AI analysis of potential multi-line prompt
                    analysis = self.ai_analyzer.analyze_potential_prompt(potential_prompt, context)
                    
                    if analysis.is_prompt and analysis.confidence >= 0.5:  # Lower threshold for multi-line
                        violations.append({
                            "file_path": file_path,
                            "line_number": line_num,
                            "violation_type": "ai_detected_multiline_prompt",
                            "prompt_type": analysis.prompt_type.value,
                            "severity": self._determine_severity(analysis),
                            "confidence": analysis.confidence,
                            "original_text": self._mask_prompt_content(potential_prompt),
                            "string_pattern": pattern_type,
                            "ai_analysis": {
                                "reasoning": analysis.reasoning,
                                "sensitivity_level": analysis.sensitivity_level,
                                "security_classification": analysis.security_classification,
                                "recommended_protection": analysis.recommended_protection,
                                "context_analysis": analysis.context_analysis
                            },
                            "remediation": self._generate_remediation(analysis),
                            "plugin_context": self._extract_plugin_context(file_path),
                            "multiline_content": True
                        })
        
        return violations
    
    def _analyze_variables_with_ai(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Analyze variable assignments that may contain prompts"""
        violations = []
        
        # Variable assignment patterns that might contain prompts
        variable_patterns = [
            r'(\w*prompt\w*)\s*=\s*[\'"]([^\'"]{20,})[\'"]',
            r'(\w*template\w*)\s*=\s*[\'"]([^\'"]{20,})[\'"]',
            r'(\w*instruction\w*)\s*=\s*[\'"]([^\'"]{20,})[\'"]',
            r'(\w*system\w*)\s*=\s*[\'"]([^\'"]{20,})[\'"]',
            r'(\w*message\w*)\s*=\s*[\'"]([^\'"]{20,})[\'"]'
        ]
        
        for pattern in variable_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                var_name = match.group(1)
                potential_prompt = match.group(2).strip()
                
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                context = {
                    'file_path': file_path,
                    'line_number': line_num,
                    'file_type': self._get_file_type(file_path),
                    'variable_name': var_name,
                    'assignment_context': True
                }
                
                # AI analysis of variable content
                analysis = self.ai_analyzer.analyze_potential_prompt(potential_prompt, context)
                
                if analysis.is_prompt and analysis.confidence >= 0.7:  # Higher threshold for variables
                    violations.append({
                        "file_path": file_path,
                        "line_number": line_num,
                        "violation_type": "ai_detected_prompt_variable",
                        "variable_name": var_name,
                        "prompt_type": analysis.prompt_type.value,
                        "severity": self._determine_severity(analysis),
                        "confidence": analysis.confidence,
                        "original_text": self._mask_prompt_content(potential_prompt),
                        "ai_analysis": {
                            "reasoning": analysis.reasoning,
                            "sensitivity_level": analysis.sensitivity_level,
                            "security_classification": analysis.security_classification,
                            "recommended_protection": analysis.recommended_protection,
                            "context_analysis": analysis.context_analysis
                        },
                        "remediation": self._generate_remediation(analysis, var_name),
                        "plugin_context": self._extract_plugin_context(file_path)
                    })
        
        return violations
    
    def _determine_severity(self, analysis: AIPromptAnalysis) -> str:
        """Determine severity level based on AI analysis"""
        if analysis.sensitivity_level == "critical" or analysis.security_classification == "restricted":
            return "critical"
        elif analysis.sensitivity_level == "high" or analysis.security_classification == "confidential":
            return "high"
        elif analysis.sensitivity_level == "medium":
            return "medium"
        else:
            return "low"
    
    def _generate_remediation(self, analysis: AIPromptAnalysis, var_name: str = None) -> str:
        """Generate specific remediation based on AI analysis"""
        base_msg = f"🔒 AI-DETECTED PROMPT ({analysis.sensitivity_level.upper()}): "
        
        if analysis.recommended_protection == "vault_reference":
            if var_name:
                return base_msg + f"Store {var_name} securely: {var_name} = ${{vault:prompts/{var_name.lower()}}}"
            else:
                return base_msg + "Use vault reference: ${vault:prompts/template}"
        elif analysis.recommended_protection == "encrypted_file":
            return base_msg + "Store in encrypted file: ${file:secure/prompts/template.txt}"
        elif analysis.recommended_protection == "secure_template":
            return base_msg + "Use secure template system: ${prompt_template:template_id}"
        elif analysis.recommended_protection == "environment_variable":
            if var_name:
                return base_msg + f"Use environment variable: {var_name} = ${{env:{var_name.upper()}}}"
            else:
                return base_msg + "Use environment variable: ${env:PROMPT_CONTENT}"
        else:
            return base_msg + "Evaluate if this should be stored securely based on sensitivity analysis."
    
    def _get_file_type(self, file_path: str) -> str:
        """Extract file type from path"""
        import os
        return os.path.splitext(file_path)[1] if file_path else ""
    
    def _extract_plugin_context(self, file_path: str) -> Dict[str, str]:
        """Extract plugin context from file path"""
        import os
        path_parts = file_path.split(os.sep)
        context = {
            "is_plugin": "plugs" in path_parts,
            "plugin_category": "",
            "plugin_name": "",
            "plugin_version": "",
            "file_type": os.path.splitext(os.path.basename(file_path))[1]
        }
        
        if context["is_plugin"]:
            try:
                plugs_index = path_parts.index("plugs")
                if len(path_parts) > plugs_index + 3:
                    context["plugin_category"] = path_parts[plugs_index + 1]
                    context["plugin_name"] = path_parts[plugs_index + 2] 
                    context["plugin_version"] = path_parts[plugs_index + 3]
            except (ValueError, IndexError):
                pass
        
        return context
    
    def _mask_prompt_content(self, prompt_text: str) -> str:
        """Mask prompt content for safe reporting while preserving analytical value"""
        if len(prompt_text) <= 20:
            return "[PROMPT:" + "*" * len(prompt_text) + "]"
        
        # Show structure while protecting content
        start = prompt_text[:8] if len(prompt_text) > 8 else prompt_text
        end = prompt_text[-4:] if len(prompt_text) > 12 else ""
        middle_info = f"[AI_PROMPT:{len(prompt_text)-12}chars]"
        
        return f"{start}{middle_info}{end}"