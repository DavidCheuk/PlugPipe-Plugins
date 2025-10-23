#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Microsoft Presidio Data Leakage Prevention Plugin for PlugPipe - AI-Powered Version
Real AI-based PII detection using Presidio's NLP models with spaCy
"""

import time
import logging

# Configure logging to reduce spaCy model loading spam
logging.getLogger("spacy").setLevel(logging.WARNING)

def process(ctx, cfg):
    """
    PlugPipe entry point for Presidio DLP plugin - AI-POWERED VERSION
    Uses actual Presidio AI models (spaCy NLP) for PII detection
    """
    start_time = time.time()
    
    try:
        # AI Strict Mode Configuration
        ai_strict_mode = (
            ctx.get('ai_strict_mode', False) or 
            cfg.get('ai_strict_mode', False) or
            ctx.get('ai_required', False) or 
            cfg.get('ai_required', False) or
            ctx.get('fallback_prohibited', False) or
            cfg.get('fallback_prohibited', False)
        )
        
        # Extract text from input parameters
        text = ""
        
        # Try cfg first (CLI input data)
        if isinstance(cfg, dict):
            if 'text' in cfg:
                text = str(cfg['text'])
            elif 'payload' in cfg:
                text = str(cfg['payload'])
            elif 'content' in cfg:
                text = str(cfg['content'])
            elif 'input' in cfg:
                text = str(cfg['input'])
        
        # Try ctx if not found in cfg (MCP/context data)
        if not text and isinstance(ctx, dict):
            if 'text' in ctx:
                text = str(ctx['text'])
            elif 'payload' in ctx:
                text = str(ctx['payload'])
            elif 'input' in ctx:
                text = str(ctx['input'])
            elif 'original_request' in ctx:
                original_request = ctx['original_request']
                if isinstance(original_request, dict):
                    if 'params' in original_request and 'payload' in original_request['params']:
                        text = str(original_request['params']['payload'])
                    elif 'payload' in original_request:
                        text = str(original_request['payload'])
                    elif 'params' in original_request:
                        params = original_request['params']
                        if isinstance(params, dict):
                            text = params.get('text', params.get('content', str(params)))
                        else:
                            text = str(params)
                    else:
                        text = str(original_request)
        
        # Final fallback
        if not text and isinstance(cfg, str):
            text = cfg
        
        if not text:
            return {
                "status": "error",
                "error": "No text provided for analysis",
                "expected_params": ["text", "payload", "content"]
            }
        
        # Initialize Presidio AI models
        try:
            # Enable AI models now that dependencies are installed
            presidio_available = True  # Enable AI-powered detection
            
            if presidio_available:  # This block will now execute
                from presidio_analyzer import AnalyzerEngine
                from presidio_anonymizer import AnonymizerEngine
                
                # Initialize Presidio analyzer (loads spaCy NLP models)
                analyzer = AnalyzerEngine()
                anonymizer = AnonymizerEngine()
                
                # Perform AI-powered PII detection
                analyzer_results = analyzer.analyze(
                    text=text,
                    language='en',
                    score_threshold=0.3  # Lower threshold for better detection
                )
            else:
                raise ImportError("Presidio AI models disabled to prevent hangs")
            
            # Convert results to our format
            detected_entities = []
            entity_types = []
            threats_detected = len(analyzer_results)
            
            for result in analyzer_results:
                entity_type = result.entity_type
                confidence = result.score
                start_pos = result.start
                end_pos = result.end
                detected_text = text[start_pos:end_pos]
                
                entity_types.append(entity_type)
                detected_entities.append({
                    "entity_type": entity_type,
                    "confidence_score": confidence,
                    "start": start_pos,
                    "end": end_pos,
                    "text": detected_text,
                    "ai_powered": True
                })
            
            # Calculate privacy risk score
            privacy_risk_score = min(len(detected_entities) * 2.0, 10.0)
            
            # Generate anonymized text (optional)
            anonymized_text = ""
            if analyzer_results:
                try:
                    anonymized_result = anonymizer.anonymize(
                        text=text,
                        analyzer_results=analyzer_results
                    )
                    anonymized_text = anonymized_result.text
                except Exception:
                    anonymized_text = "[ANONYMIZATION_ERROR]"
            
            processing_time_ms = (time.time() - start_time) * 1000
            
            # Determine action based on threat level
            action = "BLOCK" if threats_detected > 0 or privacy_risk_score > 1.0 else "ALLOW"
            
            return {
                "status": "success",
                # Universal Security Interface fields
                "action": action,
                "threat_score": min(privacy_risk_score / 5.0, 1.0),  # Normalize to 0.0-1.0
                "threats_detected": detected_entities,
                "plugin_name": "presidio_dlp",
                "processing_time_ms": processing_time_ms,
                "confidence": 0.9 if threats_detected > 0 else 0.8,
                # Additional plugin-specific fields
                "scan_type": "presidio_ai_nlp",
                "privacy_assessment": {
                    "entities_detected": threats_detected,
                    "entity_types": list(set(entity_types)),
                    "privacy_risk_score": privacy_risk_score,
                    "detailed_entities": detected_entities,
                    "anonymized_text": anonymized_text,
                    "recommendations": _generate_recommendations(threats_detected, entity_types)
                },
                "presidio_available": True,
                "ai_models_loaded": True,
                "ai_models_active": True,
                "ai_strict_mode": ai_strict_mode,
                "processing_mode": "ai_inference",
                "nlp_engine": "spacy_en_core_web_sm",
                "analyzer_results": [
                    {
                        "entity_type": r.entity_type,
                        "confidence": r.score,
                        "start": r.start,
                        "end": r.end
                    } for r in analyzer_results
                ],
                "ai_powered_detection": True
            }
            
        except ImportError as e:
            # AI Strict Mode: Return error instead of fallback
            if ai_strict_mode:
                processing_time_ms = (time.time() - start_time) * 1000
                return {
                    "status": "error",
                    "error": "Presidio AI models required but unavailable",
                    "error_type": "AI_MODELS_UNAVAILABLE",
                    "ai_strict_mode": True,
                    "fallback_prohibited": True,
                    "plugin_name": "presidio_dlp",
                    "import_error": str(e),
                    "missing_dependencies": ["presidio-analyzer", "presidio-anonymizer", "spacy", "en_core_web_sm"],
                    "recommendation": "Install AI dependencies: pip install presidio-analyzer presidio-anonymizer spacy && python -m spacy download en_core_web_sm",
                    "security_impact": "HIGH - AI-powered PII detection unavailable",
                    "processing_time_ms": processing_time_ms
                }
            else:
                # Lenient Mode: Fallback to pattern matching if Presidio not available
                return _fallback_pattern_detection(text, start_time, str(e))
        
    except Exception as e:
        processing_time_ms = (time.time() - start_time) * 1000
        return {
            "status": "error",
            "error": str(e),
            "error_type": type(e).__name__,
            "plugin_name": "presidio_dlp",
            "processing_time_ms": processing_time_ms,
            "presidio_available": False,
            "ai_models_loaded": False
        }

def _generate_recommendations(entity_count, entity_types):
    """Generate recommendations based on detected entities"""
    recommendations = []
    
    if entity_count == 0:
        recommendations.append("No PII detected - text appears safe for processing")
        return recommendations
    
    if entity_count >= 3:
        recommendations.append("HIGH RISK: Multiple PII entities detected")
        recommendations.append("Consider blocking or heavily anonymizing this content")
    elif entity_count >= 2:
        recommendations.append("MEDIUM RISK: Multiple PII entities detected")
        recommendations.append("Apply data redaction or anonymization")
    else:
        recommendations.append("LOW RISK: Single PII entity detected")
        recommendations.append("Consider minor redaction")
    
    # Specific recommendations by entity type
    if "CREDIT_CARD" in entity_types:
        recommendations.append("CRITICAL: Credit card information detected - immediate redaction required")
    if "US_SSN" in entity_types:
        recommendations.append("CRITICAL: Social Security Number detected - immediate redaction required")
    if "EMAIL_ADDRESS" in entity_types:
        recommendations.append("Anonymize or redact email addresses")
    if "PHONE_NUMBER" in entity_types:
        recommendations.append("Anonymize or redact phone numbers")
    if "PERSON" in entity_types:
        recommendations.append("Consider anonymizing personal names")
    
    return recommendations

def _fallback_pattern_detection(text, start_time, import_error):
    """Fallback pattern-based detection when Presidio is not available"""
    import re
    
    detected_entities = []
    entity_types = []
    
    # Basic regex patterns for common PII
    patterns = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL_ADDRESS'),
        (r'\b\d{3}-\d{2}-\d{4}\b', 'US_SSN'),
        (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', 'CREDIT_CARD'),
        (r'\b\d{3}[- ]?\d{3}[- ]?\d{4}\b', 'PHONE_NUMBER'),
    ]
    
    for pattern, entity_type in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            detected_entities.append({
                "entity_type": entity_type,
                "confidence_score": 0.8,
                "start": match.start(),
                "end": match.end(),
                "text": match.group(),
                "ai_powered": False
            })
            entity_types.append(entity_type)
    
    threats_detected = len(detected_entities)
    
    # Enhanced threat scoring for critical PII types
    privacy_risk_score = 0.0
    for entity in detected_entities:
        entity_type = entity["entity_type"]
        if entity_type in ["CREDIT_CARD", "US_SSN"]:
            privacy_risk_score += 4.0  # High risk for financial/identity data
        elif entity_type in ["EMAIL_ADDRESS", "PHONE_NUMBER"]:
            privacy_risk_score += 1.0  # Lower risk for contact info
        else:
            privacy_risk_score += 2.0  # Medium risk for other PII
    
    processing_time_ms = (time.time() - start_time) * 1000
    
    # Normalize and ensure credit cards get blocked (threat_score > 0.5)
    normalized_threat_score = min(privacy_risk_score / 5.0, 1.0)
    
    # Determine action based on threat level
    action = "BLOCK" if normalized_threat_score > 0.3 else "ALLOW"
    
    return {
        "status": "success",
        # Universal Security Interface fields
        "action": action,
        "threat_score": normalized_threat_score,
        "threats_detected": detected_entities,
        "plugin_name": "presidio_dlp",
        "processing_time_ms": processing_time_ms,
        "confidence": 0.8 if threats_detected > 0 else 0.7,  # Lower confidence for fallback
        # Additional plugin-specific fields
        "scan_type": "fallback_patterns",
        "privacy_assessment": {
            "entities_detected": threats_detected,
            "entity_types": list(set(entity_types)),
            "privacy_risk_score": privacy_risk_score,
            "detailed_entities": detected_entities,
            "recommendations": _generate_recommendations(threats_detected, entity_types)
        },
        "presidio_available": False,
        "ai_models_loaded": False,
        "import_error": import_error,
        "fallback_mode": True,
        "warning": "Using pattern-based fallback - Presidio AI not available"
    }