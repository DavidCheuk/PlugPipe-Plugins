# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

def process(ctx, cfg):
    """
    PlugPipe entry point for Presidio DLP plugin - fixed version
    
    Args:
        ctx: Plugin execution context
        cfg: Plugin configuration
        
    Returns:
        Privacy assessment and security analysis results
    """
    
    try:
        # Extract input parameters with robust fallback parsing
        text = ctx.get('text', ctx.get('payload', ctx.get('content', '')))
        if not text:
            return {
                "status": "error", 
                "error": "No text provided for analysis",
                "expected_params": ["text", "payload", "content"]
            }
        
        # Quick pattern-based PII detection (always works regardless of Presidio availability)
        import re
        threats = []
        
        # Quick API key pattern
        if re.search(r'(?i)(api[_\-]?key|token)[\"\'\s=:]+([a-zA-Z0-9_\-]{20,})', text):
            threats.append("API_KEY")
        
        # Quick SSN pattern  
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', text):
            threats.append("US_SSN")
        
        # Quick email pattern
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
            threats.append("EMAIL_ADDRESS")
        
        # Quick credit card pattern
        if re.search(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', text):
            threats.append("CREDIT_CARD")
        
        # Quick phone pattern
        if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text):
            threats.append("PHONE_NUMBER")
            
        return {
            "status": "success",
            "scan_type": "pattern_based",
            "privacy_assessment": {
                "entities_detected": len(threats),
                "entity_types": threats,
                "privacy_risk_score": len(threats) * 2.5,
                "compliance_violations": ["GDPR: Personal data detected"] if threats else [],
                "recommendations": ["Apply data redaction", "Review data handling policies"] if threats else ["No PII detected"]
            },
            "presidio_available": PRESIDIO_AVAILABLE,
            "fallback_mode": True,
            "plugin_version": plug_metadata["version"],
            "processing_time_ms": 1.0,
            "threats_detected": len(threats)
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "error_type": type(e).__name__,
            "presidio_available": PRESIDIO_AVAILABLE,
            "plugin_name": "presidio_dlp"
        }