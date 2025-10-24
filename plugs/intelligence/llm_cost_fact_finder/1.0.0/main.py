# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
🔍 LLM Cost Fact-Finder Plugin

AI-powered fact-finder that uses existing PlugPipe agent ecosystem to dynamically discover
and validate LLM provider pricing. Leverages validation agents, web search agents, and
research agents to ensure accurate real-time cost calculations.

Key Features:
- Reuses existing agent factories (web_search, research_validation, financial_verification)
- Agent-based multi-source validation (APIs, pricing pages, documentation)
- AI-powered pricing analysis using LLM services
- Automatic cost estimator integration
- Provider pricing alerts with confidence scoring
- Plugin composition following PlugPipe principles

Architecture:
- Uses pp() function for plugin discovery
- Composes existing validation agents for fact-finding
- Leverages research_validation_agent for data verification
- Integrates with financial_verification_agent for cost validation
- Uses web_search_agent for pricing page discovery

Author: PlugPipe AI Infrastructure Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
import sqlite3
from pathlib import Path

# Add PlugPipe paths for plugin discovery
sys.path.insert(0, get_plugpipe_root())
sys.path.insert(0, get_plugpipe_path("cores"))

# Plugin discovery using pp() pattern
try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
except ImportError:
    # Fallback for testing
    def pp(plugin_name): return None
    def get_llm_config(primary=True): return {}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PricingUpdate:
    """Data class for pricing update results"""
    provider: str
    model: str
    input_cost: float
    output_cost: float
    currency: str = "USD"
    source: str = "fact_finder"
    confidence: float = 0.95
    timestamp: str = None
    change_percentage: float = 0.0
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class PricingAlert:
    """Data class for pricing change alerts"""
    provider: str
    model: str
    old_price: float
    new_price: float
    change_percentage: float
    severity: str
    message: str
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


class LLMCostFactFinder:
    """Agent-powered fact-finder for dynamic LLM cost discovery using PlugPipe ecosystem"""
    
    # Provider information for agent-based discovery
    PROVIDER_SOURCES = {
        'openai': {
            'official_site': 'https://openai.com',
            'pricing_page': 'https://openai.com/api/pricing/',
            'api_docs': 'https://platform.openai.com/docs/api-reference',
            'models': ['gpt-4', 'gpt-4-turbo', 'gpt-3.5-turbo', 'gpt-4o', 'gpt-4o-mini']
        },
        'anthropic': {
            'official_site': 'https://anthropic.com',
            'pricing_page': 'https://www.anthropic.com/api',
            'api_docs': 'https://docs.anthropic.com/claude/reference',
            'models': ['claude-3-opus', 'claude-3-sonnet', 'claude-3-haiku', 'claude-3-5-sonnet']
        },
        'ollama': {
            'official_site': 'https://ollama.ai',
            'pricing_page': 'https://ollama.ai/pricing',
            'api_docs': 'https://github.com/jmorganca/ollama/blob/main/docs/api.md',
            'models': ['mistral:latest', 'llama2:latest', 'codellama:latest']
        }
    }
    
    # Change thresholds for alerts
    ALERT_THRESHOLDS = {
        'minor': 5.0,      # 5% change
        'moderate': 15.0,  # 15% change
        'major': 25.0,     # 25% change
        'critical': 50.0   # 50% change
    }
    
    def __init__(self, db_path: str = "llm_cost_fact_finder.db"):
        """Initialize fact-finder with PlugPipe agent ecosystem"""
        self.db_path = db_path
        self.cost_estimator = None  # Will be loaded lazily via pp()
        
        # Initialize agent plugins using pp() discovery
        self.web_search_agent = None
        self.research_validation_agent = None
        self.financial_verification_agent = None
        
        self._init_database()
        self._init_agent_ecosystem()
        
    def _init_database(self):
        """Initialize SQLite database for pricing data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Pricing updates history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pricing_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    input_cost REAL NOT NULL,
                    output_cost REAL NOT NULL,
                    currency TEXT DEFAULT 'USD',
                    source TEXT NOT NULL,
                    confidence REAL DEFAULT 0.95,
                    timestamp TEXT NOT NULL,
                    change_percentage REAL DEFAULT 0.0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Pricing alerts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pricing_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    old_price REAL NOT NULL,
                    new_price REAL NOT NULL,
                    change_percentage REAL NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Fact-finder sources tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pricing_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    last_check TEXT,
                    status TEXT DEFAULT 'active',
                    reliability_score REAL DEFAULT 1.0,
                    error_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Discovery jobs tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS discovery_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    providers_checked INTEGER DEFAULT 0,
                    updates_found INTEGER DEFAULT 0,
                    alerts_generated INTEGER DEFAULT 0,
                    start_time TEXT,
                    end_time TEXT,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"✅ Fact-finder database initialized: {self.db_path}")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
    
    def _init_agent_ecosystem(self):
        """Initialize agent plugins using PlugPipe discovery"""
        try:
            # Use pp() function for plugin discovery as per CLAUDE.md
            logger.info("🔍 Discovering agent plugins via pp() function...")
            
            # Web search agent for pricing page discovery
            self.web_search_agent = pp('web_search_agent_factory', version='1.0.0')
            if self.web_search_agent:
                logger.info("✅ Web search agent factory loaded")
            
            # Research validation agent for data verification
            self.research_validation_agent = pp('research_validation_agent_factory', version='1.0.0')
            if self.research_validation_agent:
                logger.info("✅ Research validation agent factory loaded")
            
            # Financial verification agent for cost validation
            self.financial_verification_agent = pp('financial_verification_agent_factory', version='1.0.0')
            if self.financial_verification_agent:
                logger.info("✅ Financial verification agent factory loaded")
            
            # LLM service for AI-powered analysis
            self.llm_service = pp('llm_service', version='1.0.0')
            if self.llm_service:
                logger.info("✅ LLM service loaded for pricing analysis")
            
        except Exception as e:
            logger.warning(f"Agent ecosystem initialization warning: {e}")
    
    def _get_cost_estimator(self):
        """Lazy load the cost estimator plugin using pp()"""
        if self.cost_estimator is None:
            try:
                # Use pp() function as per CLAUDE.md guidelines
                self.cost_estimator = pp('llm_cost_estimator', version='1.0.0')
                if self.cost_estimator:
                    logger.info("✅ Cost estimator plugin loaded via pp()")
                else:
                    logger.warning("Cost estimator not discoverable via pp()")
            except Exception as e:
                logger.warning(f"Cost estimator loading failed: {e}")
        return self.cost_estimator
    
    async def discover_pricing_updates(self, providers: List[str] = None) -> Dict[str, Any]:
        """
        Main fact-finder operation: discover pricing updates across providers
        
        Args:
            providers: List of providers to check, or None for all
            
        Returns:
            Discovery results with updates found and alerts generated
        """
        if providers is None:
            providers = list(self.PRICING_SOURCES.keys())
        
        # Start discovery job
        job_id = await self._start_discovery_job("pricing_discovery", providers)
        
        try:
            all_updates = []
            all_alerts = []
            
            logger.info(f"🔍 Starting pricing discovery for providers: {providers}")
            
            # Discover pricing for each provider
            for provider in providers:
                try:
                    updates, alerts = await self._discover_provider_pricing(provider)
                    all_updates.extend(updates)
                    all_alerts.extend(alerts)
                    
                except Exception as e:
                    logger.error(f"❌ Provider {provider} discovery failed: {e}")
                    continue
            
            # Update cost estimator with new pricing
            if all_updates and self._get_cost_estimator():
                await self._update_cost_estimator(all_updates)
            
            # Complete discovery job
            await self._complete_discovery_job(job_id, len(providers), len(all_updates), len(all_alerts))
            
            return {
                "success": True,
                "job_id": job_id,
                "providers_checked": len(providers),
                "pricing_updates": [asdict(update) for update in all_updates],
                "alerts_generated": [asdict(alert) for alert in all_alerts],
                "total_updates": len(all_updates),
                "total_alerts": len(all_alerts),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            await self._fail_discovery_job(job_id, str(e))
            logger.error(f"❌ Pricing discovery failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "job_id": job_id
            }
    
    async def _discover_provider_pricing(self, provider: str) -> Tuple[List[PricingUpdate], List[PricingAlert]]:
        """Discover pricing updates for a specific provider"""
        updates = []
        alerts = []
        
        if provider not in self.PROVIDER_SOURCES:
            logger.warning(f"⚠️ Unknown provider: {provider}")
            return updates, alerts
        
        source_config = self.PROVIDER_SOURCES[provider]
        
        # Use agent-based discovery methods following PlugPipe principles
        discovery_methods = [
            self._discover_via_web_search_agent,
            self._discover_via_research_validation_agent,
            self._discover_via_llm_service_analysis
        ]
        
        for method_name, method in zip(
            ['web_search_agent', 'research_validation_agent', 'llm_service'],
            discovery_methods
        ):
            try:
                logger.info(f"🔍 Attempting discovery via {method_name}")
                method_updates, method_alerts = await method(provider, source_config)
                
                # Validate updates using financial verification agent
                for update in method_updates:
                    if await self._validate_pricing_with_agents(update):
                        updates.append(update)
                        
                        # Check for significant price changes
                        alert = await self._check_price_changes(update)
                        if alert:
                            alerts.append(alert)
                
                if updates:  # If we found updates, use this method
                    logger.info(f"✅ Successful discovery via {method_name}")
                    break
                    
            except Exception as e:
                logger.warning(f"⚠️ Method {method_name} failed for {provider}: {e}")
                continue
        
        # Store updates and alerts
        for update in updates:
            await self._store_pricing_update(update)
        
        for alert in alerts:
            await self._store_pricing_alert(alert)
        
        logger.info(f"✅ Provider {provider}: {len(updates)} updates, {len(alerts)} alerts")
        return updates, alerts
    
    async def _discover_via_web_search_agent(self, provider: str, config: Dict) -> Tuple[List[PricingUpdate], List[PricingAlert]]:
        """Discover pricing using web search agent factory"""
        updates = []
        
        if not self.web_search_agent:
            logger.warning("Web search agent not available")
            return updates, []
        
        try:
            # Create web search agent for pricing discovery
            search_config = {
                "operation": "create_agent",
                "agent_type": "pricing_researcher",
                "search_queries": [
                    f"{provider} LLM pricing per token 2025",
                    f"{provider} API pricing model costs",
                    f"{provider} pricing page official"
                ],
                "target_urls": [config.get('pricing_page', ''), config.get('official_site', '')],
                "validation_required": True
            }
            
            # Use web search agent to find pricing information
            search_result = await self.web_search_agent.process({}, search_config)
            
            if search_result.get('success') and search_result.get('search_results'):
                # Parse search results for pricing data
                updates = await self._parse_web_search_results(provider, search_result['search_results'])
                
        except Exception as e:
            logger.warning(f"Web search agent discovery failed for {provider}: {e}")
        
        return updates, []
    
    async def _discover_via_research_validation_agent(self, provider: str, config: Dict) -> Tuple[List[PricingUpdate], List[PricingAlert]]:
        """Discover pricing using research validation agent factory"""
        updates = []
        
        if not self.research_validation_agent:
            logger.warning("Research validation agent not available")
            return updates, []
        
        try:
            # Create research validation agent for pricing verification
            research_config = {
                "operation": "create_agent",
                "agent_type": "financial_data_researcher",
                "research_topic": f"{provider} LLM API pricing structure and token costs",
                "validation_criteria": [
                    "Verify pricing is from official sources",
                    "Cross-reference multiple documentation sources", 
                    "Validate pricing format consistency",
                    "Check for recent pricing updates"
                ],
                "sources_to_validate": [
                    config.get('pricing_page', ''),
                    config.get('api_docs', ''),
                    config.get('official_site', '')
                ]
            }
            
            # Use research validation agent
            research_result = await self.research_validation_agent.process({}, research_config)
            
            if research_result.get('success') and research_result.get('validation_results'):
                # Parse research validation results for pricing
                updates = await self._parse_research_validation_results(provider, research_result['validation_results'])
                
        except Exception as e:
            logger.warning(f"Research validation agent discovery failed for {provider}: {e}")
        
        return updates, []
    
    async def _discover_via_llm_service_analysis(self, provider: str, config: Dict) -> Tuple[List[PricingUpdate], List[PricingAlert]]:
        """Use PlugPipe LLM service for pricing analysis"""
        updates = []
        
        if not self.llm_service:
            logger.warning("LLM service not available")
            return updates, []
        
        try:
            # Create comprehensive pricing analysis prompt
            analysis_prompt = f"""
            You are a financial data analyst specializing in AI/LLM service pricing.
            
            Research and extract current pricing information for {provider} LLM services:
            
            Provider: {provider}
            Official pricing page: {config.get('pricing_page', 'Not available')}
            API documentation: {config.get('api_docs', 'Not available')}
            Models to analyze: {', '.join(config.get('models', []))}
            
            Extract the following pricing data:
            1. Model names (exact names as used by the provider)
            2. Input token costs per 1K tokens in USD
            3. Output token costs per 1K tokens in USD  
            4. Any special pricing tiers or volume discounts
            5. Last updated date of pricing information
            
            Respond with structured JSON data only. Include confidence scores for each price.
            
            Expected format:
            {{
                "provider": "{provider}",
                "pricing_data": [
                    {{
                        "model": "model-name",
                        "input_cost_per_1k": 0.0000,
                        "output_cost_per_1k": 0.0000,
                        "confidence": 0.95,
                        "source": "official_pricing_page"
                    }}
                ],
                "last_updated": "2025-01-XX",
                "extraction_confidence": 0.90
            }}
            """
            
            # Use LLM service for analysis
            llm_config = {
                "operation": "generate",
                "prompt": analysis_prompt,
                "temperature": 0.1,  # Low temperature for factual extraction
                "max_tokens": 2000,
                "model_preference": ["gpt-4", "claude-3-sonnet", "mistral:latest"]
            }
            
            llm_result = await self.llm_service.process({}, llm_config)
            
            if llm_result.get('success') and llm_result.get('response'):
                # Parse LLM service response for pricing
                updates = await self._parse_llm_service_response(provider, llm_result['response'])
                
        except Exception as e:
            logger.warning(f"LLM service analysis failed for {provider}: {e}")
        
        return updates, []
    
    async def _parse_openai_api(self, api_data: Dict) -> List[PricingUpdate]:
        """Parse OpenAI API response for pricing updates"""
        updates = []
        
        # Note: OpenAI API doesn't currently provide pricing in model listings
        # This is a placeholder for when pricing becomes available via API
        # For now, we'll use fallback pricing or web scraping
        
        return updates
    
    async def _parse_anthropic_api(self, api_data: Dict) -> List[PricingUpdate]:
        """Parse Anthropic API response for pricing updates"""
        updates = []
        
        # Similar to OpenAI, Anthropic API doesn't expose pricing directly
        # This would be implemented when pricing becomes available via API
        
        return updates
    
    async def _parse_pricing_page(self, provider: str, content: str, selectors: Dict) -> List[PricingUpdate]:
        """Parse pricing page HTML content using regex selectors"""
        updates = []
        
        try:
            for model, patterns in selectors.items():
                input_pattern = patterns.get('input_pattern')
                output_pattern = patterns.get('output_pattern')
                
                input_cost = None
                output_cost = None
                
                # Extract input pricing
                if input_pattern:
                    match = re.search(input_pattern, content, re.IGNORECASE)
                    if match:
                        input_cost = float(match.group(1))
                
                # Extract output pricing
                if output_pattern:
                    match = re.search(output_pattern, content, re.IGNORECASE)
                    if match:
                        output_cost = float(match.group(1))
                
                # Create update if we found pricing
                if input_cost is not None and output_cost is not None:
                    update = PricingUpdate(
                        provider=provider,
                        model=model,
                        input_cost=input_cost,
                        output_cost=output_cost,
                        source="web_scraping",
                        confidence=0.85  # Lower confidence for web scraping
                    )
                    updates.append(update)
                    
        except Exception as e:
            logger.error(f"Pricing page parsing failed: {e}")
        
        return updates
    
    async def _parse_web_search_results(self, provider: str, search_results: List[Dict]) -> List[PricingUpdate]:
        """Parse web search agent results for pricing data"""
        updates = []
        
        try:
            for result in search_results:
                if result.get('type') == 'pricing_info' and result.get('confidence', 0) > 0.7:
                    # Extract pricing from search result
                    pricing_data = result.get('pricing_data', {})
                    
                    for model, pricing in pricing_data.items():
                        if isinstance(pricing, dict) and 'input_cost' in pricing and 'output_cost' in pricing:
                            update = PricingUpdate(
                                provider=provider,
                                model=model,
                                input_cost=float(pricing['input_cost']),
                                output_cost=float(pricing['output_cost']),
                                source="web_search_agent",
                                confidence=result.get('confidence', 0.8)
                            )
                            updates.append(update)
                            
        except Exception as e:
            logger.error(f"Web search results parsing failed: {e}")
        
        return updates
    
    async def _parse_research_validation_results(self, provider: str, validation_results: List[Dict]) -> List[PricingUpdate]:
        """Parse research validation agent results for pricing data"""
        updates = []
        
        try:
            for result in validation_results:
                if result.get('validation_type') == 'pricing_verification' and result.get('validated'):
                    # Extract validated pricing data
                    pricing_info = result.get('validated_data', {})
                    
                    if 'pricing_models' in pricing_info:
                        for model_data in pricing_info['pricing_models']:
                            update = PricingUpdate(
                                provider=provider,
                                model=model_data.get('model_name'),
                                input_cost=float(model_data.get('input_cost_per_1k', 0)),
                                output_cost=float(model_data.get('output_cost_per_1k', 0)),
                                source="research_validation_agent",
                                confidence=result.get('confidence_score', 0.9)
                            )
                            updates.append(update)
                            
        except Exception as e:
            logger.error(f"Research validation results parsing failed: {e}")
        
        return updates
    
    async def _parse_llm_service_response(self, provider: str, llm_response: str) -> List[PricingUpdate]:
        """Parse LLM service response for pricing data"""
        updates = []
        
        try:
            # Try to extract JSON from LLM service response
            import re
            json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)
            if json_match:
                pricing_data = json.loads(json_match.group())
                
                # Process pricing data from LLM service
                if 'pricing_data' in pricing_data:
                    for model_pricing in pricing_data['pricing_data']:
                        update = PricingUpdate(
                            provider=provider,
                            model=model_pricing.get('model'),
                            input_cost=float(model_pricing.get('input_cost_per_1k', 0)),
                            output_cost=float(model_pricing.get('output_cost_per_1k', 0)),
                            source="llm_service_analysis",
                            confidence=model_pricing.get('confidence', pricing_data.get('extraction_confidence', 0.85))
                        )
                        updates.append(update)
                        
        except Exception as e:
            logger.error(f"LLM service response parsing failed: {e}")
        
        return updates
    
    async def _fetch_pricing_content(self, url: str) -> str:
        """Fetch content from pricing page for LLM analysis"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (compatible; PlugPipe-FactFinder/1.0)'
                }
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        return await response.text()
        except Exception as e:
            logger.warning(f"Failed to fetch content from {url}: {e}")
        
        return ""
    
    async def _make_llm_request(self, prompt: str, llm_config: Dict) -> Optional[str]:
        """Make request to LLM for pricing analysis"""
        try:
            # This is a simplified implementation for Ollama
            # In production, you'd use the actual LLM client
            import aiohttp
            
            ollama_url = f"{llm_config['endpoint']}/api/generate"
            payload = {
                "model": llm_config['model'],
                "prompt": prompt,
                "stream": False
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(ollama_url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('response', '')
                        
        except Exception as e:
            logger.warning(f"LLM request failed: {e}")
        
        return None
    
    async def _validate_pricing_with_agents(self, update: PricingUpdate) -> bool:
        """Validate pricing update using PlugPipe agents"""
        try:
            # Basic validation
            if update.input_cost < 0 or update.output_cost < 0:
                return False
            
            # Use financial verification agent if available
            if self.financial_verification_agent:
                validation_config = {
                    "operation": "create_agent",
                    "agent_type": "pricing_validator",
                    "validation_data": {
                        "provider": update.provider,
                        "model": update.model,
                        "input_cost": update.input_cost,
                        "output_cost": update.output_cost,
                        "source": update.source
                    },
                    "validation_criteria": [
                        "Verify pricing is within reasonable market range",
                        "Cross-check against known provider pricing patterns",
                        "Validate pricing format and currency consistency",
                        "Check for suspicious pricing anomalies"
                    ]
                }
                
                validation_result = await self.financial_verification_agent.process({}, validation_config)
                
                if validation_result.get('success'):
                    # Update confidence based on agent validation
                    agent_confidence = validation_result.get('confidence_score', 0.5)
                    update.confidence = min(update.confidence, agent_confidence)
                    
                    # Check validation warnings
                    if validation_result.get('warnings'):
                        logger.warning(f"Agent validation warnings for {update.provider}/{update.model}: {validation_result['warnings']}")
                    
                    return validation_result.get('validation_passed', True)
            
            # Fallback to basic validation
            # Reasonable price range validation (per 1K tokens)
            if update.input_cost > 1.0 or update.output_cost > 1.0:  # $1 per 1K tokens seems excessive
                logger.warning(f"Suspicious pricing: {update.provider}/{update.model} - ${update.input_cost}/${update.output_cost}")
                return False
            
            # Check against historical data for major deviations
            historical_avg = await self._get_historical_average(update.provider, update.model)
            if historical_avg:
                change_percent = abs((update.input_cost - historical_avg) / historical_avg) * 100
                if change_percent > 200:  # 200% change seems suspicious
                    logger.warning(f"Major price deviation detected: {change_percent:.1f}% for {update.provider}/{update.model}")
                    update.confidence *= 0.5  # Reduce confidence
            
            return True
            
        except Exception as e:
            logger.error(f"Agent-based pricing validation failed: {e}")
            return False
    
    async def _check_price_changes(self, update: PricingUpdate) -> Optional[PricingAlert]:
        """Check for significant price changes and generate alerts"""
        try:
            # Get previous pricing
            previous_price = await self._get_previous_price(update.provider, update.model)
            if not previous_price:
                return None
            
            # Calculate change percentage
            change_percent = ((update.input_cost - previous_price) / previous_price) * 100
            update.change_percentage = change_percent
            
            # Determine alert severity
            abs_change = abs(change_percent)
            severity = "info"
            
            if abs_change >= self.ALERT_THRESHOLDS['critical']:
                severity = "critical"
            elif abs_change >= self.ALERT_THRESHOLDS['major']:
                severity = "major"
            elif abs_change >= self.ALERT_THRESHOLDS['moderate']:
                severity = "moderate"
            elif abs_change >= self.ALERT_THRESHOLDS['minor']:
                severity = "minor"
            else:
                return None  # No alert needed for small changes
            
            # Create alert
            direction = "increased" if change_percent > 0 else "decreased"
            alert = PricingAlert(
                provider=update.provider,
                model=update.model,
                old_price=previous_price,
                new_price=update.input_cost,
                change_percentage=change_percent,
                severity=severity,
                message=f"{update.provider}/{update.model} pricing {direction} by {abs_change:.1f}% (${previous_price:.4f} → ${update.input_cost:.4f})"
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Price change check failed: {e}")
            return None
    
    async def _get_historical_average(self, provider: str, model: str) -> Optional[float]:
        """Get historical average pricing for validation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get average from last 30 days
            since_date = (datetime.utcnow() - timedelta(days=30)).isoformat()
            cursor.execute('''
                SELECT AVG(input_cost) FROM pricing_updates
                WHERE provider = ? AND model = ? AND timestamp >= ?
            ''', (provider, model, since_date))
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result and result[0] else None
            
        except Exception as e:
            logger.error(f"Historical average query failed: {e}")
            return None
    
    async def _get_previous_price(self, provider: str, model: str) -> Optional[float]:
        """Get most recent price for comparison"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT input_cost FROM pricing_updates
                WHERE provider = ? AND model = ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (provider, model))
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
            
        except Exception as e:
            logger.error(f"Previous price query failed: {e}")
            return None
    
    async def _store_pricing_update(self, update: PricingUpdate):
        """Store pricing update in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO pricing_updates 
                (provider, model, input_cost, output_cost, currency, source, confidence, timestamp, change_percentage)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (update.provider, update.model, update.input_cost, update.output_cost,
                 update.currency, update.source, update.confidence, update.timestamp, update.change_percentage))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Store pricing update failed: {e}")
    
    async def _store_pricing_alert(self, alert: PricingAlert):
        """Store pricing alert in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO pricing_alerts 
                (provider, model, old_price, new_price, change_percentage, severity, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (alert.provider, alert.model, alert.old_price, alert.new_price,
                 alert.change_percentage, alert.severity, alert.message, alert.timestamp))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Store pricing alert failed: {e}")
    
    async def _update_cost_estimator(self, updates: List[PricingUpdate]):
        """Update cost estimator with new pricing data"""
        try:
            estimator = self._get_cost_estimator()
            if not estimator:
                logger.warning("Cost estimator not available for updates")
                return
            
            # Update pricing tables in cost estimator
            for update in updates:
                if hasattr(estimator, 'PROVIDER_PRICING'):
                    if update.provider not in estimator.PROVIDER_PRICING:
                        estimator.PROVIDER_PRICING[update.provider] = {}
                    
                    estimator.PROVIDER_PRICING[update.provider][update.model] = {
                        'input': update.input_cost,
                        'output': update.output_cost
                    }
            
            logger.info(f"✅ Updated cost estimator with {len(updates)} pricing updates")
            
        except Exception as e:
            logger.error(f"Cost estimator update failed: {e}")
    
    async def _start_discovery_job(self, job_type: str, providers: List[str]) -> int:
        """Start a discovery job and return job ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO discovery_jobs (job_type, status, start_time)
                VALUES (?, ?, ?)
            ''', (job_type, 'running', datetime.utcnow().isoformat()))
            
            job_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return job_id
            
        except Exception as e:
            logger.error(f"Start discovery job failed: {e}")
            return 0
    
    async def _complete_discovery_job(self, job_id: int, providers_checked: int, updates: int, alerts: int):
        """Complete discovery job with results"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE discovery_jobs 
                SET status = ?, end_time = ?, providers_checked = ?, updates_found = ?, alerts_generated = ?
                WHERE id = ?
            ''', ('completed', datetime.utcnow().isoformat(), providers_checked, updates, alerts, job_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Complete discovery job failed: {e}")
    
    async def _fail_discovery_job(self, job_id: int, error: str):
        """Mark discovery job as failed"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE discovery_jobs 
                SET status = ?, end_time = ?, error_message = ?
                WHERE id = ?
            ''', ('failed', datetime.utcnow().isoformat(), error, job_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Fail discovery job failed: {e}")
    
    async def get_pricing_alerts(self, hours: int = 24, severity: str = None) -> Dict[str, Any]:
        """Get pricing alerts from the specified time period"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query
            conditions = []
            params = []
            
            # Time window
            since_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            conditions.append("timestamp >= ?")
            params.append(since_time)
            
            # Severity filter
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            where_clause = "WHERE " + " AND ".join(conditions)
            
            cursor.execute(f'''
                SELECT provider, model, old_price, new_price, change_percentage, 
                       severity, message, timestamp
                FROM pricing_alerts 
                {where_clause}
                ORDER BY timestamp DESC
            ''', params)
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    "provider": row[0],
                    "model": row[1],
                    "old_price": row[2],
                    "new_price": row[3],
                    "change_percentage": row[4],
                    "severity": row[5],
                    "message": row[6],
                    "timestamp": row[7]
                })
            
            conn.close()
            
            return {
                "success": True,
                "alerts": alerts,
                "total_alerts": len(alerts),
                "time_window_hours": hours
            }
            
        except Exception as e:
            logger.error(f"Get pricing alerts failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_discovery_history(self, limit: int = 10) -> Dict[str, Any]:
        """Get discovery job history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT job_type, status, providers_checked, updates_found, 
                       alerts_generated, start_time, end_time, error_message
                FROM discovery_jobs
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))
            
            jobs = []
            for row in cursor.fetchall():
                jobs.append({
                    "job_type": row[0],
                    "status": row[1],
                    "providers_checked": row[2] or 0,
                    "updates_found": row[3] or 0,
                    "alerts_generated": row[4] or 0,
                    "start_time": row[5],
                    "end_time": row[6],
                    "error_message": row[7]
                })
            
            conn.close()
            
            return {
                "success": True,
                "discovery_jobs": jobs,
                "total_jobs": len(jobs)
            }
            
        except Exception as e:
            logger.error(f"Get discovery history failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }


# Plugin metadata
plug_metadata = {
    "name": "llm_cost_fact_finder",
    "owner": "plugpipe_ai_team",
    "version": "1.0.0",
    "status": "stable",
    "description": "AI-powered fact-finder agents for dynamic LLM cost discovery and real-time pricing updates",
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["discover_pricing", "get_alerts", "get_discovery_history"]
            },
            "providers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of providers to check (optional)"
            },
            "hours": {
                "type": "integer",
                "description": "Time window for alerts/history (default: 24)"
            },
            "severity": {
                "type": "string",
                "enum": ["minor", "moderate", "major", "critical"],
                "description": "Filter alerts by severity"
            },
            "limit": {
                "type": "integer",
                "description": "Limit for history results (default: 10)"
            }
        },
        "required": ["operation"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "job_id": {"type": "integer"},
            "providers_checked": {"type": "integer"},
            "pricing_updates": {"type": "array"},
            "alerts_generated": {"type": "array"},
            "total_updates": {"type": "integer"},
            "total_alerts": {"type": "integer"},
            "discovery_jobs": {"type": "array"},
            "alerts": {"type": "array"},
            "timestamp": {"type": "string"},
            "error": {"type": "string"}
        }
    }
}

# Global fact-finder instance
fact_finder = None

def get_fact_finder():
    """Get or create the global fact-finder instance"""
    global fact_finder
    if fact_finder is None:
        fact_finder = LLMCostFactFinder()
    return fact_finder


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point
    
    Operations:
    - discover_pricing: Run fact-finder to discover pricing updates
    - get_alerts: Get pricing change alerts  
    - get_discovery_history: Get discovery job history
    """
    operation = cfg.get('operation', 'discover_pricing')
    
    try:
        finder = get_fact_finder()
        
        if operation == 'discover_pricing':
            return await finder.discover_pricing_updates(
                providers=cfg.get('providers')
            )
        
        elif operation == 'get_alerts':
            return await finder.get_pricing_alerts(
                hours=cfg.get('hours', 24),
                severity=cfg.get('severity')
            )
        
        elif operation == 'get_discovery_history':
            return await finder.get_discovery_history(
                limit=cfg.get('limit', 10)
            )
        
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "supported_operations": [
                    "discover_pricing", "get_alerts", "get_discovery_history"
                ]
            }
    
    except Exception as e:
        logger.error(f"❌ Fact-finder operation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test the plugin
    async def test_fact_finder():
        """Test fact-finder functionality"""
        print("🔍 Testing LLM Cost Fact-Finder Plugin...")
        
        # Test pricing discovery
        result = await process({}, {
            'operation': 'discover_pricing',
            'providers': ['openai', 'anthropic']
        })
        print(f"Pricing Discovery: {result}")
        
        # Test alerts
        result = await process({}, {
            'operation': 'get_alerts',
            'hours': 24
        })
        print(f"Pricing Alerts: {result}")
        
        # Test discovery history
        result = await process({}, {
            'operation': 'get_discovery_history',
            'limit': 5
        })
        print(f"Discovery History: {result}")
        
        print("✅ Fact-finder tests completed!")
    
    asyncio.run(test_fact_finder())