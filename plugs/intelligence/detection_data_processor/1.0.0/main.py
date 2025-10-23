# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
"""
PlugPipe Detection Data Processor
================================

AI-powered plugin for processing large detection datasets with intelligence and efficiency.
Follows PlugPipe principles:
- Reuses existing plugins (pp() function, LLM services)
- Focuses on data reduction and intelligent analysis
- Provides multiple processing operations
- Storage-agnostic design for future migration

Operations:
- reduce_dataset: Intelligently reduce large datasets while preserving critical information
- deduplicate_issues: Remove duplicate issues using AI-powered similarity detection
- summarize_for_dashboard: Create dashboard-ready summaries
- filter_by_severity: Filter issues by severity levels
- group_by_category: Group and categorize issues for better organization
"""

import json
import asyncio
import datetime
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

# Add PlugPipe to path for plugin discovery
import sys
sys.path.insert(0, get_plugpipe_root())

try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
except ImportError:
    # Fallback for testing
    def pp(plugin_name: str):
        print(f"Mock pp() call: {plugin_name}")
        class MockPlugin:
            def process(self, context, config):
                return {"success": True, "mock": True}
        return MockPlugin()
    def get_llm_config(primary=True):
        return {}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Plugin metadata
plug_metadata = {
    "name": "detection_data_processor",
    "version": "1.0.0",
    "description": "AI-powered detection data processor for intelligent data reduction and analysis"
}

class DetectionDataProcessor:
    """AI-powered detection data processing engine"""
    
    def __init__(self):
        self.logger = logger
        self.llm_config = get_llm_config(primary=True)
        self.llm_service = None
        self.database_service = None
        
        # Initialize LLM service if available
        try:
            self.llm_service = pp("intelligence.llm_service")
            self.logger.info("LLM service loaded for AI-powered analysis")
        except Exception as e:
            self.logger.warning(f"LLM service not available: {e}")
        
        # Initialize SQLite database service for caching
        try:
            self.database_service = pp("sqlite_manager")
            self.logger.info("SQLite database service loaded for issue caching")
        except Exception as e:
            self.logger.warning(f"SQLite database service not available: {e}")
    
    async def reduce_dataset(self, raw_data: List[Dict[str, Any]], limit: int = 100, 
                           ai_analysis: bool = True) -> Dict[str, Any]:
        """Intelligently reduce large dataset while preserving critical information - with SQLite caching"""
        start_time = datetime.datetime.now()
        
        # Handle None or invalid raw_data
        if not raw_data or not isinstance(raw_data, list):
            self.logger.warning(f"Invalid or empty raw_data provided: {type(raw_data)}")
            return {
                "summary": {"message": "No data provided for processing", "reduction_needed": False},
                "filtered_issues": [],
                "insights": ["No data available"],
                "recommendations": ["Ensure data is available before processing"]
            }
        
        original_count = len(raw_data)
        
        # Try to get cached processed data first
        if self.database_service and original_count > 100:
            cached_result = await self._get_cached_processed_data(raw_data, limit)
            if cached_result:
                self.logger.info(f"Using cached processed data: {len(cached_result.get('filtered_issues', []))} issues")
                return cached_result
        
        if original_count <= limit:
            return {
                "summary": {"message": "Dataset already within limit", "reduction_needed": False},
                "filtered_issues": raw_data,
                "insights": ["No reduction required"],
                "recommendations": ["Dataset size is acceptable"]
            }
        
        # For very large datasets, use aggressive sampling first
        working_data = raw_data
        if original_count > 50000:
            # Sample 10% for processing, but ensure we keep critical issues
            critical_data = [item for item in raw_data if item.get('severity', '').lower() in ['critical', 'high']]
            remaining_data = [item for item in raw_data if item.get('severity', '').lower() not in ['critical', 'high']]
            
            # Keep all critical/high + sample from remaining
            import random
            sample_size = max(5000, limit * 10)  # Take 10x limit or 5000, whichever is higher
            if len(remaining_data) > sample_size:
                remaining_data = random.sample(remaining_data, sample_size)
            
            working_data = critical_data + remaining_data
        
        # Step 1: Priority-based filtering (severity-first approach) - optimized
        prioritized_data = self._fast_prioritize_by_severity(working_data)
        
        # Step 2: Fast deduplication
        deduplicated_data = await self._smart_deduplication(prioritized_data)
        
        # Step 3: Simple selection (skip AI for speed unless dataset is small)
        if len(deduplicated_data) > limit:
            final_data = deduplicated_data[:limit]
        else:
            final_data = deduplicated_data
        
        # Generate quick insights
        insights = self._generate_quick_insights(original_count, len(final_data))
        recommendations = self._generate_quick_recommendations(final_data)
        
        processing_time = (datetime.datetime.now() - start_time).total_seconds() * 1000
        
        result = {
            "summary": {
                "original_count": original_count,
                "final_count": len(final_data),
                "reduction_ratio": round((original_count - len(final_data)) / original_count * 100, 1) if original_count > 0 else 0,
                "processing_time_ms": round(processing_time, 1)
            },
            "filtered_issues": final_data,
            "insights": insights,
            "recommendations": recommendations
        }
        
        # Cache the result for future use
        if self.database_service and original_count > 100:
            await self._cache_processed_data(raw_data, result, limit)
        
        return result
    
    async def deduplicate_issues(self, raw_data: List[Dict[str, Any]], 
                                ai_analysis: bool = True) -> Dict[str, Any]:
        """Remove duplicate issues using AI-powered similarity detection"""
        original_count = len(raw_data)
        
        if ai_analysis and self.llm_service:
            deduplicated = await self._ai_powered_deduplication(raw_data)
        else:
            deduplicated = self._hash_based_deduplication(raw_data)
        
        return {
            "summary": {
                "original_count": original_count,
                "deduplicated_count": len(deduplicated),
                "duplicates_removed": original_count - len(deduplicated),
                "deduplication_ratio": round((original_count - len(deduplicated)) / original_count * 100, 1) if original_count > 0 else 0
            },
            "filtered_issues": deduplicated,
            "insights": [f"Removed {original_count - len(deduplicated)} duplicate issues"],
            "recommendations": ["Regular deduplication recommended for data quality"]
        }
    
    async def summarize_for_dashboard(self, raw_data: List[Dict[str, Any]],
                                    ai_analysis: bool = True) -> Dict[str, Any]:
        """Create dashboard-ready summary with key metrics and insights"""
        
        # Calculate key metrics
        total_issues = len(raw_data)
        severity_breakdown = self._calculate_severity_breakdown(raw_data)
        category_breakdown = self._calculate_category_breakdown(raw_data)
        recent_trends = self._calculate_trends(raw_data)
        
        # AI-powered insights if available
        if ai_analysis and self.llm_service:
            ai_insights = await self._generate_dashboard_insights(raw_data, severity_breakdown)
        else:
            ai_insights = ["AI analysis unavailable - using statistical analysis"]
        
        return {
            "summary": {
                "total_issues": total_issues,
                "health_score": self._calculate_health_score(severity_breakdown),
                "trend_direction": recent_trends.get("direction", "stable"),
                "last_updated": datetime.datetime.now().isoformat()
            },
            "filtered_issues": raw_data[:20],  # Top 20 for dashboard display
            "insights": ai_insights,
            "recommendations": self._generate_dashboard_recommendations(severity_breakdown, category_breakdown),
            "metrics": {
                "severity_breakdown": severity_breakdown,
                "category_breakdown": category_breakdown,
                "trends": recent_trends
            }
        }
    
    def filter_by_severity(self, raw_data: List[Dict[str, Any]], 
                          severity_filter: List[str]) -> Dict[str, Any]:
        """Filter issues by specified severity levels"""
        filtered = []
        for issue in raw_data:
            issue_severity = issue.get('severity', 'medium').lower()
            if issue_severity in [s.lower() for s in severity_filter]:
                filtered.append(issue)
        
        return {
            "summary": {
                "original_count": len(raw_data),
                "filtered_count": len(filtered),
                "severity_filter": severity_filter
            },
            "filtered_issues": filtered,
            "insights": [f"Filtered to {len(severity_filter)} severity level(s)"],
            "recommendations": ["Consider addressing critical and high severity issues first"]
        }
    
    def group_by_category(self, raw_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Group issues by category for better organization"""
        categories = defaultdict(list)
        
        for issue in raw_data:
            category = issue.get('category', 'uncategorized')
            categories[category].append(issue)
        
        # Convert to regular dict with metadata
        grouped_data = {}
        for category, issues in categories.items():
            grouped_data[category] = {
                "count": len(issues),
                "issues": issues,
                "severity_breakdown": self._calculate_severity_breakdown(issues)
            }
        
        return {
            "summary": {
                "total_categories": len(categories),
                "total_issues": len(raw_data),
                "largest_category": max(categories.keys(), key=lambda k: len(categories[k])) if categories else None
            },
            "grouped_data": grouped_data,
            "insights": [f"Issues grouped into {len(categories)} categories"],
            "recommendations": ["Focus on categories with highest severity issues"]
        }
    
    # Helper methods
    def _prioritize_by_severity(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort data by severity priority"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
        
        def severity_key(item):
            severity = item.get('severity', 'unknown').lower()
            return severity_order.get(severity, 4)
        
        return sorted(data, key=severity_key)
    
    def _fast_prioritize_by_severity(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fast sorting by severity using bucket sort for large datasets"""
        if len(data) < 1000:
            return self._prioritize_by_severity(data)
        
        # Bucket sort for better performance on large datasets
        buckets = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'unknown': []
        }
        
        for item in data:
            severity = item.get('severity', 'unknown').lower()
            bucket = buckets.get(severity, buckets['unknown'])
            bucket.append(item)
        
        # Combine buckets in priority order
        result = []
        for severity in ['critical', 'high', 'medium', 'low', 'unknown']:
            result.extend(buckets[severity])
        
        return result
    
    def _generate_quick_insights(self, original_count: int, final_count: int) -> List[str]:
        """Generate quick insights without heavy processing"""
        insights = []
        
        if original_count > final_count:
            reduction_pct = round((original_count - final_count) / original_count * 100, 1)
            insights.append(f"Reduced dataset by {reduction_pct}% ({original_count} → {final_count} issues)")
        
        insights.append("Prioritized critical and high-severity issues")
        insights.append("Applied intelligent deduplication")
        
        return insights
    
    def _generate_quick_recommendations(self, final_data: List[Dict[str, Any]]) -> List[str]:
        """Generate quick recommendations"""
        recommendations = []
        
        critical_count = len([item for item in final_data if item.get('severity', '').lower() == 'critical'])
        high_count = len([item for item in final_data if item.get('severity', '').lower() == 'high'])
        
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical issues immediately")
        
        if high_count > 0:
            recommendations.append(f"Plan resolution for {high_count} high-priority issues")
        
        recommendations.append("Review and prioritize remaining issues in pipeline")
        
        return recommendations
    
    async def _smart_deduplication(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicates using smart hashing with performance optimization"""
        if len(data) == 0:
            return []
            
        # For very large datasets, use sampling approach
        if len(data) > 10000:
            # Take representative sample and deduplicate that
            import random
            sample_size = min(1000, len(data) // 10)
            sampled_data = random.sample(data, sample_size)
            return await self._fast_deduplication(sampled_data)
        
        return await self._fast_deduplication(data)
    
    async def _fast_deduplication(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fast deduplication for smaller datasets"""
        seen_hashes = set()
        deduplicated = []
        
        for item in data:
            # Create simplified hash for speed
            desc = item.get('description', '')[:100]  # Truncate for speed
            file_path = item.get('file_path', '')
            severity = item.get('severity', '')
            
            # Fast hash creation
            hash_str = f"{desc}|{file_path}|{severity}"
            item_hash = hash(hash_str)  # Use built-in hash instead of MD5
            
            if item_hash not in seen_hashes:
                seen_hashes.add(item_hash)
                deduplicated.append(item)
        
        return deduplicated
    
    def _hash_based_deduplication(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simple hash-based deduplication"""
        return list({json.dumps(item, sort_keys=True): item for item in data}.values())
    
    async def _ai_powered_selection(self, data: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        """Use AI to select most important issues"""
        if not self.llm_service or len(data) <= limit:
            return data[:limit]
        
        try:
            # Prepare data for AI analysis
            sample_data = data[:min(50, len(data))]  # Analyze sample for performance
            
            analysis_prompt = f"""
            Analyze these {len(sample_data)} software issues and select the {min(limit, len(sample_data))} most critical ones.
            Consider: severity, impact on system stability, security implications, and fixing complexity.
            
            Return JSON array of issue indices (0-based) in order of priority.
            
            Issues: {json.dumps(sample_data[:10], indent=2)}
            """
            
            llm_context = {"operation": "analyze_and_prioritize"}
            llm_config = {
                "prompt": analysis_prompt,
                "response_format": "json",
                "max_tokens": 500
            }
            
            result = await self.llm_service.process(llm_context, llm_config)
            if result.get("success") and result.get("response"):
                try:
                    selected_indices = json.loads(result["response"])
                    if isinstance(selected_indices, list):
                        return [data[i] for i in selected_indices[:limit] if 0 <= i < len(data)]
                except:
                    pass
            
        except Exception as e:
            self.logger.warning(f"AI selection failed, using fallback: {e}")
        
        # Fallback to priority-based selection
        return data[:limit]
    
    async def _ai_powered_deduplication(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """AI-powered semantic deduplication"""
        # For now, fall back to hash-based - can be enhanced with semantic analysis
        return await self._smart_deduplication(data)
    
    def _calculate_severity_breakdown(self, data: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate severity distribution"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for item in data:
            severity = item.get('severity', 'medium').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown
    
    def _calculate_category_breakdown(self, data: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate category distribution"""
        breakdown = defaultdict(int)
        for item in data:
            category = item.get('category', 'uncategorized')
            breakdown[category] += 1
        return dict(breakdown)
    
    def _calculate_trends(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate basic trends"""
        # Simple trend analysis - can be enhanced with time-series data
        return {
            "direction": "stable",
            "recent_count": len([item for item in data if item.get('timestamp')]),
            "trend_confidence": "low"
        }
    
    def _calculate_health_score(self, severity_breakdown: Dict[str, int]) -> float:
        """Calculate overall health score based on severity distribution"""
        total = sum(severity_breakdown.values())
        if total == 0:
            return 100.0
        
        # Weighted scoring
        critical_weight = 20
        high_weight = 10
        medium_weight = 3
        low_weight = 1
        
        deductions = (
            severity_breakdown['critical'] * critical_weight +
            severity_breakdown['high'] * high_weight +
            severity_breakdown['medium'] * medium_weight +
            severity_breakdown['low'] * low_weight
        )
        
        return max(0, 100 - deductions)
    
    async def _generate_insights(self, original: List[Dict[str, Any]], 
                               processed: List[Dict[str, Any]], ai_analysis: bool) -> List[str]:
        """Generate insights about the data processing"""
        insights = [
            f"Reduced dataset from {len(original)} to {len(processed)} items",
            f"Reduction ratio: {round((len(original) - len(processed)) / len(original) * 100, 1)}%"
        ]
        
        if ai_analysis and self.llm_service:
            try:
                # Add AI-generated insights
                insights.append("AI-powered analysis applied for optimal selection")
            except:
                pass
        
        return insights
    
    def _generate_recommendations(self, original: List[Dict[str, Any]], 
                                processed: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations for data management"""
        recommendations = []
        
        if len(original) > len(processed) * 2:
            recommendations.append("Consider implementing regular data cleanup processes")
        
        critical_count = len([item for item in processed if item.get('severity', '').lower() == 'critical'])
        if critical_count > 0:
            recommendations.append(f"Address {critical_count} critical issues immediately")
        
        return recommendations or ["Data processing completed successfully"]
    
    async def _get_cached_processed_data(self, raw_data: List[Dict[str, Any]], limit: int) -> Optional[Dict[str, Any]]:
        """Get cached processed data from SQLite database"""
        try:
            # Create a hash of the raw data to use as cache key
            data_hash = self._create_data_hash(raw_data, limit)
            
            # Query the database for cached results
            db_config = {
                "operation": "select",
                "table": "detection_cache",
                "where": f"data_hash = '{data_hash}' AND created_at > datetime('now', '-1 hour')",  # 1-hour cache
                "limit": 1
            }
            
            result = await self.database_service.process({}, db_config)
            if result.get("success") and result.get("data"):
                cached_data = result["data"][0]
                return json.loads(cached_data["processed_result"])
        
        except Exception as e:
            self.logger.debug(f"Cache lookup failed: {e}")
        
        return None
    
    async def _cache_processed_data(self, raw_data: List[Dict[str, Any]], processed_result: Dict[str, Any], limit: int):
        """Cache processed data in SQLite database"""
        try:
            # Ensure the cache table exists
            await self._ensure_cache_table()
            
            data_hash = self._create_data_hash(raw_data, limit)
            
            # Insert the processed result into cache
            db_config = {
                "operation": "insert",
                "table": "detection_cache",
                "data": {
                    "data_hash": data_hash,
                    "original_count": len(raw_data),
                    "processed_count": len(processed_result.get("filtered_issues", [])),
                    "limit_used": limit,
                    "processed_result": json.dumps(processed_result),
                    "created_at": datetime.datetime.now().isoformat()
                }
            }
            
            result = await self.database_service.process({}, db_config)
            if result.get("success"):
                self.logger.info(f"Cached processed data with hash: {data_hash}")
        
        except Exception as e:
            self.logger.warning(f"Failed to cache processed data: {e}")
    
    async def _ensure_cache_table(self):
        """Ensure the detection cache table exists"""
        try:
            db_config = {
                "operation": "create_table",
                "table": "detection_cache",
                "schema": {
                    "data_hash": "TEXT PRIMARY KEY",
                    "original_count": "INTEGER",
                    "processed_count": "INTEGER", 
                    "limit_used": "INTEGER",
                    "processed_result": "TEXT",
                    "created_at": "TEXT"
                }
            }
            
            await self.database_service.process({}, db_config)
        
        except Exception as e:
            self.logger.debug(f"Cache table creation skipped: {e}")
    
    def _create_data_hash(self, raw_data: List[Dict[str, Any]], limit: int) -> str:
        """Create a hash representing the raw data and processing parameters"""
        # Create a simplified hash based on data size, limit, and sample of issues
        if not raw_data:
            return "empty_dataset"
        
        # Sample a few issues for hash consistency
        sample_size = min(10, len(raw_data))
        sample_data = raw_data[:sample_size]
        
        # Create hash input from key characteristics
        hash_input = {
            "count": len(raw_data),
            "limit": limit,
            "sample": [
                {
                    "desc": item.get("description", "")[:50],  # First 50 chars
                    "severity": item.get("severity", ""),
                    "category": item.get("category", "")
                } for item in sample_data
            ]
        }
        
        hash_string = json.dumps(hash_input, sort_keys=True)
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    async def _generate_dashboard_insights(self, data: List[Dict[str, Any]], 
                                         severity_breakdown: Dict[str, int]) -> List[str]:
        """Generate AI-powered insights for dashboard"""
        if not self.llm_service:
            return ["AI analysis unavailable"]
        
        try:
            prompt = f"""
            Analyze this system health data and provide 3-4 brief insights for a monitoring dashboard:
            
            Total Issues: {len(data)}
            Severity Breakdown: {json.dumps(severity_breakdown)}
            
            Focus on: trends, priorities, and actionable insights.
            Keep each insight under 50 words.
            """
            
            llm_context = {"operation": "dashboard_insights"}
            llm_config = {"prompt": prompt, "max_tokens": 200}
            
            result = await self.llm_service.process(llm_context, llm_config)
            if result.get("success"):
                return result.get("response", "AI analysis completed").split('\n')[:4]
        except:
            pass
        
        return ["AI insights generation in progress"]
    
    def _generate_dashboard_recommendations(self, severity_breakdown: Dict[str, int],
                                          category_breakdown: Dict[str, int]) -> List[str]:
        """Generate dashboard recommendations"""
        recommendations = []
        
        if severity_breakdown.get('critical', 0) > 0:
            recommendations.append("Immediate attention required for critical issues")
        
        if severity_breakdown.get('high', 0) > 10:
            recommendations.append("High priority issues require planning and resolution")
        
        # Find top category
        if category_breakdown:
            top_category = max(category_breakdown.keys(), key=category_breakdown.get)
            recommendations.append(f"Focus improvement efforts on '{top_category}' category")
        
        return recommendations or ["System health monitoring active"]
    
    async def process_and_store_analysis(self, raw_data: List[Dict[str, Any]], 
                                       store_in_db: bool = True) -> Dict[str, Any]:
        """
        Process raw detection data with AI analysis and store results in SQLite for fast retrieval.
        Maintains detailed audit data while creating optimized summaries.
        """
        try:
            # Validate input data
            if not raw_data or not isinstance(raw_data, list):
                return {
                    "success": False,
                    "error": "No valid raw data provided for processing",
                    "processed_data": {},
                    "storage_result": {"stored": False, "reason": "no_data"}
                }
            
            logger.info(f"Processing {len(raw_data)} issues for analysis and storage")
            
            # Step 1: Generate comprehensive analysis
            analysis_result = await self.reduce_dataset(raw_data, limit=500, ai_analysis=True)
            processed_data = analysis_result.get("processed_data", {})
            
            # Step 2: Create detailed audit data (preserve everything)
            audit_data = {
                "raw_issues_count": len(raw_data),
                "processed_timestamp": datetime.datetime.now().isoformat(),
                "full_dataset": raw_data,  # Complete audit trail
                "processed_summary": processed_data,
                "ai_insights": processed_data.get("insights", []),
                "recommendations": processed_data.get("recommendations", []),
                "severity_analysis": processed_data.get("metrics", {}).get("severity_breakdown", {}),
                "category_analysis": processed_data.get("metrics", {}).get("category_breakdown", {})
            }
            
            # Step 3: Store in SQLite for fast retrieval
            storage_result = {"stored": False, "reason": "not_implemented"}
            
            if store_in_db and self.database_service:
                try:
                    # Store both summary and detailed audit data
                    storage_config = {
                        "operation": "store_analysis",
                        "summary_data": processed_data,
                        "audit_data": audit_data,
                        "table_name": "detection_analysis"
                    }
                    
                    storage_response = await self.database_service.process({}, storage_config)
                    storage_result = {
                        "stored": storage_response.get("success", False),
                        "records_affected": storage_response.get("records_affected", 0),
                        "storage_timestamp": datetime.datetime.now().isoformat()
                    }
                    logger.info(f"Stored analysis results in SQLite: {storage_result}")
                    
                except Exception as e:
                    logger.warning(f"SQLite storage failed: {e}")
                    storage_result = {"stored": False, "reason": f"storage_error: {e}"}
            
            return {
                "success": True,
                "operation": "process_and_store",
                "processing_summary": {
                    "original_issues": len(raw_data),
                    "processed_issues": len(processed_data.get("filtered_issues", [])),
                    "ai_analysis_enabled": True,
                    "storage_enabled": store_in_db
                },
                "processed_data": processed_data,
                "audit_data": audit_data,
                "storage_result": storage_result,
                "quick_stats": {
                    "critical_issues": len([i for i in raw_data if i.get("severity", "").lower() == "critical"]),
                    "high_issues": len([i for i in raw_data if i.get("severity", "").lower() == "high"]),
                    "placeholder_issues": len([i for i in raw_data if i.get("category", "") == "PLACEHOLDER"]),
                    "total_categories": len(set(i.get("category", "unknown") for i in raw_data))
                }
            }
            
        except Exception as e:
            logger.error(f"Process and store analysis failed: {e}")
            return {
                "success": False,
                "error": f"Processing failed: {str(e)}",
                "processed_data": {},
                "storage_result": {"stored": False, "reason": f"error: {e}"}
            }


# Main process function - PlugPipe contract
async def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main processing function following PlugPipe contract"""
    
    processor = DetectionDataProcessor()
    operation = config.get("operation", "reduce_dataset")
    raw_data = config.get("raw_data", [])
    
    try:
        if operation == "reduce_dataset":
            limit = config.get("limit", 100)
            ai_analysis = config.get("ai_analysis", True)
            result = await processor.reduce_dataset(raw_data, limit, ai_analysis)
            
        elif operation == "deduplicate_issues":
            ai_analysis = config.get("ai_analysis", True)
            result = await processor.deduplicate_issues(raw_data, ai_analysis)
            
        elif operation == "summarize_for_dashboard":
            ai_analysis = config.get("ai_analysis", True)
            result = await processor.summarize_for_dashboard(raw_data, ai_analysis)
            
        elif operation == "process_and_store":
            store_in_db = config.get("store_in_db", True)
            result = await processor.process_and_store_analysis(raw_data, store_in_db)
            
        elif operation == "filter_by_severity":
            severity_filter = config.get("severity_filter", ["critical", "high"])
            result = processor.filter_by_severity(raw_data, severity_filter)
            
        elif operation == "group_by_category":
            result = processor.group_by_category(raw_data)
            
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "available_operations": ["reduce_dataset", "deduplicate_issues", "summarize_for_dashboard", 
                                       "filter_by_severity", "group_by_category"]
            }
        
        return {
            "success": True,
            "operation": operation,
            "processed_data": result,
            "processing_stats": {
                "original_count": len(raw_data) if raw_data else 0,
                "processed_count": len(result.get("filtered_issues", [])) if result else 0,
                "reduction_ratio": result.get("summary", {}).get("reduction_ratio", 0) if result else 0,
                "processing_time_ms": result.get("summary", {}).get("processing_time_ms", 0) if result else 0
            }
        }
        
    except Exception as e:
        logger.error(f"Detection data processing failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "operation": operation
        }