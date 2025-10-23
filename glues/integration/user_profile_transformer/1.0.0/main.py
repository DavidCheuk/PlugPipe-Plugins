# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
User Profile Transformer Glue
Transforms user profiles between System A and System B formats
"""

def process(ctx, cfg):
    """Transform user profile between systems"""

    # Basic validation
    if not cfg:
        return {
            "status": "error",
            "error": "No configuration provided"
        }

    operation = cfg.get("operation", "transform")

    if operation == "transform":
        source_profile = cfg.get("source_profile", {})

        if not source_profile:
            return {
                "status": "error",
                "error": "No source_profile provided"
            }

        # Transform System A format to System B format
        transformed_profile = {
            "id": source_profile.get("user_id", "unknown"),
            "name": source_profile.get("full_name", ""),
            "email": source_profile.get("email_address", ""),
            "role": source_profile.get("user_role", "user"),
            "created": source_profile.get("created_date", ""),
            "active": source_profile.get("is_active", True)
        }

        return {
            "status": "success",
            "operation": "transform",
            "source_schema": "system_a_user",
            "target_schema": "system_b_user",
            "transformed_profile": transformed_profile,
            "transformation_count": 1
        }

    elif operation == "health_check":
        return {
            "status": "success",
            "message": "User Profile Transformer is healthy",
            "supported_operations": ["transform", "health_check"]
        }

    else:
        return {
            "status": "error",
            "error": f"Unknown operation: {operation}",
            "supported_operations": ["transform", "health_check"]
        }

if __name__ == "__main__":
    # Test the transformer
    test_ctx = {}
    test_cfg = {
        "operation": "transform",
        "source_profile": {
            "user_id": "12345",
            "full_name": "John Doe",
            "email_address": "john@example.com",
            "user_role": "admin",
            "created_date": "2025-01-01",
            "is_active": True
        }
    }

    result = process(test_ctx, test_cfg)
    print(f"Test result: {result}")