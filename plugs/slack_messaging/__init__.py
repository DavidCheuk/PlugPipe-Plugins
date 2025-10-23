# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

# slack_messaging plugin
import sys
import os
from pathlib import Path

plugin_path = Path(__file__).parent / "1.0.0" / "main.py"
if plugin_path.exists():
    import importlib.util
    spec = importlib.util.spec_from_file_location("main", plugin_path)
    main_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main_module)
    
    process = main_module.process
    plug_metadata = main_module.plug_metadata
else:
    def process(ctx, cfg):
        return {"error": "Plugin not found", "status": "error"}
    
    plug_metadata = {
        "name": "slack_messaging",
        "version": "1.0.0",
        "description": "Slack messaging plugin",
        "status": "stable"
    }
