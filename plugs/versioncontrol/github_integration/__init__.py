# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

# github_integration plugin - fixed versioned import
import importlib.util
import os

# Import from versioned directory
plugin_path = os.path.join(os.path.dirname(__file__), "1.0.0", "main.py")
spec = importlib.util.spec_from_file_location("github_integration_main", plugin_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Export the main functions
process = module.process
plug_metadata = module.plug_metadata
