# Contributing to PlugPipe Plugins

Thank you for contributing to the PlugPipe plugin ecosystem!

## Contribution Guidelines

### Plugin Structure

All plugins must follow the standard structure:

```
plugs/category/plugin_name/version/
├── plug.yaml              # Required: Plugin manifest
├── main.py                # Required: Plugin implementation
├── README.md              # Required: Documentation
├── requirements.txt       # Optional: Python dependencies
└── tests/                 # Optional: Plugin tests
```

### Manifest Requirements

Every `plug.yaml` must include:

```yaml
name: plugin_name                    # Required: Lowercase with underscores
version: 1.0.0                       # Required: Semantic versioning
display_name: "Professional Name"    # Required: User-facing name
description: "Plugin description"    # Required: Clear description
category: category_name              # Required: Plugin category
author: "Your Name"                  # Required: Author name
copyright: "Copyright 2025 Your Name"# Required: Copyright notice
license: "MIT"                       # Required: License identifier
```

### Copyright Requirements

All Python files must include SPDX header:

```python
# SPDX-License-Identifier: MIT
# Copyright 2025 Your Name
# https://github.com/${REPO_FULL_NAME}
```

### Quality Standards

- ✅ Schema validation passes
- ✅ Copyright headers present
- ✅ Documentation complete
- ✅ No security vulnerabilities
- ✅ Tests included (recommended)

## Contribution Process

1. **Fork** the repository
2. **Create branch**: `git checkout -b feature/your-plugin-name`
3. **Add plugin** to appropriate category directory
4. **Test locally**: Run validation scripts
5. **Commit**: Use conventional commits
6. **Push**: `git push origin feature/your-plugin-name`
7. **Create Pull Request**: Describe your plugin

## Questions?

- Open an issue for questions
- Email: plugins@plugpipe.com
