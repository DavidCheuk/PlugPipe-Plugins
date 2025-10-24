---
name: Bug Report
about: Report a bug or issue with an existing plugin
title: '[BUG] '
labels: bug
assignees: ''
---

## Bug Description

**Plugin Name**: `plugin_name`
**Plugin Version**: `1.0.0`

**Clear description of the bug**:
<!-- What happened that shouldn't have? -->

---

## Steps to Reproduce

1. Step 1
2. Step 2
3. Step 3

**Minimal code to reproduce**:
```python
# Your code here
from shares.loader import pp

result = pp('plugin_name', {'param': 'value'})
```

---

## Expected Behavior

<!-- What should have happened? -->

---

## Actual Behavior

<!-- What actually happened? -->

**Error Message** (if applicable):
```
Paste full error message and stack trace
```

---

## Environment

- **PlugPipe Version**: [e.g., 1.0.0]
- **Python Version**: [e.g., 3.11]
- **Operating System**: [e.g., Ubuntu 22.04, macOS 14, Windows 11]
- **Installation Method**: [pip, git clone, docker]

**Plugin Discovery Method**:
- [ ] Local filesystem
- [ ] GitHub backend
- [ ] SQLite cache
- [ ] Other: _______

---

## Additional Context

<!-- Any additional information, screenshots, or context -->

**Related Issues**: #

**Workaround** (if known):
