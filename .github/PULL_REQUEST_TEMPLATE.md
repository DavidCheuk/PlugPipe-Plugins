# Plugin Submission Checklist

## Plugin Information

**Plugin Name**: `plugin_name` (lowercase_with_underscores)
**Version**: `1.0.0` (semantic versioning)
**Category**: `category_name`
**Author**: Your Name

## Pre-Submission Validation Checklist

### ✅ Required (Must Pass for Approval)

- [ ] **Schema Validation**: Plugin manifest follows [min_plug_schema.json](https://github.com/DavidCheuk/PlugPipe/blob/main/schemas/min_plug_schema.json)
- [ ] **Copyright Headers**: All Python files include SPDX header (`# SPDX-License-Identifier: MIT`)
- [ ] **Manifest Copyright**: `plug.yaml` includes copyright field
- [ ] **README Documentation**: Complete usage examples and API documentation
- [ ] **Naming Convention**: Uses underscores (not hyphens) in plugin name
- [ ] **A2A Compliance**: Plugin supports agent-to-agent protocol (DEFAULT requirement)
  - [ ] `agent-card.json` generated or can be generated
  - [ ] Stateless invocation supported (no persistent instance state)
  - [ ] Standard `execute()` function implemented

### ⚠️ Recommended (Improves Quality Score)

- [ ] **Tests Included**: Unit tests in `tests/` directory
- [ ] **SBOM Generated**: Software bill of materials for dependencies
- [ ] **Security Scan**: No vulnerabilities detected in dependencies
- [ ] **Examples Provided**: Working examples in README or `examples/` directory

### 🔒 Security-Specific (If Security Plugin)

- [ ] **Input Validation**: Uses `universal_input_sanitizer` for user inputs
- [ ] **MCP Guardian**: If MCP plugin, includes `mcp_guardian` dependency

### 📋 Optional (For MCP Plugins Only)

- [ ] **MCP Opt-In**: Manifest includes `mcp_server: true` or `mcp` in name
- [ ] **MCP Compliance**: Plugin passes MCP protocol validation

---

## Changes Description

<!-- Describe what this plugin does and why it's useful -->

**Purpose**:
**Key Features**:
- Feature 1
- Feature 2

**Use Cases**:
- Use case 1
- Use case 2

---

## Testing Performed

<!-- How did you test this plugin? -->

**Local Testing**:
```bash
# Commands you ran to validate
./pp run my_plugin --test
```

**Expected Behavior**:
**Actual Behavior**:

---

## Quality Score Preview

<!-- Run local validation and paste results here -->

**Estimated Score**: XX/100 (Grade: X)

**Validation Results**:
```
# Paste output from local validation
```

**Known Issues** (if score < 90):
- Issue 1: Description and plan to fix
- Issue 2: Description and plan to fix

---

## Dependencies

**External Dependencies** (from `requirements.txt`):
- dependency-1==1.0.0
- dependency-2>=2.0.0

**Plugin Dependencies** (from manifest):
- plugin_dependency_1
- plugin_dependency_2

**No Known Vulnerabilities**: [ ] Yes / [ ] No (if No, explain below)

---

## Additional Notes

<!-- Any additional context, questions, or concerns -->

---

## Contributor Agreement

By submitting this PR, I confirm that:

- [ ] I have read and agree to the [Contributing Guidelines](CONTRIBUTING.md)
- [ ] This code is my original work or properly attributed
- [ ] I grant PlugPipe Team permission to use this plugin under MIT license
- [ ] I have tested this plugin and verified it works as documented
- [ ] I understand plugins may be rejected if quality score < 70

---

**For Maintainers**: Quality scoring will run automatically. Manual review required for scores 70-89.
