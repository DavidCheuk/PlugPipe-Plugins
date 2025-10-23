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

## Local Validation Commands

Before submitting a PR, validate your plugin locally:

### Quick Validation

```bash
# 1. Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('plugs/category/my_plugin/1.0.0/plug.yaml'))"

# 2. Verify copyright headers
find plugs/category/my_plugin -name "*.py" | while read f; do
  grep -q "SPDX-License-Identifier:" "$f" || echo "Missing: $f"
done

# 3. Check semantic versioning
grep "^version:" plugs/category/my_plugin/1.0.0/plug.yaml | grep -E "[0-9]+\.[0-9]+\.[0-9]+"

# 4. Validate required fields
python3 << 'EOF'
import yaml
data = yaml.safe_load(open('plugs/category/my_plugin/1.0.0/plug.yaml'))
required = ['name', 'version', 'category', 'description', 'copyright']
missing = [f for f in required if f not in data]
if missing:
    print(f"Missing fields: {', '.join(missing)}")
    exit(1)
else:
    print("✅ All required fields present")
EOF
```

### Pre-Commit Hooks (Recommended)

Install pre-commit hooks to automatically validate before each commit:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
cd PlugPipe-Plugins
pre-commit install

# Manually run all checks
pre-commit run --all-files
```

### Quality Score Preview

**Note**: Full quality scoring requires the main PlugPipe repository. For now, use the quick validation above. Full standalone validation toolkit coming soon.

---

## Contribution Process

### 1. Fork & Setup

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/PlugPipe-Plugins.git
cd PlugPipe-Plugins

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### 2. Create Plugin

**Option A: Use Scaffold Script (Recommended)**

```bash
# Create branch
git checkout -b feature/my-awesome-plugin

# Generate plugin structure automatically
python3 scripts/create_plugin.py plug my_plugin "Your Name" "Plugin description" [category] [version]

# Example: Create plugin in 'integration' category
python3 scripts/create_plugin.py plug api_connector "Your Name" "Connects to external APIs" integration 1.0.0

# For pipelines:
python3 scripts/create_plugin.py pipe my_workflow "Your Name" "Data processing workflow" etl 1.0.0

# For glue components:
python3 scripts/create_plugin.py glue data_transformer "Your Name" "Transform data formats" transformation 1.0.0
```

The scaffold script will create:
- ✅ Proper directory structure (plugs/category/name/version/)
- ✅ plug.yaml with all required fields
- ✅ main.py with SPDX headers and execute() function
- ✅ SBOM scaffolding
- ✅ Security-validated names and versions

**Option B: Manual Creation** (if scaffold unavailable)

```bash
# Create plugin structure manually
mkdir -p plugs/category/my_plugin/1.0.0
cd plugs/category/my_plugin/1.0.0

# Create required files
touch plug.yaml main.py README.md
```

### 3. Implement Plugin

**Required Files**:
- `plug.yaml` - Plugin manifest with all required fields
- `main.py` - Plugin implementation with SPDX header
- `README.md` - Documentation with usage examples

**Template** `plug.yaml`:
```yaml
name: my_plugin
version: 1.0.0
display_name: "My Awesome Plugin"
description: "Clear description of what this plugin does"
category: category_name
author: "Your Name"
copyright: "Copyright 2025 Your Name"
license: "MIT"
```

**Template** `main.py`:
```python
# SPDX-License-Identifier: MIT
# Copyright 2025 Your Name
# https://github.com/DavidCheuk/PlugPipe-Plugins

"""
My Awesome Plugin

Description of what this plugin does.
"""

def execute(params: dict) -> dict:
    """
    Standard PlugPipe execution function.

    Args:
        params: Dictionary of input parameters

    Returns:
        Dictionary with success status and results
    """
    action = params.get('action', 'default')

    if action == 'example':
        return {
            'success': True,
            'result': 'Example result',
            'message': 'Operation completed successfully'
        }

    return {
        'success': False,
        'error': f'Unknown action: {action}'
    }


# Plugin metadata for discovery
plug_metadata = {
    'name': 'my_plugin',
    'version': '1.0.0',
    'description': 'My awesome plugin'
}
```

### 4. Validate Plugin

**Option A: Use Validation Toolkit (Recommended)**

```bash
# Validate your plugin automatically
python3 scripts/validate_plugin.py plugs/category/my_plugin/1.0.0/

# With strict security checks
python3 scripts/validate_plugin.py plugs/category/my_plugin/1.0.0/ --strict
```

The validation toolkit checks:
- ✅ YAML syntax and required manifest fields
- ✅ SPDX copyright headers in all Python files
- ✅ Semantic versioning format (X.Y.Z)
- ✅ Plugin naming conventions (lowercase_with_underscores)
- ✅ A2A protocol compliance (execute function, stateless design)
- ✅ Basic security patterns (eval/exec usage)
- ✅ Required file structure (plug.yaml, main.py, README.md)

**Example Output**:
```
======================================================================
Validating: plugs/category/my_plugin/1.0.0
======================================================================

📁 Checking directory structure...
📋 Validating manifest...
©️  Validating copyright headers...
🔗 Validating A2A protocol compliance...

======================================================================
VALIDATION SUMMARY
======================================================================

📊 Results: 16 passed, 0 failed

✅ VALIDATION PASSED - Plugin is ready for submission!
```

**Option B: Manual Validation** (if toolkit unavailable)

```bash
# 1. Check YAML syntax
python3 -c "import yaml; yaml.safe_load(open('plugs/category/my_plugin/1.0.0/plug.yaml'))"

# 2. Check copyright headers
find plugs/category/my_plugin -name "*.py" | while read f; do
  grep -q "SPDX-License-Identifier:" "$f" || echo "Missing: $f"
done

# 3. Check semantic versioning
grep "^version:" plugs/category/my_plugin/1.0.0/plug.yaml | grep -E "[0-9]+\.[0-9]+\.[0-9]+"

# 4. Validate required fields
python3 << 'EOF'
import yaml
data = yaml.safe_load(open('plugs/category/my_plugin/1.0.0/plug.yaml'))
required = ['name', 'version', 'category', 'description', 'copyright']
missing = [f for f in required if f not in data]
if missing:
    print(f"Missing fields: {', '.join(missing)}")
    exit(1)
else:
    print("✅ All required fields present")
EOF
```

**Option C: Pre-commit Hooks**

```bash
# Run pre-commit checks (validates on commit)
cd PlugPipe-Plugins  # Repo root
pre-commit run --files plugs/category/my_plugin/**/*
```

### 5. Commit & Push

```bash
# Add files
git add plugs/category/my_plugin/

# Commit (pre-commit hooks will run automatically)
git commit -m "feat(category): add my_plugin v1.0.0

- Feature 1
- Feature 2
- Feature 3
"

# Push to your fork
git push origin feature/my-awesome-plugin
```

### 6. Create Pull Request

1. Go to https://github.com/DavidCheuk/PlugPipe-Plugins
2. Click "New Pull Request"
3. Select your fork and branch
4. Fill out the PR template checklist
5. Submit for review

**Automated checks will run**:
- Copyright compliance
- Schema validation
- A2A protocol compliance
- Security scanning
- Architecture rules
- Quality scoring (90+ = auto-approve)

---

## Approval Process

### Quality Score Thresholds

- **90-100** (Grade A+/A): ✅ **Auto-Approve** - Automatically merged
- **70-89** (Grade B/C): ⚠️ **Manual Review** - Maintainer review required
- **0-69** (Grade D/F): ❌ **Auto-Reject** - Fix issues and resubmit

### Review Timeline

- **Auto-Approve**: Immediate (within minutes)
- **Manual Review**: 2-5 business days
- **Rejected**: Fix issues, update PR (no need to create new PR)

---

## Getting Help

### Questions About Plugin Development?

- 📖 Check the [Plugin Development Guide](https://github.com/DavidCheuk/PlugPipe/blob/main/docs/guides/getting-started.md)
- 💬 Open a [GitHub Discussion](https://github.com/DavidCheuk/PlugPipe-Plugins/discussions)
- 🐛 Report bugs via [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md)
- 💡 Suggest features via [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.md)

### Need Early Feedback?

Create a [Plugin Submission Issue](.github/ISSUE_TEMPLATE/plugin_submission.md) to track development and get feedback before submitting a PR.

### Private Security Issues?

Email: security@plugpipe.com (DO NOT create public issues for vulnerabilities)
