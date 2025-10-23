# Manual Review Guidelines for PlugPipe Plugins

**Version**: 1.0.0
**Last Updated**: October 23, 2025
**Maintainer**: PlugPipe Team

## Overview

This document provides guidelines for maintainers reviewing plugin submissions that score between **70-89** (Grade B/C) on the automated quality scoring system. These submissions require manual review before approval.

**Review Timeline**: 2-5 business days

---

## Quality Score Thresholds

| Score Range | Grade | Action | Timeline |
|-------------|-------|--------|----------|
| **90-100** | A+/A | ✅ **Auto-Approve** | Immediate (automated) |
| **70-89** | B/C | ⚠️ **Manual Review** | 2-5 business days |
| **0-69** | D/F | ❌ **Auto-Reject** | Immediate (fix required) |

---

## Review Criteria

### 1. Copyright Compliance (Weight: 10%)

**Required**:
- ✅ All Python files have SPDX headers: `# SPDX-License-Identifier: MIT`
- ✅ Copyright notice present: `# Copyright 2025 Author Name`
- ✅ GitHub repo URL included: `# https://github.com/DavidCheuk/PlugPipe-Plugins`
- ✅ Manifest has `copyright:` field

**Scoring**:
- All present: 10/10
- Missing SPDX headers: 0/10 (auto-reject)
- Missing manifest copyright: 5/10 (manual review)

**Common Issues**:
- Inconsistent copyright years across files
- Missing copyright in manifest but present in code
- Unclear authorship (multiple contributors)

**Review Decision**:
- **Approve if**: Copyright intent is clear, minor formatting issues only
- **Request changes if**: Ambiguous ownership, missing critical notices
- **Reject if**: No copyright information at all

---

### 2. SBOM Quality (Weight: 10%)

**Required**:
- ✅ SBOM file present (if external dependencies exist)
- ✅ Valid SPDX format
- ✅ All dependencies listed
- ✅ License information for dependencies

**Scoring**:
- Complete SBOM: 10/10
- Missing SBOM but no dependencies: 10/10
- Incomplete SBOM: 5/10
- No SBOM with dependencies: 0/10

**Common Issues**:
- Dependencies in code but not in SBOM
- Version ranges too broad (e.g., `>=1.0.0`)
- Missing transitive dependencies
- Unclear license compatibility

**Review Decision**:
- **Approve if**: Core dependencies documented, minor omissions acceptable
- **Request changes if**: Critical dependencies missing, license conflicts
- **Reject if**: Commercial dependencies without proper licensing

---

### 3. Security Validation (Weight: 25%)

**Required**:
- ✅ No hardcoded credentials
- ✅ Input validation present
- ✅ Error handling implemented
- ✅ No unsafe operations (eval, exec, etc.)
- ✅ Dependency vulnerabilities checked

**Scoring**:
- All checks pass: 25/25
- Minor issues (missing input validation): 15-20/25
- Major issues (unsafe operations): 5-10/25
- Critical vulnerabilities: 0/25 (auto-reject)

**Common Issues**:
- Missing input sanitization for user data
- Overly permissive file operations
- Network requests without timeout
- Inadequate error handling
- Dependency with known CVEs

**Review Decision**:
- **Approve if**: Core security practices present, no critical risks
- **Request changes if**: Missing validation, potential vulnerabilities
- **Reject if**: Obvious security holes, known exploitable dependencies

**⚠️ Security Escalation**: Report to security@plugpipe.com if:
- Intentional backdoors or malicious code
- Cryptographic vulnerabilities
- Data exfiltration attempts
- Supply chain compromise risks

---

### 4. A2A Protocol Compliance (Weight: 20%)

**Required (MANDATORY for all plugins)**:
- ✅ `a2a_enabled: true` in manifest
- ✅ Standard `execute()` function signature
- ✅ Stateless operation (no instance state)
- ✅ agent-card.json generation possible
- ✅ Discovery endpoint compatible

**Scoring**:
- Full compliance: 20/20
- Partial compliance (missing agent-card.json): 12-15/20
- Non-compliant (stateful design): 0/20 (auto-reject)

**Common Issues**:
- Plugin uses instance variables (violates stateless requirement)
- execute() has wrong signature
- Missing a2a_enabled field
- Cannot be discovered by agent discovery system

**Review Decision**:
- **Approve if**: Core A2A principles followed, minor metadata issues
- **Request changes if**: Stateless design unclear, missing discovery support
- **Reject if**: Fundamentally stateful architecture (requires redesign)

**Note**: A2A is DEFAULT/MANDATORY. All plugins must support agent-to-agent communication.

---

### 5. MCP Protocol Compliance (Weight: 5%)

**Required (OPTIONAL - only for plugins that explicitly enable MCP)**:
- ✅ `mcp_server: true` in manifest (if claiming MCP support)
- ✅ MCP server implementation present
- ✅ Tool definitions provided
- ✅ MCP 2025-06-18 specification compliance

**Scoring**:
- Full compliance: 5/5
- Partial compliance: 2-3/5
- Claims MCP but non-compliant: 0/5
- No MCP claim: 5/5 (not applicable)

**Common Issues**:
- Sets `mcp_server: true` but no MCP implementation
- Incompatible with MCP specification
- Missing required MCP endpoints

**Review Decision**:
- **Approve if**: MCP implementation complete OR no MCP claim
- **Request changes if**: Partial MCP implementation, specification violations
- **Reject if**: False MCP claim with no implementation

**Note**: MCP is OPTIONAL. Most plugins should only support A2A.

---

### 6. Schema Validation (Weight: 15%)

**Required**:
- ✅ Valid `plug.yaml` manifest
- ✅ All required fields present (name, version, category, description, author, copyright, license)
- ✅ Semantic versioning (X.Y.Z format)
- ✅ Input/output schema documented
- ✅ No deprecated fields

**Scoring**:
- Perfect schema: 15/15
- Minor issues (missing optional fields): 10-12/15
- Major issues (invalid structure): 5-8/15
- Invalid manifest: 0/15 (auto-reject)

**Common Issues**:
- Using `.yml` instead of `.yaml` extension
- Missing required fields
- Invalid semantic version format
- Unclear input/output schema
- Using deprecated manifest fields

**Review Decision**:
- **Approve if**: All required fields present, minor optional fields missing
- **Request changes if**: Schema unclear, missing critical metadata
- **Reject if**: Manifest invalid or fundamentally incomplete

---

### 7. Architecture Compliance (Weight: 15%)

**Required**:
- ✅ Follows PlugPipe plugin structure
- ✅ No hardcoded paths (uses shares/plugpipe_path_helper.py)
- ✅ No subprocess anti-patterns (uses pp() for plugin discovery)
- ✅ No circular dependencies
- ✅ Proper error handling
- ✅ Documentation complete

**Scoring**:
- Perfect architecture: 15/15
- Minor violations (hardcoded paths): 10-12/15
- Major violations (subprocess anti-patterns): 5-8/15
- Fundamental violations: 0/15 (auto-reject)

**Common Issues**:
- Hardcoded installation paths (`/mnt/c/Project/PlugPipe/...`)
- Using subprocess to call `./pp` instead of pp() function
- Importing from shares.loader (circular dependency risk)
- Missing README.md documentation
- No usage examples

**Review Decision**:
- **Approve if**: Core architecture principles followed, minor style issues
- **Request changes if**: Anti-patterns present, documentation incomplete
- **Reject if**: Violates fundamental PlugPipe principles

---

## Approval Decision Matrix

Use this matrix to make final approval decisions:

| Security | A2A | Schema | Architecture | **Decision** |
|----------|-----|--------|--------------|--------------|
| ✅ Pass | ✅ Pass | ✅ Pass | ✅ Pass | **✅ Approve** |
| ✅ Pass | ✅ Pass | ✅ Pass | ⚠️ Minor | **✅ Approve with comments** |
| ✅ Pass | ✅ Pass | ⚠️ Minor | ⚠️ Minor | **✅ Approve with comments** |
| ✅ Pass | ⚠️ Minor | ✅ Pass | ✅ Pass | **⚠️ Request changes** |
| ⚠️ Minor | ✅ Pass | ✅ Pass | ✅ Pass | **⚠️ Request changes** |
| ❌ Fail | * | * | * | **❌ Reject** |
| * | ❌ Fail | * | * | **❌ Reject** |
| * | * | ❌ Fail | * | **❌ Reject** |
| ⚠️ Minor | ⚠️ Minor | ⚠️ Minor | ⚠️ Minor | **⚠️ Request changes** |

**Legend**:
- ✅ Pass: Meets all requirements
- ⚠️ Minor: Minor issues that don't block functionality
- ❌ Fail: Critical issues that block approval

---

## Risk Assessment Framework

### Risk Categories

**🟢 Low Risk** (Immediate Approval):
- Simple data processing plugins
- No external dependencies
- No network operations
- Read-only file operations
- Well-documented code

**🟡 Medium Risk** (Standard Review):
- External API integrations
- File write operations
- Database operations
- Third-party dependencies
- Complex business logic

**🔴 High Risk** (Extended Review + Security Escalation):
- Cryptographic operations
- Authentication/authorization
- System administration tools
- Network security tools
- Cloud infrastructure management
- Financial/payment processing

### Review Timeline by Risk

| Risk Level | Review Time | Reviewers Required |
|------------|-------------|-------------------|
| 🟢 Low | 1-2 days | 1 maintainer |
| 🟡 Medium | 2-3 days | 1 maintainer |
| 🔴 High | 3-5 days | 2+ maintainers + security review |

---

## Review Process Workflow

### Step 1: Initial Triage (15 minutes)
1. Check automated quality score (should be 70-89)
2. Review PR description and plugin category
3. Assign risk level (Low/Medium/High)
4. Assign to appropriate reviewer

### Step 2: Code Review (30-60 minutes)
1. Run local validation checks:
   ```bash
   # Clone PR branch
   gh pr checkout <PR_NUMBER>

   # Run pre-commit hooks
   pre-commit run --all-files

   # Validate manifest
   python3 -c "import yaml; yaml.safe_load(open('plugs/category/plugin/version/plug.yaml'))"

   # Check copyright
   find plugs -name "*.py" | xargs grep -L "SPDX-License-Identifier:"
   ```

2. Review each quality category against criteria above
3. Test plugin functionality (if possible)
4. Check documentation completeness

### Step 3: Decision (5-10 minutes)
1. Calculate final assessment using decision matrix
2. If **Approve**:
   - Add approval comment
   - Merge PR
   - Trigger registry rebuild
3. If **Request Changes**:
   - Provide specific feedback
   - Link to relevant documentation
   - Set clear requirements for re-review
4. If **Reject**:
   - Explain rejection reasons
   - Provide guidance for resubmission
   - Close PR with clear next steps

### Step 4: Post-Approval (5 minutes)
1. Verify registry rebuild succeeded
2. Test plugin availability in production
3. Close related issues
4. Update plugin submission tracker (if exists)

---

## Review Comments Templates

### Approval Template

```markdown
## ✅ Plugin Approved

Thank you for your contribution! Your plugin has been reviewed and approved.

**Quality Score**: XX/100 (Grade: B/C)
**Review Time**: X days

**Strengths**:
- [List 2-3 positive aspects]

**Minor Suggestions** (optional, non-blocking):
- [List 1-2 improvement suggestions]

Your plugin will be available in the registry within 5-10 minutes.

Welcome to the PlugPipe plugin ecosystem! 🎉
```

### Request Changes Template

```markdown
## ⚠️ Changes Requested

Thank you for your submission. Your plugin requires some changes before approval.

**Quality Score**: XX/100 (Grade: B/C)

**Required Changes**:

1. **[Category]**: [Specific issue]
   - **Current**: [What's wrong]
   - **Required**: [What's needed]
   - **Reference**: [Link to docs]

2. **[Category]**: [Specific issue]
   - **Current**: [What's wrong]
   - **Required**: [What's needed]
   - **Reference**: [Link to docs]

**Timeline**: Please update within 7 days or the PR will be closed.

**Need Help?** Ask questions in this PR or create a [GitHub Discussion](https://github.com/DavidCheuk/PlugPipe-Plugins/discussions).
```

### Rejection Template

```markdown
## ❌ Plugin Rejected

Thank you for your submission. Unfortunately, your plugin cannot be approved in its current state.

**Quality Score**: XX/100 (Grade: B/C)

**Critical Issues**:

1. **[Category]**: [Critical issue explanation]
2. **[Category]**: [Critical issue explanation]

**Recommendation**: [Redesign needed | Fix issues and resubmit | Consider alternative approach]

**Next Steps**:
1. Review [relevant documentation link]
2. Fix critical issues listed above
3. Resubmit as a new PR

We appreciate your interest in contributing to PlugPipe. Please don't hesitate to ask for guidance before your next submission.
```

---

## Escalation Process

### When to Escalate

**Escalate to Security Team** (security@plugpipe.com):
- Suspected malicious code
- Cryptographic vulnerabilities
- Supply chain risks
- Data exfiltration attempts

**Escalate to Core Team** (GitHub @mentions):
- Architectural concerns
- PlugPipe principle violations
- Precedent-setting decisions
- License compatibility issues

**Escalate to Legal** (legal@plugpipe.com):
- Copyright disputes
- License violations
- Patent concerns
- DMCA takedown requests

### Escalation Response Time
- **Security**: 24 hours
- **Core Team**: 2-3 days
- **Legal**: 5-7 days

---

## Common Review Scenarios

### Scenario 1: Great Plugin, Minor Documentation Issues

**Quality Score**: 82/100
**Issue**: Missing usage examples in README
**Decision**: **✅ Approve with comments**

**Rationale**: Documentation can be improved post-merge. Plugin functionality is solid.

**Action**:
- Approve and merge
- Create follow-up issue for documentation improvement
- Offer to help improve docs

---

### Scenario 2: Security Concerns, But Good Intent

**Quality Score**: 75/100
**Issue**: Missing input validation for user-provided file paths
**Decision**: **⚠️ Request changes**

**Rationale**: Security risk present but plugin has value. Author can fix easily.

**Action**:
- Request specific validation implementation
- Provide code example
- Link to security guidelines
- Set 7-day response deadline

---

### Scenario 3: Architecture Anti-Patterns

**Quality Score**: 71/100
**Issue**: Uses subprocess to call `./pp` instead of pp() function
**Decision**: **⚠️ Request changes**

**Rationale**: Violates PlugPipe principles, but fixable without redesign.

**Action**:
- Explain anti-pattern clearly
- Provide correct implementation example
- Link to Dynamic Plugin Discovery Guide
- Offer to assist with refactoring

---

### Scenario 4: Borderline Quality (70-72)

**Quality Score**: 71/100
**Issue**: Multiple minor issues across categories
**Decision**: **Context-dependent**

**Factors to Consider**:
- Is this author's first contribution? (More lenient)
- Is plugin filling critical ecosystem gap? (More lenient)
- Are issues easy to fix? (Request changes)
- Would rejection discourage contributor? (Consider approving with follow-up)

**Action**:
- Use judgment based on context
- If approving, create detailed follow-up issues
- If rejecting, provide comprehensive improvement guide

---

## Review Metrics & Goals

### Maintainer Performance Metrics

**Target Response Times**:
- Initial triage: < 24 hours
- Low risk review: < 2 days
- Medium risk review: < 3 days
- High risk review: < 5 days

**Quality Metrics**:
- Approval accuracy: > 95% (no post-merge critical issues)
- Change request clarity: > 90% (contributors understand requirements)
- Rejection fairness: > 95% (clear justification, no bias)

### Ecosystem Health Metrics

**Goals**:
- Approval rate: 70-80% (within 70-89 score range)
- Average review time: < 3 days
- Contributor satisfaction: > 85%
- Post-merge issue rate: < 5%

---

## Reviewer Resources

### Tools
- [Pre-commit hooks](.pre-commit-config.yaml) - Local validation
- [Quality scoring system](../../PlugPipe/docs/claude_guidance/development/ci_cd_excellence_framework.md) - Scoring details
- [Template plugin](../plugs/examples/template_plugin/) - Reference implementation

### Documentation
- [Contributing Guide](../CONTRIBUTING.md) - Contributor instructions
- [PlugPipe Principles](../../PlugPipe/docs/claude_guidance/system/foundational_principles.md) - Core principles
- [Security Framework](../../PlugPipe/docs/claude_guidance/security/universal_plug_security_framework.md) - Security standards
- [Architecture Guide](../../PlugPipe/docs/claude_guidance/architecture/unified_plug_pipe_architecture.md) - Architecture patterns

### Support
- **Questions**: GitHub Discussions
- **Security**: security@plugpipe.com
- **Escalation**: @DavidCheuk

---

## Continuous Improvement

This document should be updated regularly based on:
- New review patterns discovered
- Common contributor confusion points
- Changes to quality scoring system
- Ecosystem growth and maturity

**Update Schedule**: Quarterly review (January, April, July, October)

**Feedback**: Maintainers should document edge cases and propose updates via pull requests to this document.

---

## Changelog

### Version 1.0.0 (October 23, 2025)
- Initial manual review guidelines created
- Decision matrix and risk framework established
- Review templates and workflow documented
- Common scenarios and escalation process defined
