# Automatic Pipe Creation Agent

**AI-Powered Business Process Automation & Intelligent Workflow Generation**

Transform business process descriptions into production-ready PlugPipe workflow templates with intelligent industry pattern analysis and automated pipe generation.

---

## 🎯 **Overview**

The Automatic Pipe Creation Agent is a sophisticated AI-powered system that automatically researches workflow patterns, analyzes business processes, and generates comprehensive pipe templates for common industry workflows.

### **Key Capabilities**
- **Intelligent Workflow Research**: Analyzes industry patterns and best practices
- **Automated Pipe Generation**: Creates complete `pipe.yaml` specifications with proper metadata
- **Multi-Industry Support**: Pre-built knowledge for E-commerce, Marketing, HR, Finance, Healthcare
- **Enterprise-Grade Output**: Generates production-ready workflows with testing and documentation

---

## 🚀 **Quick Start**

### **Basic Usage**
```bash
# Generate an e-commerce customer onboarding workflow
./pp run automatic_pipe_creation_agent \
  --action research_and_create \
  --workflow_name "customer_onboarding" \
  --industry "ecommerce"
```

### **Custom Workflow Creation**
```bash
# Create a custom workflow with description
./pp run automatic_pipe_creation_agent \
  --action research_and_create \
  --workflow_name "compliance_reporting" \
  --industry "healthcare" \
  --workflow_description "HIPAA compliance audit and reporting workflow"
```

### **Batch Processing**
```bash
# Generate multiple workflows simultaneously
./pp run automatic_pipe_creation_agent \
  --action batch_create \
  --workflow_patterns '[
    {"name": "lead_nurturing", "industry": "marketing"},
    {"name": "invoice_processing", "industry": "finance"}
  ]'
```

---

## 🏗️ **Generated Output Structure**

Each workflow generates a complete directory structure:

```
pipes/
└── {industry}/
    └── {workflow_name}/
        ├── pipe.yaml                    # Complete workflow specification
        ├── README.md                    # Usage documentation
        ├── test_{workflow_name}.py      # Automated test suite
        ├── examples/                    # Usage examples
        │   ├── basic_usage.py
        │   ├── advanced_config.py
        │   └── monitoring_setup.py
        └── docs/                        # Additional documentation
            ├── workflow_analysis.md
            └── best_practices.md
```

---

## 🌐 **Supported Industries & Workflows**

### **E-Commerce**
- **Order Processing**: Complete order lifecycle automation
- **Customer Onboarding**: Registration through first purchase
- **Return Processing**: Returns, refunds, and inventory management

### **Marketing**
- **Lead Nurturing**: Lead capture through conversion
- **Content Publishing**: Creation, approval, and distribution
- **Campaign Automation**: Multi-channel campaign orchestration

### **Human Resources**
- **Employee Onboarding**: Application through training assignment
- **Performance Review**: Goal setting through development planning
- **Leave Management**: Request through payroll adjustment

### **Finance**
- **Invoice Processing**: Receipt through payment processing
- **Expense Reporting**: Submission through reimbursement
- **Financial Reporting**: Data collection through distribution

### **Healthcare**
- **Patient Scheduling**: Appointment management and notifications
- **Medical Records**: Secure data management and compliance
- **Treatment Workflows**: Diagnosis through outcome reporting

---

## ⚙️ **Configuration Options**

### **Basic Configuration**
```yaml
# config.yaml
automatic_pipe_creation_agent:
  pipe_category: "workflow"          # Output directory category
  complexity_preference: "standard"  # simple, standard, complex
  include_testing: true              # Generate test suites
  include_documentation: true        # Generate comprehensive docs
  plugin_mapping_strategy: "optimal" # conservative, optimal, aggressive
```

### **Advanced Configuration**
```yaml
automatic_pipe_creation_agent:
  output_directory: "pipes"
  template_customization:
    timeout_strategy: "conservative"  # conservative, standard, aggressive
    retry_policy: "exponential"      # linear, exponential, custom
    error_handling: "graceful"       # strict, graceful, permissive
  industry_customization:
    ecommerce:
      payment_integration: "stripe"
      inventory_system: "shopify"
    healthcare:
      compliance_level: "hipaa"
      audit_requirements: "full"
```

---

## 🔧 **API Reference**

### **Main Actions**

#### **research_and_create**
Generate a single workflow pipe from business description.

**Parameters:**
- `workflow_name` (required): Name of the workflow to create
- `industry` (optional): Target industry for pattern matching
- `workflow_description` (optional): Custom workflow description

**Returns:**
```json
{
  "success": true,
  "pipe_created": true,
  "pipe_details": {
    "name": "customer_onboarding",
    "path": "pipes/ecommerce/customer_onboarding",
    "complexity": "standard",
    "steps": 5,
    "estimated_duration": "15-30 minutes"
  },
  "research_results": {
    "patterns_found": 3,
    "industry_best_practices": ["email_verification", "welcome_sequence"]
  }
}
```

#### **batch_create**
Generate multiple workflow pipes simultaneously.

**Parameters:**
- `workflow_patterns` (required): Array of workflow specifications

**Returns:**
```json
{
  "success": true,
  "workflows_created": 2,
  "results": [
    {"name": "lead_nurturing", "success": true, "path": "pipes/marketing/lead_nurturing"},
    {"name": "invoice_processing", "success": true, "path": "pipes/finance/invoice_processing"}
  ],
  "summary": {
    "total_workflows": 2,
    "successful": 2,
    "failed": 0
  }
}
```

---

## 📋 **Generated Pipe Specification Example**

```yaml
# Generated pipe.yaml example
apiVersion: v1
kind: Pipe
metadata:
  name: customer_onboarding
  category: ecommerce
  description: "Streamlined customer registration and welcome process"
  version: "1.0.0"
  complexity: standard
  industry: ecommerce
  tags: ["customer", "onboarding", "ecommerce", "automation"]

pipeline:
  - name: registration
    plugin: user_management
    config:
      validation_required: true
      email_verification: true
    timeout: 120

  - name: verification
    plugin: email_service
    config:
      template: "welcome_verification"
      retry_attempts: 3
    condition: "{{ steps.registration.success }}"
    timeout: 300

  - name: welcome_email
    plugin: email_service
    config:
      template: "customer_welcome"
      personalization: true
    condition: "{{ steps.verification.success }}"
    timeout: 60

config:
  timeout: 900
  retry_policy:
    max_attempts: 3
    backoff_strategy: exponential
  error_handling: graceful

success_criteria:
  - "Customer account created successfully"
  - "Email verification completed"
  - "Welcome email delivered"

required_plugins:
  - user_management
  - email_service
  - marketing_automation
```

---

## 🧪 **Testing**

### **Generated Test Suite**
Each workflow includes comprehensive automated tests:

```python
# Generated test file example
import pytest
import yaml
from pathlib import Path

class TestCustomerOnboarding:
    def setup_method(self):
        """Setup test fixtures"""
        self.pipe_spec = self._load_pipe_spec()

    def test_pipe_spec_structure(self):
        """Test pipe specification structure"""
        assert self.pipe_spec['apiVersion'] == 'v1'
        assert self.pipe_spec['kind'] == 'Pipe'
        assert 'metadata' in self.pipe_spec
        assert 'pipeline' in self.pipe_spec

    def test_metadata_completeness(self):
        """Test metadata completeness"""
        metadata = self.pipe_spec['metadata']
        required_fields = ['name', 'category', 'description', 'version']
        for field in required_fields:
            assert field in metadata
            assert len(str(metadata[field])) > 0

    def test_pipeline_steps(self):
        """Test all pipeline steps are properly defined"""
        pipeline = self.pipe_spec['pipeline']
        assert len(pipeline) > 0

        for step in pipeline:
            assert 'name' in step
            assert 'plugin' in step
            assert 'config' in step or 'with' in step
```

### **Running Tests**
```bash
# Test generated workflow
cd pipes/ecommerce/customer_onboarding
python -m pytest test_customer_onboarding.py -v

# Run integration tests
./pp run customer_onboarding --dry-run --test-mode
```

---

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Plugin Not Found**
```
Error: Plugin 'email_service' not found in registry
```
**Solution**: Ensure required plugins are installed:
```bash
./pp list | grep email_service
./pp run plugin_installer --install email_service
```

#### **Invalid Workflow Name**
```
Error: workflow_name is required for research_and_create action
```
**Solution**: Provide a valid workflow name:
```bash
./pp run automatic_pipe_creation_agent \
  --action research_and_create \
  --workflow_name "valid_workflow_name"
```

#### **Industry Pattern Not Found**
```
Warning: No workflow patterns found for industry 'custom_industry'
```
**Solution**: Provide a workflow description or use supported industry:
```bash
./pp run automatic_pipe_creation_agent \
  --action research_and_create \
  --workflow_name "custom_process" \
  --workflow_description "Detailed process description here"
```

### **Debug Mode**
```bash
# Enable verbose logging
./pp run automatic_pipe_creation_agent --verbose \
  --action research_and_create \
  --workflow_name "debug_workflow"
```

---

## 🚀 **Advanced Usage**

### **Custom Industry Patterns**
```python
# Extend industry patterns
custom_config = {
    "industry_workflows": {
        "custom_industry": {
            "custom_workflow": {
                "steps": ["step1", "step2", "step3"],
                "plugins": ["plugin1", "plugin2"],
                "complexity": "standard"
            }
        }
    }
}
```

### **Plugin Mapping Customization**
```python
# Custom plugin mapping
plugin_mapping = {
    "email_notifications": "sendgrid_integration",
    "payment_processing": "stripe_advanced",
    "inventory_management": "shopify_enterprise"
}
```

### **Monitoring Integration**
```python
# Generated monitoring configuration
monitoring_config = {
    "health_checks": True,
    "performance_metrics": True,
    "alert_thresholds": {
        "execution_time": "5m",
        "error_rate": "5%",
        "success_rate": "95%"
    }
}
```

---

## 📞 **Support**

### **Documentation**
- **Developer Guide**: `docs/claude_guidance/automation/automatic_pipe_creation_developer_guide.md`
- **Technical Guide**: `docs/claude_guidance/automation/workflow_automation_technical_guide.md`
- **API Reference**: This README and generated pipe documentation

### **Getting Help**
- Review generated workflow documentation in `pipes/{industry}/{workflow}/README.md`
- Check test results in `pipes/{industry}/{workflow}/test_{workflow}.py`
- Examine generated examples in `pipes/{industry}/{workflow}/examples/`

### **Contributing**
To extend industry patterns or improve workflow generation:
1. Review existing patterns in `main.py` industry_workflows
2. Add new industry patterns following existing structure
3. Test with `--workflow_description` parameter
4. Submit improvements via standard contribution process

---

**Version**: 1.0.0
**Category**: Automation, AI-Powered, Business Process
**Status**: Production Ready
**Enterprise Ready**: ✅
**AI-Powered**: ✅