# GRC Skill Reference

## API Reference

### PolicyGenerator Class

```python
class PolicyGenerator:
    def __init__(self, title: str, version: str = '1.0', owner: str = '', classification: str = 'Internal')
    def add_section(self, heading: str, content: str)
    def add_control(self, control_id: str, description: str)
    def set_review_schedule(self, frequency: str, next_review: str)
    def generate(self) -> str
    def to_json(self) -> str
```

### ControlAssessment Class

```python
class ControlAssessment:
    def __init__(self, control_id: str, control_name: str, framework: str = '')
    def set_description(self, description: str)
    def set_implementation(self, implementation: str)
    def add_evidence(self, filename: str, description: str, date_collected: str = '')
    def set_effectiveness(self, rating: str, notes: str = '')
    def add_gap(self, description: str, remediation: str, priority: str = 'Medium', due_date: str = '')
    def generate_report(self) -> str
```

### RiskRegister Class

```python
class RiskRegister:
    def add_risk(self, risk_id: str, title: str, description: str, category: str, likelihood: str, impact: str, inherent_risk: str = None)
    def add_mitigation(self, risk_id: str, control: str, effectiveness: str)
    def calculate_residual_risk(self, risk_id: str)
    def set_treatment(self, risk_id: str, treatment: str, owner: str, notes: str = '')
    def generate_report(self) -> str
    def generate_heatmap_data(self) -> dict
```

### ComplianceTracker Class

```python
class ComplianceTracker:
    def __init__(self, framework: str)
    def add_control(self, control_id: str, description: str = '', status: str = 'non_compliant', evidence: List[str] = None, gaps: List[str] = None)
    def update_status(self, control_id: str, status: str, evidence: List[str] = None, gaps: List[str] = None)
    def get_compliance_status(self) -> dict
    def generate_report(self) -> str
```

### FrameworkMapper Class

```python
class FrameworkMapper:
    def add_mapping(self, control_name: str, mappings: Dict[str, str])
    def get_by_framework(self, framework: str) -> List[dict]
    def find_equivalents(self, source_framework: str, control_id: str) -> dict
    def generate_matrix(self) -> str
```

### AuditPackage Class

```python
class AuditPackage:
    def __init__(self, audit_name: str, period_start: str, period_end: str)
    def add_evidence(self, request_id: str, description: str, filename: str, control_ids: List[str], provided_by: str, date_provided: str = '')
    def add_finding(self, finding_id: str, description: str, severity: str, control_ids: List[str], management_response: str = '', remediation_date: str = '')
    def generate_evidence_index(self) -> str
    def generate_finding_summary(self) -> str
```

## Valid Values

### Effectiveness Ratings
- `effective`
- `partially_effective`
- `ineffective`
- `not_tested`

### Compliance Statuses
- `compliant`
- `partially_compliant`
- `non_compliant`
- `not_applicable`

### Risk Likelihood
- `low`
- `medium`
- `high`

### Risk Impact
- `low`
- `medium`
- `high`
- `critical`

### Risk Treatments
- `accept`
- `mitigate`
- `transfer`
- `avoid`

### Gap Priorities
- `Critical`
- `High`
- `Medium`
- `Low`

## Supported Frameworks

- NIST 800-53
- NIST CSF
- ISO 27001
- SOC 2
- PCI DSS
- HIPAA
- GDPR
- CIS Controls

## Changelog

### [1.0.0] - 2024-01-01
- Initial release
- Policy generation
- Control assessments
- Risk register management
- Compliance tracking
- Framework mapping
- Audit package support
