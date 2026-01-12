#!/usr/bin/env python3
"""
GRC (Governance, Risk, Compliance) Utility Functions

Utilities for GRC documentation and assessment.

Usage:
    from grc_utils import PolicyGenerator, ControlAssessment, RiskRegister, ComplianceTracker
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class PolicyGenerator:
    """Generate security policy documents."""

    def __init__(self, title: str, version: str = '1.0',
                 owner: str = '', classification: str = 'Internal'):
        self.title = title
        self.version = version
        self.owner = owner
        self.classification = classification
        self.sections = []
        self.controls = []
        self.review_schedule = {}
        self.created_at = datetime.now()

    def add_section(self, heading: str, content: str):
        """Add policy section."""
        self.sections.append({
            'heading': heading,
            'content': content.strip()
        })

    def add_control(self, control_id: str, description: str):
        """Add related control reference."""
        self.controls.append({
            'id': control_id,
            'description': description
        })

    def set_review_schedule(self, frequency: str, next_review: str):
        """Set policy review schedule."""
        self.review_schedule = {
            'frequency': frequency,
            'next_review': next_review
        }

    def generate(self) -> str:
        """Generate policy document in markdown."""
        policy = f"""# {self.title}

**Version:** {self.version}
**Owner:** {self.owner}
**Classification:** {self.classification}
**Effective Date:** {self.created_at.strftime('%Y-%m-%d')}
**Review Frequency:** {self.review_schedule.get('frequency', 'Annual')}
**Next Review:** {self.review_schedule.get('next_review', 'TBD')}

---

"""
        for section in self.sections:
            policy += f"## {section['heading']}\n\n{section['content']}\n\n"

        if self.controls:
            policy += "## Related Controls\n\n"
            policy += "| Control ID | Description |\n"
            policy += "|------------|-------------|\n"
            for ctrl in self.controls:
                policy += f"| {ctrl['id']} | {ctrl['description']} |\n"

        policy += f"""
---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| {self.version} | {self.created_at.strftime('%Y-%m-%d')} | {self.owner} | Initial release |
"""
        return policy

    def to_json(self) -> str:
        """Export policy as JSON."""
        return json.dumps({
            'title': self.title,
            'version': self.version,
            'owner': self.owner,
            'classification': self.classification,
            'sections': self.sections,
            'controls': self.controls,
            'review_schedule': self.review_schedule,
            'created_at': self.created_at.isoformat()
        }, indent=2)


class ControlAssessment:
    """Document control assessments."""

    EFFECTIVENESS_RATINGS = ['effective', 'partially_effective', 'ineffective', 'not_tested']

    def __init__(self, control_id: str, control_name: str, framework: str = ''):
        self.control_id = control_id
        self.control_name = control_name
        self.framework = framework
        self.description = ''
        self.implementation = ''
        self.evidence = []
        self.effectiveness = None
        self.effectiveness_notes = ''
        self.gaps = []
        self.assessed_at = datetime.now()

    def set_description(self, description: str):
        """Set control description."""
        self.description = description.strip()

    def set_implementation(self, implementation: str):
        """Set implementation details."""
        self.implementation = implementation.strip()

    def add_evidence(self, filename: str, description: str, date_collected: str = ''):
        """Add evidence artifact."""
        self.evidence.append({
            'filename': filename,
            'description': description,
            'date_collected': date_collected or datetime.now().strftime('%Y-%m-%d')
        })

    def set_effectiveness(self, rating: str, notes: str = ''):
        """Set control effectiveness rating."""
        if rating not in self.EFFECTIVENESS_RATINGS:
            raise ValueError(f"Invalid rating: {rating}")
        self.effectiveness = rating
        self.effectiveness_notes = notes

    def add_gap(self, description: str, remediation: str,
                priority: str = 'Medium', due_date: str = ''):
        """Add identified gap."""
        self.gaps.append({
            'description': description,
            'remediation': remediation,
            'priority': priority,
            'due_date': due_date,
            'status': 'open'
        })

    def generate_report(self) -> str:
        """Generate assessment report."""
        report = f"""# Control Assessment: {self.control_id}

**Control Name:** {self.control_name}
**Framework:** {self.framework}
**Assessment Date:** {self.assessed_at.strftime('%Y-%m-%d')}
**Effectiveness:** {self.effectiveness.replace('_', ' ').title() if self.effectiveness else 'Not Assessed'}

---

## Control Description

{self.description}

## Implementation

{self.implementation}

## Evidence

| Document | Description | Date |
|----------|-------------|------|
"""
        for ev in self.evidence:
            report += f"| {ev['filename']} | {ev['description']} | {ev['date_collected']} |\n"

        report += f"""
## Effectiveness Assessment

**Rating:** {self.effectiveness.replace('_', ' ').title() if self.effectiveness else 'N/A'}

{self.effectiveness_notes}

## Gaps and Remediation

"""
        if self.gaps:
            report += "| Gap | Remediation | Priority | Due Date | Status |\n"
            report += "|-----|-------------|----------|----------|--------|\n"
            for gap in self.gaps:
                report += f"| {gap['description']} | {gap['remediation']} | {gap['priority']} | {gap['due_date']} | {gap['status']} |\n"
        else:
            report += "No gaps identified.\n"

        return report


class RiskRegister:
    """Maintain risk register."""

    LIKELIHOOD_VALUES = {'low': 1, 'medium': 2, 'high': 3}
    IMPACT_VALUES = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    RISK_LEVELS = {
        (1, 1): 'low', (1, 2): 'low', (1, 3): 'medium', (1, 4): 'medium',
        (2, 1): 'low', (2, 2): 'medium', (2, 3): 'high', (2, 4): 'high',
        (3, 1): 'medium', (3, 2): 'high', (3, 3): 'high', (3, 4): 'critical'
    }

    def __init__(self):
        self.risks = {}

    def add_risk(self, risk_id: str, title: str, description: str,
                 category: str, likelihood: str, impact: str,
                 inherent_risk: str = None):
        """Add risk to register."""
        self.risks[risk_id] = {
            'risk_id': risk_id,
            'title': title,
            'description': description,
            'category': category,
            'likelihood': likelihood,
            'impact': impact,
            'inherent_risk': inherent_risk or self._calculate_risk(likelihood, impact),
            'mitigations': [],
            'residual_risk': None,
            'treatment': None,
            'owner': None,
            'created_at': datetime.now().isoformat()
        }

    def _calculate_risk(self, likelihood: str, impact: str) -> str:
        """Calculate risk level from likelihood and impact."""
        l_val = self.LIKELIHOOD_VALUES.get(likelihood, 2)
        i_val = self.IMPACT_VALUES.get(impact, 2)
        return self.RISK_LEVELS.get((l_val, i_val), 'medium')

    def add_mitigation(self, risk_id: str, control: str, effectiveness: str):
        """Add mitigation control to risk."""
        if risk_id in self.risks:
            self.risks[risk_id]['mitigations'].append({
                'control': control,
                'effectiveness': effectiveness
            })

    def calculate_residual_risk(self, risk_id: str):
        """Calculate residual risk after mitigations."""
        if risk_id not in self.risks:
            return

        risk = self.risks[risk_id]
        inherent = risk['inherent_risk']

        # Simple reduction based on mitigation effectiveness
        reduction = 0
        for m in risk['mitigations']:
            if m['effectiveness'] == 'high':
                reduction += 1
            elif m['effectiveness'] == 'medium':
                reduction += 0.5

        risk_levels = ['low', 'medium', 'high', 'critical']
        current_idx = risk_levels.index(inherent)
        new_idx = max(0, current_idx - int(reduction))
        risk['residual_risk'] = risk_levels[new_idx]

    def set_treatment(self, risk_id: str, treatment: str, owner: str, notes: str = ''):
        """Set risk treatment decision."""
        if risk_id in self.risks:
            self.risks[risk_id]['treatment'] = treatment
            self.risks[risk_id]['owner'] = owner
            self.risks[risk_id]['treatment_notes'] = notes

    def generate_report(self) -> str:
        """Generate risk register report."""
        report = f"""# Risk Register

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Total Risks:** {len(self.risks)}

---

## Risk Summary

| ID | Title | Category | Inherent | Residual | Treatment | Owner |
|----|-------|----------|----------|----------|-----------|-------|
"""
        for risk in self.risks.values():
            report += f"| {risk['risk_id']} | {risk['title']} | {risk['category']} | {risk['inherent_risk']} | {risk['residual_risk'] or 'N/A'} | {risk['treatment'] or 'N/A'} | {risk['owner'] or 'N/A'} |\n"

        return report

    def generate_heatmap_data(self) -> dict:
        """Generate data for risk heatmap."""
        heatmap = defaultdict(list)
        for risk in self.risks.values():
            key = (risk['likelihood'], risk['impact'])
            heatmap[key].append(risk['risk_id'])
        return dict(heatmap)


class ComplianceTracker:
    """Track compliance status."""

    STATUSES = ['compliant', 'partially_compliant', 'non_compliant', 'not_applicable']

    def __init__(self, framework: str):
        self.framework = framework
        self.controls = {}
        self.last_updated = datetime.now()

    def add_control(self, control_id: str, description: str = '',
                    status: str = 'non_compliant', evidence: List[str] = None,
                    gaps: List[str] = None):
        """Add control to tracker."""
        if status not in self.STATUSES:
            raise ValueError(f"Invalid status: {status}")

        self.controls[control_id] = {
            'control_id': control_id,
            'description': description,
            'status': status,
            'evidence': evidence or [],
            'gaps': gaps or [],
            'last_assessed': datetime.now().isoformat()
        }

    def update_status(self, control_id: str, status: str,
                      evidence: List[str] = None, gaps: List[str] = None):
        """Update control status."""
        if control_id in self.controls:
            self.controls[control_id]['status'] = status
            if evidence:
                self.controls[control_id]['evidence'] = evidence
            if gaps:
                self.controls[control_id]['gaps'] = gaps
            self.controls[control_id]['last_assessed'] = datetime.now().isoformat()

    def get_compliance_status(self) -> dict:
        """Get compliance summary."""
        counts = defaultdict(int)
        for ctrl in self.controls.values():
            counts[ctrl['status']] += 1

        total = len(self.controls)
        return {
            'compliant': counts['compliant'],
            'partially_compliant': counts['partially_compliant'],
            'non_compliant': counts['non_compliant'],
            'not_applicable': counts['not_applicable'],
            'total': total,
            'compliance_rate': (counts['compliant'] / total * 100) if total > 0 else 0
        }

    def generate_report(self) -> str:
        """Generate compliance report."""
        status = self.get_compliance_status()

        report = f"""# {self.framework} Compliance Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

---

## Summary

| Status | Count | Percentage |
|--------|-------|------------|
| Compliant | {status['compliant']} | {status['compliant']/status['total']*100:.1f}% |
| Partially Compliant | {status['partially_compliant']} | {status['partially_compliant']/status['total']*100:.1f}% |
| Non-Compliant | {status['non_compliant']} | {status['non_compliant']/status['total']*100:.1f}% |
| Not Applicable | {status['not_applicable']} | {status['not_applicable']/status['total']*100:.1f}% |

**Overall Compliance Rate:** {status['compliance_rate']:.1f}%

## Control Details

| Control | Description | Status | Gaps |
|---------|-------------|--------|------|
"""
        for ctrl in self.controls.values():
            gaps = ', '.join(ctrl['gaps']) if ctrl['gaps'] else 'None'
            gaps = gaps[:50] + '...' if len(gaps) > 50 else gaps
            report += f"| {ctrl['control_id']} | {ctrl['description'][:30]}... | {ctrl['status']} | {gaps} |\n"

        return report


class FrameworkMapper:
    """Map controls across compliance frameworks."""

    def __init__(self):
        self.mappings = []

    def add_mapping(self, control_name: str, mappings: Dict[str, str]):
        """Add control mapping across frameworks."""
        self.mappings.append({
            'control_name': control_name,
            'mappings': mappings
        })

    def get_by_framework(self, framework: str) -> List[dict]:
        """Get all controls for a framework."""
        results = []
        for m in self.mappings:
            if framework in m['mappings']:
                results.append({
                    'control_name': m['control_name'],
                    'control_id': m['mappings'][framework]
                })
        return results

    def find_equivalents(self, source_framework: str, control_id: str) -> dict:
        """Find equivalent controls in other frameworks."""
        for m in self.mappings:
            if m['mappings'].get(source_framework) == control_id:
                return m['mappings']
        return {}

    def generate_matrix(self) -> str:
        """Generate framework mapping matrix."""
        if not self.mappings:
            return "No mappings defined."

        # Get all frameworks
        frameworks = set()
        for m in self.mappings:
            frameworks.update(m['mappings'].keys())
        frameworks = sorted(frameworks)

        report = "# Framework Control Mapping\n\n"
        report += "| Control | " + " | ".join(frameworks) + " |\n"
        report += "|---------|" + "|".join(["--------"] * len(frameworks)) + "|\n"

        for m in self.mappings:
            row = f"| {m['control_name']} |"
            for fw in frameworks:
                row += f" {m['mappings'].get(fw, 'N/A')} |"
            report += row + "\n"

        return report


class AuditPackage:
    """Manage audit evidence packages."""

    def __init__(self, audit_name: str, period_start: str, period_end: str):
        self.audit_name = audit_name
        self.period_start = period_start
        self.period_end = period_end
        self.evidence = []
        self.findings = []

    def add_evidence(self, request_id: str, description: str, filename: str,
                     control_ids: List[str], provided_by: str,
                     date_provided: str = ''):
        """Add evidence to package."""
        self.evidence.append({
            'request_id': request_id,
            'description': description,
            'filename': filename,
            'control_ids': control_ids,
            'provided_by': provided_by,
            'date_provided': date_provided or datetime.now().strftime('%Y-%m-%d')
        })

    def add_finding(self, finding_id: str, description: str, severity: str,
                    control_ids: List[str], management_response: str = '',
                    remediation_date: str = ''):
        """Add audit finding."""
        self.findings.append({
            'finding_id': finding_id,
            'description': description,
            'severity': severity,
            'control_ids': control_ids,
            'management_response': management_response,
            'remediation_date': remediation_date,
            'status': 'open'
        })

    def generate_evidence_index(self) -> str:
        """Generate evidence index."""
        report = f"""# Evidence Index: {self.audit_name}

**Audit Period:** {self.period_start} to {self.period_end}
**Generated:** {datetime.now().strftime('%Y-%m-%d')}

---

| Request ID | Description | Filename | Controls | Provided By | Date |
|------------|-------------|----------|----------|-------------|------|
"""
        for ev in self.evidence:
            controls = ', '.join(ev['control_ids'])
            report += f"| {ev['request_id']} | {ev['description']} | {ev['filename']} | {controls} | {ev['provided_by']} | {ev['date_provided']} |\n"

        return report

    def generate_finding_summary(self) -> str:
        """Generate findings summary."""
        report = f"""# Audit Findings: {self.audit_name}

**Audit Period:** {self.period_start} to {self.period_end}
**Total Findings:** {len(self.findings)}

---

| Finding | Description | Severity | Controls | Remediation Date |
|---------|-------------|----------|----------|------------------|
"""
        for f in self.findings:
            controls = ', '.join(f['control_ids'])
            report += f"| {f['finding_id']} | {f['description']} | {f['severity']} | {controls} | {f['remediation_date']} |\n"

        return report
