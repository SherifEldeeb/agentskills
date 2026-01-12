---
name: incident-response
description: |
  Incident response documentation, timeline analysis, containment procedures,
  and IR reporting. Support the full incident lifecycle from detection to
  lessons learned. Use for security incidents, breach response, and IR planning.
license: Apache-2.0
compatibility: |
  - Python 3.9+
metadata:
  author: SherifEldeeb
  version: "0.1.0"
  category: cybersecurity
  status: planned
---

# Incident Response Skill

Support the complete incident response lifecycle with documentation and analysis.

## Capabilities

- **Timeline Analysis**: Build and analyze incident timelines
- **Containment Documentation**: Document containment actions
- **IR Reporting**: Generate incident reports for various audiences
- **Evidence Tracking**: Maintain chain of custody documentation
- **Lessons Learned**: Facilitate post-incident reviews

## Status

This skill is planned for development.

## Planned Features

### Timeline Management
- Event timeline construction
- Log correlation and sequencing
- Attack path visualization
- Timeline export (CSV, JSON, DOCX)

### Documentation
- Incident report templates
- Executive summaries
- Technical details
- Regulatory notification drafts

### Evidence Handling
- Evidence collection checklists
- Chain of custody forms
- Hash verification logging
- Evidence index generation

### Playbooks
- IR playbook templates
- Phase-specific checklists
- Communication templates
- Escalation procedures

### Post-Incident
- Lessons learned facilitation
- Improvement recommendations
- Metrics and KPIs
- Timeline to remediation

## Use Cases

1. **Active Incident**
   - Real-time timeline updates
   - Action documentation
   - Stakeholder communications

2. **Investigation**
   - Evidence collection guidance
   - Analysis documentation
   - Findings compilation

3. **Reporting**
   - Executive incident summary
   - Technical incident report
   - Regulatory notifications
   - Board-level briefing

4. **Post-Incident Review**
   - Lessons learned document
   - Process improvement recommendations
   - Updated playbooks

## Related Skills

- [soc-operations](../soc-operations/): Initial detection and triage
- [threat-intelligence](../threat-intelligence/): Attribution and IOCs
- [docx](../../baseline/docx/): Report generation
