---
name: incident-response
description: |
  Incident response documentation, timeline analysis, containment procedures,
  and IR reporting. Support the full incident lifecycle from detection to
  lessons learned. Use for security incidents, breach response, and IR planning.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - No external dependencies (standard library only)
metadata:
  author: SherifEldeeb
  version: "1.0.0"
  category: cybersecurity
---

# Incident Response Skill

Support the complete incident response lifecycle with documentation, timeline analysis, and comprehensive reporting capabilities.

## Capabilities

- **Timeline Analysis**: Build and analyze incident timelines with event correlation
- **Incident Documentation**: Create structured incident records with full audit trail
- **Evidence Tracking**: Maintain chain of custody documentation
- **IR Reporting**: Generate reports for technical, executive, and regulatory audiences
- **Playbook Support**: Follow and document playbook execution
- **Lessons Learned**: Facilitate post-incident reviews

## Quick Start

```python
from ir_utils import Incident, IncidentTimeline, EvidenceTracker

# Create an incident
incident = Incident('INC-2024-001', 'Ransomware Infection', 'Critical')
incident.add_affected_system('WORKSTATION-15', 'Encrypted files detected')
incident.set_phase('containment')
incident.add_action('Isolated host from network', 'analyst1')

# Build timeline
timeline = IncidentTimeline('INC-2024-001')
timeline.add_event('2024-01-15 10:30', 'Initial alert from EDR', 'detection')
timeline.add_event('2024-01-15 10:35', 'Host isolated', 'containment')
print(timeline.generate_timeline())

# Track evidence
evidence = EvidenceTracker('INC-2024-001')
evidence.add_item('Memory dump', '/evidence/memdump.raw', 'analyst1')
```

## Usage

### Incident Management

Create and manage incident records throughout the lifecycle.

**Example**:
```python
from ir_utils import Incident

# Create incident
incident = Incident(
    incident_id='INC-2024-001',
    title='Ransomware Infection on Finance Workstation',
    severity='Critical'
)

# Add affected systems
incident.add_affected_system('WORKSTATION-15', 'Primary infected host')
incident.add_affected_system('FILESERVER-02', 'Encrypted shares detected')

# Progress through phases
incident.set_phase('identification')
incident.add_action('Confirmed ransomware variant: LockBit 3.0', 'analyst1')

incident.set_phase('containment')
incident.add_action('Isolated WORKSTATION-15 from network', 'analyst1')
incident.add_action('Blocked C2 domains at firewall', 'analyst2')

incident.set_phase('eradication')
incident.add_action('Reimaged affected workstation', 'admin1')
incident.add_action('Reset compromised credentials', 'admin1')

incident.set_phase('recovery')
incident.add_action('Restored files from backup', 'admin1')
incident.add_action('Verified system integrity', 'analyst1')

incident.set_phase('lessons_learned')
incident.add_action('Conducted post-incident review', 'manager1')

# Generate report
print(incident.generate_report())
print(incident.generate_executive_summary())
```

### Timeline Analysis

Build detailed incident timelines for analysis.

**Example**:
```python
from ir_utils import IncidentTimeline

timeline = IncidentTimeline('INC-2024-001')

# Add events with categories
timeline.add_event(
    timestamp='2024-01-15 10:00:00',
    description='Phishing email received by user',
    category='initial_access',
    source='Email logs'
)

timeline.add_event(
    timestamp='2024-01-15 10:15:00',
    description='User clicked malicious link',
    category='execution',
    source='Proxy logs'
)

timeline.add_event(
    timestamp='2024-01-15 10:20:00',
    description='Malware downloaded and executed',
    category='execution',
    source='EDR'
)

timeline.add_event(
    timestamp='2024-01-15 10:25:00',
    description='C2 beacon established',
    category='command_and_control',
    source='Network logs'
)

timeline.add_event(
    timestamp='2024-01-15 10:30:00',
    description='EDR alert triggered',
    category='detection',
    source='CrowdStrike'
)

# Generate outputs
print(timeline.generate_timeline())  # Markdown timeline
print(timeline.to_json())            # JSON export
timeline.export_csv('incident_timeline.csv')
```

### Evidence Tracking

Maintain chain of custody for digital evidence.

**Example**:
```python
from ir_utils import EvidenceTracker

evidence = EvidenceTracker('INC-2024-001')

# Add evidence items
evidence.add_item(
    name='Memory Dump - WORKSTATION-15',
    location='/evidence/INC-2024-001/memdump_ws15.raw',
    collected_by='analyst1',
    description='Full memory dump of infected workstation',
    hash_value='sha256:abc123...'
)

evidence.add_item(
    name='Malware Sample',
    location='/evidence/INC-2024-001/malware.exe',
    collected_by='analyst1',
    description='Ransomware executable',
    hash_value='sha256:def456...'
)

evidence.add_item(
    name='Network Capture',
    location='/evidence/INC-2024-001/traffic.pcap',
    collected_by='analyst2',
    description='Network traffic during incident',
    hash_value='sha256:ghi789...'
)

# Transfer custody
evidence.transfer_custody('Memory Dump - WORKSTATION-15', 'analyst1', 'forensics_team')

# Generate chain of custody report
print(evidence.generate_chain_of_custody())

# List all evidence
print(evidence.list_evidence())
```

### IR Playbooks

Document playbook execution during incidents.

**Example**:
```python
from ir_utils import PlaybookExecution

playbook = PlaybookExecution(
    playbook_name='Ransomware Response',
    incident_id='INC-2024-001',
    analyst='analyst1'
)

# Execute and document steps
playbook.start_step('Isolate affected systems')
playbook.complete_step('Isolated WORKSTATION-15 via EDR', success=True)

playbook.start_step('Preserve evidence')
playbook.complete_step('Memory dump and disk image collected', success=True)

playbook.start_step('Identify ransomware variant')
playbook.complete_step('Identified as LockBit 3.0', success=True)

playbook.start_step('Check for decryption tools')
playbook.complete_step('No free decryptor available', success=False,
                       notes='Proceeding with restoration from backup')

# Generate execution log
print(playbook.generate_log())
```

### Lessons Learned

Document post-incident reviews.

**Example**:
```python
from ir_utils import LessonsLearned

review = LessonsLearned('INC-2024-001', 'Ransomware Infection')

# Document what happened
review.set_summary('''
A phishing email bypassed email security and led to ransomware infection
on a finance department workstation. The infection spread to shared drives
before being contained. Recovery was achieved through backup restoration.
''')

# Add findings
review.add_finding(
    category='detection',
    finding='EDR alert triggered within 10 minutes of execution',
    assessment='positive'
)

review.add_finding(
    category='prevention',
    finding='Email security did not detect malicious attachment',
    assessment='negative'
)

review.add_finding(
    category='response',
    finding='Containment took 5 minutes after alert',
    assessment='positive'
)

# Add recommendations
review.add_recommendation(
    'Implement email sandboxing for attachments',
    priority='High',
    owner='Security Engineering'
)

review.add_recommendation(
    'Conduct phishing awareness training for finance team',
    priority='Medium',
    owner='Security Awareness'
)

# Generate report
print(review.generate_report())
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `IR_EVIDENCE_PATH` | Base path for evidence storage | No | `./evidence` |
| `IR_REPORT_PATH` | Path for generated reports | No | `./reports` |

## Incident Phases

The standard incident response phases:

1. **identification** - Detect and validate the incident
2. **containment** - Limit the scope and impact
3. **eradication** - Remove the threat
4. **recovery** - Restore normal operations
5. **lessons_learned** - Post-incident review

## Limitations

- **No Orchestration**: Does not automate response actions
- **Local Storage**: Evidence metadata stored locally
- **No Integrations**: Manual data entry from tools

## Troubleshooting

### Invalid Phase Error

Use only valid incident phases:
```python
incident.set_phase('containment')  # OK
incident.set_phase('contain')      # Error!
```

### Timeline Ordering

Events are automatically sorted by timestamp:
```python
# Events can be added in any order
timeline.add_event('2024-01-15 10:30', 'Event B', 'detection')
timeline.add_event('2024-01-15 10:00', 'Event A', 'initial_access')
# Timeline will display A before B
```

## Related Skills

- [soc-operations](../soc-operations/): Initial detection and triage
- [threat-intelligence](../threat-intelligence/): Attribution and IOCs
- [docx](../../baseline/docx/): Report generation

## References

- [Detailed API Reference](references/REFERENCE.md)
- [NIST SP 800-61](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
