# Incident Response Skill Reference

## API Reference

### Incident Class

```python
class Incident:
    def __init__(self, incident_id: str, title: str, severity: str)
    def set_phase(self, phase: str)
    def add_affected_system(self, system: str, description: str = '')
    def add_action(self, action: str, analyst: str, notes: str = '')
    def generate_report(self) -> str
    def generate_executive_summary(self) -> str
    def to_dict(self) -> dict
    def to_json(self) -> str
```

### IncidentTimeline Class

```python
class IncidentTimeline:
    def __init__(self, incident_id: str)
    def add_event(self, timestamp: str, description: str, category: str, source: str = '', analyst: str = '')
    def generate_timeline(self) -> str
    def export_csv(self, filepath: str)
    def to_json(self) -> str
```

### EvidenceTracker Class

```python
class EvidenceTracker:
    def __init__(self, incident_id: str)
    def add_item(self, name: str, location: str, collected_by: str, description: str = '', hash_value: str = '')
    def transfer_custody(self, item_name: str, from_holder: str, to_holder: str, notes: str = '')
    def generate_chain_of_custody(self) -> str
    def list_evidence(self) -> str
```

### PlaybookExecution Class

```python
class PlaybookExecution:
    def __init__(self, playbook_name: str, incident_id: str, analyst: str)
    def start_step(self, step_name: str)
    def complete_step(self, result: str, success: bool = True, notes: str = '')
    def generate_log(self) -> str
```

### LessonsLearned Class

```python
class LessonsLearned:
    def __init__(self, incident_id: str, incident_title: str)
    def set_summary(self, summary: str)
    def add_finding(self, category: str, finding: str, assessment: str)
    def add_recommendation(self, recommendation: str, priority: str, owner: str)
    def generate_report(self) -> str
```

## Valid Values

### Incident Phases
- `identification`
- `containment`
- `eradication`
- `recovery`
- `lessons_learned`

### Severities
- `Critical`
- `High`
- `Medium`
- `Low`

### Timeline Categories
- `initial_access`
- `execution`
- `persistence`
- `privilege_escalation`
- `defense_evasion`
- `credential_access`
- `discovery`
- `lateral_movement`
- `collection`
- `command_and_control`
- `exfiltration`
- `impact`
- `detection`
- `containment`
- `eradication`
- `recovery`

### Finding Assessments
- `positive`
- `negative`

## Changelog

### [1.0.0] - 2024-01-01
- Initial release
- Incident lifecycle management
- Timeline analysis
- Evidence tracking
- Playbook execution logging
- Lessons learned documentation
