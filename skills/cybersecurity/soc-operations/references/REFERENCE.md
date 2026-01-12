# SOC Operations Skill Reference

## API Reference

### AlertTriage Class

```python
class AlertTriage:
    def __init__(self, alert_id: str, source: str, severity: str)
    def add_note(self, note: str, analyst: str)
    def add_ioc(self, ioc_type: str, value: str, context: str = '')
    def set_disposition(self, disposition: str, analyst: str, notes: str = '')
    def escalate(self, reason: str, target: str, analyst: str)
    def to_dict(self) -> dict
    def to_json(self) -> str
```

### ShiftHandover Class

```python
class ShiftHandover:
    def __init__(self, shift_date: str, shift_type: str, analyst: str)
    def add_open_alert(self, alert_id: str, severity: str, source: str, status: str, notes: str = '')
    def add_escalation(self, incident_id: str, summary: str, team: str)
    def add_notable_event(self, event: str)
    def add_pending_task(self, task: str)
    def set_metrics(self, total_alerts: int, closed: int, false_positives: int)
    def generate_report(self) -> str
```

### SOCMetrics Class

```python
class SOCMetrics:
    def add_alert_record(self, alert_data: dict)
    def calculate_mttd(self, days: int = 30) -> float
    def calculate_mttr(self, days: int = 30) -> float
    def get_alert_volume(self, days: int = 7) -> Dict[str, int]
    def get_false_positive_rate(self, days: int = 30) -> float
    def generate_report(self) -> str
```

## Valid Values

### Dispositions
- `true_positive`
- `false_positive`
- `benign`
- `inconclusive`

### Severities
- `Critical`
- `High`
- `Medium`
- `Low`
- `Info`

## Changelog

### [1.0.0] - 2024-01-01
- Initial release
- Alert triage documentation
- Shift handover reports
- SOC metrics tracking
