#!/usr/bin/env python3
"""
SOC Operations Utility Functions

Common utilities for Security Operations Center workflows.

Usage:
    from soc_utils import AlertTriage, ShiftHandover, SOCMetrics
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


class AlertTriage:
    """Standardized alert triage documentation."""

    VALID_DISPOSITIONS = ['true_positive', 'false_positive', 'benign', 'inconclusive']
    VALID_SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info']

    def __init__(self, alert_id: str, source: str, severity: str):
        self.alert_id = alert_id
        self.source = source
        self.severity = severity
        self.timestamp_received = datetime.now()
        self.timestamp_triaged = None
        self.analyst = None
        self.disposition = None
        self.investigation_notes = []
        self.iocs = []
        self.escalated = False
        self.escalation_reason = None
        self.escalation_target = None

    def add_note(self, note: str, analyst: str):
        """Add investigation note."""
        self.investigation_notes.append({
            'timestamp': datetime.now().isoformat(),
            'analyst': analyst,
            'note': note
        })

    def add_ioc(self, ioc_type: str, value: str, context: str = ''):
        """Add indicator of compromise."""
        self.iocs.append({
            'type': ioc_type,
            'value': value,
            'context': context,
            'added_at': datetime.now().isoformat()
        })

    def set_disposition(self, disposition: str, analyst: str, notes: str = ''):
        """Set alert disposition."""
        if disposition not in self.VALID_DISPOSITIONS:
            raise ValueError(f"Invalid disposition: {disposition}")

        self.disposition = disposition
        self.timestamp_triaged = datetime.now()
        self.analyst = analyst
        if notes:
            self.add_note(notes, analyst)

    def escalate(self, reason: str, target: str, analyst: str):
        """Escalate alert."""
        self.escalated = True
        self.escalation_reason = reason
        self.escalation_target = target
        self.add_note(f"Escalated to {target}: {reason}", analyst)

    def get_triage_time_minutes(self) -> Optional[float]:
        """Get time to triage in minutes."""
        if self.timestamp_triaged:
            delta = self.timestamp_triaged - self.timestamp_received
            return delta.total_seconds() / 60
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'source': self.source,
            'severity': self.severity,
            'received': self.timestamp_received.isoformat(),
            'triaged': self.timestamp_triaged.isoformat() if self.timestamp_triaged else None,
            'triage_time_minutes': self.get_triage_time_minutes(),
            'analyst': self.analyst,
            'disposition': self.disposition,
            'escalated': self.escalated,
            'escalation_reason': self.escalation_reason,
            'notes': self.investigation_notes,
            'iocs': self.iocs
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class ShiftHandover:
    """Generate shift handover reports."""

    def __init__(self, shift_date: str, shift_type: str, analyst: str):
        self.shift_date = shift_date
        self.shift_type = shift_type
        self.analyst = analyst
        self.open_alerts = []
        self.escalated_incidents = []
        self.notable_events = []
        self.pending_tasks = []
        self.metrics = {}

    def add_open_alert(self, alert_id: str, severity: str, source: str,
                       status: str, notes: str = ''):
        """Add open alert to handover."""
        self.open_alerts.append({
            'id': alert_id,
            'severity': severity,
            'source': source,
            'status': status,
            'notes': notes
        })

    def add_escalation(self, incident_id: str, summary: str, team: str):
        """Add escalated incident."""
        self.escalated_incidents.append({
            'id': incident_id,
            'summary': summary,
            'team': team
        })

    def add_notable_event(self, event: str):
        """Add notable event."""
        self.notable_events.append(event)

    def add_pending_task(self, task: str):
        """Add pending task."""
        self.pending_tasks.append(task)

    def set_metrics(self, total_alerts: int, closed: int, false_positives: int):
        """Set shift metrics."""
        self.metrics = {
            'total_alerts': total_alerts,
            'closed': closed,
            'false_positives': false_positives,
            'pending': len(self.open_alerts)
        }

    def generate_report(self) -> str:
        """Generate markdown handover report."""
        report = f"""# SOC Shift Handover Report

**Date:** {self.shift_date}
**Shift:** {self.shift_type.title()} Shift
**Analyst:** {self.analyst}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

---

## Shift Summary

| Metric | Value |
|--------|-------|
| Total Alerts | {self.metrics.get('total_alerts', 'N/A')} |
| Closed | {self.metrics.get('closed', 'N/A')} |
| Pending | {len(self.open_alerts)} |
| Escalations | {len(self.escalated_incidents)} |

## Open/Pending Alerts

| Alert ID | Severity | Source | Status | Notes |
|----------|----------|--------|--------|-------|
"""
        for alert in self.open_alerts:
            report += f"| {alert['id']} | {alert['severity']} | {alert['source']} | {alert['status']} | {alert['notes']} |\n"

        report += "\n## Escalated Incidents\n\n"
        if self.escalated_incidents:
            for inc in self.escalated_incidents:
                report += f"- **{inc['id']}**: {inc['summary']} → {inc['team']}\n"
        else:
            report += "- No escalations during this shift\n"

        report += "\n## Notable Events\n\n"
        for event in self.notable_events:
            report += f"- {event}\n"

        report += "\n## Pending Tasks\n\n"
        for task in self.pending_tasks:
            report += f"- [ ] {task}\n"

        return report


class SOCMetrics:
    """Track SOC operational metrics."""

    def __init__(self):
        self.alerts = []

    def add_alert_record(self, alert_data: dict):
        """Add alert record for metrics."""
        self.alerts.append(alert_data)

    def calculate_mttd(self, days: int = 30) -> float:
        """Calculate Mean Time to Detect (minutes)."""
        cutoff = datetime.now() - timedelta(days=days)
        relevant = [a for a in self.alerts
                   if a.get('detected_at') and a.get('detected_at') > cutoff]

        if not relevant:
            return 0

        times = []
        for a in relevant:
            if a.get('occurred_at'):
                delta = (a['detected_at'] - a['occurred_at']).total_seconds() / 60
                times.append(delta)

        return sum(times) / len(times) if times else 0

    def calculate_mttr(self, days: int = 30) -> float:
        """Calculate Mean Time to Respond (minutes)."""
        cutoff = datetime.now() - timedelta(days=days)
        relevant = [a for a in self.alerts
                   if a.get('detected_at') and a.get('detected_at') > cutoff
                   and a.get('responded_at')]

        if not relevant:
            return 0

        times = [(a['responded_at'] - a['detected_at']).total_seconds() / 60
                for a in relevant]

        return sum(times) / len(times)

    def get_alert_volume(self, days: int = 7) -> Dict[str, int]:
        """Get alert counts by severity."""
        cutoff = datetime.now() - timedelta(days=days)
        counts = defaultdict(int)

        for alert in self.alerts:
            if alert.get('detected_at') and alert['detected_at'] > cutoff:
                counts[alert.get('severity', 'Unknown')] += 1

        return dict(counts)

    def get_false_positive_rate(self, days: int = 30) -> float:
        """Calculate false positive rate percentage."""
        cutoff = datetime.now() - timedelta(days=days)
        relevant = [a for a in self.alerts
                   if a.get('detected_at') and a.get('detected_at') > cutoff
                   and a.get('disposition')]

        if not relevant:
            return 0

        fp_count = sum(1 for a in relevant if a['disposition'] == 'false_positive')
        return (fp_count / len(relevant)) * 100

    def generate_report(self) -> str:
        """Generate metrics report."""
        volume = self.get_alert_volume()

        return f"""# SOC Metrics Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Key Performance Indicators (30 days)

| Metric | Value |
|--------|-------|
| Mean Time to Detect | {self.calculate_mttd():.1f} min |
| Mean Time to Respond | {self.calculate_mttr():.1f} min |
| False Positive Rate | {self.get_false_positive_rate():.1f}% |

## Alert Volume (7 days)

| Severity | Count |
|----------|-------|
""" + '\n'.join(f"| {sev} | {count} |" for sev, count in sorted(volume.items()))


def generate_triage_template(alert_type: str) -> str:
    """Generate a triage template for common alert types."""
    templates = {
        'malware': """## Malware Alert Triage

### Initial Assessment
- [ ] Review alert details and severity
- [ ] Check host reputation/history
- [ ] Verify file hash against threat intel

### Investigation Steps
- [ ] Examine process tree
- [ ] Check network connections
- [ ] Review file system changes
- [ ] Analyze user activity

### Disposition Criteria
- **True Positive**: Confirmed malicious activity
- **False Positive**: Known good/approved software
- **Benign**: Suspicious but authorized behavior
""",
        'network': """## Network Alert Triage

### Initial Assessment
- [ ] Review source and destination IPs
- [ ] Check against threat intel feeds
- [ ] Verify traffic patterns

### Investigation Steps
- [ ] Analyze packet captures
- [ ] Review DNS queries
- [ ] Check for data exfiltration indicators
- [ ] Correlate with endpoint activity

### Disposition Criteria
- **True Positive**: Confirmed malicious traffic
- **False Positive**: Known good traffic/misconfigured rule
- **Benign**: Unusual but legitimate traffic
""",
        'authentication': """## Authentication Alert Triage

### Initial Assessment
- [ ] Review failed/successful attempts
- [ ] Check source locations
- [ ] Verify user account status

### Investigation Steps
- [ ] Analyze login patterns
- [ ] Check for credential stuffing indicators
- [ ] Review MFA status
- [ ] Contact user if needed

### Disposition Criteria
- **True Positive**: Confirmed unauthorized access attempt
- **False Positive**: User error/password reset
- **Benign**: Legitimate but unusual access
"""
    }
    return templates.get(alert_type, templates['malware'])
