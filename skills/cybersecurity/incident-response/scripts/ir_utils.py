#!/usr/bin/env python3
"""
Incident Response Utility Functions

Utilities for managing incident response documentation and workflows.

Usage:
    from ir_utils import Incident, IncidentTimeline, EvidenceTracker
"""

import json
import csv
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class Incident:
    """Manage incident lifecycle and documentation."""

    VALID_PHASES = [
        'identification', 'containment', 'eradication',
        'recovery', 'lessons_learned'
    ]
    VALID_SEVERITIES = ['Critical', 'High', 'Medium', 'Low']

    def __init__(self, incident_id: str, title: str, severity: str):
        if severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        self.incident_id = incident_id
        self.title = title
        self.severity = severity
        self.created_at = datetime.now()
        self.current_phase = 'identification'
        self.affected_systems = []
        self.actions = []
        self.phase_history = [{'phase': 'identification', 'timestamp': datetime.now().isoformat()}]

    def set_phase(self, phase: str):
        """Set current incident phase."""
        if phase not in self.VALID_PHASES:
            raise ValueError(f"Invalid phase: {phase}. Valid: {self.VALID_PHASES}")
        self.current_phase = phase
        self.phase_history.append({
            'phase': phase,
            'timestamp': datetime.now().isoformat()
        })

    def add_affected_system(self, system: str, description: str = ''):
        """Add an affected system."""
        self.affected_systems.append({
            'system': system,
            'description': description,
            'added_at': datetime.now().isoformat()
        })

    def add_action(self, action: str, analyst: str, notes: str = ''):
        """Add a response action."""
        self.actions.append({
            'action': action,
            'analyst': analyst,
            'phase': self.current_phase,
            'timestamp': datetime.now().isoformat(),
            'notes': notes
        })

    def generate_report(self) -> str:
        """Generate detailed incident report."""
        report = f"""# Incident Report: {self.incident_id}

**Title:** {self.title}
**Severity:** {self.severity}
**Created:** {self.created_at.strftime('%Y-%m-%d %H:%M')}
**Current Phase:** {self.current_phase.replace('_', ' ').title()}

---

## Affected Systems

| System | Description |
|--------|-------------|
"""
        for sys in self.affected_systems:
            report += f"| {sys['system']} | {sys['description']} |\n"

        report += "\n## Response Actions\n\n"
        for phase in self.VALID_PHASES:
            phase_actions = [a for a in self.actions if a['phase'] == phase]
            if phase_actions:
                report += f"### {phase.replace('_', ' ').title()}\n\n"
                for action in phase_actions:
                    report += f"- **{action['timestamp']}** ({action['analyst']}): {action['action']}\n"
                    if action['notes']:
                        report += f"  - Notes: {action['notes']}\n"
                report += "\n"

        return report

    def generate_executive_summary(self) -> str:
        """Generate executive summary."""
        return f"""# Executive Summary: {self.incident_id}

**Incident:** {self.title}
**Severity:** {self.severity}
**Status:** {self.current_phase.replace('_', ' ').title()}
**Duration:** {(datetime.now() - self.created_at).total_seconds() / 3600:.1f} hours

## Impact
- Affected Systems: {len(self.affected_systems)}
- Response Actions Taken: {len(self.actions)}

## Key Actions
"""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'incident_id': self.incident_id,
            'title': self.title,
            'severity': self.severity,
            'created_at': self.created_at.isoformat(),
            'current_phase': self.current_phase,
            'affected_systems': self.affected_systems,
            'actions': self.actions,
            'phase_history': self.phase_history
        }

    def to_json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.to_dict(), indent=2)


class IncidentTimeline:
    """Build and manage incident timelines."""

    CATEGORIES = [
        'initial_access', 'execution', 'persistence', 'privilege_escalation',
        'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
        'collection', 'command_and_control', 'exfiltration', 'impact',
        'detection', 'containment', 'eradication', 'recovery'
    ]

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.events = []

    def add_event(self, timestamp: str, description: str, category: str,
                  source: str = '', analyst: str = ''):
        """Add timeline event."""
        self.events.append({
            'timestamp': timestamp,
            'description': description,
            'category': category,
            'source': source,
            'analyst': analyst,
            'added_at': datetime.now().isoformat()
        })
        # Sort by timestamp
        self.events.sort(key=lambda x: x['timestamp'])

    def generate_timeline(self) -> str:
        """Generate markdown timeline."""
        report = f"""# Incident Timeline: {self.incident_id}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Events:** {len(self.events)}

---

| Timestamp | Category | Description | Source |
|-----------|----------|-------------|--------|
"""
        for event in self.events:
            report += f"| {event['timestamp']} | {event['category']} | {event['description']} | {event['source']} |\n"

        return report

    def export_csv(self, filepath: str):
        """Export timeline to CSV."""
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'category', 'description', 'source', 'analyst'])
            writer.writeheader()
            writer.writerows(self.events)

    def to_json(self) -> str:
        """Convert to JSON."""
        return json.dumps({
            'incident_id': self.incident_id,
            'events': self.events
        }, indent=2)


class EvidenceTracker:
    """Track digital evidence and chain of custody."""

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.items = {}

    def add_item(self, name: str, location: str, collected_by: str,
                 description: str = '', hash_value: str = ''):
        """Add evidence item."""
        self.items[name] = {
            'name': name,
            'location': location,
            'description': description,
            'hash_value': hash_value,
            'collected_at': datetime.now().isoformat(),
            'collected_by': collected_by,
            'custody_chain': [{
                'holder': collected_by,
                'received_at': datetime.now().isoformat(),
                'notes': 'Initial collection'
            }]
        }

    def transfer_custody(self, item_name: str, from_holder: str,
                         to_holder: str, notes: str = ''):
        """Transfer evidence custody."""
        if item_name not in self.items:
            raise ValueError(f"Evidence item not found: {item_name}")

        item = self.items[item_name]
        current_holder = item['custody_chain'][-1]['holder']

        if current_holder != from_holder:
            raise ValueError(f"Current holder is {current_holder}, not {from_holder}")

        item['custody_chain'].append({
            'holder': to_holder,
            'received_at': datetime.now().isoformat(),
            'transferred_from': from_holder,
            'notes': notes
        })

    def generate_chain_of_custody(self) -> str:
        """Generate chain of custody report."""
        report = f"""# Chain of Custody Report

**Incident:** {self.incident_id}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

---

"""
        for name, item in self.items.items():
            report += f"""## {name}

**Location:** {item['location']}
**Hash:** {item['hash_value']}
**Description:** {item['description']}

### Custody Chain

| Timestamp | Holder | Notes |
|-----------|--------|-------|
"""
            for entry in item['custody_chain']:
                report += f"| {entry['received_at']} | {entry['holder']} | {entry.get('notes', '')} |\n"
            report += "\n"

        return report

    def list_evidence(self) -> str:
        """List all evidence items."""
        report = f"""# Evidence Index: {self.incident_id}

| Item | Location | Hash | Collected By |
|------|----------|------|--------------|
"""
        for item in self.items.values():
            report += f"| {item['name']} | {item['location']} | {item['hash_value'][:16]}... | {item['collected_by']} |\n"

        return report


class PlaybookExecution:
    """Document playbook execution during incidents."""

    def __init__(self, playbook_name: str, incident_id: str, analyst: str):
        self.playbook_name = playbook_name
        self.incident_id = incident_id
        self.analyst = analyst
        self.started_at = datetime.now()
        self.steps = []
        self.current_step = None

    def start_step(self, step_name: str):
        """Start a playbook step."""
        self.current_step = {
            'name': step_name,
            'started_at': datetime.now().isoformat(),
            'completed_at': None,
            'result': None,
            'notes': None,
            'success': None
        }

    def complete_step(self, result: str, success: bool = True, notes: str = ''):
        """Complete current step."""
        if not self.current_step:
            raise ValueError("No step in progress")

        self.current_step['completed_at'] = datetime.now().isoformat()
        self.current_step['result'] = result
        self.current_step['success'] = success
        self.current_step['notes'] = notes
        self.steps.append(self.current_step)
        self.current_step = None

    def generate_log(self) -> str:
        """Generate playbook execution log."""
        report = f"""# Playbook Execution Log

**Playbook:** {self.playbook_name}
**Incident:** {self.incident_id}
**Analyst:** {self.analyst}
**Started:** {self.started_at.strftime('%Y-%m-%d %H:%M')}

---

| Step | Status | Result | Notes |
|------|--------|--------|-------|
"""
        for step in self.steps:
            status = 'Pass' if step['success'] else 'Fail'
            report += f"| {step['name']} | {status} | {step['result']} | {step['notes']} |\n"

        return report


class LessonsLearned:
    """Document post-incident lessons learned."""

    def __init__(self, incident_id: str, incident_title: str):
        self.incident_id = incident_id
        self.incident_title = incident_title
        self.summary = ''
        self.findings = []
        self.recommendations = []

    def set_summary(self, summary: str):
        """Set incident summary."""
        self.summary = summary.strip()

    def add_finding(self, category: str, finding: str, assessment: str):
        """Add a finding (positive or negative)."""
        self.findings.append({
            'category': category,
            'finding': finding,
            'assessment': assessment  # 'positive' or 'negative'
        })

    def add_recommendation(self, recommendation: str, priority: str, owner: str):
        """Add improvement recommendation."""
        self.recommendations.append({
            'recommendation': recommendation,
            'priority': priority,
            'owner': owner,
            'status': 'open'
        })

    def generate_report(self) -> str:
        """Generate lessons learned report."""
        report = f"""# Lessons Learned: {self.incident_id}

**Incident:** {self.incident_title}
**Review Date:** {datetime.now().strftime('%Y-%m-%d')}

---

## Summary

{self.summary}

## Findings

### What Went Well

"""
        positive = [f for f in self.findings if f['assessment'] == 'positive']
        for f in positive:
            report += f"- **{f['category'].title()}**: {f['finding']}\n"

        report += "\n### Areas for Improvement\n\n"
        negative = [f for f in self.findings if f['assessment'] == 'negative']
        for f in negative:
            report += f"- **{f['category'].title()}**: {f['finding']}\n"

        report += "\n## Recommendations\n\n"
        report += "| Recommendation | Priority | Owner | Status |\n"
        report += "|----------------|----------|-------|--------|\n"
        for r in self.recommendations:
            report += f"| {r['recommendation']} | {r['priority']} | {r['owner']} | {r['status']} |\n"

        return report
