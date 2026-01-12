#!/usr/bin/env python3
"""
Cyber Threat Intelligence Utility Functions

Utilities for CTI gathering, analysis, and dissemination.

Usage:
    from cti_utils import IOCExtractor, ThreatActor, IntelReport
"""

import re
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger(__name__)


class IOCExtractor:
    """Extract indicators of compromise from text."""

    # Regex patterns for IOC extraction
    PATTERNS = {
        'ip': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        'cve': r'CVE-\d{4}-\d{4,7}'
    }

    def extract_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract all IOC types from text."""
        # Refang common defanged patterns first
        text = self.refang(text)

        results = {
            'ip': list(set(re.findall(self.PATTERNS['ip'], text))),
            'domain': list(set(re.findall(self.PATTERNS['domain'], text))),
            'url': list(set(re.findall(self.PATTERNS['url'], text))),
            'hash': [],
            'email': list(set(re.findall(self.PATTERNS['email'], text))),
            'cve': list(set(re.findall(self.PATTERNS['cve'], text)))
        }

        # Collect hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            results['hash'].extend(re.findall(self.PATTERNS[hash_type], text))
        results['hash'] = list(set(results['hash']))

        # Filter out IPs from domains
        results['domain'] = [d for d in results['domain']
                           if not re.match(self.PATTERNS['ip'], d)]

        return results

    def defang(self, ioc: str) -> str:
        """Defang an IOC for safe sharing."""
        result = ioc
        result = result.replace('http://', 'hxxp://')
        result = result.replace('https://', 'hxxps://')
        result = result.replace('.', '[.]')
        return result

    def refang(self, text: str) -> str:
        """Refang defanged IOCs."""
        result = text
        result = result.replace('hxxp://', 'http://')
        result = result.replace('hxxps://', 'https://')
        result = result.replace('[.]', '.')
        result = result.replace('[@]', '@')
        return result

    def validate_ioc(self, ioc_type: str, value: str) -> bool:
        """Validate IOC format."""
        if ioc_type == 'ip':
            parts = value.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(p) <= 255 for p in parts if p.isdigit())
        elif ioc_type in self.PATTERNS:
            return bool(re.fullmatch(self.PATTERNS[ioc_type], value))
        return True


class IOCCollection:
    """Manage a collection of IOCs."""

    def __init__(self, name: str):
        self.name = name
        self.iocs = []
        self.created_at = datetime.now()

    def add_ioc(self, ioc_type: str, value: str, context: str = '',
                confidence: str = 'medium', source: str = ''):
        """Add IOC to collection."""
        self.iocs.append({
            'type': ioc_type,
            'value': value,
            'context': context,
            'confidence': confidence,
            'source': source,
            'added_at': datetime.now().isoformat()
        })

    def deduplicate(self):
        """Remove duplicate IOCs."""
        seen = set()
        unique = []
        for ioc in self.iocs:
            key = (ioc['type'], ioc['value'])
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        self.iocs = unique

    def to_csv(self) -> str:
        """Export to CSV format."""
        lines = ['type,value,context,confidence,source']
        for ioc in self.iocs:
            lines.append(f"{ioc['type']},{ioc['value']},{ioc['context']},{ioc['confidence']},{ioc['source']}")
        return '\n'.join(lines)

    def to_json(self) -> str:
        """Export to JSON format."""
        return json.dumps({
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'iocs': self.iocs
        }, indent=2)

    def to_stix(self) -> str:
        """Export to STIX 2.1 format (simplified)."""
        stix_objects = []
        for ioc in self.iocs:
            stix_obj = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f"indicator--{hashlib.md5(ioc['value'].encode()).hexdigest()}",
                'created': ioc['added_at'],
                'pattern_type': 'stix',
                'pattern': f"[{ioc['type']}:value = '{ioc['value']}']",
                'valid_from': ioc['added_at']
            }
            stix_objects.append(stix_obj)

        return json.dumps({
            'type': 'bundle',
            'id': f'bundle--{hashlib.md5(self.name.encode()).hexdigest()}',
            'objects': stix_objects
        }, indent=2)


class ThreatActor:
    """Document threat actor profiles."""

    def __init__(self, name: str, aliases: List[str] = None):
        self.name = name
        self.aliases = aliases or []
        self.motivation = None
        self.sophistication = None
        self.origin = None
        self.ttps = []
        self.target_sectors = []
        self.target_regions = []
        self.tools = []
        self.infrastructure = []

    def set_motivation(self, motivation: str):
        """Set actor motivation (espionage, financial, hacktivism, etc.)."""
        self.motivation = motivation

    def set_sophistication(self, level: str):
        """Set sophistication level (novice, intermediate, advanced, expert)."""
        self.sophistication = level

    def set_origin(self, origin: str):
        """Set suspected origin/attribution."""
        self.origin = origin

    def add_ttp(self, technique_id: str, description: str):
        """Add MITRE ATT&CK technique."""
        self.ttps.append({'id': technique_id, 'description': description})

    def add_target_sector(self, sector: str):
        """Add targeted sector."""
        self.target_sectors.append(sector)

    def add_target_region(self, region: str):
        """Add targeted region."""
        self.target_regions.append(region)

    def add_tool(self, tool: str):
        """Add known tool used by actor."""
        self.tools.append(tool)

    def add_infrastructure(self, infra_type: str, value: str, context: str = ''):
        """Add known infrastructure."""
        self.infrastructure.append({
            'type': infra_type,
            'value': value,
            'context': context
        })

    def generate_profile(self) -> str:
        """Generate threat actor profile."""
        aliases = ', '.join(self.aliases) if self.aliases else 'None known'

        report = f"""# Threat Actor Profile: {self.name}

**Aliases:** {aliases}
**Motivation:** {self.motivation or 'Unknown'}
**Sophistication:** {self.sophistication or 'Unknown'}
**Suspected Origin:** {self.origin or 'Unknown'}

---

## Targeting

### Sectors
"""
        for sector in self.target_sectors:
            report += f"- {sector}\n"

        report += "\n### Regions\n"
        for region in self.target_regions:
            report += f"- {region}\n"

        report += "\n## TTPs (MITRE ATT&CK)\n\n"
        report += "| Technique ID | Description |\n"
        report += "|--------------|-------------|\n"
        for ttp in self.ttps:
            report += f"| {ttp['id']} | {ttp['description']} |\n"

        report += "\n## Tools\n\n"
        for tool in self.tools:
            report += f"- {tool}\n"

        report += "\n## Known Infrastructure\n\n"
        report += "| Type | Value | Context |\n"
        report += "|------|-------|--------|\n"
        for infra in self.infrastructure:
            report += f"| {infra['type']} | {infra['value']} | {infra['context']} |\n"

        return report


class Campaign:
    """Track threat campaigns."""

    def __init__(self, name: str, first_seen: str, threat_actor: str = ''):
        self.name = name
        self.first_seen = first_seen
        self.threat_actor = threat_actor
        self.description = ''
        self.objective = ''
        self.iocs = []
        self.ttps = []
        self.targets = []
        self.events = []

    def set_description(self, description: str):
        """Set campaign description."""
        self.description = description.strip()

    def set_objective(self, objective: str):
        """Set campaign objective."""
        self.objective = objective

    def add_ioc(self, ioc_type: str, value: str, context: str = ''):
        """Add campaign IOC."""
        self.iocs.append({'type': ioc_type, 'value': value, 'context': context})

    def add_ttp(self, technique_id: str, description: str):
        """Add TTP."""
        self.ttps.append({'id': technique_id, 'description': description})

    def add_target(self, sector: str, region: str):
        """Add target."""
        self.targets.append({'sector': sector, 'region': region})

    def add_event(self, date: str, description: str):
        """Add campaign timeline event."""
        self.events.append({'date': date, 'description': description})
        self.events.sort(key=lambda x: x['date'])

    def generate_report(self) -> str:
        """Generate campaign report."""
        report = f"""# Campaign Report: {self.name}

**Threat Actor:** {self.threat_actor or 'Unknown'}
**First Seen:** {self.first_seen}
**Objective:** {self.objective or 'Unknown'}

---

## Description

{self.description}

## Targets

| Sector | Region |
|--------|--------|
"""
        for target in self.targets:
            report += f"| {target['sector']} | {target['region']} |\n"

        report += "\n## TTPs\n\n"
        for ttp in self.ttps:
            report += f"- **{ttp['id']}**: {ttp['description']}\n"

        report += "\n## Indicators of Compromise\n\n"
        report += "| Type | Value | Context |\n"
        report += "|------|-------|--------|\n"
        for ioc in self.iocs:
            report += f"| {ioc['type']} | {ioc['value']} | {ioc['context']} |\n"

        report += "\n## Timeline\n\n"
        for event in self.events:
            report += f"- **{event['date']}**: {event['description']}\n"

        return report


class ATTACKMapper:
    """Map threats to MITRE ATT&CK framework."""

    TACTICS = [
        'reconnaissance', 'resource_development', 'initial_access',
        'execution', 'persistence', 'privilege_escalation', 'defense_evasion',
        'credential_access', 'discovery', 'lateral_movement', 'collection',
        'command_and_control', 'exfiltration', 'impact'
    ]

    def __init__(self):
        self.techniques = []

    def add_technique(self, technique_id: str, context: str = ''):
        """Add ATT&CK technique."""
        self.techniques.append({
            'id': technique_id,
            'context': context,
            'added_at': datetime.now().isoformat()
        })

    def generate_matrix(self) -> str:
        """Generate ATT&CK matrix view."""
        report = """# MITRE ATT&CK Mapping

| Technique ID | Context |
|--------------|---------|
"""
        for tech in self.techniques:
            report += f"| {tech['id']} | {tech['context']} |\n"

        return report

    def get_technique_info(self, technique_id: str) -> dict:
        """Get technique information."""
        for tech in self.techniques:
            if tech['id'] == technique_id:
                return tech
        return {}

    def export_navigator(self, filepath: str):
        """Export for ATT&CK Navigator."""
        layer = {
            'name': 'Threat Analysis',
            'versions': {'attack': '12', 'navigator': '4.8'},
            'domain': 'enterprise-attack',
            'techniques': [
                {'techniqueID': t['id'], 'score': 100, 'comment': t['context']}
                for t in self.techniques
            ]
        }
        with open(filepath, 'w') as f:
            json.dump(layer, f, indent=2)


class IntelReport:
    """Generate threat intelligence reports."""

    def __init__(self, title: str, classification: str = 'TLP:GREEN'):
        self.title = title
        self.classification = classification
        self.created_at = datetime.now()
        self.summary = ''
        self.findings = []
        self.iocs = []
        self.ttps = []
        self.recommendations = []

    def set_summary(self, summary: str):
        """Set executive summary."""
        self.summary = summary.strip()

    def add_finding(self, finding: str):
        """Add key finding."""
        self.findings.append(finding)

    def add_ioc(self, ioc_type: str, value: str, context: str = ''):
        """Add IOC."""
        self.iocs.append({'type': ioc_type, 'value': value, 'context': context})

    def add_ttp(self, technique_id: str, description: str):
        """Add TTP."""
        self.ttps.append({'id': technique_id, 'description': description})

    def add_recommendation(self, recommendation: str):
        """Add recommendation."""
        self.recommendations.append(recommendation)

    def generate(self) -> str:
        """Generate full intelligence report."""
        report = f"""# {self.title}

**Classification:** {self.classification}
**Date:** {self.created_at.strftime('%Y-%m-%d')}

---

## Executive Summary

{self.summary}

## Key Findings

"""
        for i, finding in enumerate(self.findings, 1):
            report += f"{i}. {finding}\n"

        report += "\n## Indicators of Compromise\n\n"
        report += "| Type | Value | Context |\n"
        report += "|------|-------|--------|\n"
        for ioc in self.iocs:
            report += f"| {ioc['type']} | {ioc['value']} | {ioc['context']} |\n"

        report += "\n## TTPs\n\n"
        for ttp in self.ttps:
            report += f"- **{ttp['id']}**: {ttp['description']}\n"

        report += "\n## Recommendations\n\n"
        for rec in self.recommendations:
            report += f"- {rec}\n"

        return report

    def generate_executive_brief(self) -> str:
        """Generate executive brief."""
        return f"""# Executive Brief: {self.title}

**Classification:** {self.classification}
**Date:** {self.created_at.strftime('%Y-%m-%d')}

## Summary

{self.summary}

## Key Points

- **Findings:** {len(self.findings)}
- **IOCs Identified:** {len(self.iocs)}
- **TTPs Mapped:** {len(self.ttps)}

## Immediate Actions Required

"""
