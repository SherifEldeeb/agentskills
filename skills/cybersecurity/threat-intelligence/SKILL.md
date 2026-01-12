---
name: threat-intelligence
description: |
  Cyber Threat Intelligence gathering, IOC extraction, threat analysis, and
  intelligence reporting. Process threat data and produce actionable intelligence.
  Use for CTI work, threat research, and intelligence dissemination.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Network access for threat feeds
metadata:
  author: SherifEldeeb
  version: "0.1.0"
  category: cybersecurity
  status: planned
---

# Threat Intelligence Skill

Gather, analyze, and disseminate cyber threat intelligence.

## Capabilities

- **IOC Extraction**: Extract indicators from various sources
- **Threat Analysis**: Analyze threat actor TTPs
- **Intelligence Reporting**: Generate threat reports
- **Feed Processing**: Process threat intelligence feeds
- **MITRE ATT&CK Mapping**: Map threats to ATT&CK framework

## Status

This skill is planned for development.

## Planned Features

### IOC Management
- Extract IOCs from reports and logs
- IOC deduplication and validation
- Export to STIX/TAXII format
- IOC enrichment with context

### Threat Analysis
- Threat actor profiling
- Campaign tracking
- TTP documentation
- Attribution analysis

### Reporting
- Threat bulletins
- Actor profiles
- Campaign reports
- Strategic intelligence assessments

### Framework Mapping
- MITRE ATT&CK mapping
- Kill chain analysis
- Diamond model application
- Threat modeling support

### Feed Integration
- OSINT feed processing
- Commercial feed integration
- Feed aggregation
- Alert generation

## Use Cases

1. **Daily Intelligence**
   - Morning threat briefing
   - Relevant threat updates
   - New IOCs for detection

2. **Threat Research**
   - Actor investigation
   - Malware analysis support
   - Campaign tracking

3. **Strategic Intelligence**
   - Quarterly threat landscape
   - Industry-specific threats
   - Emerging threat trends

4. **Operational Support**
   - Hunt hypotheses
   - Detection rule suggestions
   - Incident context enrichment

## Related Skills

- [incident-response](../incident-response/): Apply CTI during incidents
- [soc-operations](../soc-operations/): CTI-informed detection
- [research](../../baseline/research/): General research capabilities
