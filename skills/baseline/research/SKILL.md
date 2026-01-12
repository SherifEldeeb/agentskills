---
name: research
description: |
  Gather and synthesize information from web sources, APIs, and databases.
  Compile research findings into structured reports. Use when researching
  topics, gathering threat intelligence, or compiling background information.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Required packages: requests, beautifulsoup4
  - Network access required
metadata:
  author: SherifEldeeb
  version: "0.1.0"
  category: baseline
  status: planned
---

# Research Skill

Gather and synthesize information from various sources.

## Capabilities

- **Web Research**: Fetch and extract information from web pages
- **API Integration**: Query APIs for structured data
- **Information Synthesis**: Compile findings into reports
- **Source Tracking**: Maintain references and citations

## Status

This skill is planned for development. See the [docx skill](../docx/) for an example of a completed baseline skill.

## Planned Features

- Extract content from web pages
- Query security databases (NVD, MITRE, etc.)
- Compile research into markdown reports
- Track and cite sources
- Summarize findings
- Support for authenticated API queries
- Rate limiting and caching

## Related Skills

- [threat-intelligence](../../cybersecurity/threat-intelligence/): CTI-specific research
- [docx](../docx/): Generate reports from research findings
