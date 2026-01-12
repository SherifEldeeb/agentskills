# Cybersecurity Agent Skills

A collection of [Agent Skills](https://agentskills.io) for cybersecurity professionals, designed to enhance AI agent capabilities for consulting, SOC operations, incident response, threat intelligence, and more.

## Overview

This repository contains two categories of skills:

### Baseline Skills
Core utility skills for document processing and general tasks:
- **docx** - Read, modify, and create Word documents
- **xlsx** - Excel spreadsheet manipulation
- **pptx** - PowerPoint presentation creation and editing
- **pdf** - PDF processing and manipulation
- **research** - Web research and information gathering
- **image-generation** - Create diagrams, charts, and visual assets

### Cybersecurity Domain Skills
Specialized skills for security operations:
- **soc-operations** - Security Operations Center workflows and automation
- **incident-response** - IR playbooks, timeline analysis, and reporting
- **threat-intelligence** - CTI gathering, IOC extraction, and threat analysis
- **vulnerability-management** - Vulnerability assessment and remediation tracking
- **grc** - Governance, Risk, and Compliance documentation and assessments

## Quick Start

### Using with Claude Code

1. Clone this repository:
   ```bash
   git clone https://github.com/SherifEldeeb/agentskills.git
   ```

2. Add skills to your Claude Code configuration:
   ```bash
   cd agentskills
   # Skills are automatically discovered from the skills/ directory
   ```

3. Skills will be available when working with Claude Code on relevant tasks.

### Manual Skill Loading

Reference a specific skill in your conversation:
```
Use the docx skill to convert my markdown report to a Word document using the company template.
```

## Repository Structure

```
agentskills/
├── README.md                    # This file
├── DEVELOPMENT.md               # Development guidelines and standards
├── CONTRIBUTING.md              # Contribution guidelines
├── LICENSE                      # License information
├── skills/
│   ├── baseline/                # Core utility skills
│   │   ├── docx/
│   │   ├── xlsx/
│   │   ├── pptx/
│   │   ├── pdf/
│   │   ├── research/
│   │   └── image-generation/
│   └── cybersecurity/           # Domain-specific skills
│       ├── soc-operations/
│       ├── incident-response/
│       ├── threat-intelligence/
│       ├── vulnerability-management/
│       └── grc/
└── templates/
    └── skill-template/          # Template for creating new skills
```

## Skill Format

Each skill follows the [Agent Skills Specification](https://agentskills.io/specification):

```
skill-name/
├── SKILL.md           # Required: Frontmatter + instructions
├── scripts/           # Optional: Executable code
├── references/        # Optional: Additional documentation
└── assets/            # Optional: Templates, data files
```

### SKILL.md Structure

```yaml
---
name: skill-name
description: What this skill does and when to use it.
license: Apache-2.0
compatibility: Requirements for using this skill
metadata:
  author: your-org
  version: "1.0"
---

# Skill Instructions

Detailed instructions for the AI agent...
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for:
- Skill development guidelines
- Testing procedures
- Code style and conventions
- Architecture decisions

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to submit new skills
- Pull request process
- Code review guidelines
- Community standards

## Use Cases

### Security Consulting
- Generate professional security reports from markdown notes
- Create executive presentations from assessment findings
- Maintain consistent branding across deliverables

### SOC Operations
- Automate alert triage documentation
- Generate shift handover reports
- Create incident timelines from log data

### Incident Response
- Build IR reports from investigation notes
- Create executive summaries for stakeholders
- Document containment and remediation steps

### Threat Intelligence
- Format threat reports for different audiences
- Extract and structure IOCs from raw intelligence
- Create threat briefings and bulletins

### GRC
- Generate compliance assessment reports
- Create policy documents from templates
- Track control implementations and gaps

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Anthropic Skills](https://github.com/anthropics/skills) - Reference implementation
- [Agent Skills Specification](https://agentskills.io) - Open standard for agent skills
