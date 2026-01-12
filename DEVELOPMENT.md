# Development Guidelines

This document provides guidelines for developing skills in the Cybersecurity Agent Skills repository.

## Architecture Overview

### Skill Categories

#### Baseline Skills
Core utility skills that provide foundational document and media capabilities:

| Skill | Purpose | Dependencies |
|-------|---------|--------------|
| `docx` | Word document manipulation | python-docx |
| `xlsx` | Excel spreadsheet operations | openpyxl |
| `pptx` | PowerPoint presentations | python-pptx |
| `pdf` | PDF processing | PyPDF2, reportlab |
| `research` | Web research and gathering | requests, beautifulsoup4 |
| `image-generation` | Visual asset creation | pillow, matplotlib |

#### Cybersecurity Domain Skills
Specialized skills for security operations:

| Skill | Purpose | Use Cases |
|-------|---------|-----------|
| `soc-operations` | SOC workflows | Alert triage, shift handovers, metrics |
| `incident-response` | IR processes | Timelines, containment, reporting |
| `threat-intelligence` | CTI workflows | IOC extraction, threat analysis |
| `vulnerability-management` | Vuln tracking | Assessment reports, remediation |
| `grc` | Compliance | Policy docs, control assessments |

## Skill Structure

### Directory Layout

```
skill-name/
├── SKILL.md              # Required: Main skill file
├── scripts/              # Optional: Executable code
│   ├── main.py
│   └── utils.py
├── references/           # Optional: Additional documentation
│   ├── REFERENCE.md
│   └── examples.md
└── assets/               # Optional: Static resources
    ├── templates/
    └── data/
```

### SKILL.md Requirements

Every SKILL.md must include:

#### 1. YAML Frontmatter (Required)

```yaml
---
name: skill-name                    # Required: lowercase, hyphens only
description: |                       # Required: 1-1024 chars
  Brief description of what this skill does.
  Include when to use it and key capabilities.
license: Apache-2.0                  # Optional
compatibility: |                     # Optional
  - Python 3.9+
  - Required packages: python-docx
metadata:                            # Optional
  author: SherifEldeeb
  version: "1.0.0"
  category: baseline                 # baseline or cybersecurity
---
```

#### 2. Markdown Body (Required)

Structure your SKILL.md body with these sections:

```markdown
# Skill Name

Brief overview paragraph.

## Capabilities

- Capability 1
- Capability 2

## Quick Start

Minimal working example.

## Usage

### Task 1
Detailed instructions...

### Task 2
Detailed instructions...

## Examples

Concrete input/output examples.

## Limitations

Known limitations and edge cases.

## Related Skills

Links to related skills.
```

## Coding Standards

### Python Scripts

All Python scripts should follow these conventions:

```python
#!/usr/bin/env python3
"""
Script description.

Usage:
    python script.py <input> <output>
"""

import sys
from pathlib import Path

def main():
    """Main entry point."""
    # Implementation
    pass

if __name__ == "__main__":
    main()
```

#### Requirements

1. **Shebang**: Always include `#!/usr/bin/env python3`
2. **Docstrings**: Module, class, and function docstrings required
3. **Type hints**: Use type hints for function signatures
4. **Error handling**: Graceful error handling with informative messages
5. **Dependencies**: Minimize external dependencies

#### Dependency Management

Each skill with Python scripts should include a `requirements.txt`:

```
# scripts/requirements.txt
python-docx>=0.8.11
lxml>=4.9.0
```

### Bash Scripts

```bash
#!/usr/bin/env bash
set -euo pipefail

# Description of script
# Usage: ./script.sh <arg1> <arg2>

main() {
    # Implementation
    :
}

main "$@"
```

## Testing

### Manual Testing

Before submitting a skill, verify:

1. **SKILL.md parses correctly**
   ```bash
   # Check YAML frontmatter
   python -c "import yaml; yaml.safe_load(open('SKILL.md').read().split('---')[1])"
   ```

2. **Scripts execute without errors**
   ```bash
   python scripts/main.py --help
   ```

3. **All referenced files exist**
   ```bash
   # Check all relative links in SKILL.md
   grep -oP '\[.*?\]\(\K[^)]+' SKILL.md | while read -r link; do
     [ -f "$link" ] || echo "Missing: $link"
   done
   ```

### Test Cases

Document test cases in `references/TESTING.md`:

```markdown
# Test Cases

## Happy Path
1. Input: [describe input]
   Expected: [describe expected output]

## Edge Cases
1. Empty input
2. Malformed input
3. Large files

## Error Cases
1. Missing dependencies
2. Invalid file formats
```

## Security Considerations

### Input Validation

All skills handling external input must:

1. Validate file types before processing
2. Sanitize file paths to prevent traversal attacks
3. Limit file sizes to prevent resource exhaustion
4. Handle malformed input gracefully

### Credential Handling

- Never hardcode credentials
- Use environment variables for sensitive data
- Document required environment variables clearly

### Code Execution

- Avoid executing arbitrary code from documents
- Sanitize any content that could be interpreted as code
- Use safe parsing libraries (defusedxml for XML)

## Performance Guidelines

### Context Efficiency

Skills should be context-efficient:

1. **SKILL.md**: Keep under 500 lines
2. **Progressive disclosure**: Move details to references/
3. **Lazy loading**: Load resources only when needed

### File Size Limits

| File Type | Recommended Max |
|-----------|-----------------|
| SKILL.md | 50KB |
| Scripts | 100KB each |
| References | 100KB each |
| Assets | 1MB each |

## Documentation Standards

### Writing Style

1. **Active voice**: "The skill extracts..." not "Extraction is performed..."
2. **Present tense**: "Returns a list..." not "Will return..."
3. **Concise**: Avoid unnecessary words
4. **Examples**: Include concrete examples for every capability

### Code Examples

Always include:
- Input description
- Code snippet
- Expected output

```markdown
### Extract Text from DOCX

**Input**: A Word document at `report.docx`

**Usage**:
\`\`\`python
from docx import Document
doc = Document('report.docx')
text = '\n'.join([p.text for p in doc.paragraphs])
\`\`\`

**Output**: Plain text content of the document
```

## Versioning

### Semantic Versioning

Use semantic versioning in metadata:

- **MAJOR**: Breaking changes to skill interface
- **MINOR**: New capabilities, backward compatible
- **PATCH**: Bug fixes, documentation updates

### Changelog

Maintain a changelog in `references/CHANGELOG.md`:

```markdown
# Changelog

## [1.1.0] - 2024-01-15
### Added
- New template support for quarterly reports

## [1.0.0] - 2024-01-01
### Initial Release
- Core document manipulation capabilities
```

## Common Patterns

### Template-Based Generation

For skills that generate documents from templates:

```python
def generate_from_template(template_path: Path, data: dict, output_path: Path):
    """
    Generate document from template with data substitution.

    Args:
        template_path: Path to template file
        data: Dictionary of placeholder values
        output_path: Path for generated output
    """
    # Load template
    # Substitute placeholders
    # Save output
```

### Markdown Conversion

For converting markdown to other formats:

```python
def markdown_to_docx(md_path: Path, template_path: Path, output_path: Path):
    """
    Convert markdown to DOCX using template styling.

    Args:
        md_path: Path to markdown source
        template_path: Path to DOCX template for styling
        output_path: Path for output DOCX
    """
    # Parse markdown
    # Apply template styles
    # Generate DOCX
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| YAML parse error | Check frontmatter delimiters (`---`) |
| Missing dependency | Add to requirements.txt |
| Path not found | Use relative paths from skill root |
| Encoding error | Ensure UTF-8 encoding |

### Debug Mode

Enable verbose output in scripts:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG if os.getenv('DEBUG') else logging.INFO,
    format='%(levelname)s: %(message)s'
)
```
