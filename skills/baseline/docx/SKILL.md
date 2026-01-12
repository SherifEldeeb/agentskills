---
name: docx
description: |
  Read, modify, and create Microsoft Word documents (.docx). Convert markdown
  to formatted Word documents using templates. Use when working with Word
  documents, generating reports, or converting markdown to professional documents.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Required packages: python-docx, markdown, lxml
metadata:
  author: SherifEldeeb
  version: "1.0.0"
  category: baseline
---

# DOCX Skill

Read, modify, and create Microsoft Word documents with support for converting markdown content into professionally formatted documents using templates.

## Capabilities

- **Read Documents**: Extract text, tables, and metadata from DOCX files
- **Create Documents**: Generate new DOCX files from scratch or templates
- **Modify Documents**: Edit existing documents, add content, modify styles
- **Markdown Conversion**: Convert markdown files to DOCX using template styling
- **Template-Based Generation**: Use DOCX templates to maintain consistent formatting

## Quick Start

```python
from docx import Document

# Read a document
doc = Document('report.docx')
for para in doc.paragraphs:
    print(para.text)

# Create a document
doc = Document()
doc.add_heading('Report Title', 0)
doc.add_paragraph('Content here.')
doc.save('output.docx')
```

## Usage

### Reading Documents

Extract content from existing DOCX files.

**Input**: Path to a DOCX file

**Process**:
1. Open document with python-docx
2. Iterate through paragraphs, tables, or other elements
3. Extract text, styles, or metadata

**Example**:
```python
from docx import Document

doc = Document('input.docx')

# Extract all text
full_text = []
for para in doc.paragraphs:
    full_text.append(para.text)
text = '\n'.join(full_text)

# Extract tables
for table in doc.tables:
    for row in table.rows:
        row_data = [cell.text for cell in row.cells]
        print(row_data)

# Get document properties
props = doc.core_properties
print(f"Title: {props.title}")
print(f"Author: {props.author}")
```

### Creating New Documents

Generate DOCX files from scratch.

**Input**: Content to include (text, tables, images)

**Process**:
1. Create new Document object
2. Add headings, paragraphs, tables
3. Apply styles as needed
4. Save to file

**Example**:
```python
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH

doc = Document()

# Add title
title = doc.add_heading('Security Assessment Report', 0)
title.alignment = WD_ALIGN_PARAGRAPH.CENTER

# Add metadata paragraph
doc.add_paragraph('Prepared by: Security Team')
doc.add_paragraph('Date: January 2024')

# Add section heading
doc.add_heading('Executive Summary', level=1)

# Add content paragraph
para = doc.add_paragraph()
para.add_run('This assessment identified ').bold = False
para.add_run('3 critical findings').bold = True
para.add_run(' requiring immediate attention.')

# Add a table
table = doc.add_table(rows=1, cols=3)
table.style = 'Table Grid'
header = table.rows[0].cells
header[0].text = 'Finding'
header[1].text = 'Severity'
header[2].text = 'Status'

# Add data rows
data = [
    ('SQL Injection', 'Critical', 'Open'),
    ('XSS Vulnerability', 'High', 'In Progress'),
]
for finding, severity, status in data:
    row = table.add_row().cells
    row[0].text = finding
    row[1].text = severity
    row[2].text = status

doc.save('report.docx')
```

### Modifying Existing Documents

Edit and update existing DOCX files.

**Input**: Path to existing DOCX file

**Process**:
1. Open existing document
2. Locate content to modify
3. Make changes
4. Save (same or new file)

**Example**:
```python
from docx import Document

doc = Document('template.docx')

# Replace placeholder text
for para in doc.paragraphs:
    if '{{CLIENT_NAME}}' in para.text:
        para.text = para.text.replace('{{CLIENT_NAME}}', 'Acme Corp')
    if '{{DATE}}' in para.text:
        para.text = para.text.replace('{{DATE}}', '2024-01-15')

# Add new section at end
doc.add_heading('Additional Findings', level=1)
doc.add_paragraph('New content added during modification.')

doc.save('modified_report.docx')
```

### Markdown to DOCX Conversion

Convert markdown files to Word documents using template styling.

**Input**:
- Markdown file path
- DOCX template file path (optional)
- Output file path

**Process**:
1. Parse markdown content
2. Load template document for styles (if provided)
3. Map markdown elements to Word styles
4. Generate formatted DOCX

**Using the conversion script**:
```bash
python scripts/md_to_docx.py report.md --template company_template.docx --output final_report.docx
```

**Programmatic usage**:
```python
from scripts.md_to_docx import MarkdownToDocx

converter = MarkdownToDocx(template_path='template.docx')
converter.convert('input.md', 'output.docx')
```

**Style Mapping**:

| Markdown | Word Style |
|----------|------------|
| `# Heading 1` | Heading 1 |
| `## Heading 2` | Heading 2 |
| `### Heading 3` | Heading 3 |
| `**bold**` | Bold run |
| `*italic*` | Italic run |
| `` `code` `` | Code character style |
| `- item` | List Bullet |
| `1. item` | List Number |
| Code blocks | Code block style |
| `> quote` | Quote style |
| Tables | Table Grid |

**Template Requirements**:

For best results, your template should define these styles:
- Heading 1, Heading 2, Heading 3
- Normal (body text)
- List Bullet, List Number
- Quote (for blockquotes)
- Code (character style for inline code)

### Working with Styles

Apply consistent formatting using document styles.

**Example**:
```python
from docx import Document
from docx.shared import Pt, RGBColor
from docx.enum.style import WD_STYLE_TYPE

doc = Document()

# Create a custom style
styles = doc.styles
style = styles.add_style('Finding Critical', WD_STYLE_TYPE.PARAGRAPH)
style.font.bold = True
style.font.size = Pt(12)
style.font.color.rgb = RGBColor(255, 0, 0)

# Use the style
doc.add_paragraph('CRITICAL: SQL Injection Found', style='Finding Critical')

doc.save('styled_report.docx')
```

### Adding Images

Insert images into documents.

**Example**:
```python
from docx import Document
from docx.shared import Inches

doc = Document()
doc.add_heading('Network Diagram', level=1)
doc.add_picture('network_diagram.png', width=Inches(6))
doc.add_paragraph('Figure 1: Current network architecture')

doc.save('report_with_images.docx')
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DOCX_TEMPLATE_DIR` | Default template directory | No | `./assets/templates` |

### Script Options

| Option | Type | Description |
|--------|------|-------------|
| `--template` | path | DOCX template for styling |
| `--output` | path | Output file path |
| `--toc` | flag | Generate table of contents |
| `--verbose` | flag | Enable verbose logging |

## Examples

### Example 1: Security Report from Markdown

**Scenario**: Convert a penetration test report written in markdown to a professional Word document.

**Input** (`report.md`):
```markdown
# Penetration Test Report

## Executive Summary

The assessment identified **3 critical** and **5 high** severity findings.

## Findings

### Finding 1: SQL Injection

**Severity**: Critical

The application is vulnerable to SQL injection in the login form.

| Parameter | Payload | Result |
|-----------|---------|--------|
| username | `' OR 1=1--` | Auth bypass |

### Remediation

1. Use parameterized queries
2. Implement input validation
3. Apply least privilege
```

**Command**:
```bash
python scripts/md_to_docx.py report.md --template corporate_template.docx --output pentest_report.docx
```

**Output**: Professional DOCX with corporate styling applied.

### Example 2: Batch Document Generation

**Scenario**: Generate multiple reports from a template with different data.

```python
from docx import Document
import json

# Load client data
with open('clients.json') as f:
    clients = json.load(f)

for client in clients:
    doc = Document('assessment_template.docx')

    # Replace placeholders
    for para in doc.paragraphs:
        for key, value in client.items():
            placeholder = f'{{{{{key}}}}}'
            if placeholder in para.text:
                para.text = para.text.replace(placeholder, str(value))

    doc.save(f"reports/{client['name']}_assessment.docx")
```

## Limitations

- **Complex formatting**: Some advanced Word features (SmartArt, embedded objects) may not be fully supported
- **Track changes**: Limited support for revision tracking
- **Macros**: VBA macros are not supported for security reasons
- **Large tables**: Tables with merged cells may have rendering inconsistencies

## Troubleshooting

### Style Not Applied

**Problem**: Custom styles from template not appearing in output

**Solution**: Ensure the style exists in the template and use exact style name:
```python
# Check available styles
for style in doc.styles:
    print(style.name)
```

### Encoding Issues

**Problem**: Special characters not displaying correctly

**Solution**: Ensure UTF-8 encoding when reading source files:
```python
with open('input.md', 'r', encoding='utf-8') as f:
    content = f.read()
```

### Missing Images

**Problem**: Images not appearing in output

**Solution**: Use absolute paths or verify relative path from script location:
```python
from pathlib import Path
image_path = Path(__file__).parent / 'assets' / 'logo.png'
doc.add_picture(str(image_path))
```

## Related Skills

- [pdf](../pdf/): Convert DOCX to PDF or extract content from PDFs
- [xlsx](../xlsx/): Work with Excel files for data that feeds into reports
- [pptx](../pptx/): Create presentations from document content

## References

- [Detailed API Reference](references/REFERENCE.md)
- [python-docx Documentation](https://python-docx.readthedocs.io/)
- [Markdown Syntax Guide](references/MARKDOWN.md)
