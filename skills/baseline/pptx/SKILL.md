---
name: pptx
description: |
  Read, modify, and create Microsoft PowerPoint presentations (.pptx). Generate
  slides from content, apply templates, and build executive presentations.
  Use when creating presentations or converting content to slides.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Required packages: python-pptx
metadata:
  author: SherifEldeeb
  version: "1.0.0"
  category: baseline
---

# PPTX Skill

Read, modify, and create Microsoft PowerPoint presentations with support for templates, charts, tables, and professional formatting.

## Capabilities

- **Read Presentations**: Extract text, images, and notes from PPTX files
- **Create Presentations**: Generate new presentations from scratch or templates
- **Modify Presentations**: Edit existing slides, add or remove content
- **Charts & Tables**: Add data visualizations and formatted tables
- **Template-Based Generation**: Use corporate templates for consistency
- **Markdown Conversion**: Convert markdown content to presentation slides

## Quick Start

```python
from pptx import Presentation
from pptx.util import Inches, Pt

# Create a presentation
prs = Presentation()

# Add a title slide
title_slide_layout = prs.slide_layouts[0]
slide = prs.slides.add_slide(title_slide_layout)
title = slide.shapes.title
subtitle = slide.placeholders[1]

title.text = "Security Assessment"
subtitle.text = "Q1 2024 Executive Summary"

prs.save('presentation.pptx')
```

## Usage

### Reading Presentations

Extract content from existing PowerPoint files.

**Input**: Path to a PPTX file

**Process**:
1. Open presentation with python-pptx
2. Iterate through slides
3. Extract text, shapes, and notes

**Example**:
```python
from pptx import Presentation
from pathlib import Path

def extract_presentation_content(file_path: Path) -> dict:
    """Extract all content from a PowerPoint presentation."""
    prs = Presentation(file_path)
    content = {
        'slide_count': len(prs.slides),
        'slides': []
    }

    for slide_num, slide in enumerate(prs.slides, 1):
        slide_content = {
            'number': slide_num,
            'text': [],
            'notes': ''
        }

        # Extract text from shapes
        for shape in slide.shapes:
            if hasattr(shape, 'text') and shape.text:
                slide_content['text'].append(shape.text)

        # Extract notes
        if slide.has_notes_slide:
            notes_slide = slide.notes_slide
            if notes_slide.notes_text_frame:
                slide_content['notes'] = notes_slide.notes_text_frame.text

        content['slides'].append(slide_content)

    return content

# Usage
content = extract_presentation_content(Path('briefing.pptx'))
for slide in content['slides']:
    print(f"\n--- Slide {slide['number']} ---")
    for text in slide['text']:
        print(text)
```

### Creating Presentations

Generate PowerPoint files from scratch.

**Input**: Content to include in slides

**Process**:
1. Create Presentation object
2. Add slides using layouts
3. Populate content
4. Save to file

**Example**:
```python
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

def create_presentation(title: str, slides_content: list, output_path: str):
    """Create a presentation with multiple slides."""
    prs = Presentation()

    # Title slide
    title_slide = prs.slides.add_slide(prs.slide_layouts[0])
    title_slide.shapes.title.text = title
    title_slide.placeholders[1].text = "Prepared by Security Team"

    # Content slides
    for slide_info in slides_content:
        slide_type = slide_info.get('type', 'bullet')

        if slide_type == 'bullet':
            slide = prs.slides.add_slide(prs.slide_layouts[1])
            slide.shapes.title.text = slide_info['title']

            body = slide.placeholders[1]
            tf = body.text_frame

            for i, point in enumerate(slide_info.get('points', [])):
                if i == 0:
                    tf.paragraphs[0].text = point
                else:
                    p = tf.add_paragraph()
                    p.text = point
                    p.level = slide_info.get('level', 0)

        elif slide_type == 'blank':
            slide = prs.slides.add_slide(prs.slide_layouts[6])
            # Add custom content

    prs.save(output_path)

# Usage
slides = [
    {
        'type': 'bullet',
        'title': 'Executive Summary',
        'points': [
            'Assessment completed on schedule',
            '15 vulnerabilities identified',
            '3 critical findings require immediate attention',
            'Overall security posture: Moderate'
        ]
    },
    {
        'type': 'bullet',
        'title': 'Critical Findings',
        'points': [
            'SQL Injection in login form',
            'Exposed admin credentials',
            'Unpatched server vulnerabilities'
        ]
    }
]
create_presentation('Security Assessment Report', slides, 'report.pptx')
```

### Adding Tables

Include formatted tables in slides.

**Example**:
```python
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor

def add_table_slide(prs, title: str, headers: list, rows: list):
    """Add a slide with a formatted table."""
    slide = prs.slides.add_slide(prs.slide_layouts[5])  # Title only layout
    slide.shapes.title.text = title

    # Define table dimensions
    x, y = Inches(0.5), Inches(1.5)
    cx, cy = Inches(9), Inches(0.8 * (len(rows) + 1))

    table = slide.shapes.add_table(
        len(rows) + 1, len(headers), x, y, cx, cy
    ).table

    # Style header row
    for col_idx, header in enumerate(headers):
        cell = table.cell(0, col_idx)
        cell.text = header
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(44, 62, 80)
        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.color.rgb = RGBColor(255, 255, 255)
        paragraph.font.size = Pt(12)

    # Add data rows
    for row_idx, row_data in enumerate(rows, 1):
        for col_idx, value in enumerate(row_data):
            cell = table.cell(row_idx, col_idx)
            cell.text = str(value)
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(11)

    return slide

# Usage
prs = Presentation()
headers = ['Finding', 'Severity', 'Status', 'Due Date']
rows = [
    ['SQL Injection', 'Critical', 'Open', '2024-02-01'],
    ['XSS Vulnerability', 'High', 'In Progress', '2024-02-15'],
    ['Weak Passwords', 'Medium', 'Fixed', '2024-01-20']
]
add_table_slide(prs, 'Findings Summary', headers, rows)
prs.save('findings.pptx')
```

### Adding Charts

Create data visualizations in slides.

**Example**:
```python
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE
from pptx.util import Inches

def add_chart_slide(prs, title: str, chart_type: str, categories: list, series: dict):
    """Add a slide with a chart."""
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = title

    # Create chart data
    chart_data = CategoryChartData()
    chart_data.categories = categories

    for series_name, values in series.items():
        chart_data.add_series(series_name, values)

    # Determine chart type
    chart_types = {
        'bar': XL_CHART_TYPE.BAR_CLUSTERED,
        'column': XL_CHART_TYPE.COLUMN_CLUSTERED,
        'pie': XL_CHART_TYPE.PIE,
        'line': XL_CHART_TYPE.LINE
    }
    xl_chart_type = chart_types.get(chart_type, XL_CHART_TYPE.COLUMN_CLUSTERED)

    # Add chart to slide
    x, y, cx, cy = Inches(1), Inches(1.5), Inches(8), Inches(5)
    chart = slide.shapes.add_chart(xl_chart_type, x, y, cx, cy, chart_data).chart

    return slide

# Usage
prs = Presentation()

# Add title slide
title_slide = prs.slides.add_slide(prs.slide_layouts[0])
title_slide.shapes.title.text = 'Security Metrics Dashboard'

# Add bar chart
categories = ['Critical', 'High', 'Medium', 'Low']
series = {'Findings': [3, 8, 15, 22]}
add_chart_slide(prs, 'Findings by Severity', 'column', categories, series)

# Add pie chart
add_chart_slide(prs, 'Severity Distribution', 'pie', categories, series)

prs.save('metrics.pptx')
```

### Using Templates

Apply corporate templates for consistent branding.

**Example**:
```python
from pptx import Presentation
from pptx.util import Inches, Pt

def create_from_template(template_path: str, output_path: str, content: list):
    """Create presentation from a template."""
    prs = Presentation(template_path)

    for slide_content in content:
        # Use template's slide layouts
        layout_index = slide_content.get('layout', 1)
        slide = prs.slides.add_slide(prs.slide_layouts[layout_index])

        # Fill in placeholders
        if slide.shapes.title:
            slide.shapes.title.text = slide_content.get('title', '')

        # Fill body placeholder if available
        for placeholder in slide.placeholders:
            if placeholder.placeholder_format.idx == 1:  # Body placeholder
                tf = placeholder.text_frame
                points = slide_content.get('points', [])
                for i, point in enumerate(points):
                    if i == 0:
                        tf.paragraphs[0].text = point
                    else:
                        p = tf.add_paragraph()
                        p.text = point

    prs.save(output_path)

# Usage
content = [
    {
        'layout': 1,
        'title': 'Assessment Overview',
        'points': ['Scope: Web Application', 'Duration: 2 weeks', 'Methodology: OWASP']
    },
    {
        'layout': 1,
        'title': 'Key Findings',
        'points': ['3 Critical vulnerabilities', '5 High severity issues', '12 Medium findings']
    }
]
create_from_template('corporate_template.pptx', 'assessment.pptx', content)
```

### Markdown to Slides

Convert markdown content to presentation slides.

**Example**:
```python
from pptx import Presentation
from pptx.util import Inches, Pt
import re

def markdown_to_slides(markdown_content: str, output_path: str):
    """Convert markdown to PowerPoint slides."""
    prs = Presentation()

    # Split by headers (slides)
    sections = re.split(r'\n(?=# )', markdown_content.strip())

    for section in sections:
        lines = section.strip().split('\n')
        if not lines:
            continue

        # Get title (# heading)
        title_match = re.match(r'^#\s+(.+)$', lines[0])
        if not title_match:
            continue

        title = title_match.group(1)

        # Get bullet points
        points = []
        for line in lines[1:]:
            bullet_match = re.match(r'^[-*]\s+(.+)$', line.strip())
            if bullet_match:
                points.append(bullet_match.group(1))

        # Create slide
        if points:
            slide = prs.slides.add_slide(prs.slide_layouts[1])
            slide.shapes.title.text = title

            body = slide.placeholders[1]
            tf = body.text_frame

            for i, point in enumerate(points):
                if i == 0:
                    tf.paragraphs[0].text = point
                else:
                    p = tf.add_paragraph()
                    p.text = point
        else:
            # Title only slide
            slide = prs.slides.add_slide(prs.slide_layouts[5])
            slide.shapes.title.text = title

    prs.save(output_path)

# Usage
markdown = """
# Security Assessment Report

- Conducted comprehensive penetration test
- Identified 15 vulnerabilities
- Prioritized remediation roadmap

# Critical Findings

- SQL Injection in authentication module
- Remote code execution via file upload
- Exposed API credentials in source code

# Recommendations

- Implement input validation
- Deploy WAF protection
- Rotate all exposed credentials
"""
markdown_to_slides(markdown, 'assessment.pptx')
```

### Adding Speaker Notes

Include speaker notes for presentations.

**Example**:
```python
from pptx import Presentation

def add_slide_with_notes(prs, title: str, points: list, notes: str):
    """Add a slide with speaker notes."""
    slide = prs.slides.add_slide(prs.slide_layouts[1])
    slide.shapes.title.text = title

    body = slide.placeholders[1]
    tf = body.text_frame

    for i, point in enumerate(points):
        if i == 0:
            tf.paragraphs[0].text = point
        else:
            p = tf.add_paragraph()
            p.text = point

    # Add speaker notes
    notes_slide = slide.notes_slide
    notes_slide.notes_text_frame.text = notes

    return slide

# Usage
prs = Presentation()

add_slide_with_notes(
    prs,
    'Executive Summary',
    ['15 findings identified', '3 critical issues', 'Immediate action required'],
    'Key talking points:\n- Emphasize urgency of critical findings\n- Discuss remediation timeline\n- Request budget approval for fixes'
)

prs.save('briefing.pptx')
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PPTX_TEMPLATE_DIR` | Default template directory | No | `./assets/templates` |

### Script Options

| Option | Type | Description |
|--------|------|-------------|
| `--input` | path | Input file (PPTX or Markdown) |
| `--output` | path | Output PPTX file |
| `--template` | path | Template to use |
| `--verbose` | flag | Enable verbose logging |

## Examples

### Example 1: Security Briefing Generator

**Scenario**: Generate executive security briefing from findings data.

```python
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor

def generate_security_briefing(findings: list, output_path: str):
    """Generate a security briefing presentation."""
    prs = Presentation()

    # Title slide
    title_slide = prs.slides.add_slide(prs.slide_layouts[0])
    title_slide.shapes.title.text = 'Security Assessment Briefing'
    title_slide.placeholders[1].text = 'Confidential - Executive Summary'

    # Summary statistics
    critical = sum(1 for f in findings if f['severity'] == 'Critical')
    high = sum(1 for f in findings if f['severity'] == 'High')
    medium = sum(1 for f in findings if f['severity'] == 'Medium')

    summary_slide = prs.slides.add_slide(prs.slide_layouts[1])
    summary_slide.shapes.title.text = 'Executive Summary'

    body = summary_slide.placeholders[1]
    tf = body.text_frame
    tf.paragraphs[0].text = f'Total Findings: {len(findings)}'
    tf.add_paragraph().text = f'Critical: {critical}'
    tf.add_paragraph().text = f'High: {high}'
    tf.add_paragraph().text = f'Medium: {medium}'

    # Individual finding slides
    for finding in findings:
        if finding['severity'] in ['Critical', 'High']:
            slide = prs.slides.add_slide(prs.slide_layouts[1])
            slide.shapes.title.text = f"[{finding['severity']}] {finding['title']}"

            body = slide.placeholders[1]
            tf = body.text_frame
            tf.paragraphs[0].text = finding.get('description', '')
            tf.add_paragraph().text = f"Risk: {finding.get('risk', 'N/A')}"
            tf.add_paragraph().text = f"Remediation: {finding.get('remediation', 'N/A')}"

    prs.save(output_path)

# Usage
findings = [
    {
        'title': 'SQL Injection',
        'severity': 'Critical',
        'description': 'Authentication bypass via SQL injection',
        'risk': 'Complete system compromise',
        'remediation': 'Implement parameterized queries'
    },
    {
        'title': 'XSS Vulnerability',
        'severity': 'High',
        'description': 'Stored XSS in user profile',
        'risk': 'Session hijacking',
        'remediation': 'Implement output encoding'
    }
]
generate_security_briefing(findings, 'security_briefing.pptx')
```

### Example 2: Metrics Dashboard Presentation

**Scenario**: Create a metrics dashboard presentation with charts.

```python
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.enum.chart import XL_CHART_TYPE
from pptx.util import Inches

def create_metrics_dashboard(metrics: dict, output_path: str):
    """Create a metrics dashboard presentation."""
    prs = Presentation()

    # Title slide
    title_slide = prs.slides.add_slide(prs.slide_layouts[0])
    title_slide.shapes.title.text = 'Security Metrics Dashboard'
    title_slide.placeholders[1].text = 'Monthly Report'

    # Vulnerability trend chart
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = 'Vulnerability Trend'

    chart_data = CategoryChartData()
    chart_data.categories = metrics['months']
    chart_data.add_series('Open', metrics['open_vulns'])
    chart_data.add_series('Closed', metrics['closed_vulns'])

    chart = slide.shapes.add_chart(
        XL_CHART_TYPE.LINE, Inches(1), Inches(1.5), Inches(8), Inches(5), chart_data
    ).chart

    # Severity distribution
    slide2 = prs.slides.add_slide(prs.slide_layouts[5])
    slide2.shapes.title.text = 'Current Severity Distribution'

    chart_data2 = CategoryChartData()
    chart_data2.categories = list(metrics['severity_dist'].keys())
    chart_data2.add_series('Count', list(metrics['severity_dist'].values()))

    slide2.shapes.add_chart(
        XL_CHART_TYPE.PIE, Inches(2), Inches(1.5), Inches(6), Inches(5), chart_data2
    )

    prs.save(output_path)

# Usage
metrics = {
    'months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
    'open_vulns': [45, 52, 48, 35, 28, 22],
    'closed_vulns': [30, 45, 55, 60, 65, 70],
    'severity_dist': {'Critical': 3, 'High': 12, 'Medium': 25, 'Low': 40}
}
create_metrics_dashboard(metrics, 'dashboard.pptx')
```

## Limitations

- **Animations**: Cannot create or modify slide animations
- **Transitions**: Slide transitions are not supported
- **Videos**: Limited support for embedded videos
- **Audio**: Cannot add or modify audio clips
- **SmartArt**: Cannot create SmartArt graphics
- **Complex Charts**: Some advanced chart types may have limited support

## Troubleshooting

### Layout Not Found

**Problem**: Getting KeyError when accessing slide layout

**Solution**: Check available layouts:
```python
prs = Presentation()
for i, layout in enumerate(prs.slide_layouts):
    print(f"{i}: {layout.name}")
```

### Text Not Fitting

**Problem**: Text overflows placeholder

**Solution**: Adjust font size or use auto-fit:
```python
from pptx.util import Pt

tf = placeholder.text_frame
tf.auto_size = True
# Or manually set font size
for paragraph in tf.paragraphs:
    paragraph.font.size = Pt(14)
```

### Template Issues

**Problem**: Custom template not applying correctly

**Solution**: Verify template has expected placeholders:
```python
prs = Presentation('template.pptx')
for layout in prs.slide_layouts:
    print(f"\n{layout.name}:")
    for placeholder in layout.placeholders:
        print(f"  {placeholder.placeholder_format.idx}: {placeholder.name}")
```

## Related Skills

- [docx](../docx/): Convert Word reports to presentations
- [xlsx](../xlsx/): Import data for charts and tables
- [image-generation](../image-generation/): Create visual assets for slides
- [pdf](../pdf/): Export presentations to PDF

## References

- [Detailed API Reference](references/REFERENCE.md)
- [python-pptx Documentation](https://python-pptx.readthedocs.io/)
