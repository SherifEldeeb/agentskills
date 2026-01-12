---
name: pdf
description: |
  Read, create, and manipulate PDF documents. Extract text and tables,
  merge documents, fill forms, and convert to/from other formats.
  Use when working with PDF files or generating PDF reports.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Required packages: PyPDF2, reportlab, pdfplumber
metadata:
  author: SherifEldeeb
  version: "1.0.0"
  category: baseline
---

# PDF Skill

Read, create, and manipulate PDF documents with support for text extraction, document generation, merging, and form filling.

## Capabilities

- **Read PDFs**: Extract text, tables, and metadata from PDF files
- **Create PDFs**: Generate PDF documents from scratch using ReportLab
- **Merge PDFs**: Combine multiple PDFs into a single document
- **Split PDFs**: Extract specific pages from PDF documents
- **Form Operations**: Fill PDF forms programmatically
- **Watermarks**: Add watermarks and headers/footers to documents
- **Convert**: Convert between PDF and other formats

## Quick Start

```python
import pdfplumber
from PyPDF2 import PdfReader, PdfWriter

# Read text from PDF
with pdfplumber.open('document.pdf') as pdf:
    for page in pdf.pages:
        print(page.extract_text())

# Merge PDFs
merger = PdfWriter()
for pdf_file in ['doc1.pdf', 'doc2.pdf']:
    merger.append(pdf_file)
merger.write('merged.pdf')
```

## Usage

### Extracting Text from PDFs

Extract text content from PDF files with layout preservation.

**Input**: Path to a PDF file

**Process**:
1. Open PDF with pdfplumber for accurate text extraction
2. Iterate through pages
3. Extract text, optionally preserving layout

**Example**:
```python
import pdfplumber
from pathlib import Path

def extract_text(pdf_path: Path) -> str:
    """Extract all text from a PDF file."""
    text_content = []

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                text_content.append(text)

    return '\n\n'.join(text_content)

# Usage
text = extract_text(Path('report.pdf'))
print(text)
```

### Extracting Tables from PDFs

Extract tabular data from PDF files into structured formats.

**Input**: Path to PDF file containing tables

**Process**:
1. Open PDF with pdfplumber
2. Detect and extract tables from each page
3. Return as list of lists (rows and cells)

**Example**:
```python
import pdfplumber
import csv

def extract_tables(pdf_path: str, output_csv: str = None):
    """Extract tables from PDF, optionally save to CSV."""
    all_tables = []

    with pdfplumber.open(pdf_path) as pdf:
        for page_num, page in enumerate(pdf.pages, 1):
            tables = page.extract_tables()
            for table_num, table in enumerate(tables, 1):
                all_tables.append({
                    'page': page_num,
                    'table_num': table_num,
                    'data': table
                })

    # Optionally save to CSV
    if output_csv and all_tables:
        with open(output_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            for table in all_tables:
                writer.writerow([f"Page {table['page']}, Table {table['table_num']}"])
                writer.writerows(table['data'])
                writer.writerow([])  # Empty row between tables

    return all_tables

# Usage
tables = extract_tables('financial_report.pdf', 'extracted_tables.csv')
for table in tables:
    print(f"Page {table['page']}, Table {table['table_num']}")
    for row in table['data']:
        print(row)
```

### Creating PDF Documents

Generate PDF documents from scratch using ReportLab.

**Input**: Content to include in the PDF

**Process**:
1. Create a canvas or use higher-level constructs
2. Add text, tables, images
3. Save to file

**Example**:
```python
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

def create_report(output_path: str, title: str, content: list):
    """Create a formatted PDF report."""
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Add title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    story.append(Paragraph(title, title_style))

    # Add content paragraphs
    for item in content:
        if isinstance(item, str):
            story.append(Paragraph(item, styles['Normal']))
            story.append(Spacer(1, 12))
        elif isinstance(item, list):
            # Treat as table data
            table = Table(item)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
            story.append(Spacer(1, 20))

    doc.build(story)

# Usage
create_report(
    'security_report.pdf',
    'Security Assessment Report',
    [
        'This report summarizes the findings from our security assessment.',
        [
            ['Finding', 'Severity', 'Status'],
            ['SQL Injection', 'Critical', 'Open'],
            ['XSS Vulnerability', 'High', 'Remediated'],
            ['Weak Password Policy', 'Medium', 'In Progress']
        ],
        'Immediate remediation is recommended for all critical findings.'
    ]
)
```

### Merging PDF Documents

Combine multiple PDF files into a single document.

**Input**: List of PDF file paths

**Process**:
1. Create a PdfWriter object
2. Append each PDF
3. Write to output file

**Example**:
```python
from PyPDF2 import PdfWriter, PdfReader
from pathlib import Path

def merge_pdfs(pdf_list: list, output_path: str, add_bookmarks: bool = True):
    """Merge multiple PDFs into one document."""
    writer = PdfWriter()

    for pdf_path in pdf_list:
        reader = PdfReader(pdf_path)

        # Add bookmark for this document
        if add_bookmarks:
            bookmark_title = Path(pdf_path).stem
            writer.add_outline_item(bookmark_title, len(writer.pages))

        # Add all pages from this PDF
        for page in reader.pages:
            writer.add_page(page)

    # Write the merged PDF
    with open(output_path, 'wb') as output_file:
        writer.write(output_file)

    return output_path

# Usage
pdfs_to_merge = [
    'cover_page.pdf',
    'executive_summary.pdf',
    'detailed_findings.pdf',
    'appendix.pdf'
]
merge_pdfs(pdfs_to_merge, 'complete_report.pdf')
```

### Splitting PDF Documents

Extract specific pages from a PDF into new documents.

**Input**: PDF path and page ranges

**Process**:
1. Open source PDF
2. Select specific pages
3. Write to new PDF

**Example**:
```python
from PyPDF2 import PdfReader, PdfWriter

def split_pdf(input_path: str, page_ranges: list, output_prefix: str):
    """
    Split a PDF into multiple files based on page ranges.

    Args:
        input_path: Source PDF file
        page_ranges: List of tuples (start, end) - 1-indexed, inclusive
        output_prefix: Prefix for output files

    Returns:
        List of created file paths
    """
    reader = PdfReader(input_path)
    output_files = []

    for i, (start, end) in enumerate(page_ranges, 1):
        writer = PdfWriter()

        # Pages are 0-indexed in PyPDF2
        for page_num in range(start - 1, min(end, len(reader.pages))):
            writer.add_page(reader.pages[page_num])

        output_path = f"{output_prefix}_part{i}.pdf"
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)

        output_files.append(output_path)

    return output_files

# Usage - Split a 20-page document
split_pdf('large_report.pdf', [(1, 5), (6, 10), (11, 20)], 'report')
# Creates: report_part1.pdf, report_part2.pdf, report_part3.pdf
```

### Adding Watermarks

Add watermarks to PDF pages.

**Input**: PDF file and watermark content

**Process**:
1. Create watermark PDF
2. Overlay on each page
3. Save result

**Example**:
```python
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO

def add_watermark(input_path: str, output_path: str, watermark_text: str):
    """Add a text watermark to all pages of a PDF."""
    # Create watermark
    watermark_buffer = BytesIO()
    c = canvas.Canvas(watermark_buffer, pagesize=letter)

    # Configure watermark appearance
    c.setFont("Helvetica", 50)
    c.setFillColorRGB(0.5, 0.5, 0.5, alpha=0.3)
    c.saveState()
    c.translate(300, 400)
    c.rotate(45)
    c.drawCentredString(0, 0, watermark_text)
    c.restoreState()
    c.save()

    watermark_buffer.seek(0)
    watermark_pdf = PdfReader(watermark_buffer)
    watermark_page = watermark_pdf.pages[0]

    # Apply watermark to each page
    reader = PdfReader(input_path)
    writer = PdfWriter()

    for page in reader.pages:
        page.merge_page(watermark_page)
        writer.add_page(page)

    with open(output_path, 'wb') as output_file:
        writer.write(output_file)

# Usage
add_watermark('report.pdf', 'report_confidential.pdf', 'CONFIDENTIAL')
```

### Extracting Metadata

Read and modify PDF metadata.

**Example**:
```python
from PyPDF2 import PdfReader, PdfWriter

def get_pdf_metadata(pdf_path: str) -> dict:
    """Extract metadata from a PDF file."""
    reader = PdfReader(pdf_path)
    metadata = reader.metadata

    return {
        'title': metadata.get('/Title', ''),
        'author': metadata.get('/Author', ''),
        'subject': metadata.get('/Subject', ''),
        'creator': metadata.get('/Creator', ''),
        'producer': metadata.get('/Producer', ''),
        'creation_date': metadata.get('/CreationDate', ''),
        'modification_date': metadata.get('/ModDate', ''),
        'page_count': len(reader.pages)
    }

def set_pdf_metadata(input_path: str, output_path: str, metadata: dict):
    """Set metadata on a PDF file."""
    reader = PdfReader(input_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.add_metadata(metadata)

    with open(output_path, 'wb') as output_file:
        writer.write(output_file)

# Usage
meta = get_pdf_metadata('document.pdf')
print(f"Title: {meta['title']}")
print(f"Pages: {meta['page_count']}")

set_pdf_metadata('input.pdf', 'output.pdf', {
    '/Title': 'Security Assessment Report',
    '/Author': 'Security Team',
    '/Subject': 'Q1 2024 Assessment'
})
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PDF_TEMPLATE_DIR` | Default template directory | No | `./assets/templates` |
| `PDF_OUTPUT_DIR` | Default output directory | No | `./output` |

### Script Options

| Option | Type | Description |
|--------|------|-------------|
| `--input` | path | Input PDF file |
| `--output` | path | Output file path |
| `--pages` | string | Page range (e.g., "1-5,8,10-12") |
| `--verbose` | flag | Enable verbose logging |

## Examples

### Example 1: Generate a Security Report PDF

**Scenario**: Create a professional security assessment report as PDF.

```python
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer

def generate_security_report(findings: list, output_path: str):
    """Generate a security report PDF from findings data."""
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("Security Assessment Report", styles['Title']))
    story.append(Spacer(1, 20))

    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading1']))
    critical = sum(1 for f in findings if f['severity'] == 'Critical')
    high = sum(1 for f in findings if f['severity'] == 'High')
    story.append(Paragraph(
        f"This assessment identified {critical} critical and {high} high severity findings.",
        styles['Normal']
    ))
    story.append(Spacer(1, 20))

    # Findings Table
    story.append(Paragraph("Findings Summary", styles['Heading1']))
    table_data = [['ID', 'Finding', 'Severity', 'Status']]
    for i, f in enumerate(findings, 1):
        table_data.append([str(i), f['title'], f['severity'], f['status']])

    table = Table(table_data, colWidths=[40, 250, 80, 80])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')])
    ]))
    story.append(table)

    doc.build(story)

# Usage
findings = [
    {'title': 'SQL Injection in Login Form', 'severity': 'Critical', 'status': 'Open'},
    {'title': 'Reflected XSS', 'severity': 'High', 'status': 'Open'},
    {'title': 'Missing Security Headers', 'severity': 'Medium', 'status': 'Fixed'}
]
generate_security_report(findings, 'pentest_report.pdf')
```

### Example 2: Extract and Analyze PDF Content

**Scenario**: Extract text and tables from a vendor security questionnaire.

```python
import pdfplumber
import json

def analyze_questionnaire(pdf_path: str) -> dict:
    """Extract and analyze a security questionnaire PDF."""
    results = {
        'total_pages': 0,
        'questions': [],
        'tables': [],
        'text_content': ''
    }

    with pdfplumber.open(pdf_path) as pdf:
        results['total_pages'] = len(pdf.pages)

        for page_num, page in enumerate(pdf.pages, 1):
            # Extract text
            text = page.extract_text() or ''
            results['text_content'] += f"\n--- Page {page_num} ---\n{text}"

            # Find questions (lines ending with ?)
            for line in text.split('\n'):
                if line.strip().endswith('?'):
                    results['questions'].append({
                        'page': page_num,
                        'question': line.strip()
                    })

            # Extract tables
            for table in page.extract_tables():
                if table:
                    results['tables'].append({
                        'page': page_num,
                        'rows': len(table),
                        'data': table
                    })

    return results

# Usage
analysis = analyze_questionnaire('vendor_questionnaire.pdf')
print(f"Total pages: {analysis['total_pages']}")
print(f"Questions found: {len(analysis['questions'])}")
print(f"Tables found: {len(analysis['tables'])}")
```

### Example 3: Batch PDF Processing

**Scenario**: Process multiple PDFs, extract metadata, and generate a summary.

```python
from PyPDF2 import PdfReader
from pathlib import Path
import csv

def batch_analyze_pdfs(directory: str, output_csv: str):
    """Analyze all PDFs in a directory and create a summary CSV."""
    pdf_dir = Path(directory)
    results = []

    for pdf_path in pdf_dir.glob('*.pdf'):
        try:
            reader = PdfReader(pdf_path)
            meta = reader.metadata or {}

            results.append({
                'filename': pdf_path.name,
                'pages': len(reader.pages),
                'title': meta.get('/Title', ''),
                'author': meta.get('/Author', ''),
                'encrypted': reader.is_encrypted,
                'size_kb': pdf_path.stat().st_size / 1024
            })
        except Exception as e:
            results.append({
                'filename': pdf_path.name,
                'error': str(e)
            })

    # Write CSV summary
    with open(output_csv, 'w', newline='') as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

    return results

# Usage
summary = batch_analyze_pdfs('./reports/', 'pdf_inventory.csv')
```

## Limitations

- **Scanned PDFs**: Text extraction requires OCR for image-based PDFs (not included by default)
- **Complex Layouts**: Multi-column or heavily formatted PDFs may have extraction issues
- **Form Fields**: Complex interactive forms may not be fully supported
- **Digital Signatures**: Cannot create or verify digital signatures
- **Encryption**: Limited support for encrypted PDFs (password-protected reading only)
- **Large Files**: Very large PDFs (1000+ pages) may require streaming approaches

## Troubleshooting

### Text Extraction Returns Empty

**Problem**: `extract_text()` returns empty or garbled text

**Solutions**:
1. The PDF may be image-based (scanned). Use OCR:
   ```python
   # Install: pip install pdf2image pytesseract
   from pdf2image import convert_from_path
   import pytesseract

   images = convert_from_path('scanned.pdf')
   text = '\n'.join(pytesseract.image_to_string(img) for img in images)
   ```

2. Try different extraction settings:
   ```python
   with pdfplumber.open('document.pdf') as pdf:
       page = pdf.pages[0]
       text = page.extract_text(layout=True)  # Preserve layout
   ```

### Merge Fails with Encrypted PDF

**Problem**: Cannot merge password-protected PDFs

**Solution**:
```python
reader = PdfReader('protected.pdf')
if reader.is_encrypted:
    reader.decrypt('password')
# Then proceed with merging
```

### Table Extraction Incorrect

**Problem**: Table cells are misaligned or merged incorrectly

**Solution**: Use explicit table settings:
```python
with pdfplumber.open('document.pdf') as pdf:
    page = pdf.pages[0]
    tables = page.extract_tables(table_settings={
        "vertical_strategy": "text",
        "horizontal_strategy": "text",
        "snap_tolerance": 3,
    })
```

## Related Skills

- [docx](../docx/): Convert between DOCX and PDF formats
- [xlsx](../xlsx/): Extract tabular data for spreadsheet analysis
- [image-generation](../image-generation/): Generate charts and diagrams for PDF reports

## References

- [Detailed API Reference](references/REFERENCE.md)
- [PyPDF2 Documentation](https://pypdf2.readthedocs.io/)
- [pdfplumber Documentation](https://github.com/jsvine/pdfplumber)
- [ReportLab User Guide](https://www.reportlab.com/docs/reportlab-userguide.pdf)
