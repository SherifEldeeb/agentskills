# DOCX Skill Reference

Detailed technical reference for the DOCX skill.

## API Reference

### MarkdownToDocx Class

Main converter class for markdown to DOCX conversion.

```python
class MarkdownToDocx:
    def __init__(self, template_path: Optional[Path] = None):
        """
        Initialize converter.

        Args:
            template_path: Optional path to DOCX template for styling.
                          If provided, styles from this template will be used.
        """

    def convert(self, input_path: Path, output_path: Path) -> bool:
        """
        Convert markdown file to DOCX.

        Args:
            input_path: Path to input markdown file
            output_path: Path for output DOCX file

        Returns:
            True if conversion succeeded, False otherwise
        """
```

### Utility Functions

#### read_docx

```python
def read_docx(file_path: Path) -> Dict[str, Any]:
    """
    Read a DOCX file and extract its contents.

    Args:
        file_path: Path to the DOCX file

    Returns:
        Dictionary containing:
        - paragraphs: List[str] - All paragraph texts
        - text: str - Full text content joined by newlines
        - tables: List[List[List[str]]] - All tables as nested lists
        - metadata: Dict - Document properties (title, author, etc.)
    """
```

#### replace_placeholders

```python
def replace_placeholders(
    doc: Document,
    replacements: Dict[str, str],
    placeholder_pattern: str = r'\{\{(\w+)\}\}'
) -> Document:
    """
    Replace placeholders in a document.

    Args:
        doc: Document object to modify
        replacements: Dictionary mapping placeholder names to values
        placeholder_pattern: Regex pattern for placeholders

    Returns:
        Modified document object

    Example:
        replacements = {'CLIENT': 'Acme Corp', 'DATE': '2024-01-15'}
        replace_placeholders(doc, replacements)
        # Replaces {{CLIENT}} with 'Acme Corp' and {{DATE}} with '2024-01-15'
    """
```

#### extract_tables

```python
def extract_tables(doc: Document) -> List[List[List[str]]]:
    """
    Extract all tables from a document.

    Args:
        doc: Document object

    Returns:
        List of tables. Each table is a list of rows.
        Each row is a list of cell text values.

    Example:
        tables = extract_tables(doc)
        for table in tables:
            header = table[0]  # First row
            for row in table[1:]:  # Data rows
                print(row)
    """
```

#### add_table_from_data

```python
def add_table_from_data(
    doc: Document,
    data: List[List[str]],
    has_header: bool = True,
    style: str = 'Table Grid'
) -> Table:
    """
    Add a table to the document from data.

    Args:
        doc: Document object
        data: 2D list of cell values
        has_header: If True, first row is bolded as header
        style: Word table style name

    Returns:
        Created Table object

    Example:
        data = [
            ['Finding', 'Severity', 'Status'],
            ['SQL Injection', 'Critical', 'Open'],
            ['XSS', 'High', 'Fixed']
        ]
        add_table_from_data(doc, data)
    """
```

#### merge_documents

```python
def merge_documents(
    docs: List[Path],
    output_path: Path,
    add_breaks: bool = True
) -> bool:
    """
    Merge multiple DOCX files into one.

    Args:
        docs: List of DOCX file paths to merge (in order)
        output_path: Path for merged output file
        add_breaks: If True, add page breaks between documents

    Returns:
        True if merge succeeded

    Example:
        docs = [Path('intro.docx'), Path('findings.docx'), Path('appendix.docx')]
        merge_documents(docs, Path('full_report.docx'))
    """
```

## Style Mapping

### Markdown to Word Style Mapping

| Markdown Element | Word Style | Notes |
|-----------------|------------|-------|
| `# Heading` | Heading 1 | Top-level heading |
| `## Heading` | Heading 2 | Section heading |
| `### Heading` | Heading 3 | Subsection heading |
| `#### Heading` | Heading 4 | Minor heading |
| `##### Heading` | Heading 5 | - |
| `###### Heading` | Heading 6 | - |
| Normal text | Normal | Default body text |
| `**bold**` | Bold run | - |
| `*italic*` | Italic run | - |
| `***bold italic***` | Bold + Italic | - |
| `` `code` `` | Consolas font | 10pt monospace |
| `- item` | List Bullet | - |
| `1. item` | List Number | - |
| `> quote` | Indented + border | Left border applied |
| Code block | Monospace + shading | Gray background |
| `---` | Horizontal rule | Border line |
| Table | Table Grid | First row bolded |

### Template Style Requirements

For optimal results, templates should include these styles:

**Required Styles:**
- Heading 1, Heading 2, Heading 3
- Normal
- List Bullet
- List Number

**Recommended Styles:**
- Title
- Subtitle
- Quote
- Table Grid (table style)

## File Format Details

### DOCX Structure

A DOCX file is a ZIP archive containing:

```
document.docx (ZIP)
├── [Content_Types].xml
├── _rels/
│   └── .rels
├── docProps/
│   ├── app.xml
│   └── core.xml          # Document properties
└── word/
    ├── document.xml      # Main content
    ├── styles.xml        # Style definitions
    ├── settings.xml
    ├── fontTable.xml
    └── _rels/
        └── document.xml.rels
```

### Supported Elements

**Fully Supported:**
- Paragraphs with all formatting
- Headings (levels 1-9)
- Tables (including merged cells for reading)
- Bulleted lists
- Numbered lists
- Bold, italic, underline
- Font size and color
- Images (PNG, JPEG, GIF)
- Page breaks
- Hyperlinks

**Partially Supported:**
- Headers and footers (basic)
- Footnotes (read-only)
- Table of contents (manual)

**Not Supported:**
- SmartArt
- Charts (use images instead)
- Macros (security)
- Track changes
- Comments

## Error Handling

### Common Exceptions

```python
# File not found
try:
    doc = Document('nonexistent.docx')
except FileNotFoundError:
    print("Document not found")

# Invalid file format
try:
    doc = Document('not_a_docx.txt')
except Exception as e:
    print(f"Invalid format: {e}")

# Style not found
try:
    para = doc.add_paragraph(style='NonexistentStyle')
except KeyError:
    para = doc.add_paragraph()  # Use default
```

### Validation

```python
def validate_docx(file_path: Path) -> bool:
    """Check if file is a valid DOCX."""
    try:
        doc = Document(file_path)
        # Basic validation
        _ = len(doc.paragraphs)
        return True
    except Exception:
        return False
```

## Performance Considerations

### Memory Usage

| Document Size | Approximate Memory |
|--------------|-------------------|
| < 1 MB | < 50 MB RAM |
| 1-10 MB | 50-200 MB RAM |
| 10-50 MB | 200-500 MB RAM |
| > 50 MB | Consider streaming |

### Optimization Tips

1. **Large Documents**: Process in chunks
   ```python
   # Add content in batches
   for chunk in content_chunks:
       doc.add_paragraph(chunk)
       if len(doc.paragraphs) % 100 == 0:
           doc.save('temp.docx')  # Periodic save
   ```

2. **Many Tables**: Pre-allocate rows
   ```python
   table = doc.add_table(rows=len(data), cols=num_cols)
   # More efficient than adding rows one by one
   ```

3. **Images**: Resize before adding
   ```python
   # Add with specific width (height auto-calculated)
   doc.add_picture('large_image.png', width=Inches(6))
   ```

## Integration Examples

### With Jinja2 Templates

```python
from jinja2 import Template

# Use Jinja2 for complex templating, then convert
template_md = Template("""
# {{ title }}

## Executive Summary
{{ summary }}

## Findings
{% for finding in findings %}
### {{ finding.title }}
**Severity**: {{ finding.severity }}
{{ finding.description }}
{% endfor %}
""")

rendered = template_md.render(
    title="Security Assessment",
    summary="Assessment complete.",
    findings=[
        {'title': 'SQL Injection', 'severity': 'Critical', 'description': '...'},
    ]
)

# Save rendered markdown, then convert
Path('temp.md').write_text(rendered)
converter.convert(Path('temp.md'), Path('report.docx'))
```

### With pandas DataFrames

```python
import pandas as pd

# DataFrame to table
df = pd.DataFrame({
    'Finding': ['SQL Injection', 'XSS'],
    'Severity': ['Critical', 'High'],
    'Status': ['Open', 'Fixed']
})

data = [df.columns.tolist()] + df.values.tolist()
add_table_from_data(doc, data)
```

## Changelog

### [1.0.0] - 2024-01-01
- Initial release
- Core document manipulation (read, create, modify)
- Markdown to DOCX conversion
- Template-based styling
- Table and list support
