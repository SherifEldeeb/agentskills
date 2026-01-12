# PDF Skill Reference

Detailed technical reference for the PDF skill.

## API Reference

### pdf_utils Module

#### extract_text

```python
def extract_text(file_path: Path, preserve_layout: bool = False) -> str:
    """
    Extract all text from a PDF file.

    Args:
        file_path: Path to the PDF file
        preserve_layout: Whether to preserve the original layout

    Returns:
        Extracted text content as a string
    """
```

#### extract_text_by_page

```python
def extract_text_by_page(file_path: Path) -> List[Dict[str, Any]]:
    """
    Extract text from each page of a PDF.

    Args:
        file_path: Path to the PDF file

    Returns:
        List of dictionaries containing:
        - page_number: int
        - text: str
        - width: float
        - height: float
    """
```

#### extract_tables

```python
def extract_tables(file_path: Path) -> List[Dict[str, Any]]:
    """
    Extract all tables from a PDF file.

    Args:
        file_path: Path to the PDF file

    Returns:
        List of dictionaries containing:
        - page: int - Page number
        - table_num: int - Table number on page
        - rows: int - Number of rows
        - cols: int - Number of columns
        - data: List[List[str]] - Table data
    """
```

#### get_metadata

```python
def get_metadata(file_path: Path) -> Dict[str, Any]:
    """
    Extract metadata from a PDF file.

    Args:
        file_path: Path to the PDF file

    Returns:
        Dictionary containing:
        - title: str
        - author: str
        - subject: str
        - keywords: str
        - creator: str
        - producer: str
        - creation_date: str
        - modification_date: str
        - page_count: int
        - encrypted: bool
    """
```

#### merge_pdfs

```python
def merge_pdfs(
    pdf_list: List[Path],
    output_path: Path,
    add_bookmarks: bool = True
) -> bool:
    """
    Merge multiple PDF files into one.

    Args:
        pdf_list: List of PDF file paths to merge
        output_path: Output file path
        add_bookmarks: Add bookmarks for each source document

    Returns:
        True if successful
    """
```

#### split_pdf

```python
def split_pdf(
    input_path: Path,
    page_ranges: List[Tuple[int, int]],
    output_prefix: str
) -> List[Path]:
    """
    Split a PDF into multiple files.

    Args:
        input_path: Source PDF file
        page_ranges: List of (start, end) tuples (1-indexed, inclusive)
        output_prefix: Prefix for output files

    Returns:
        List of created file paths
    """
```

#### add_watermark

```python
def add_watermark(
    input_path: Path,
    output_path: Path,
    watermark_text: str,
    font_size: int = 50,
    opacity: float = 0.3,
    angle: int = 45
) -> bool:
    """
    Add a text watermark to all pages of a PDF.

    Args:
        input_path: Source PDF file
        output_path: Output file path
        watermark_text: Text to use as watermark
        font_size: Size of watermark text
        opacity: Opacity of watermark (0-1)
        angle: Rotation angle of watermark

    Returns:
        True if successful
    """
```

#### encrypt_pdf

```python
def encrypt_pdf(
    input_path: Path,
    output_path: Path,
    password: str,
    owner_password: Optional[str] = None
) -> bool:
    """
    Encrypt a PDF with a password.

    Args:
        input_path: Source PDF file
        output_path: Output file path
        password: User password for opening
        owner_password: Owner password for permissions

    Returns:
        True if successful
    """
```

#### decrypt_pdf

```python
def decrypt_pdf(
    input_path: Path,
    output_path: Path,
    password: str
) -> bool:
    """
    Decrypt a password-protected PDF.

    Args:
        input_path: Source PDF file
        output_path: Output file path
        password: Password to decrypt

    Returns:
        True if successful
    """
```

### PDFReportGenerator Class

```python
class PDFReportGenerator:
    """Generate professional PDF reports."""

    def __init__(self, pagesize=letter):
        """
        Initialize report generator.

        Args:
            pagesize: Page size (letter, A4, etc.)
        """

    def create_report(
        self,
        output_path: Path,
        title: str,
        content: List[Dict[str, Any]],
        subtitle: Optional[str] = None,
        author: Optional[str] = None
    ) -> bool:
        """
        Create a PDF report.

        Args:
            output_path: Path for output PDF
            title: Report title
            content: List of content blocks
            subtitle: Optional subtitle
            author: Optional author name

        Returns:
            True if successful
        """
```

### Content Block Types

The `create_report` method accepts content blocks with these types:

| Type | Properties | Description |
|------|------------|-------------|
| `heading` | text | Section heading |
| `paragraph` | text | Body paragraph |
| `table` | data, col_widths | Data table |
| `list` | items, ordered | Bullet or numbered list |
| `finding` | title, severity, description, remediation | Security finding |
| `spacer` | height | Vertical space |
| `page_break` | - | Force new page |

## Command Line Interface

### pdf_report.py

```bash
python pdf_report.py [OPTIONS]

Options:
  -o, --output PATH     Output PDF file (required)
  -t, --title TEXT      Report title
  -i, --input PATH      Input JSON file with report data
  -a, --author TEXT     Report author
  --template TYPE       Report template (security, general)
  -v, --verbose         Enable verbose output
```

### Input JSON Format

```json
{
  "findings": [
    {
      "title": "Finding Title",
      "severity": "Critical",
      "description": "Description of the finding",
      "remediation": "How to fix it",
      "status": "Open"
    }
  ],
  "content": [
    {"type": "heading", "text": "Section Title"},
    {"type": "paragraph", "text": "Body text..."},
    {"type": "table", "data": [["Header1", "Header2"], ["Data1", "Data2"]]}
  ]
}
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| PyPDF2 | >=3.0.0 | PDF reading, writing, merging |
| pdfplumber | >=0.9.0 | Text and table extraction |
| reportlab | >=4.0.0 | PDF generation |

## Performance Considerations

### Memory Usage

| Operation | Memory Impact |
|-----------|---------------|
| Extract text (small PDF) | Low (~50MB) |
| Extract text (large PDF) | Medium (~200MB) |
| Merge PDFs | Linear with total pages |
| Generate report | Low (~100MB) |

### Optimization Tips

1. **Large PDFs**: Process pages in batches
   ```python
   # Read specific pages only
   reader = PdfReader('large.pdf')
   for i in range(0, len(reader.pages), 100):
       batch = reader.pages[i:i+100]
       # Process batch
   ```

2. **Memory-efficient extraction**: Use generators
   ```python
   def extract_pages_gen(pdf_path):
       with pdfplumber.open(pdf_path) as pdf:
           for page in pdf.pages:
               yield page.extract_text()
   ```

3. **Batch operations**: Combine similar operations
   ```python
   # Better: Single writer for multiple operations
   writer = PdfWriter()
   for pdf in pdfs:
       writer.append(pdf)
   writer.write('output.pdf')
   ```

## Error Handling

### Common Exceptions

| Exception | Cause | Solution |
|-----------|-------|----------|
| `FileNotFoundError` | PDF file not found | Verify file path exists |
| `PdfReadError` | Corrupted or invalid PDF | Validate file format |
| `PermissionError` | Encrypted PDF | Decrypt first with password |
| `ValueError` | Invalid page range | Check page numbers are valid |

### Validation Functions

```python
def validate_pdf(file_path: Path) -> bool:
    """Check if file is a valid PDF."""
    try:
        reader = PdfReader(file_path)
        _ = len(reader.pages)
        return True
    except Exception:
        return False

def can_extract_text(file_path: Path) -> bool:
    """Check if text can be extracted from PDF."""
    try:
        with pdfplumber.open(file_path) as pdf:
            if pdf.pages:
                text = pdf.pages[0].extract_text()
                return text is not None and len(text) > 0
        return False
    except Exception:
        return False
```

## Security Considerations

1. **File validation**: Always validate PDF files before processing
2. **Path sanitization**: Sanitize output paths to prevent directory traversal
3. **Password handling**: Don't log or store passwords in plaintext
4. **Size limits**: Implement file size limits for untrusted sources
5. **Temporary files**: Clean up temporary files after processing

## Changelog

### [1.0.0] - 2024-01-01

- Initial release
- Text and table extraction with pdfplumber
- PDF merging, splitting, and page extraction
- Watermark support
- PDF report generation with ReportLab
- Encryption and decryption support
- Comprehensive metadata handling
