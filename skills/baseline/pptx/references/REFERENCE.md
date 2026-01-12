# PPTX Skill Reference

Detailed technical reference for the PPTX skill.

## API Reference

### pptx_utils Module

#### extract_content

```python
def extract_content(file_path: Path) -> Dict[str, Any]:
    """
    Extract all content from a PowerPoint presentation.

    Args:
        file_path: Path to the PPTX file

    Returns:
        Dictionary containing:
        - slide_count: int
        - slides: List of slide content dictionaries
    """
```

#### create_presentation

```python
def create_presentation(
    title: str,
    subtitle: str = '',
    template_path: Optional[Path] = None
) -> Presentation:
    """
    Create a new presentation with a title slide.

    Args:
        title: Presentation title
        subtitle: Subtitle text
        template_path: Optional template to use

    Returns:
        Presentation object
    """
```

#### add_content_slide

```python
def add_content_slide(
    prs: Presentation,
    title: str,
    points: List[str],
    notes: str = ''
) -> Any:
    """
    Add a content slide with bullet points.

    Args:
        prs: Presentation object
        title: Slide title
        points: List of bullet points
        notes: Speaker notes

    Returns:
        Created slide
    """
```

#### add_table_slide

```python
def add_table_slide(
    prs: Presentation,
    title: str,
    headers: List[str],
    rows: List[List[str]],
    header_color: RGBColor = None
) -> Any:
    """
    Add a slide with a formatted table.

    Args:
        prs: Presentation object
        title: Slide title
        headers: Table headers
        rows: Table data rows
        header_color: Header background color

    Returns:
        Created slide
    """
```

#### add_chart_slide

```python
def add_chart_slide(
    prs: Presentation,
    title: str,
    chart_type: str,
    categories: List[str],
    series_data: Dict[str, List[float]],
    position: tuple = None
) -> Any:
    """
    Add a slide with a chart.

    Args:
        prs: Presentation object
        title: Slide title
        chart_type: Type of chart ('bar', 'column', 'pie', 'line')
        categories: Category labels
        series_data: Dictionary of series names to values
        position: Tuple of (x, y, width, height) in inches

    Returns:
        Created slide
    """
```

#### markdown_to_presentation

```python
def markdown_to_presentation(
    markdown_content: str,
    output_path: Path,
    template_path: Optional[Path] = None
) -> bool:
    """
    Convert markdown content to a PowerPoint presentation.

    Args:
        markdown_content: Markdown text
        output_path: Output file path
        template_path: Optional template

    Returns:
        True if successful
    """
```

#### create_security_briefing

```python
def create_security_briefing(
    findings: List[Dict[str, Any]],
    output_path: Path,
    title: str = "Security Assessment Briefing"
) -> bool:
    """
    Generate a security briefing presentation from findings.

    Args:
        findings: List of finding dictionaries
        output_path: Output file path
        title: Presentation title

    Returns:
        True if successful
    """
```

## Slide Layouts

Standard slide layout indices:

| Index | Name | Description |
|-------|------|-------------|
| 0 | Title Slide | Title and subtitle |
| 1 | Title and Content | Title with bullet points |
| 2 | Section Header | Section divider |
| 3 | Two Content | Two columns |
| 4 | Comparison | Side-by-side comparison |
| 5 | Title Only | Title with blank content |
| 6 | Blank | Completely blank |
| 7 | Content with Caption | Content with side caption |
| 8 | Picture with Caption | Image with caption |

## Chart Types

| Type | Constant | Use Case |
|------|----------|----------|
| `bar` | BAR_CLUSTERED | Horizontal comparisons |
| `column` | COLUMN_CLUSTERED | Vertical comparisons |
| `pie` | PIE | Part-to-whole relationships |
| `line` | LINE | Trends over time |
| `area` | AREA | Cumulative totals |

## Color Constants

```python
COLORS = {
    'dark_blue': RGBColor(44, 62, 80),
    'white': RGBColor(255, 255, 255),
    'critical': RGBColor(231, 76, 60),
    'high': RGBColor(230, 126, 34),
    'medium': RGBColor(241, 196, 15),
    'low': RGBColor(52, 152, 219),
    'info': RGBColor(149, 165, 166)
}
```

## Units

```python
from pptx.util import Inches, Pt, Emu

# Common conversions
Inches(1)      # 1 inch
Pt(12)         # 12 points (font size)
Emu(914400)    # 914400 EMUs = 1 inch
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| python-pptx | >=0.6.21 | PowerPoint file operations |

## Performance Considerations

| Operation | Impact |
|-----------|--------|
| Add text slide | Low |
| Add table | Medium |
| Add chart | Medium |
| Add image | High (depends on size) |
| Merge presentations | High |

## Error Handling

| Exception | Cause | Solution |
|-----------|-------|----------|
| `FileNotFoundError` | File not found | Verify path |
| `PackageNotFoundError` | Invalid PPTX | Check file format |
| `KeyError` | Layout index invalid | Check available layouts |

## Changelog

### [1.0.0] - 2024-01-01

- Initial release
- Read/write presentations
- Table and chart support
- Markdown conversion
- Security briefing generator
- Template support
