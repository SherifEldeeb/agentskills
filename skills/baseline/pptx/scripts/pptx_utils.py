#!/usr/bin/env python3
"""
PPTX Utility Functions

Common utilities for working with PowerPoint presentations.

Usage:
    from pptx_utils import create_presentation, add_slide, add_table
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from pptx import Presentation
    from pptx.util import Inches, Pt
    from pptx.dml.color import RGBColor
    from pptx.chart.data import CategoryChartData
    from pptx.enum.chart import XL_CHART_TYPE
    from pptx.enum.text import PP_ALIGN
except ImportError:
    raise ImportError("python-pptx is required. Install with: pip install python-pptx")


logger = logging.getLogger(__name__)

# Color constants
COLORS = {
    'dark_blue': RGBColor(44, 62, 80),
    'white': RGBColor(255, 255, 255),
    'critical': RGBColor(231, 76, 60),
    'high': RGBColor(230, 126, 34),
    'medium': RGBColor(241, 196, 15),
    'low': RGBColor(52, 152, 219),
    'info': RGBColor(149, 165, 166)
}


def extract_content(file_path: Path) -> Dict[str, Any]:
    """
    Extract all content from a PowerPoint presentation.

    Args:
        file_path: Path to the PPTX file

    Returns:
        Dictionary with presentation content
    """
    prs = Presentation(file_path)
    content = {
        'slide_count': len(prs.slides),
        'slides': []
    }

    for slide_num, slide in enumerate(prs.slides, 1):
        slide_content = {
            'number': slide_num,
            'text': [],
            'notes': '',
            'shapes': []
        }

        for shape in slide.shapes:
            if hasattr(shape, 'text') and shape.text:
                slide_content['text'].append(shape.text)

            slide_content['shapes'].append({
                'name': shape.name,
                'type': shape.shape_type,
                'has_text': hasattr(shape, 'text')
            })

        if slide.has_notes_slide:
            notes_slide = slide.notes_slide
            if notes_slide.notes_text_frame:
                slide_content['notes'] = notes_slide.notes_text_frame.text

        content['slides'].append(slide_content)

    return content


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
    if template_path and template_path.exists():
        prs = Presentation(template_path)
    else:
        prs = Presentation()

    # Add title slide
    title_slide = prs.slides.add_slide(prs.slide_layouts[0])
    title_slide.shapes.title.text = title

    if len(title_slide.placeholders) > 1:
        title_slide.placeholders[1].text = subtitle

    return prs


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

    if notes:
        notes_slide = slide.notes_slide
        notes_slide.notes_text_frame.text = notes

    return slide


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
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = title

    header_color = header_color or COLORS['dark_blue']

    # Calculate dimensions
    x, y = Inches(0.5), Inches(1.5)
    cx = Inches(9)
    cy = Inches(0.5 * (len(rows) + 1))

    table = slide.shapes.add_table(
        len(rows) + 1, len(headers), x, y, cx, cy
    ).table

    # Style header row
    for col_idx, header in enumerate(headers):
        cell = table.cell(0, col_idx)
        cell.text = header
        cell.fill.solid()
        cell.fill.fore_color.rgb = header_color

        paragraph = cell.text_frame.paragraphs[0]
        paragraph.font.bold = True
        paragraph.font.color.rgb = COLORS['white']
        paragraph.font.size = Pt(12)
        paragraph.alignment = PP_ALIGN.CENTER

    # Add data rows
    for row_idx, row_data in enumerate(rows, 1):
        for col_idx, value in enumerate(row_data):
            cell = table.cell(row_idx, col_idx)
            cell.text = str(value)
            paragraph = cell.text_frame.paragraphs[0]
            paragraph.font.size = Pt(11)

    return slide


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
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = title

    chart_data = CategoryChartData()
    chart_data.categories = categories

    for series_name, values in series_data.items():
        chart_data.add_series(series_name, values)

    chart_types = {
        'bar': XL_CHART_TYPE.BAR_CLUSTERED,
        'column': XL_CHART_TYPE.COLUMN_CLUSTERED,
        'pie': XL_CHART_TYPE.PIE,
        'line': XL_CHART_TYPE.LINE,
        'area': XL_CHART_TYPE.AREA
    }
    xl_chart_type = chart_types.get(chart_type.lower(), XL_CHART_TYPE.COLUMN_CLUSTERED)

    if position:
        x, y, cx, cy = [Inches(p) for p in position]
    else:
        x, y, cx, cy = Inches(1), Inches(1.5), Inches(8), Inches(5)

    slide.shapes.add_chart(xl_chart_type, x, y, cx, cy, chart_data)

    return slide


def add_image_slide(
    prs: Presentation,
    title: str,
    image_path: Path,
    caption: str = ''
) -> Any:
    """
    Add a slide with an image.

    Args:
        prs: Presentation object
        title: Slide title
        image_path: Path to image file
        caption: Optional caption

    Returns:
        Created slide
    """
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = title

    # Center the image
    left = Inches(1)
    top = Inches(1.5)
    width = Inches(8)

    slide.shapes.add_picture(str(image_path), left, top, width=width)

    if caption:
        # Add caption text box
        textbox = slide.shapes.add_textbox(
            Inches(1), Inches(6.5), Inches(8), Inches(0.5)
        )
        tf = textbox.text_frame
        tf.paragraphs[0].text = caption
        tf.paragraphs[0].alignment = PP_ALIGN.CENTER

    return slide


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
    try:
        if template_path and template_path.exists():
            prs = Presentation(template_path)
        else:
            prs = Presentation()

        # Split by level 1 headers
        sections = re.split(r'\n(?=# )', markdown_content.strip())

        for section in sections:
            lines = section.strip().split('\n')
            if not lines:
                continue

            # Get title
            title_match = re.match(r'^#\s+(.+)$', lines[0])
            if not title_match:
                continue

            title = title_match.group(1)
            points = []

            for line in lines[1:]:
                # Level 1 bullets
                bullet_match = re.match(r'^[-*]\s+(.+)$', line.strip())
                if bullet_match:
                    points.append(bullet_match.group(1))

            if points:
                add_content_slide(prs, title, points)
            else:
                slide = prs.slides.add_slide(prs.slide_layouts[5])
                slide.shapes.title.text = title

        prs.save(output_path)
        return True
    except Exception as e:
        logger.error(f"Failed to convert markdown: {e}")
        return False


def merge_presentations(
    presentation_paths: List[Path],
    output_path: Path
) -> bool:
    """
    Merge multiple presentations into one.

    Args:
        presentation_paths: List of presentation paths
        output_path: Output file path

    Returns:
        True if successful
    """
    try:
        if not presentation_paths:
            return False

        # Start with first presentation
        merged = Presentation(presentation_paths[0])

        for pptx_path in presentation_paths[1:]:
            source = Presentation(pptx_path)

            for slide in source.slides:
                # Copy slide layout
                slide_layout = merged.slide_layouts[5]  # Blank layout

                new_slide = merged.slides.add_slide(slide_layout)

                for shape in slide.shapes:
                    # Copy shapes (simplified - text only)
                    if hasattr(shape, 'text') and shape.text:
                        textbox = new_slide.shapes.add_textbox(
                            shape.left, shape.top, shape.width, shape.height
                        )
                        textbox.text_frame.text = shape.text

        merged.save(output_path)
        return True
    except Exception as e:
        logger.error(f"Failed to merge presentations: {e}")
        return False


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
    try:
        prs = create_presentation(title, "Confidential - Executive Summary")

        # Calculate summary
        severity_counts = {}
        for f in findings:
            sev = f.get('severity', 'Info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Summary slide
        summary_points = [
            f"Total Findings: {len(findings)}",
            f"Critical: {severity_counts.get('Critical', 0)}",
            f"High: {severity_counts.get('High', 0)}",
            f"Medium: {severity_counts.get('Medium', 0)}",
            f"Low: {severity_counts.get('Low', 0)}"
        ]
        add_content_slide(prs, "Executive Summary", summary_points)

        # Findings table
        headers = ['Finding', 'Severity', 'Status']
        rows = [[f['title'], f['severity'], f.get('status', 'Open')]
                for f in findings]
        add_table_slide(prs, "Findings Summary", headers, rows)

        # Chart slide
        categories = list(severity_counts.keys())
        series = {'Count': list(severity_counts.values())}
        add_chart_slide(prs, "Severity Distribution", 'pie', categories, series)

        # Individual critical/high finding slides
        for finding in findings:
            if finding.get('severity') in ['Critical', 'High']:
                points = [
                    finding.get('description', ''),
                    f"Risk: {finding.get('risk', 'N/A')}",
                    f"Remediation: {finding.get('remediation', 'N/A')}"
                ]
                add_content_slide(
                    prs,
                    f"[{finding['severity']}] {finding['title']}",
                    points
                )

        prs.save(output_path)
        return True
    except Exception as e:
        logger.error(f"Failed to create briefing: {e}")
        return False


def get_presentation_info(file_path: Path) -> Dict[str, Any]:
    """
    Get information about a presentation.

    Args:
        file_path: Path to PPTX file

    Returns:
        Dictionary with presentation info
    """
    prs = Presentation(file_path)

    info = {
        'slide_count': len(prs.slides),
        'slide_width': prs.slide_width,
        'slide_height': prs.slide_height,
        'layouts': [layout.name for layout in prs.slide_layouts]
    }

    return info
