#!/usr/bin/env python3
"""
PDF Report Generator

Generate professional PDF reports using ReportLab.

Usage:
    python pdf_report.py --title "Report Title" --output report.pdf
    python pdf_report.py --input data.json --template security --output report.pdf
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, ListFlowable, ListItem
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
except ImportError:
    print("Error: reportlab is required. Install with: pip install reportlab")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """Generate professional PDF reports."""

    def __init__(self, pagesize=letter):
        """
        Initialize report generator.

        Args:
            pagesize: Page size (letter, A4, etc.)
        """
        self.pagesize = pagesize
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Set up custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#2c3e50')
        ))

        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Normal'],
            fontSize=14,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#7f8c8d')
        ))

        # Section heading
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#2c3e50')
        ))

        # Body text
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            alignment=TA_JUSTIFY
        ))

        # Finding styles by severity
        for severity, color in [
            ('Critical', '#e74c3c'),
            ('High', '#e67e22'),
            ('Medium', '#f1c40f'),
            ('Low', '#3498db'),
            ('Info', '#95a5a6')
        ]:
            self.styles.add(ParagraphStyle(
                name=f'Finding{severity}',
                parent=self.styles['Normal'],
                fontSize=11,
                textColor=colors.HexColor(color),
                fontName='Helvetica-Bold'
            ))

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
        try:
            doc = SimpleDocTemplate(
                str(output_path),
                pagesize=self.pagesize,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )

            story = []

            # Title page
            story.append(Spacer(1, 2 * inch))
            story.append(Paragraph(title, self.styles['ReportTitle']))

            if subtitle:
                story.append(Paragraph(subtitle, self.styles['ReportSubtitle']))

            if author:
                story.append(Spacer(1, inch))
                story.append(Paragraph(
                    f"Prepared by: {author}",
                    self.styles['ReportSubtitle']
                ))

            story.append(Paragraph(
                f"Date: {datetime.now().strftime('%B %d, %Y')}",
                self.styles['ReportSubtitle']
            ))

            story.append(PageBreak())

            # Process content blocks
            for block in content:
                self._add_content_block(story, block)

            doc.build(story)
            logger.info(f"Report saved to: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to create report: {e}")
            return False

    def _add_content_block(self, story: List, block: Dict[str, Any]):
        """Add a content block to the story."""
        block_type = block.get('type', 'paragraph')

        if block_type == 'heading':
            story.append(Paragraph(
                block.get('text', ''),
                self.styles['SectionHeading']
            ))

        elif block_type == 'paragraph':
            story.append(Paragraph(
                block.get('text', ''),
                self.styles['BodyText']
            ))

        elif block_type == 'table':
            self._add_table(story, block)

        elif block_type == 'list':
            self._add_list(story, block)

        elif block_type == 'finding':
            self._add_finding(story, block)

        elif block_type == 'spacer':
            story.append(Spacer(1, block.get('height', 20)))

        elif block_type == 'page_break':
            story.append(PageBreak())

    def _add_table(self, story: List, block: Dict[str, Any]):
        """Add a table to the story."""
        data = block.get('data', [])
        if not data:
            return

        col_widths = block.get('col_widths', None)
        table = Table(data, colWidths=col_widths)

        # Default table style
        style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#ecf0f1')])
        ]

        table.setStyle(TableStyle(style))
        story.append(table)
        story.append(Spacer(1, 20))

    def _add_list(self, story: List, block: Dict[str, Any]):
        """Add a list to the story."""
        items = block.get('items', [])
        ordered = block.get('ordered', False)

        bullet_type = '1' if ordered else 'bullet'
        list_items = []

        for item in items:
            list_items.append(ListItem(
                Paragraph(item, self.styles['BodyText']),
                leftIndent=35,
                value=bullet_type
            ))

        story.append(ListFlowable(
            list_items,
            bulletType=bullet_type,
            start='1' if ordered else None
        ))
        story.append(Spacer(1, 12))

    def _add_finding(self, story: List, block: Dict[str, Any]):
        """Add a security finding block."""
        title = block.get('title', 'Finding')
        severity = block.get('severity', 'Info')
        description = block.get('description', '')
        remediation = block.get('remediation', '')

        # Finding title with severity
        style_name = f'Finding{severity}'
        if style_name not in self.styles:
            style_name = 'FindingInfo'

        story.append(Paragraph(
            f"[{severity.upper()}] {title}",
            self.styles[style_name]
        ))

        if description:
            story.append(Paragraph(
                f"<b>Description:</b> {description}",
                self.styles['BodyText']
            ))

        if remediation:
            story.append(Paragraph(
                f"<b>Remediation:</b> {remediation}",
                self.styles['BodyText']
            ))

        story.append(Spacer(1, 15))


def create_security_report(
    findings: List[Dict[str, Any]],
    output_path: Path,
    title: str = "Security Assessment Report",
    author: Optional[str] = None
) -> bool:
    """
    Create a security assessment report from findings.

    Args:
        findings: List of finding dictionaries
        output_path: Output PDF path
        title: Report title
        author: Report author

    Returns:
        True if successful
    """
    generator = PDFReportGenerator()

    # Calculate summary statistics
    severity_counts = {}
    for finding in findings:
        sev = finding.get('severity', 'Info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Build content
    content = [
        {'type': 'heading', 'text': 'Executive Summary'},
        {'type': 'paragraph', 'text': (
            f"This security assessment identified {len(findings)} findings. "
            f"Critical: {severity_counts.get('Critical', 0)}, "
            f"High: {severity_counts.get('High', 0)}, "
            f"Medium: {severity_counts.get('Medium', 0)}, "
            f"Low: {severity_counts.get('Low', 0)}."
        )},
        {'type': 'spacer', 'height': 20},
        {'type': 'heading', 'text': 'Findings Summary'},
        {
            'type': 'table',
            'data': [['#', 'Finding', 'Severity', 'Status']] + [
                [str(i + 1), f['title'], f['severity'], f.get('status', 'Open')]
                for i, f in enumerate(findings)
            ],
            'col_widths': [30, 280, 80, 80]
        },
        {'type': 'page_break'},
        {'type': 'heading', 'text': 'Detailed Findings'}
    ]

    # Add individual findings
    for finding in findings:
        content.append({
            'type': 'finding',
            'title': finding.get('title', 'Untitled'),
            'severity': finding.get('severity', 'Info'),
            'description': finding.get('description', ''),
            'remediation': finding.get('remediation', '')
        })

    return generator.create_report(
        output_path,
        title,
        content,
        subtitle="Confidential Security Assessment",
        author=author
    )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate PDF reports',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        required=True,
        help='Output PDF file'
    )

    parser.add_argument(
        '-t', '--title',
        default='Report',
        help='Report title'
    )

    parser.add_argument(
        '-i', '--input',
        type=Path,
        help='Input JSON file with report data'
    )

    parser.add_argument(
        '-a', '--author',
        help='Report author'
    )

    parser.add_argument(
        '--template',
        choices=['security', 'general'],
        default='general',
        help='Report template to use'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load input data if provided
    if args.input and args.input.exists():
        with open(args.input) as f:
            data = json.load(f)
    else:
        data = {}

    if args.template == 'security':
        findings = data.get('findings', [])
        success = create_security_report(
            findings,
            args.output,
            title=args.title,
            author=args.author
        )
    else:
        generator = PDFReportGenerator()
        content = data.get('content', [
            {'type': 'paragraph', 'text': 'No content provided.'}
        ])
        success = generator.create_report(
            args.output,
            args.title,
            content,
            author=args.author
        )

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
