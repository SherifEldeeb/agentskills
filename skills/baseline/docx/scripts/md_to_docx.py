#!/usr/bin/env python3
"""
Markdown to DOCX Converter

Converts markdown files to Word documents (.docx) with support for
template-based styling. Preserves formatting from the template while
converting markdown content.

Usage:
    python md_to_docx.py <input.md> --output <output.docx>
    python md_to_docx.py <input.md> --template <template.docx> --output <output.docx>

Examples:
    python md_to_docx.py report.md --output report.docx
    python md_to_docx.py report.md --template corporate.docx --output final.docx
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.style import WD_STYLE_TYPE
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
except ImportError:
    print("Error: python-docx is required. Install with: pip install python-docx")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class MarkdownBlock:
    """Represents a parsed markdown block."""
    block_type: str  # 'heading', 'paragraph', 'code', 'list', 'table', 'quote', 'hr'
    content: str
    level: int = 0  # For headings (1-6) or list nesting
    language: str = ''  # For code blocks
    items: List[str] = field(default_factory=list)  # For lists
    rows: List[List[str]] = field(default_factory=list)  # For tables
    ordered: bool = False  # For ordered lists


class MarkdownParser:
    """Parse markdown content into structured blocks."""

    # Regex patterns for markdown elements
    PATTERNS = {
        'heading': re.compile(r'^(#{1,6})\s+(.+)$'),
        'code_block_start': re.compile(r'^```(\w*)$'),
        'code_block_end': re.compile(r'^```$'),
        'unordered_list': re.compile(r'^(\s*)[-*+]\s+(.+)$'),
        'ordered_list': re.compile(r'^(\s*)\d+\.\s+(.+)$'),
        'blockquote': re.compile(r'^>\s*(.*)$'),
        'horizontal_rule': re.compile(r'^[-*_]{3,}$'),
        'table_row': re.compile(r'^\|(.+)\|$'),
        'table_separator': re.compile(r'^\|[-:\s|]+\|$'),
    }

    def parse(self, content: str) -> List[MarkdownBlock]:
        """Parse markdown content into blocks."""
        lines = content.split('\n')
        blocks = []
        i = 0

        while i < len(lines):
            line = lines[i]

            # Skip empty lines
            if not line.strip():
                i += 1
                continue

            # Check for code block
            code_match = self.PATTERNS['code_block_start'].match(line)
            if code_match:
                block, i = self._parse_code_block(lines, i, code_match.group(1))
                blocks.append(block)
                continue

            # Check for heading
            heading_match = self.PATTERNS['heading'].match(line)
            if heading_match:
                level = len(heading_match.group(1))
                blocks.append(MarkdownBlock(
                    block_type='heading',
                    content=heading_match.group(2),
                    level=level
                ))
                i += 1
                continue

            # Check for horizontal rule
            if self.PATTERNS['horizontal_rule'].match(line):
                blocks.append(MarkdownBlock(block_type='hr', content=''))
                i += 1
                continue

            # Check for blockquote
            quote_match = self.PATTERNS['blockquote'].match(line)
            if quote_match:
                block, i = self._parse_blockquote(lines, i)
                blocks.append(block)
                continue

            # Check for table
            if self.PATTERNS['table_row'].match(line):
                block, i = self._parse_table(lines, i)
                if block:
                    blocks.append(block)
                continue

            # Check for unordered list
            ul_match = self.PATTERNS['unordered_list'].match(line)
            if ul_match:
                block, i = self._parse_list(lines, i, ordered=False)
                blocks.append(block)
                continue

            # Check for ordered list
            ol_match = self.PATTERNS['ordered_list'].match(line)
            if ol_match:
                block, i = self._parse_list(lines, i, ordered=True)
                blocks.append(block)
                continue

            # Default: paragraph
            block, i = self._parse_paragraph(lines, i)
            blocks.append(block)

        return blocks

    def _parse_code_block(self, lines: List[str], start: int, language: str) -> tuple:
        """Parse a fenced code block."""
        content_lines = []
        i = start + 1

        while i < len(lines):
            if self.PATTERNS['code_block_end'].match(lines[i]):
                i += 1
                break
            content_lines.append(lines[i])
            i += 1

        return MarkdownBlock(
            block_type='code',
            content='\n'.join(content_lines),
            language=language
        ), i

    def _parse_blockquote(self, lines: List[str], start: int) -> tuple:
        """Parse a blockquote."""
        content_lines = []
        i = start

        while i < len(lines):
            match = self.PATTERNS['blockquote'].match(lines[i])
            if match:
                content_lines.append(match.group(1))
                i += 1
            else:
                break

        return MarkdownBlock(
            block_type='quote',
            content='\n'.join(content_lines)
        ), i

    def _parse_list(self, lines: List[str], start: int, ordered: bool) -> tuple:
        """Parse a list (ordered or unordered)."""
        items = []
        i = start
        pattern = self.PATTERNS['ordered_list'] if ordered else self.PATTERNS['unordered_list']

        while i < len(lines):
            match = pattern.match(lines[i])
            if match:
                items.append(match.group(2))
                i += 1
            elif lines[i].strip() == '':
                # Empty line might end list or be within it
                if i + 1 < len(lines) and pattern.match(lines[i + 1]):
                    i += 1
                else:
                    break
            else:
                break

        return MarkdownBlock(
            block_type='list',
            content='',
            items=items,
            ordered=ordered
        ), i

    def _parse_table(self, lines: List[str], start: int) -> tuple:
        """Parse a markdown table."""
        rows = []
        i = start

        while i < len(lines):
            line = lines[i]
            row_match = self.PATTERNS['table_row'].match(line)

            if row_match:
                # Skip separator row
                if self.PATTERNS['table_separator'].match(line):
                    i += 1
                    continue

                cells = [cell.strip() for cell in row_match.group(1).split('|')]
                rows.append(cells)
                i += 1
            else:
                break

        if rows:
            return MarkdownBlock(
                block_type='table',
                content='',
                rows=rows
            ), i
        return None, i

    def _parse_paragraph(self, lines: List[str], start: int) -> tuple:
        """Parse a paragraph (continuous non-special lines)."""
        content_lines = []
        i = start

        while i < len(lines):
            line = lines[i]

            # Check if this line starts a new block type
            if (not line.strip() or
                self.PATTERNS['heading'].match(line) or
                self.PATTERNS['code_block_start'].match(line) or
                self.PATTERNS['unordered_list'].match(line) or
                self.PATTERNS['ordered_list'].match(line) or
                self.PATTERNS['blockquote'].match(line) or
                self.PATTERNS['table_row'].match(line) or
                self.PATTERNS['horizontal_rule'].match(line)):
                break

            content_lines.append(line)
            i += 1

        return MarkdownBlock(
            block_type='paragraph',
            content=' '.join(content_lines)
        ), i


class InlineFormatter:
    """Handle inline markdown formatting (bold, italic, code, links)."""

    # Patterns for inline formatting
    BOLD_PATTERN = re.compile(r'\*\*(.+?)\*\*|__(.+?)__')
    ITALIC_PATTERN = re.compile(r'\*(.+?)\*|_(.+?)_')
    CODE_PATTERN = re.compile(r'`([^`]+)`')
    LINK_PATTERN = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
    BOLD_ITALIC_PATTERN = re.compile(r'\*\*\*(.+?)\*\*\*')

    @classmethod
    def add_formatted_text(cls, paragraph, text: str):
        """Add text with inline formatting to a paragraph."""
        # Process text segment by segment
        segments = cls._parse_inline(text)

        for segment in segments:
            run = paragraph.add_run(segment['text'])
            if segment.get('bold'):
                run.bold = True
            if segment.get('italic'):
                run.italic = True
            if segment.get('code'):
                run.font.name = 'Consolas'
                run.font.size = Pt(10)

    @classmethod
    def _parse_inline(cls, text: str) -> List[Dict[str, Any]]:
        """Parse inline formatting into segments."""
        segments = []
        remaining = text

        while remaining:
            # Find the earliest match of any pattern
            earliest_match = None
            earliest_pos = len(remaining)
            match_type = None

            # Check for bold+italic
            match = cls.BOLD_ITALIC_PATTERN.search(remaining)
            if match and match.start() < earliest_pos:
                earliest_match = match
                earliest_pos = match.start()
                match_type = 'bold_italic'

            # Check for bold
            match = cls.BOLD_PATTERN.search(remaining)
            if match and match.start() < earliest_pos:
                earliest_match = match
                earliest_pos = match.start()
                match_type = 'bold'

            # Check for italic
            match = cls.ITALIC_PATTERN.search(remaining)
            if match and match.start() < earliest_pos:
                earliest_match = match
                earliest_pos = match.start()
                match_type = 'italic'

            # Check for code
            match = cls.CODE_PATTERN.search(remaining)
            if match and match.start() < earliest_pos:
                earliest_match = match
                earliest_pos = match.start()
                match_type = 'code'

            # Check for link (convert to just text)
            match = cls.LINK_PATTERN.search(remaining)
            if match and match.start() < earliest_pos:
                earliest_match = match
                earliest_pos = match.start()
                match_type = 'link'

            if earliest_match:
                # Add text before match
                if earliest_pos > 0:
                    segments.append({'text': remaining[:earliest_pos]})

                # Add formatted segment
                if match_type == 'bold_italic':
                    segments.append({
                        'text': earliest_match.group(1),
                        'bold': True,
                        'italic': True
                    })
                elif match_type == 'bold':
                    content = earliest_match.group(1) or earliest_match.group(2)
                    segments.append({'text': content, 'bold': True})
                elif match_type == 'italic':
                    content = earliest_match.group(1) or earliest_match.group(2)
                    segments.append({'text': content, 'italic': True})
                elif match_type == 'code':
                    segments.append({'text': earliest_match.group(1), 'code': True})
                elif match_type == 'link':
                    segments.append({'text': earliest_match.group(1)})

                remaining = remaining[earliest_match.end():]
            else:
                # No more matches, add remaining text
                if remaining:
                    segments.append({'text': remaining})
                break

        return segments


class MarkdownToDocx:
    """Convert markdown to DOCX with template styling support."""

    def __init__(self, template_path: Optional[Path] = None):
        """
        Initialize converter.

        Args:
            template_path: Optional path to DOCX template for styling
        """
        self.template_path = template_path
        self.parser = MarkdownParser()

    def convert(self, input_path: Path, output_path: Path) -> bool:
        """
        Convert markdown file to DOCX.

        Args:
            input_path: Path to markdown file
            output_path: Path for output DOCX

        Returns:
            True if conversion succeeded
        """
        try:
            # Read markdown content
            logger.info(f"Reading markdown: {input_path}")
            content = input_path.read_text(encoding='utf-8')

            # Parse markdown
            logger.info("Parsing markdown content...")
            blocks = self.parser.parse(content)

            # Create document (from template or new)
            if self.template_path and self.template_path.exists():
                logger.info(f"Using template: {self.template_path}")
                doc = Document(self.template_path)
                # Clear template content but keep styles
                self._clear_document_content(doc)
            else:
                logger.info("Creating new document")
                doc = Document()
                self._setup_default_styles(doc)

            # Convert blocks to DOCX
            logger.info("Converting to DOCX...")
            self._render_blocks(doc, blocks)

            # Save output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            doc.save(output_path)
            logger.info(f"Saved: {output_path}")

            return True

        except Exception as e:
            logger.error(f"Conversion failed: {e}")
            return False

    def _clear_document_content(self, doc: Document):
        """Remove content from template while preserving styles."""
        # Remove all paragraphs except empty ones needed for structure
        for para in doc.paragraphs:
            p = para._element
            p.getparent().remove(p)

        # Remove all tables
        for table in doc.tables:
            t = table._element
            t.getparent().remove(t)

    def _setup_default_styles(self, doc: Document):
        """Set up default styles for a new document."""
        styles = doc.styles

        # Ensure code style exists
        try:
            styles['Code']
        except KeyError:
            code_style = styles.add_style('Code', WD_STYLE_TYPE.CHARACTER)
            code_style.font.name = 'Consolas'
            code_style.font.size = Pt(10)

    def _render_blocks(self, doc: Document, blocks: List[MarkdownBlock]):
        """Render markdown blocks to document."""
        for block in blocks:
            if block.block_type == 'heading':
                self._render_heading(doc, block)
            elif block.block_type == 'paragraph':
                self._render_paragraph(doc, block)
            elif block.block_type == 'code':
                self._render_code_block(doc, block)
            elif block.block_type == 'list':
                self._render_list(doc, block)
            elif block.block_type == 'table':
                self._render_table(doc, block)
            elif block.block_type == 'quote':
                self._render_blockquote(doc, block)
            elif block.block_type == 'hr':
                self._render_horizontal_rule(doc)

    def _render_heading(self, doc: Document, block: MarkdownBlock):
        """Render a heading."""
        # Map markdown levels to Word heading levels
        level = min(block.level, 9)  # Word supports up to Heading 9
        doc.add_heading(block.content, level=level)

    def _render_paragraph(self, doc: Document, block: MarkdownBlock):
        """Render a paragraph with inline formatting."""
        para = doc.add_paragraph()
        InlineFormatter.add_formatted_text(para, block.content)

    def _render_code_block(self, doc: Document, block: MarkdownBlock):
        """Render a code block."""
        para = doc.add_paragraph()

        # Style as code
        run = para.add_run(block.content)
        run.font.name = 'Consolas'
        run.font.size = Pt(10)

        # Add light gray background (using paragraph shading)
        self._add_paragraph_shading(para, 'F5F5F5')

    def _add_paragraph_shading(self, paragraph, color: str):
        """Add background shading to a paragraph."""
        shading = OxmlElement('w:shd')
        shading.set(qn('w:fill'), color)
        paragraph._element.get_or_add_pPr().append(shading)

    def _render_list(self, doc: Document, block: MarkdownBlock):
        """Render an ordered or unordered list."""
        style = 'List Number' if block.ordered else 'List Bullet'

        for item in block.items:
            para = doc.add_paragraph(style=style)
            InlineFormatter.add_formatted_text(para, item)

    def _render_table(self, doc: Document, block: MarkdownBlock):
        """Render a table."""
        if not block.rows:
            return

        num_cols = len(block.rows[0])
        table = doc.add_table(rows=len(block.rows), cols=num_cols)
        table.style = 'Table Grid'

        for i, row_data in enumerate(block.rows):
            row = table.rows[i]
            for j, cell_text in enumerate(row_data):
                if j < len(row.cells):
                    cell = row.cells[j]
                    # Clear default paragraph and add formatted text
                    cell.text = ''
                    para = cell.paragraphs[0]
                    InlineFormatter.add_formatted_text(para, cell_text)

                    # Bold first row (header)
                    if i == 0:
                        for run in para.runs:
                            run.bold = True

    def _render_blockquote(self, doc: Document, block: MarkdownBlock):
        """Render a blockquote."""
        para = doc.add_paragraph()

        # Add left indent for quote appearance
        para.paragraph_format.left_indent = Inches(0.5)

        # Add italic formatting
        run = para.add_run(block.content)
        run.italic = True

        # Add left border styling
        self._add_left_border(para)

    def _add_left_border(self, paragraph):
        """Add a left border to simulate blockquote styling."""
        pPr = paragraph._element.get_or_add_pPr()
        pBdr = OxmlElement('w:pBdr')
        left = OxmlElement('w:left')
        left.set(qn('w:val'), 'single')
        left.set(qn('w:sz'), '24')
        left.set(qn('w:color'), '999999')
        pBdr.append(left)
        pPr.append(pBdr)

    def _render_horizontal_rule(self, doc: Document):
        """Render a horizontal rule."""
        para = doc.add_paragraph()
        para.paragraph_format.space_after = Pt(12)

        # Add a bottom border to simulate HR
        pPr = para._element.get_or_add_pPr()
        pBdr = OxmlElement('w:pBdr')
        bottom = OxmlElement('w:bottom')
        bottom.set(qn('w:val'), 'single')
        bottom.set(qn('w:sz'), '6')
        bottom.set(qn('w:color'), 'CCCCCC')
        pBdr.append(bottom)
        pPr.append(pBdr)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Convert Markdown to DOCX with template styling',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s report.md --output report.docx
  %(prog)s report.md --template corporate.docx --output final.docx
  %(prog)s report.md -t template.docx -o output.docx --verbose
        """
    )

    parser.add_argument(
        'input',
        type=Path,
        help='Input markdown file'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        required=True,
        help='Output DOCX file'
    )

    parser.add_argument(
        '-t', '--template',
        type=Path,
        default=None,
        help='DOCX template for styling (optional)'
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

    # Validate input
    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        return 1

    if args.template and not args.template.exists():
        logger.warning(f"Template not found: {args.template}, using default styles")

    # Convert
    converter = MarkdownToDocx(template_path=args.template)
    success = converter.convert(args.input, args.output)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
