#!/usr/bin/env python3
"""
PDF Utility Functions

Common utilities for working with PDF documents.

Usage:
    from pdf_utils import extract_text, merge_pdfs, split_pdf, add_watermark
"""

import logging
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

try:
    from PyPDF2 import PdfReader, PdfWriter
except ImportError:
    raise ImportError("PyPDF2 is required. Install with: pip install PyPDF2")

try:
    import pdfplumber
except ImportError:
    raise ImportError("pdfplumber is required. Install with: pip install pdfplumber")

try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
except ImportError:
    raise ImportError("reportlab is required. Install with: pip install reportlab")


logger = logging.getLogger(__name__)


def extract_text(file_path: Path, preserve_layout: bool = False) -> str:
    """
    Extract all text from a PDF file.

    Args:
        file_path: Path to the PDF file
        preserve_layout: Whether to preserve the original layout

    Returns:
        Extracted text content
    """
    text_content = []

    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            if preserve_layout:
                text = page.extract_text(layout=True)
            else:
                text = page.extract_text()
            if text:
                text_content.append(text)

    return '\n\n'.join(text_content)


def extract_text_by_page(file_path: Path) -> List[Dict[str, Any]]:
    """
    Extract text from each page of a PDF.

    Args:
        file_path: Path to the PDF file

    Returns:
        List of dictionaries with page number and text
    """
    pages = []

    with pdfplumber.open(file_path) as pdf:
        for i, page in enumerate(pdf.pages, 1):
            text = page.extract_text() or ''
            pages.append({
                'page_number': i,
                'text': text,
                'width': page.width,
                'height': page.height
            })

    return pages


def extract_tables(file_path: Path) -> List[Dict[str, Any]]:
    """
    Extract all tables from a PDF file.

    Args:
        file_path: Path to the PDF file

    Returns:
        List of tables with page info and data
    """
    all_tables = []

    with pdfplumber.open(file_path) as pdf:
        for page_num, page in enumerate(pdf.pages, 1):
            tables = page.extract_tables()
            for table_num, table in enumerate(tables, 1):
                if table:
                    all_tables.append({
                        'page': page_num,
                        'table_num': table_num,
                        'rows': len(table),
                        'cols': len(table[0]) if table else 0,
                        'data': table
                    })

    return all_tables


def get_metadata(file_path: Path) -> Dict[str, Any]:
    """
    Extract metadata from a PDF file.

    Args:
        file_path: Path to the PDF file

    Returns:
        Dictionary containing PDF metadata
    """
    reader = PdfReader(file_path)
    metadata = reader.metadata or {}

    return {
        'title': metadata.get('/Title', ''),
        'author': metadata.get('/Author', ''),
        'subject': metadata.get('/Subject', ''),
        'keywords': metadata.get('/Keywords', ''),
        'creator': metadata.get('/Creator', ''),
        'producer': metadata.get('/Producer', ''),
        'creation_date': str(metadata.get('/CreationDate', '')),
        'modification_date': str(metadata.get('/ModDate', '')),
        'page_count': len(reader.pages),
        'encrypted': reader.is_encrypted
    }


def set_metadata(
    input_path: Path,
    output_path: Path,
    title: Optional[str] = None,
    author: Optional[str] = None,
    subject: Optional[str] = None,
    keywords: Optional[str] = None
) -> bool:
    """
    Set metadata on a PDF file.

    Args:
        input_path: Source PDF file
        output_path: Output PDF file
        title: Document title
        author: Document author
        subject: Document subject
        keywords: Document keywords

    Returns:
        True if successful
    """
    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        metadata = {}
        if title:
            metadata['/Title'] = title
        if author:
            metadata['/Author'] = author
        if subject:
            metadata['/Subject'] = subject
        if keywords:
            metadata['/Keywords'] = keywords

        if metadata:
            writer.add_metadata(metadata)

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        logger.error(f"Failed to set metadata: {e}")
        return False


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
    if not pdf_list:
        return False

    try:
        writer = PdfWriter()

        for pdf_path in pdf_list:
            reader = PdfReader(pdf_path)

            if add_bookmarks:
                bookmark_title = Path(pdf_path).stem
                writer.add_outline_item(bookmark_title, len(writer.pages))

            for page in reader.pages:
                writer.add_page(page)

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        logger.error(f"Failed to merge PDFs: {e}")
        return False


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
    reader = PdfReader(input_path)
    output_files = []

    for i, (start, end) in enumerate(page_ranges, 1):
        writer = PdfWriter()

        for page_num in range(start - 1, min(end, len(reader.pages))):
            writer.add_page(reader.pages[page_num])

        output_path = Path(f"{output_prefix}_part{i}.pdf")
        with open(output_path, 'wb') as f:
            writer.write(f)

        output_files.append(output_path)

    return output_files


def extract_pages(
    input_path: Path,
    output_path: Path,
    pages: List[int]
) -> bool:
    """
    Extract specific pages from a PDF.

    Args:
        input_path: Source PDF file
        output_path: Output file path
        pages: List of page numbers to extract (1-indexed)

    Returns:
        True if successful
    """
    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()

        for page_num in pages:
            if 1 <= page_num <= len(reader.pages):
                writer.add_page(reader.pages[page_num - 1])

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        logger.error(f"Failed to extract pages: {e}")
        return False


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
    try:
        # Create watermark PDF
        watermark_buffer = BytesIO()
        c = canvas.Canvas(watermark_buffer, pagesize=letter)

        c.setFont("Helvetica", font_size)
        c.setFillColorRGB(0.5, 0.5, 0.5, alpha=opacity)
        c.saveState()
        c.translate(300, 400)
        c.rotate(angle)
        c.drawCentredString(0, 0, watermark_text)
        c.restoreState()
        c.save()

        watermark_buffer.seek(0)
        watermark_pdf = PdfReader(watermark_buffer)
        watermark_page = watermark_pdf.pages[0]

        # Apply to all pages
        reader = PdfReader(input_path)
        writer = PdfWriter()

        for page in reader.pages:
            page.merge_page(watermark_page)
            writer.add_page(page)

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        logger.error(f"Failed to add watermark: {e}")
        return False


def rotate_pages(
    input_path: Path,
    output_path: Path,
    rotation: int,
    pages: Optional[List[int]] = None
) -> bool:
    """
    Rotate pages in a PDF.

    Args:
        input_path: Source PDF file
        output_path: Output file path
        rotation: Rotation angle (90, 180, 270)
        pages: Specific pages to rotate (1-indexed), None for all

    Returns:
        True if successful
    """
    if rotation not in (90, 180, 270):
        logger.error("Rotation must be 90, 180, or 270 degrees")
        return False

    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()

        for i, page in enumerate(reader.pages, 1):
            if pages is None or i in pages:
                page.rotate(rotation)
            writer.add_page(page)

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        logger.error(f"Failed to rotate pages: {e}")
        return False


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
    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        writer.encrypt(password, owner_password or password)

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        logger.error(f"Failed to encrypt PDF: {e}")
        return False


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
    try:
        reader = PdfReader(input_path)

        if reader.is_encrypted:
            reader.decrypt(password)

        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        with open(output_path, 'wb') as f:
            writer.write(f)

        return True
    except Exception as e:
        logger.error(f"Failed to decrypt PDF: {e}")
        return False


def get_page_count(file_path: Path) -> int:
    """
    Get the number of pages in a PDF.

    Args:
        file_path: Path to the PDF file

    Returns:
        Number of pages
    """
    reader = PdfReader(file_path)
    return len(reader.pages)


def is_encrypted(file_path: Path) -> bool:
    """
    Check if a PDF is encrypted.

    Args:
        file_path: Path to the PDF file

    Returns:
        True if encrypted
    """
    reader = PdfReader(file_path)
    return reader.is_encrypted
