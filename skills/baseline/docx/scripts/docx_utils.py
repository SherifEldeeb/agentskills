#!/usr/bin/env python3
"""
DOCX Utility Functions

Common utilities for working with Word documents.

Usage:
    from docx_utils import read_docx, replace_placeholders, extract_tables
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from docx import Document
    from docx.shared import Inches, Pt
    from docx.table import Table
except ImportError:
    raise ImportError("python-docx is required. Install with: pip install python-docx")


def read_docx(file_path: Path) -> Dict[str, Any]:
    """
    Read a DOCX file and extract its contents.

    Args:
        file_path: Path to the DOCX file

    Returns:
        Dictionary with text, tables, and metadata
    """
    doc = Document(file_path)

    # Extract text from paragraphs
    paragraphs = [para.text for para in doc.paragraphs]

    # Extract tables
    tables = []
    for table in doc.tables:
        table_data = []
        for row in table.rows:
            row_data = [cell.text for cell in row.cells]
            table_data.append(row_data)
        tables.append(table_data)

    # Extract metadata
    props = doc.core_properties
    metadata = {
        'title': props.title,
        'author': props.author,
        'subject': props.subject,
        'keywords': props.keywords,
        'created': props.created,
        'modified': props.modified,
    }

    return {
        'paragraphs': paragraphs,
        'text': '\n'.join(paragraphs),
        'tables': tables,
        'metadata': metadata
    }


def replace_placeholders(
    doc: Document,
    replacements: Dict[str, str],
    placeholder_pattern: str = r'\{\{(\w+)\}\}'
) -> Document:
    """
    Replace placeholders in a document.

    Args:
        doc: Document object to modify
        replacements: Dictionary of placeholder -> value mappings
        placeholder_pattern: Regex pattern for placeholders (default: {{name}})

    Returns:
        Modified document
    """
    pattern = re.compile(placeholder_pattern)

    # Replace in paragraphs
    for para in doc.paragraphs:
        if pattern.search(para.text):
            for key, value in replacements.items():
                placeholder = f'{{{{{key}}}}}'
                if placeholder in para.text:
                    para.text = para.text.replace(placeholder, str(value))

    # Replace in tables
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    if pattern.search(para.text):
                        for key, value in replacements.items():
                            placeholder = f'{{{{{key}}}}}'
                            if placeholder in para.text:
                                para.text = para.text.replace(placeholder, str(value))

    return doc


def extract_tables(doc: Document) -> List[List[List[str]]]:
    """
    Extract all tables from a document.

    Args:
        doc: Document object

    Returns:
        List of tables, each table is a list of rows, each row is a list of cell values
    """
    tables = []
    for table in doc.tables:
        table_data = []
        for row in table.rows:
            row_data = [cell.text.strip() for cell in row.cells]
            table_data.append(row_data)
        tables.append(table_data)
    return tables


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
        data: List of rows, each row is a list of cell values
        has_header: Whether first row is a header (will be bolded)
        style: Table style to apply

    Returns:
        Created Table object
    """
    if not data:
        raise ValueError("Data cannot be empty")

    num_rows = len(data)
    num_cols = len(data[0])

    table = doc.add_table(rows=num_rows, cols=num_cols)
    table.style = style

    for i, row_data in enumerate(data):
        row = table.rows[i]
        for j, cell_value in enumerate(row_data):
            cell = row.cells[j]
            cell.text = str(cell_value)

            # Bold header row
            if has_header and i == 0:
                for para in cell.paragraphs:
                    for run in para.runs:
                        run.bold = True

    return table


def copy_styles_from_template(template_path: Path, target_doc: Document) -> Document:
    """
    Copy styles from a template document to a target document.

    Note: This is a simplified version. Full style copying requires
    more complex XML manipulation.

    Args:
        template_path: Path to template DOCX
        target_doc: Document to copy styles to

    Returns:
        Modified target document
    """
    template = Document(template_path)

    # Copy paragraph styles that exist in template
    for style in template.styles:
        if style.type == 1:  # Paragraph style
            try:
                # Check if style exists in target
                target_doc.styles[style.name]
            except KeyError:
                # Style doesn't exist, would need to create it
                # Full implementation would copy style properties
                pass

    return target_doc


def get_document_structure(doc: Document) -> Dict[str, Any]:
    """
    Analyze document structure (headings, sections).

    Args:
        doc: Document object

    Returns:
        Dictionary describing document structure
    """
    structure = {
        'headings': [],
        'paragraph_count': 0,
        'table_count': len(doc.tables),
        'sections': []
    }

    current_section = None

    for para in doc.paragraphs:
        structure['paragraph_count'] += 1

        # Check if this is a heading
        if para.style.name.startswith('Heading'):
            level = int(para.style.name.split()[-1]) if para.style.name[-1].isdigit() else 0
            heading_info = {
                'text': para.text,
                'level': level,
                'style': para.style.name
            }
            structure['headings'].append(heading_info)

            # Track sections based on Heading 1
            if level == 1:
                if current_section:
                    structure['sections'].append(current_section)
                current_section = {
                    'title': para.text,
                    'subsections': []
                }
            elif level == 2 and current_section:
                current_section['subsections'].append(para.text)

    if current_section:
        structure['sections'].append(current_section)

    return structure


def merge_documents(docs: List[Path], output_path: Path, add_breaks: bool = True) -> bool:
    """
    Merge multiple DOCX files into one.

    Args:
        docs: List of paths to DOCX files to merge
        output_path: Path for output file
        add_breaks: Add page breaks between documents

    Returns:
        True if successful
    """
    if not docs:
        return False

    # Start with first document
    merged = Document(docs[0])

    # Append remaining documents
    for doc_path in docs[1:]:
        if add_breaks:
            merged.add_page_break()

        doc = Document(doc_path)
        for element in doc.element.body:
            merged.element.body.append(element)

    merged.save(output_path)
    return True


def set_document_properties(
    doc: Document,
    title: Optional[str] = None,
    author: Optional[str] = None,
    subject: Optional[str] = None,
    keywords: Optional[str] = None
) -> Document:
    """
    Set document metadata properties.

    Args:
        doc: Document object
        title: Document title
        author: Document author
        subject: Document subject
        keywords: Document keywords

    Returns:
        Modified document
    """
    props = doc.core_properties

    if title is not None:
        props.title = title
    if author is not None:
        props.author = author
    if subject is not None:
        props.subject = subject
    if keywords is not None:
        props.keywords = keywords

    return doc
