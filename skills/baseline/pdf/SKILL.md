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
  version: "0.1.0"
  category: baseline
  status: planned
---

# PDF Skill

Read, create, and manipulate PDF documents.

## Capabilities

- **Read PDFs**: Extract text, tables, and metadata from PDF files
- **Create PDFs**: Generate PDF documents from scratch
- **Merge PDFs**: Combine multiple PDFs into one
- **Convert**: Convert DOCX to PDF, extract images

## Status

This skill is planned for development. See the [docx skill](../docx/) for an example of a completed baseline skill.

## Planned Features

- Extract text with layout preservation
- Extract tables to structured data
- Merge multiple PDFs with bookmarks
- Add watermarks and headers/footers
- Fill PDF forms programmatically
- Convert DOCX reports to PDF
- OCR for scanned documents

## Related Skills

- [docx](../docx/): Word document manipulation
- [xlsx](../xlsx/): Excel data that may be included in PDFs
