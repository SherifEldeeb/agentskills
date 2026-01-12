---
name: xlsx
description: |
  Read, create, and manipulate Excel spreadsheets (.xlsx). Extract data,
  create formatted workbooks, apply formulas, and generate charts.
  Use when working with Excel files, data analysis, or spreadsheet reports.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Required packages: openpyxl, pandas
metadata:
  author: SherifEldeeb
  version: "1.0.0"
  category: baseline
---

# XLSX Skill

Read, create, and manipulate Excel spreadsheets with support for formatting, formulas, charts, and data analysis.

## Capabilities

- **Read Workbooks**: Extract data, formulas, and formatting from Excel files
- **Create Workbooks**: Generate new Excel files with multiple sheets
- **Data Operations**: Filter, sort, pivot, and transform data
- **Formatting**: Apply cell styles, conditional formatting, and themes
- **Charts**: Create various chart types from data
- **Formulas**: Add and evaluate Excel formulas
- **Data Validation**: Add dropdown lists and input validation

## Quick Start

```python
from openpyxl import Workbook, load_workbook
import pandas as pd

# Read Excel file
df = pd.read_excel('data.xlsx', sheet_name='Sheet1')
print(df.head())

# Create Excel file
wb = Workbook()
ws = wb.active
ws['A1'] = 'Hello'
ws['B1'] = 'World'
wb.save('output.xlsx')
```

## Usage

### Reading Excel Files

Extract data from Excel workbooks.

**Input**: Path to an Excel file

**Process**:
1. Load workbook with openpyxl or pandas
2. Access specific sheets
3. Read cell values, formulas, or ranges

**Example with openpyxl**:
```python
from openpyxl import load_workbook
from pathlib import Path

def read_workbook(file_path: Path) -> dict:
    """Read all data from an Excel workbook."""
    wb = load_workbook(file_path, data_only=True)
    data = {}

    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        sheet_data = []

        for row in ws.iter_rows(values_only=True):
            if any(cell is not None for cell in row):
                sheet_data.append(list(row))

        data[sheet_name] = sheet_data

    return data

# Usage
workbook_data = read_workbook(Path('report.xlsx'))
for sheet, rows in workbook_data.items():
    print(f"\n{sheet}:")
    for row in rows[:5]:  # First 5 rows
        print(row)
```

**Example with pandas**:
```python
import pandas as pd

def read_all_sheets(file_path: str) -> dict:
    """Read all sheets from Excel into DataFrames."""
    xlsx = pd.ExcelFile(file_path)
    dataframes = {}

    for sheet_name in xlsx.sheet_names:
        dataframes[sheet_name] = pd.read_excel(xlsx, sheet_name=sheet_name)

    return dataframes

# Usage
dfs = read_all_sheets('data.xlsx')
for name, df in dfs.items():
    print(f"\n{name}: {len(df)} rows")
    print(df.head())
```

### Creating Excel Workbooks

Generate Excel files with data and formatting.

**Input**: Data to write

**Process**:
1. Create Workbook object
2. Add sheets and data
3. Apply formatting
4. Save to file

**Example**:
```python
from openpyxl import Workbook
from openpyxl.styles import Font, Fill, PatternFill, Border, Side, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows
import pandas as pd

def create_formatted_workbook(data: dict, output_path: str):
    """Create a formatted Excel workbook."""
    wb = Workbook()

    # Remove default sheet
    wb.remove(wb.active)

    # Header style
    header_font = Font(bold=True, color='FFFFFF')
    header_fill = PatternFill(start_color='2C3E50', end_color='2C3E50', fill_type='solid')
    thin_border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )

    for sheet_name, sheet_data in data.items():
        ws = wb.create_sheet(title=sheet_name)

        # Write data
        for row_idx, row in enumerate(sheet_data, 1):
            for col_idx, value in enumerate(row, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.border = thin_border

                # Style header row
                if row_idx == 1:
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = Alignment(horizontal='center')

        # Auto-adjust column widths
        for column in ws.columns:
            max_length = max(len(str(cell.value or '')) for cell in column)
            ws.column_dimensions[column[0].column_letter].width = max_length + 2

    wb.save(output_path)

# Usage
data = {
    'Findings': [
        ['ID', 'Finding', 'Severity', 'Status'],
        [1, 'SQL Injection', 'Critical', 'Open'],
        [2, 'XSS Vulnerability', 'High', 'Fixed'],
        [3, 'Weak Password', 'Medium', 'In Progress']
    ],
    'Summary': [
        ['Severity', 'Count'],
        ['Critical', 1],
        ['High', 1],
        ['Medium', 1]
    ]
}
create_formatted_workbook(data, 'security_report.xlsx')
```

### Working with DataFrames

Use pandas for efficient data manipulation.

**Example**:
```python
import pandas as pd
from openpyxl import load_workbook
from openpyxl.utils.dataframe import dataframe_to_rows

def df_to_excel_sheet(df: pd.DataFrame, workbook_path: str, sheet_name: str):
    """Write DataFrame to a specific sheet in an existing workbook."""
    try:
        wb = load_workbook(workbook_path)
    except FileNotFoundError:
        wb = Workbook()
        wb.remove(wb.active)

    if sheet_name in wb.sheetnames:
        del wb[sheet_name]

    ws = wb.create_sheet(title=sheet_name)

    for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), 1):
        for c_idx, value in enumerate(row, 1):
            ws.cell(row=r_idx, column=c_idx, value=value)

    wb.save(workbook_path)

# Usage
df = pd.DataFrame({
    'Finding': ['SQL Injection', 'XSS', 'CSRF'],
    'Severity': ['Critical', 'High', 'Medium'],
    'CVSS': [9.8, 7.5, 6.5]
})
df_to_excel_sheet(df, 'report.xlsx', 'Vulnerabilities')
```

### Adding Formulas

Include Excel formulas in cells.

**Example**:
```python
from openpyxl import Workbook

def create_workbook_with_formulas(data: list, output_path: str):
    """Create workbook with formulas for calculations."""
    wb = Workbook()
    ws = wb.active
    ws.title = 'Calculations'

    # Headers
    headers = ['Item', 'Quantity', 'Price', 'Total']
    for col, header in enumerate(headers, 1):
        ws.cell(row=1, column=col, value=header)

    # Data with formulas
    for row_idx, (item, qty, price) in enumerate(data, 2):
        ws.cell(row=row_idx, column=1, value=item)
        ws.cell(row=row_idx, column=2, value=qty)
        ws.cell(row=row_idx, column=3, value=price)
        # Formula for total (Quantity * Price)
        ws.cell(row=row_idx, column=4, value=f'=B{row_idx}*C{row_idx}')

    # Sum formula at the bottom
    last_row = len(data) + 1
    ws.cell(row=last_row + 1, column=3, value='Grand Total:')
    ws.cell(row=last_row + 1, column=4, value=f'=SUM(D2:D{last_row})')

    wb.save(output_path)

# Usage
items = [
    ('Penetration Test', 40, 150),
    ('Vulnerability Scan', 8, 500),
    ('Security Audit', 24, 200)
]
create_workbook_with_formulas(items, 'invoice.xlsx')
```

### Conditional Formatting

Apply conditional formatting rules.

**Example**:
```python
from openpyxl import Workbook
from openpyxl.styles import PatternFill
from openpyxl.formatting.rule import CellIsRule

def apply_severity_formatting(ws, data_range: str):
    """Apply color coding based on severity values."""
    # Red for Critical
    red_fill = PatternFill(start_color='E74C3C', end_color='E74C3C', fill_type='solid')
    ws.conditional_formatting.add(
        data_range,
        CellIsRule(operator='equal', formula=['"Critical"'], fill=red_fill)
    )

    # Orange for High
    orange_fill = PatternFill(start_color='E67E22', end_color='E67E22', fill_type='solid')
    ws.conditional_formatting.add(
        data_range,
        CellIsRule(operator='equal', formula=['"High"'], fill=orange_fill)
    )

    # Yellow for Medium
    yellow_fill = PatternFill(start_color='F1C40F', end_color='F1C40F', fill_type='solid')
    ws.conditional_formatting.add(
        data_range,
        CellIsRule(operator='equal', formula=['"Medium"'], fill=yellow_fill)
    )

# Usage
wb = Workbook()
ws = wb.active
ws.append(['Finding', 'Severity'])
ws.append(['SQL Injection', 'Critical'])
ws.append(['XSS', 'High'])
ws.append(['Info Disclosure', 'Medium'])

apply_severity_formatting(ws, 'B2:B4')
wb.save('formatted_findings.xlsx')
```

### Creating Charts

Generate charts from data.

**Example**:
```python
from openpyxl import Workbook
from openpyxl.chart import BarChart, PieChart, Reference

def create_summary_charts(data: dict, output_path: str):
    """Create workbook with summary charts."""
    wb = Workbook()
    ws = wb.active
    ws.title = 'Summary'

    # Write data
    ws.append(['Severity', 'Count'])
    for severity, count in data.items():
        ws.append([severity, count])

    # Create bar chart
    bar_chart = BarChart()
    bar_chart.title = 'Findings by Severity'
    bar_chart.x_axis.title = 'Severity'
    bar_chart.y_axis.title = 'Count'

    data_ref = Reference(ws, min_col=2, min_row=1, max_col=2, max_row=len(data) + 1)
    categories = Reference(ws, min_col=1, min_row=2, max_row=len(data) + 1)

    bar_chart.add_data(data_ref, titles_from_data=True)
    bar_chart.set_categories(categories)
    ws.add_chart(bar_chart, 'D2')

    # Create pie chart
    pie_chart = PieChart()
    pie_chart.title = 'Severity Distribution'
    pie_chart.add_data(data_ref, titles_from_data=True)
    pie_chart.set_categories(categories)
    ws.add_chart(pie_chart, 'D18')

    wb.save(output_path)

# Usage
severity_counts = {
    'Critical': 3,
    'High': 8,
    'Medium': 15,
    'Low': 22
}
create_summary_charts(severity_counts, 'findings_charts.xlsx')
```

### Data Validation

Add dropdown lists and input validation.

**Example**:
```python
from openpyxl import Workbook
from openpyxl.worksheet.datavalidation import DataValidation

def add_data_validation(ws, column: str, options: list, start_row: int = 2, end_row: int = 100):
    """Add dropdown validation to a column."""
    dv = DataValidation(
        type='list',
        formula1=f'"{",".join(options)}"',
        allow_blank=True,
        showDropDown=False,
        showErrorMessage=True,
        errorTitle='Invalid Entry',
        error='Please select from the dropdown list.'
    )

    ws.add_data_validation(dv)
    dv.add(f'{column}{start_row}:{column}{end_row}')

# Usage
wb = Workbook()
ws = wb.active
ws.append(['Finding', 'Severity', 'Status'])

add_data_validation(ws, 'B', ['Critical', 'High', 'Medium', 'Low', 'Info'])
add_data_validation(ws, 'C', ['Open', 'In Progress', 'Fixed', 'Accepted'])

wb.save('findings_template.xlsx')
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `XLSX_TEMPLATE_DIR` | Default template directory | No | `./assets/templates` |

### Script Options

| Option | Type | Description |
|--------|------|-------------|
| `--input` | path | Input Excel file |
| `--output` | path | Output file path |
| `--sheet` | string | Sheet name to process |
| `--format` | string | Output format (xlsx, csv) |

## Examples

### Example 1: Security Findings Tracker

**Scenario**: Create a comprehensive findings tracker workbook.

```python
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation

def create_findings_tracker(output_path: str):
    """Create a security findings tracking workbook."""
    wb = Workbook()

    # Findings sheet
    ws_findings = wb.active
    ws_findings.title = 'Findings'

    headers = ['ID', 'Title', 'Severity', 'Status', 'Assignee', 'Due Date', 'Notes']
    ws_findings.append(headers)

    # Style headers
    header_font = Font(bold=True, color='FFFFFF')
    header_fill = PatternFill(start_color='2C3E50', fill_type='solid')

    for col, header in enumerate(headers, 1):
        cell = ws_findings.cell(row=1, column=col)
        cell.font = header_font
        cell.fill = header_fill

    # Add data validation
    severity_dv = DataValidation(type='list', formula1='"Critical,High,Medium,Low,Info"')
    status_dv = DataValidation(type='list', formula1='"Open,In Progress,Fixed,Verified,Closed"')

    ws_findings.add_data_validation(severity_dv)
    ws_findings.add_data_validation(status_dv)

    severity_dv.add('C2:C1000')
    status_dv.add('D2:D1000')

    # Dashboard sheet
    ws_dashboard = wb.create_sheet('Dashboard')
    ws_dashboard['A1'] = 'Security Findings Dashboard'
    ws_dashboard['A3'] = 'Summary by Severity'
    ws_dashboard['A4'] = 'Critical:'
    ws_dashboard['B4'] = '=COUNTIF(Findings!C:C,"Critical")'

    wb.save(output_path)

create_findings_tracker('findings_tracker.xlsx')
```

### Example 2: Generate Report from JSON

**Scenario**: Create Excel report from JSON data.

```python
import pandas as pd
import json
from openpyxl import load_workbook
from openpyxl.chart import BarChart, Reference

def generate_report_from_json(json_path: str, output_path: str):
    """Generate formatted Excel report from JSON data."""
    with open(json_path) as f:
        data = json.load(f)

    findings_df = pd.DataFrame(data['findings'])
    summary_df = findings_df.groupby('severity').size().reset_index(name='count')

    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        findings_df.to_excel(writer, sheet_name='Findings', index=False)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)

    # Add chart
    wb = load_workbook(output_path)
    ws = wb['Summary']

    chart = BarChart()
    chart.title = 'Findings by Severity'
    data_ref = Reference(ws, min_col=2, min_row=1, max_row=len(summary_df) + 1)
    cats = Reference(ws, min_col=1, min_row=2, max_row=len(summary_df) + 1)
    chart.add_data(data_ref, titles_from_data=True)
    chart.set_categories(cats)
    ws.add_chart(chart, 'D2')

    wb.save(output_path)
```

## Limitations

- **Large Files**: Performance may degrade with very large files (100k+ rows)
- **Complex Formulas**: Some Excel formulas may not be fully supported
- **Macros**: VBA macros are not supported
- **Pivot Tables**: Cannot create native Excel pivot tables programmatically
- **Advanced Charts**: Some chart types have limited customization

## Troubleshooting

### File Opens Corrupted in Excel

**Problem**: Excel shows repair message when opening file

**Solution**: Ensure proper save and close:
```python
wb.save('output.xlsx')
```

### Formulas Show as Text

**Problem**: Formula appears as text instead of calculating

**Solution**: Don't use quotes around the formula:
```python
# Correct
ws['A1'] = '=SUM(B1:B10)'
```

### Formatting Lost After Save

**Problem**: Styles disappear after save/load cycle

**Solution**: Load without data_only:
```python
wb = load_workbook('file.xlsx')  # Not data_only=True
```

## Related Skills

- [docx](../docx/): Generate Word reports from Excel data
- [pdf](../pdf/): Export Excel data to PDF reports
- [research](../research/): Gather data to populate spreadsheets

## References

- [Detailed API Reference](references/REFERENCE.md)
- [openpyxl Documentation](https://openpyxl.readthedocs.io/)
- [pandas Excel Documentation](https://pandas.pydata.org/docs/reference/api/pandas.read_excel.html)
