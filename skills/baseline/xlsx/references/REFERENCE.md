# XLSX Skill Reference

Detailed technical reference for the XLSX skill.

## API Reference

### xlsx_utils Module

#### read_workbook

```python
def read_workbook(file_path: Path, data_only: bool = True) -> Dict[str, List[List[Any]]]:
    """
    Read all sheets from an Excel workbook.

    Args:
        file_path: Path to the Excel file
        data_only: If True, read calculated values instead of formulas

    Returns:
        Dictionary mapping sheet names to data (list of rows)
    """
```

#### read_sheet

```python
def read_sheet(file_path: Path, sheet_name: str = None, data_only: bool = True) -> List[List[Any]]:
    """
    Read a specific sheet from an Excel workbook.

    Args:
        file_path: Path to the Excel file
        sheet_name: Name of sheet to read (default: active sheet)
        data_only: If True, read calculated values instead of formulas

    Returns:
        List of rows (each row is a list of cell values)
    """
```

#### read_to_dataframe

```python
def read_to_dataframe(file_path: Path, sheet_name: str = None) -> pd.DataFrame:
    """
    Read Excel sheet into a pandas DataFrame.

    Args:
        file_path: Path to the Excel file
        sheet_name: Name of sheet to read (default: first sheet)

    Returns:
        pandas DataFrame
    """
```

#### create_workbook

```python
def create_workbook(
    data: Dict[str, List[List[Any]]],
    output_path: Path,
    format_headers: bool = True
) -> bool:
    """
    Create a new Excel workbook with multiple sheets.

    Args:
        data: Dictionary mapping sheet names to data
        output_path: Path for output file
        format_headers: Whether to format the first row as headers

    Returns:
        True if successful
    """
```

#### dataframe_to_workbook

```python
def dataframe_to_workbook(
    dataframes: Dict[str, pd.DataFrame],
    output_path: Path,
    format_headers: bool = True
) -> bool:
    """
    Write multiple DataFrames to an Excel workbook.

    Args:
        dataframes: Dictionary mapping sheet names to DataFrames
        output_path: Path for output file
        format_headers: Whether to format headers

    Returns:
        True if successful
    """
```

#### add_chart

```python
def add_chart(
    workbook_path: Path,
    sheet_name: str,
    chart_type: str,
    data_range: tuple,
    category_range: tuple,
    title: str,
    position: str = 'E2'
) -> bool:
    """
    Add a chart to a worksheet.

    Args:
        workbook_path: Path to workbook
        sheet_name: Sheet to add chart to
        chart_type: Type of chart ('bar', 'pie', 'line')
        data_range: Tuple of (min_col, min_row, max_col, max_row)
        category_range: Tuple of (min_col, min_row, max_col, max_row)
        title: Chart title
        position: Cell position for chart

    Returns:
        True if successful
    """
```

#### add_data_validation

```python
def add_data_validation(
    workbook_path: Path,
    sheet_name: str,
    column: str,
    options: List[str],
    start_row: int = 2,
    end_row: int = 1000
) -> bool:
    """
    Add dropdown validation to a column.

    Args:
        workbook_path: Path to workbook
        sheet_name: Sheet name
        column: Column letter (e.g., 'B')
        options: List of valid options
        start_row: First row to apply validation
        end_row: Last row to apply validation

    Returns:
        True if successful
    """
```

#### merge_workbooks

```python
def merge_workbooks(
    workbook_paths: List[Path],
    output_path: Path,
    prefix_sheets: bool = True
) -> bool:
    """
    Merge multiple workbooks into one.

    Args:
        workbook_paths: List of workbook paths to merge
        output_path: Output file path
        prefix_sheets: Add source filename prefix to sheet names

    Returns:
        True if successful
    """
```

## Style Constants

```python
# Header styling
HEADER_FONT = Font(bold=True, color='FFFFFF')
HEADER_FILL = PatternFill(start_color='2C3E50', fill_type='solid')
THIN_BORDER = Border(
    left=Side(style='thin'),
    right=Side(style='thin'),
    top=Side(style='thin'),
    bottom=Side(style='thin')
)

# Severity color coding
SEVERITY_COLORS = {
    'Critical': 'E74C3C',
    'High': 'E67E22',
    'Medium': 'F1C40F',
    'Low': '3498DB',
    'Info': '95A5A6'
}
```

## Chart Types

| Type | Class | Use Case |
|------|-------|----------|
| `bar` | BarChart | Comparing categories |
| `pie` | PieChart | Showing proportions |
| `line` | LineChart | Trends over time |

## Cell Reference Formats

| Format | Description | Example |
|--------|-------------|---------|
| Single cell | Column + Row | `A1`, `B5` |
| Range | Start:End | `A1:C10` |
| Column | Letter only | `A:A` |
| Row | Number only | `1:1` |

## Common Operations

### Reading Data

```python
# Read entire workbook
data = read_workbook(Path('file.xlsx'))

# Read specific sheet to DataFrame
df = read_to_dataframe(Path('file.xlsx'), 'Sheet1')

# Read all sheets to DataFrames
dfs = read_all_sheets_to_dataframes(Path('file.xlsx'))
```

### Writing Data

```python
# Create from dictionary
data = {'Sheet1': [['A', 'B'], [1, 2]], 'Sheet2': [['X', 'Y'], [3, 4]]}
create_workbook(data, Path('output.xlsx'))

# Create from DataFrames
dataframe_to_workbook({'Data': df}, Path('output.xlsx'))
```

### Formatting

```python
# Apply severity formatting
apply_conditional_formatting(Path('file.xlsx'), 'Findings', 'C')

# Add data validation dropdowns
add_data_validation(Path('file.xlsx'), 'Sheet1', 'B', ['Yes', 'No'])
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| openpyxl | >=3.1.0 | Excel file operations |
| pandas | >=2.0.0 | Data manipulation |

## Performance Considerations

### Memory Usage

| Operation | File Size | Memory |
|-----------|-----------|--------|
| Read small file | <1MB | ~50MB |
| Read large file | 10MB | ~200MB |
| Write with formatting | Any | +50% overhead |

### Optimization Tips

1. **Read large files**: Use `data_only=True` to skip formula parsing
2. **Write large files**: Use `write_only` mode in openpyxl
3. **Process data**: Use pandas for large data transformations

## Error Handling

| Exception | Cause | Solution |
|-----------|-------|----------|
| `FileNotFoundError` | File doesn't exist | Check file path |
| `InvalidFileException` | Not a valid Excel file | Verify file format |
| `KeyError` | Sheet name not found | Check sheet names |
| `PermissionError` | File is open | Close file in Excel |

## Changelog

### [1.0.0] - 2024-01-01

- Initial release
- Read/write workbooks with multiple sheets
- DataFrame integration
- Chart creation
- Data validation
- Conditional formatting
- Workbook merging
- CSV export
