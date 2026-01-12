# Image Generation Skill Reference

Detailed technical reference for the Image Generation skill.

## API Reference

### image_utils Module

#### create_bar_chart

```python
def create_bar_chart(
    data: Dict[str, int],
    title: str = 'Chart',
    xlabel: str = '',
    ylabel: str = 'Count',
    colors: Dict[str, str] = None,
    output_path: str = 'chart.png',
    horizontal: bool = False
) -> str:
    """
    Create a bar chart.

    Args:
        data: Dictionary of labels to values
        title: Chart title
        xlabel: X-axis label
        ylabel: Y-axis label
        colors: Color mapping for labels
        output_path: Output file path
        horizontal: If True, create horizontal bar chart

    Returns:
        Path to created image
    """
```

#### create_pie_chart

```python
def create_pie_chart(
    data: Dict[str, int],
    title: str = 'Distribution',
    colors: List[str] = None,
    output_path: str = 'pie.png'
) -> str:
    """
    Create a pie chart.

    Returns:
        Path to created image
    """
```

#### create_line_chart

```python
def create_line_chart(
    x_values: List[Any],
    series: Dict[str, List[float]],
    title: str = 'Trend',
    xlabel: str = '',
    ylabel: str = '',
    output_path: str = 'trend.png'
) -> str:
    """
    Create a line chart with multiple series.

    Returns:
        Path to created image
    """
```

#### create_heatmap

```python
def create_heatmap(
    data: List[List[float]],
    x_labels: List[str],
    y_labels: List[str],
    title: str = 'Heatmap',
    output_path: str = 'heatmap.png',
    cmap: str = 'RdYlGn_r'
) -> str:
    """
    Create a heatmap.

    Returns:
        Path to created image
    """
```

#### create_network_diagram

```python
def create_network_diagram(
    nodes: List[Dict[str, str]],
    edges: List[Dict[str, str]],
    title: str = 'Network Diagram',
    output_path: str = 'network',
    direction: str = 'TB'
) -> Optional[str]:
    """
    Create a network topology diagram using Graphviz.

    Returns:
        Path to created image or None if Graphviz unavailable
    """
```

#### create_flowchart

```python
def create_flowchart(
    steps: List[Dict[str, Any]],
    title: str = 'Flowchart',
    output_path: str = 'flowchart',
    direction: str = 'TB'
) -> Optional[str]:
    """
    Create a process flowchart.

    Returns:
        Path to created image or None if Graphviz unavailable
    """
```

#### create_dashboard

```python
def create_dashboard(
    metrics: Dict[str, Any],
    title: str = 'Security Dashboard',
    output_path: str = 'dashboard.png'
) -> str:
    """
    Create a multi-panel security dashboard.

    Returns:
        Path to created image
    """
```

## Color Constants

```python
SEVERITY_COLORS = {
    'Critical': '#e74c3c',
    'High': '#e67e22',
    'Medium': '#f1c40f',
    'Low': '#3498db',
    'Info': '#95a5a6'
}

STATUS_COLORS = {
    'Open': '#e74c3c',
    'In Progress': '#f1c40f',
    'Fixed': '#2ecc71',
    'Verified': '#3498db',
    'Closed': '#95a5a6'
}
```

## Node Types (Graphviz)

| Type | Shape | Use Case |
|------|-------|----------|
| firewall | box3d | Firewall devices |
| server | box | Server systems |
| database | cylinder | Database servers |
| client | ellipse | Client devices |
| router | diamond | Network routers |
| cloud | cloud | Cloud services |

## Flowchart Step Types

| Type | Shape | Color | Use |
|------|-------|-------|-----|
| start | ellipse | green | Process start |
| end | ellipse | red | Process end |
| process | box | blue | Action step |
| decision | diamond | yellow | Decision point |
| io | parallelogram | lavender | Input/Output |

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| matplotlib | >=3.7.0 | Charts and plots |
| pillow | >=9.0.0 | Image processing |
| graphviz | >=0.20.0 | Diagrams (Python) |
| numpy | >=1.24.0 | Numerical operations |

### System Requirements

- Graphviz system package must be installed for diagram generation

## Output Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| PNG | .png | Web, documents |
| SVG | .svg | Scalable graphics |
| PDF | .pdf | Print quality |

## Changelog

### [1.0.0] - 2024-01-01

- Initial release
- Bar, pie, line charts
- Heatmaps and risk matrices
- Network diagrams
- Flowcharts
- Dashboard generation
