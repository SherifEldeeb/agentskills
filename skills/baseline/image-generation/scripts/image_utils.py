#!/usr/bin/env python3
"""
Image Generation Utility Functions

Common utilities for creating diagrams, charts, and visualizations.

Usage:
    from image_utils import create_bar_chart, create_network_diagram, create_flowchart
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    import numpy as np
except ImportError:
    raise ImportError("matplotlib is required. Install with: pip install matplotlib")

try:
    from graphviz import Digraph
except ImportError:
    Digraph = None


logger = logging.getLogger(__name__)


# Color schemes
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

DEFAULT_DPI = 150


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
    labels = list(data.keys())
    values = list(data.values())

    colors = colors or SEVERITY_COLORS
    bar_colors = [colors.get(l, '#3498db') for l in labels]

    plt.figure(figsize=(10, 6))

    if horizontal:
        bars = plt.barh(labels, values, color=bar_colors, edgecolor='white')
        for bar, val in zip(bars, values):
            plt.text(val + 0.5, bar.get_y() + bar.get_height()/2,
                     str(val), va='center', fontweight='bold')
    else:
        bars = plt.bar(labels, values, color=bar_colors, edgecolor='white')
        for bar, val in zip(bars, values):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                     str(val), ha='center', va='bottom', fontweight='bold')

    plt.title(title, fontsize=14, fontweight='bold')
    plt.xlabel(xlabel, fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.tight_layout()
    plt.savefig(output_path, dpi=DEFAULT_DPI, bbox_inches='tight')
    plt.close()

    return output_path


def create_pie_chart(
    data: Dict[str, int],
    title: str = 'Distribution',
    colors: List[str] = None,
    output_path: str = 'pie.png'
) -> str:
    """
    Create a pie chart.

    Args:
        data: Dictionary of labels to values
        title: Chart title
        colors: List of colors
        output_path: Output file path

    Returns:
        Path to created image
    """
    labels = list(data.keys())
    sizes = list(data.values())

    colors = colors or ['#e74c3c', '#e67e22', '#f1c40f', '#3498db', '#95a5a6']

    plt.figure(figsize=(10, 8))
    plt.pie(sizes, labels=labels, colors=colors[:len(labels)],
            autopct='%1.1f%%', startangle=90, explode=[0.02]*len(labels))
    plt.title(title, fontsize=14, fontweight='bold')
    plt.axis('equal')
    plt.savefig(output_path, dpi=DEFAULT_DPI, bbox_inches='tight')
    plt.close()

    return output_path


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

    Args:
        x_values: X-axis values (dates, labels, etc.)
        series: Dictionary of series names to values
        title: Chart title
        xlabel: X-axis label
        ylabel: Y-axis label
        output_path: Output file path

    Returns:
        Path to created image
    """
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#9b59b6', '#f1c40f']

    plt.figure(figsize=(12, 6))

    for i, (name, values) in enumerate(series.items()):
        plt.plot(x_values, values, marker='o', linewidth=2,
                 label=name, color=colors[i % len(colors)])

    plt.title(title, fontsize=14, fontweight='bold')
    plt.xlabel(xlabel, fontsize=12)
    plt.ylabel(ylabel, fontsize=12)
    plt.legend(loc='best')
    plt.xticks(rotation=45)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=DEFAULT_DPI, bbox_inches='tight')
    plt.close()

    return output_path


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

    Args:
        data: 2D array of values
        x_labels: X-axis labels
        y_labels: Y-axis labels
        title: Chart title
        output_path: Output file path
        cmap: Colormap name

    Returns:
        Path to created image
    """
    fig, ax = plt.subplots(figsize=(10, 8))

    im = ax.imshow(data, cmap=cmap, aspect='auto')

    ax.set_xticks(np.arange(len(x_labels)))
    ax.set_yticks(np.arange(len(y_labels)))
    ax.set_xticklabels(x_labels)
    ax.set_yticklabels(y_labels)

    # Add annotations
    for i in range(len(y_labels)):
        for j in range(len(x_labels)):
            val = data[i][j]
            text_color = 'white' if val > np.mean(data) else 'black'
            ax.text(j, i, f'{val:.0f}', ha='center', va='center',
                   color=text_color, fontsize=10, fontweight='bold')

    ax.set_title(title, fontsize=14, fontweight='bold')
    plt.colorbar(im)
    plt.tight_layout()
    plt.savefig(output_path, dpi=DEFAULT_DPI, bbox_inches='tight')
    plt.close()

    return output_path


def create_network_diagram(
    nodes: List[Dict[str, str]],
    edges: List[Dict[str, str]],
    title: str = 'Network Diagram',
    output_path: str = 'network',
    direction: str = 'TB'
) -> Optional[str]:
    """
    Create a network topology diagram using Graphviz.

    Args:
        nodes: List of node dictionaries with id, label, type, color
        edges: List of edge dictionaries with from, to, label
        title: Diagram title
        output_path: Output file path (without extension)
        direction: Graph direction (TB, LR, BT, RL)

    Returns:
        Path to created image or None if Graphviz unavailable
    """
    if Digraph is None:
        logger.error("Graphviz not available")
        return None

    shapes = {
        'firewall': 'box3d',
        'server': 'box',
        'database': 'cylinder',
        'client': 'ellipse',
        'router': 'diamond',
        'cloud': 'cloud',
        'switch': 'box'
    }

    dot = Digraph(comment=title)
    dot.attr(rankdir=direction, label=title, fontsize='16')

    for node in nodes:
        node_id = node['id']
        label = node.get('label', node_id)
        node_type = node.get('type', 'server')
        color = node.get('color', 'lightblue')

        dot.node(node_id, label,
                 shape=shapes.get(node_type, 'box'),
                 style='filled',
                 fillcolor=color)

    for edge in edges:
        dot.edge(edge['from'], edge['to'], label=edge.get('label', ''))

    dot.render(output_path, format='png', cleanup=True)

    return f"{output_path}.png"


def create_flowchart(
    steps: List[Dict[str, Any]],
    title: str = 'Flowchart',
    output_path: str = 'flowchart',
    direction: str = 'TB'
) -> Optional[str]:
    """
    Create a process flowchart.

    Args:
        steps: List of step dictionaries with id, label, type, next
        title: Diagram title
        output_path: Output file path (without extension)
        direction: Graph direction

    Returns:
        Path to created image or None if Graphviz unavailable
    """
    if Digraph is None:
        logger.error("Graphviz not available")
        return None

    shapes = {
        'start': 'ellipse',
        'end': 'ellipse',
        'process': 'box',
        'decision': 'diamond',
        'io': 'parallelogram'
    }

    colors = {
        'start': 'lightgreen',
        'end': 'lightcoral',
        'process': 'lightblue',
        'decision': 'lightyellow',
        'io': 'lavender'
    }

    dot = Digraph(comment=title)
    dot.attr(rankdir=direction, label=title, fontsize='16')

    for step in steps:
        step_id = step['id']
        label = step.get('label', step_id)
        step_type = step.get('type', 'process')

        dot.node(step_id, label,
                 shape=shapes.get(step_type, 'box'),
                 style='filled',
                 fillcolor=colors.get(step_type, 'white'))

        if 'next' in step:
            next_items = step['next'] if isinstance(step['next'], list) else [step['next']]
            for next_item in next_items:
                if isinstance(next_item, dict):
                    dot.edge(step_id, next_item['to'], label=next_item.get('label', ''))
                else:
                    dot.edge(step_id, next_item)

    dot.render(output_path, format='png', cleanup=True)

    return f"{output_path}.png"


def create_dashboard(
    metrics: Dict[str, Any],
    title: str = 'Security Dashboard',
    output_path: str = 'dashboard.png'
) -> str:
    """
    Create a multi-panel security dashboard.

    Args:
        metrics: Dictionary containing various metrics
        title: Dashboard title
        output_path: Output file path

    Returns:
        Path to created image
    """
    fig = plt.figure(figsize=(16, 12))

    # Severity distribution (top-left)
    if 'severity' in metrics:
        ax1 = fig.add_subplot(2, 2, 1)
        data = metrics['severity']
        colors = [SEVERITY_COLORS.get(k, '#333') for k in data.keys()]
        ax1.bar(data.keys(), data.values(), color=colors)
        ax1.set_title('Findings by Severity', fontweight='bold')

    # Trend chart (top-right)
    if 'trend' in metrics:
        ax2 = fig.add_subplot(2, 2, 2)
        trend = metrics['trend']
        for name, values in trend.get('series', {}).items():
            ax2.plot(trend.get('labels', []), values, '-o', label=name)
        ax2.set_title('Trend', fontweight='bold')
        ax2.legend()

    # Status distribution (bottom-left)
    if 'status' in metrics:
        ax3 = fig.add_subplot(2, 2, 3)
        data = metrics['status']
        colors = [STATUS_COLORS.get(k, '#333') for k in data.keys()]
        ax3.pie(data.values(), labels=data.keys(), colors=colors, autopct='%1.1f%%')
        ax3.set_title('Status Distribution', fontweight='bold')

    # Category breakdown (bottom-right)
    if 'categories' in metrics:
        ax4 = fig.add_subplot(2, 2, 4)
        data = metrics['categories']
        ax4.barh(list(data.keys()), list(data.values()), color='#3498db')
        ax4.set_title('By Category', fontweight='bold')

    plt.suptitle(title, fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_path, dpi=DEFAULT_DPI, bbox_inches='tight')
    plt.close()

    return output_path
