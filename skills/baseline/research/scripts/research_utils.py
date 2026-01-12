#!/usr/bin/env python3
"""
Research Utility Functions

Common utilities for gathering and synthesizing research data.

Usage:
    from research_utils import fetch_url, search_nvd, aggregate_feeds
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    raise ImportError("requests is required. Install with: pip install requests")

try:
    from bs4 import BeautifulSoup
except ImportError:
    raise ImportError("beautifulsoup4 is required. Install with: pip install beautifulsoup4")

try:
    import feedparser
except ImportError:
    feedparser = None


logger = logging.getLogger(__name__)


# Default configuration
DEFAULT_USER_AGENT = 'ResearchBot/1.0 (Security Research)'
DEFAULT_TIMEOUT = 30
DEFAULT_CACHE_TTL = 24 * 3600  # 24 hours


class ResearchCache:
    """File-based cache for research data."""

    def __init__(self, cache_dir: str = '.research_cache', ttl_seconds: int = DEFAULT_CACHE_TTL):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_seconds = ttl_seconds

    def _get_cache_path(self, key: str) -> Path:
        cache_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{cache_key}.json"

    def get(self, key: str) -> Optional[Any]:
        cache_file = self._get_cache_path(key)
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text())
                if time.time() - data.get('timestamp', 0) < self.ttl_seconds:
                    return data.get('content')
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    def set(self, key: str, content: Any):
        cache_file = self._get_cache_path(key)
        cache_file.write_text(json.dumps({
            'timestamp': time.time(),
            'key': key,
            'content': content
        }, default=str))

    def clear(self):
        for cache_file in self.cache_dir.glob('*.json'):
            cache_file.unlink()


class RateLimiter:
    """Rate limiter for API requests."""

    def __init__(self, requests_per_minute: int = 30):
        self.min_interval = 60.0 / requests_per_minute
        self.last_request = 0

    def wait(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()


# Global instances
_cache = ResearchCache()
_rate_limiter = RateLimiter()


def fetch_url(
    url: str,
    use_cache: bool = True,
    headers: Dict[str, str] = None
) -> str:
    """
    Fetch content from a URL with caching and rate limiting.

    Args:
        url: URL to fetch
        use_cache: Whether to use cache
        headers: Optional custom headers

    Returns:
        Response text
    """
    if use_cache:
        cached = _cache.get(url)
        if cached:
            return cached

    _rate_limiter.wait()

    default_headers = {'User-Agent': DEFAULT_USER_AGENT}
    if headers:
        default_headers.update(headers)

    response = requests.get(url, headers=default_headers, timeout=DEFAULT_TIMEOUT)
    response.raise_for_status()

    if use_cache:
        _cache.set(url, response.text)

    return response.text


def extract_page_content(url: str) -> Dict[str, Any]:
    """
    Extract content from a web page.

    Args:
        url: URL to extract from

    Returns:
        Dictionary with title, description, text, and links
    """
    html = fetch_url(url)
    soup = BeautifulSoup(html, 'html.parser')

    # Remove unwanted elements
    for element in soup(['script', 'style', 'nav', 'footer', 'header']):
        element.decompose()

    title = soup.find('title')
    description = soup.find('meta', attrs={'name': 'description'})
    main_content = soup.find('main') or soup.find('article') or soup.find('body')

    return {
        'url': url,
        'title': title.text.strip() if title else '',
        'description': description.get('content', '') if description else '',
        'text': main_content.get_text(separator='\n', strip=True) if main_content else '',
        'links': [urljoin(url, a['href']) for a in soup.find_all('a', href=True)][:50]
    }


def search_nvd(
    keyword: str = None,
    cve_id: str = None,
    severity: str = None,
    days_back: int = 30
) -> List[Dict[str, Any]]:
    """
    Search NVD for CVEs.

    Args:
        keyword: Search keyword
        cve_id: Specific CVE ID
        severity: CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)
        days_back: Number of days to search

    Returns:
        List of CVE records
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {}

    if cve_id:
        params['cveId'] = cve_id
    if keyword:
        params['keywordSearch'] = keyword
    if severity:
        params['cvssV3Severity'] = severity.upper()

    if days_back and not cve_id:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        params['pubStartDate'] = start_date.strftime('%Y-%m-%dT00:00:00.000')
        params['pubEndDate'] = end_date.strftime('%Y-%m-%dT23:59:59.999')

    _rate_limiter.wait()

    response = requests.get(base_url, params=params, timeout=60)
    response.raise_for_status()
    data = response.json()

    cves = []
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})

        # Extract CVSS score
        cvss_score = 0
        metrics = cve.get('metrics', {})
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0)
                break

        cves.append({
            'id': cve.get('id'),
            'description': cve.get('descriptions', [{}])[0].get('value', ''),
            'published': cve.get('published'),
            'lastModified': cve.get('lastModified'),
            'cvss_score': cvss_score,
            'references': [ref.get('url') for ref in cve.get('references', [])]
        })

    return cves


def get_cve_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a specific CVE.

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)

    Returns:
        CVE details or None if not found
    """
    results = search_nvd(cve_id=cve_id)
    return results[0] if results else None


def fetch_feed(feed_url: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Fetch and parse an RSS/Atom feed.

    Args:
        feed_url: URL of the feed
        limit: Maximum entries to return

    Returns:
        List of feed entries
    """
    if feedparser is None:
        raise ImportError("feedparser is required. Install with: pip install feedparser")

    feed = feedparser.parse(feed_url)
    entries = []

    for entry in feed.entries[:limit]:
        entries.append({
            'title': entry.get('title', ''),
            'link': entry.get('link', ''),
            'summary': entry.get('summary', '')[:500] if entry.get('summary') else '',
            'published': entry.get('published', ''),
            'source': feed.feed.get('title', '')
        })

    return entries


SECURITY_FEEDS = {
    'us_cert': 'https://www.cisa.gov/uscert/ncas/alerts.xml',
    'nist': 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
}


def aggregate_security_feeds(feeds: Dict[str, str] = None, limit_per_feed: int = 5) -> List[Dict]:
    """
    Aggregate entries from multiple security feeds.

    Args:
        feeds: Dictionary of feed names to URLs
        limit_per_feed: Max entries per feed

    Returns:
        List of aggregated feed entries
    """
    feeds = feeds or SECURITY_FEEDS
    all_entries = []

    for name, url in feeds.items():
        try:
            entries = fetch_feed(url, limit_per_feed)
            for entry in entries:
                entry['feed_name'] = name
            all_entries.extend(entries)
        except Exception as e:
            logger.error(f"Error fetching feed {name}: {e}")

    return all_entries


def generate_report(
    topic: str,
    findings: List[Dict[str, Any]],
    sources: List[str],
    format: str = 'markdown'
) -> str:
    """
    Generate a research report.

    Args:
        topic: Research topic
        findings: List of finding dictionaries
        sources: List of source URLs
        format: Output format ('markdown' or 'text')

    Returns:
        Formatted report string
    """
    if format == 'markdown':
        return _generate_markdown_report(topic, findings, sources)
    else:
        return _generate_text_report(topic, findings, sources)


def _generate_markdown_report(topic: str, findings: List[Dict], sources: List[str]) -> str:
    """Generate markdown formatted report."""
    lines = [
        f"# Research Report: {topic}",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Sources Consulted:** {len(sources)}",
        f"**Findings:** {len(findings)}",
        "",
        "## Executive Summary",
        "",
        f"This report compiles {len(findings)} findings related to {topic}.",
        "",
        "## Key Findings",
        ""
    ]

    for i, finding in enumerate(findings, 1):
        lines.append(f"### {i}. {finding.get('title', 'Finding ' + str(i))}")
        lines.append("")
        if finding.get('summary'):
            lines.append(finding['summary'])
            lines.append("")
        if finding.get('details'):
            lines.append(f"**Details:** {finding['details']}")
            lines.append("")
        if finding.get('source'):
            lines.append(f"*Source: {finding['source']}*")
            lines.append("")

    lines.extend(["", "## Sources", ""])
    for i, source in enumerate(sources, 1):
        lines.append(f"{i}. <{source}>")

    return '\n'.join(lines)


def _generate_text_report(topic: str, findings: List[Dict], sources: List[str]) -> str:
    """Generate plain text report."""
    lines = [
        f"RESEARCH REPORT: {topic.upper()}",
        "=" * 60,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Sources: {len(sources)}",
        f"Findings: {len(findings)}",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f"This report compiles {len(findings)} findings related to {topic}.",
        "",
        "KEY FINDINGS",
        "-" * 40,
    ]

    for i, finding in enumerate(findings, 1):
        lines.append(f"\n{i}. {finding.get('title', 'Finding ' + str(i))}")
        if finding.get('summary'):
            lines.append(f"   {finding['summary']}")

    lines.extend(["\n", "SOURCES", "-" * 40])
    for i, source in enumerate(sources, 1):
        lines.append(f"{i}. {source}")

    return '\n'.join(lines)
