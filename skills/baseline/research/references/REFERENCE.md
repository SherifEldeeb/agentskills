# Research Skill Reference

Detailed technical reference for the Research skill.

## API Reference

### research_utils Module

#### fetch_url

```python
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
```

#### extract_page_content

```python
def extract_page_content(url: str) -> Dict[str, Any]:
    """
    Extract content from a web page.

    Args:
        url: URL to extract from

    Returns:
        Dictionary containing:
        - url: str
        - title: str
        - description: str
        - text: str
        - links: List[str]
    """
```

#### search_nvd

```python
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
        List of CVE records with id, description, cvss_score, etc.
    """
```

#### fetch_feed

```python
def fetch_feed(feed_url: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Fetch and parse an RSS/Atom feed.

    Args:
        feed_url: URL of the feed
        limit: Maximum entries to return

    Returns:
        List of feed entries with title, link, summary, published
    """
```

#### generate_report

```python
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
```

### ResearchCache Class

```python
class ResearchCache:
    """File-based cache for research data."""

    def __init__(self, cache_dir: str = '.research_cache', ttl_seconds: int = 86400):
        """Initialize cache."""

    def get(self, key: str) -> Optional[Any]:
        """Get cached content by key."""

    def set(self, key: str, content: Any):
        """Store content in cache."""

    def clear(self):
        """Clear all cached data."""
```

### RateLimiter Class

```python
class RateLimiter:
    """Rate limiter for API requests."""

    def __init__(self, requests_per_minute: int = 30):
        """Initialize rate limiter."""

    def wait(self):
        """Wait if necessary to respect rate limit."""
```

## Security Feeds

Built-in feed URLs:

| Name | URL | Description |
|------|-----|-------------|
| us_cert | CISA Alerts RSS | US-CERT security alerts |
| nist | NVD RSS | NVD vulnerability feed |

## Data Sources

### NVD (National Vulnerability Database)

- **Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Rate Limit**: 5 requests per 30 seconds (without API key)
- **Documentation**: https://nvd.nist.gov/developers

### MITRE ATT&CK

- **Endpoint**: GitHub raw content
- **Data**: Enterprise, Mobile, ICS matrices
- **Documentation**: https://attack.mitre.org/

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28.0 | HTTP requests |
| beautifulsoup4 | >=4.11.0 | HTML parsing |
| feedparser | >=6.0.0 | RSS/Atom parsing |

## Error Handling

| Exception | Cause | Handling |
|-----------|-------|----------|
| `requests.Timeout` | Request timeout | Retry with backoff |
| `requests.HTTPError` | HTTP error response | Check status code |
| `json.JSONDecodeError` | Invalid JSON | Handle as text |

## Changelog

### [1.0.0] - 2024-01-01

- Initial release
- Web page content extraction
- NVD CVE search
- RSS/Atom feed parsing
- Research report generation
- Caching and rate limiting
