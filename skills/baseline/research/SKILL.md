---
name: research
description: |
  Gather and synthesize information from web sources, APIs, and databases.
  Compile research findings into structured reports. Use when researching
  topics, gathering threat intelligence, or compiling background information.
license: Apache-2.0
compatibility: |
  - Python 3.9+
  - Required packages: requests, beautifulsoup4, feedparser
  - Network access required
metadata:
  author: SherifEldeeb
  version: "1.0.0"
  category: baseline
---

# Research Skill

Gather and synthesize information from web sources, APIs, and databases with support for structured data extraction and report generation.

## Capabilities

- **Web Research**: Fetch and extract information from web pages
- **API Integration**: Query APIs for structured data (NVD, MITRE, etc.)
- **Information Synthesis**: Compile findings into structured reports
- **Source Tracking**: Maintain references and citations
- **Data Extraction**: Parse HTML, JSON, and XML content
- **RSS/Atom Feeds**: Monitor security feeds and news sources

## Quick Start

```python
import requests
from bs4 import BeautifulSoup

# Fetch web page content
response = requests.get('https://example.com/security-advisory')
soup = BeautifulSoup(response.text, 'html.parser')

# Extract title and content
title = soup.find('h1').text
content = soup.find('article').text
print(f"Title: {title}")
```

## Usage

### Web Page Content Extraction

Extract text and structured data from web pages.

**Input**: URL to fetch

**Process**:
1. Send HTTP request
2. Parse HTML response
3. Extract relevant content

**Example**:
```python
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List
from urllib.parse import urljoin

def extract_page_content(url: str) -> Dict[str, Any]:
    """Extract content from a web page."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; ResearchBot/1.0)'
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')

    # Remove script and style elements
    for element in soup(['script', 'style', 'nav', 'footer']):
        element.decompose()

    # Extract metadata
    title = soup.find('title')
    description = soup.find('meta', attrs={'name': 'description'})

    # Extract main content
    main_content = soup.find('main') or soup.find('article') or soup.find('body')

    return {
        'url': url,
        'title': title.text.strip() if title else '',
        'description': description['content'] if description else '',
        'text': main_content.get_text(separator='\n', strip=True) if main_content else '',
        'links': [urljoin(url, a['href']) for a in soup.find_all('a', href=True)][:20]
    }

# Usage
content = extract_page_content('https://nvd.nist.gov/vuln/detail/CVE-2024-1234')
print(f"Title: {content['title']}")
print(f"Content length: {len(content['text'])} chars")
```

### API Data Retrieval

Query security-related APIs for structured data.

**Example - NVD CVE Lookup**:
```python
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any

def search_nvd_cves(
    keyword: str = None,
    cvss_severity: str = None,
    days_back: int = 30
) -> List[Dict[str, Any]]:
    """
    Search NVD for CVEs matching criteria.

    Args:
        keyword: Search keyword
        cvss_severity: LOW, MEDIUM, HIGH, or CRITICAL
        days_back: Number of days to look back

    Returns:
        List of CVE records
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {}
    if keyword:
        params['keywordSearch'] = keyword

    if cvss_severity:
        params['cvssV3Severity'] = cvss_severity

    # Date range
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    params['pubStartDate'] = start_date.strftime('%Y-%m-%dT00:00:00.000')
    params['pubEndDate'] = end_date.strftime('%Y-%m-%dT23:59:59.999')

    response = requests.get(base_url, params=params, timeout=60)
    response.raise_for_status()

    data = response.json()
    cves = []

    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cves.append({
            'id': cve.get('id'),
            'description': cve.get('descriptions', [{}])[0].get('value', ''),
            'published': cve.get('published'),
            'cvss_score': extract_cvss_score(cve),
            'references': [ref.get('url') for ref in cve.get('references', [])]
        })

    return cves

def extract_cvss_score(cve: dict) -> float:
    """Extract CVSS v3 score from CVE data."""
    metrics = cve.get('metrics', {})
    cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
    if cvss_v3:
        return cvss_v3[0].get('cvssData', {}).get('baseScore', 0)
    return 0

# Usage
critical_cves = search_nvd_cves(keyword='apache', cvss_severity='CRITICAL', days_back=90)
for cve in critical_cves[:5]:
    print(f"{cve['id']} (CVSS: {cve['cvss_score']})")
    print(f"  {cve['description'][:100]}...")
```

### RSS/Atom Feed Monitoring

Monitor security news and advisory feeds.

**Example**:
```python
import feedparser
from datetime import datetime
from typing import List, Dict, Any

SECURITY_FEEDS = {
    'us_cert': 'https://www.cisa.gov/uscert/ncas/alerts.xml',
    'nist': 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',
    'krebs': 'https://krebsonsecurity.com/feed/',
    'schneier': 'https://www.schneier.com/feed/atom/',
    'threatpost': 'https://threatpost.com/feed/'
}

def fetch_feed(feed_url: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Fetch and parse an RSS/Atom feed."""
    feed = feedparser.parse(feed_url)

    entries = []
    for entry in feed.entries[:limit]:
        entries.append({
            'title': entry.get('title', ''),
            'link': entry.get('link', ''),
            'summary': entry.get('summary', '')[:500],
            'published': entry.get('published', ''),
            'source': feed.feed.get('title', '')
        })

    return entries

def aggregate_security_news(feeds: dict = None, limit_per_feed: int = 5) -> List[Dict]:
    """Aggregate news from multiple security feeds."""
    feeds = feeds or SECURITY_FEEDS
    all_entries = []

    for name, url in feeds.items():
        try:
            entries = fetch_feed(url, limit_per_feed)
            for entry in entries:
                entry['feed_name'] = name
            all_entries.extend(entries)
        except Exception as e:
            print(f"Error fetching {name}: {e}")

    return all_entries

# Usage
news = aggregate_security_news(limit_per_feed=3)
for item in news[:10]:
    print(f"[{item['feed_name']}] {item['title']}")
    print(f"  {item['link']}\n")
```

### MITRE ATT&CK Research

Query MITRE ATT&CK framework data.

**Example**:
```python
import requests
from typing import Dict, List, Any, Optional

ATTACK_BASE_URL = "https://raw.githubusercontent.com/mitre/cti/master"

def get_attack_techniques(
    tactic: Optional[str] = None,
    platform: str = 'enterprise'
) -> List[Dict[str, Any]]:
    """
    Get ATT&CK techniques, optionally filtered by tactic.

    Args:
        tactic: Tactic name (e.g., 'initial-access', 'execution')
        platform: 'enterprise', 'mobile', or 'ics'

    Returns:
        List of technique information
    """
    url = f"{ATTACK_BASE_URL}/{platform}-attack/{platform}-attack.json"

    response = requests.get(url, timeout=60)
    response.raise_for_status()
    data = response.json()

    techniques = []
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue

        # Filter by tactic if specified
        if tactic:
            kill_chain = obj.get('kill_chain_phases', [])
            tactics = [p.get('phase_name') for p in kill_chain]
            if tactic not in tactics:
                continue

        technique_id = ''
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                technique_id = ref.get('external_id', '')
                break

        techniques.append({
            'id': technique_id,
            'name': obj.get('name'),
            'description': obj.get('description', '')[:500],
            'tactics': [p.get('phase_name') for p in obj.get('kill_chain_phases', [])],
            'platforms': obj.get('x_mitre_platforms', []),
            'detection': obj.get('x_mitre_detection', '')[:300]
        })

    return techniques

# Usage
initial_access = get_attack_techniques(tactic='initial-access')
for technique in initial_access[:5]:
    print(f"{technique['id']}: {technique['name']}")
    print(f"  Platforms: {', '.join(technique['platforms'])}")
```

### Research Report Generation

Compile research findings into structured reports.

**Example**:
```python
from datetime import datetime
from typing import List, Dict, Any

def generate_research_report(
    topic: str,
    findings: List[Dict[str, Any]],
    sources: List[str]
) -> str:
    """Generate a markdown research report."""
    report = []

    # Header
    report.append(f"# Research Report: {topic}")
    report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    report.append(f"**Sources Consulted:** {len(sources)}")
    report.append("")

    # Executive Summary
    report.append("## Executive Summary")
    report.append(f"\nThis report compiles {len(findings)} findings related to {topic}.")
    report.append("")

    # Findings
    report.append("## Key Findings")
    for i, finding in enumerate(findings, 1):
        report.append(f"\n### Finding {i}: {finding.get('title', 'Untitled')}")
        report.append(f"\n{finding.get('summary', '')}")

        if finding.get('details'):
            report.append(f"\n**Details:** {finding['details']}")

        if finding.get('source'):
            report.append(f"\n*Source: {finding['source']}*")

    # Sources
    report.append("\n## Sources")
    for i, source in enumerate(sources, 1):
        report.append(f"{i}. {source}")

    return '\n'.join(report)

# Usage
findings = [
    {
        'title': 'Critical RCE in Apache Struts',
        'summary': 'A remote code execution vulnerability allows attackers to execute arbitrary commands.',
        'details': 'CVE-2024-XXXX affects versions 2.0.0 through 2.5.30',
        'source': 'NVD'
    },
    {
        'title': 'Active Exploitation Reported',
        'summary': 'CISA has added this vulnerability to KEV catalog.',
        'source': 'CISA Alerts'
    }
]
sources = [
    'https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX',
    'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
]

report = generate_research_report('Apache Struts Vulnerability', findings, sources)
print(report)
```

### Caching and Rate Limiting

Implement responsible data collection practices.

**Example**:
```python
import requests
import time
import hashlib
import json
from pathlib import Path
from functools import wraps
from typing import Callable, Any

class ResearchCache:
    """Simple file-based cache for research data."""

    def __init__(self, cache_dir: str = '.research_cache', ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600

    def _get_cache_key(self, url: str) -> str:
        return hashlib.md5(url.encode()).hexdigest()

    def get(self, url: str) -> Any:
        cache_file = self.cache_dir / f"{self._get_cache_key(url)}.json"
        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            if time.time() - data['timestamp'] < self.ttl_seconds:
                return data['content']
        return None

    def set(self, url: str, content: Any):
        cache_file = self.cache_dir / f"{self._get_cache_key(url)}.json"
        cache_file.write_text(json.dumps({
            'timestamp': time.time(),
            'url': url,
            'content': content
        }))

class RateLimiter:
    """Simple rate limiter."""

    def __init__(self, requests_per_minute: int = 30):
        self.min_interval = 60.0 / requests_per_minute
        self.last_request = 0

    def wait(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()

# Usage
cache = ResearchCache()
rate_limiter = RateLimiter(requests_per_minute=10)

def fetch_with_cache(url: str) -> str:
    """Fetch URL with caching and rate limiting."""
    cached = cache.get(url)
    if cached:
        return cached

    rate_limiter.wait()
    response = requests.get(url, timeout=30)
    content = response.text

    cache.set(url, content)
    return content
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `RESEARCH_CACHE_DIR` | Cache directory | No | `.research_cache` |
| `RESEARCH_CACHE_TTL` | Cache TTL in hours | No | `24` |
| `RESEARCH_RATE_LIMIT` | Requests per minute | No | `30` |
| `NVD_API_KEY` | NVD API key for higher rate limits | No | None |

### Script Options

| Option | Type | Description |
|--------|------|-------------|
| `--query` | string | Search query |
| `--source` | string | Data source to query |
| `--output` | path | Output file path |
| `--format` | string | Output format (json, markdown, csv) |

## Examples

### Example 1: Vulnerability Research Report

**Scenario**: Generate a report on recent critical vulnerabilities.

```python
import requests
from datetime import datetime

def research_critical_vulns(keyword: str, days: int = 30) -> dict:
    """Research critical vulnerabilities for a technology."""
    results = {
        'keyword': keyword,
        'date_range': f'Last {days} days',
        'cves': [],
        'sources': []
    }

    # Query NVD
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': keyword,
        'cvssV3Severity': 'CRITICAL'
    }

    try:
        response = requests.get(nvd_url, params=params, timeout=60)
        data = response.json()

        for item in data.get('vulnerabilities', [])[:10]:
            cve = item['cve']
            results['cves'].append({
                'id': cve['id'],
                'description': cve['descriptions'][0]['value'][:300],
                'published': cve['published']
            })

        results['sources'].append(nvd_url)
    except Exception as e:
        results['errors'] = [str(e)]

    return results

# Usage
research = research_critical_vulns('Microsoft Exchange')
print(f"Found {len(research['cves'])} critical CVEs")
```

### Example 2: Threat Actor Research

**Scenario**: Compile information about a threat actor.

```python
def research_threat_actor(actor_name: str) -> dict:
    """Compile threat actor intelligence."""
    report = {
        'name': actor_name,
        'aliases': [],
        'techniques': [],
        'campaigns': [],
        'sources': []
    }

    # This would query MITRE ATT&CK groups data
    # Simplified example
    attack_url = f"https://attack.mitre.org/groups/"

    # In practice, you'd parse the ATT&CK data
    # and extract relevant information

    return report
```

## Limitations

- **Rate Limits**: External APIs have rate limits that must be respected
- **Data Freshness**: Cached data may be stale
- **Access Restrictions**: Some sources require authentication or subscriptions
- **Content Parsing**: Dynamic/JavaScript-rendered pages may not extract properly
- **Legal Compliance**: Ensure compliance with robots.txt and terms of service

## Troubleshooting

### Request Blocked

**Problem**: Requests returning 403 or blocked status

**Solution**: Use proper headers and respect rate limits:
```python
headers = {
    'User-Agent': 'YourBot/1.0 (contact@example.com)',
    'Accept': 'text/html,application/json'
}
```

### Incomplete Content

**Problem**: Missing content from dynamic pages

**Solution**: For JavaScript-rendered content, consider using selenium or playwright.

### API Rate Limit Exceeded

**Problem**: Getting 429 Too Many Requests

**Solution**: Implement exponential backoff:
```python
import time

for attempt in range(5):
    response = requests.get(url)
    if response.status_code != 429:
        break
    time.sleep(2 ** attempt)
```

## Related Skills

- [threat-intelligence](../../cybersecurity/threat-intelligence/): CTI-specific research
- [docx](../docx/): Generate reports from research findings
- [xlsx](../xlsx/): Export research data to spreadsheets

## References

- [Detailed API Reference](references/REFERENCE.md)
- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [BeautifulSoup Documentation](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
