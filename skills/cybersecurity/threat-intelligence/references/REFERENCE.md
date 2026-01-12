# Threat Intelligence Skill Reference

## API Reference

### IOCExtractor Class

```python
class IOCExtractor:
    def extract_from_text(self, text: str) -> Dict[str, List[str]]
    def defang(self, ioc: str) -> str
    def refang(self, text: str) -> str
    def validate_ioc(self, ioc_type: str, value: str) -> bool
```

### IOCCollection Class

```python
class IOCCollection:
    def __init__(self, name: str)
    def add_ioc(self, ioc_type: str, value: str, context: str = '', confidence: str = 'medium', source: str = '')
    def deduplicate(self)
    def to_csv(self) -> str
    def to_json(self) -> str
    def to_stix(self) -> str
```

### ThreatActor Class

```python
class ThreatActor:
    def __init__(self, name: str, aliases: List[str] = None)
    def set_motivation(self, motivation: str)
    def set_sophistication(self, level: str)
    def set_origin(self, origin: str)
    def add_ttp(self, technique_id: str, description: str)
    def add_target_sector(self, sector: str)
    def add_target_region(self, region: str)
    def add_tool(self, tool: str)
    def add_infrastructure(self, infra_type: str, value: str, context: str = '')
    def generate_profile(self) -> str
```

### Campaign Class

```python
class Campaign:
    def __init__(self, name: str, first_seen: str, threat_actor: str = '')
    def set_description(self, description: str)
    def set_objective(self, objective: str)
    def add_ioc(self, ioc_type: str, value: str, context: str = '')
    def add_ttp(self, technique_id: str, description: str)
    def add_target(self, sector: str, region: str)
    def add_event(self, date: str, description: str)
    def generate_report(self) -> str
```

### ATTACKMapper Class

```python
class ATTACKMapper:
    def add_technique(self, technique_id: str, context: str = '')
    def generate_matrix(self) -> str
    def get_technique_info(self, technique_id: str) -> dict
    def export_navigator(self, filepath: str)
```

### IntelReport Class

```python
class IntelReport:
    def __init__(self, title: str, classification: str = 'TLP:GREEN')
    def set_summary(self, summary: str)
    def add_finding(self, finding: str)
    def add_ioc(self, ioc_type: str, value: str, context: str = '')
    def add_ttp(self, technique_id: str, description: str)
    def add_recommendation(self, recommendation: str)
    def generate(self) -> str
    def generate_executive_brief(self) -> str
```

## Valid Values

### IOC Types
- `ip` - IPv4/IPv6 addresses
- `domain` - Domain names
- `url` - Full URLs
- `hash` - MD5, SHA1, SHA256
- `email` - Email addresses
- `cve` - CVE identifiers

### Confidence Levels
- `high`
- `medium`
- `low`

### TLP Classifications
- `TLP:RED`
- `TLP:AMBER`
- `TLP:GREEN`
- `TLP:CLEAR`

### Motivations
- `espionage`
- `financial`
- `hacktivism`
- `destruction`

### Sophistication Levels
- `novice`
- `intermediate`
- `advanced`
- `expert`

## Changelog

### [1.0.0] - 2024-01-01
- Initial release
- IOC extraction and management
- Threat actor profiling
- Campaign tracking
- MITRE ATT&CK mapping
- Intelligence report generation
