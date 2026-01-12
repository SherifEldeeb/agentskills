# Markdown Syntax Guide

Reference for markdown syntax supported by the DOCX converter.

## Basic Syntax

### Headings

```markdown
# Heading 1
## Heading 2
### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6
```

### Paragraphs

Separate paragraphs with a blank line:

```markdown
This is the first paragraph.

This is the second paragraph.
```

### Emphasis

```markdown
*italic* or _italic_
**bold** or __bold__
***bold and italic***
```

### Inline Code

```markdown
Use the `print()` function.
```

## Lists

### Unordered Lists

```markdown
- Item 1
- Item 2
  - Nested item
- Item 3

* Alternative marker
+ Another alternative
```

### Ordered Lists

```markdown
1. First item
2. Second item
3. Third item
```

## Code Blocks

### Fenced Code Blocks

````markdown
```python
def hello():
    print("Hello, World!")
```
````

### Language Support

Supported language identifiers:
- `python`, `py`
- `javascript`, `js`
- `bash`, `shell`
- `sql`
- `json`
- `yaml`
- `xml`
- `html`
- `css`
- `java`
- `csharp`, `cs`
- `go`
- `rust`

## Tables

```markdown
| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
| Cell 1   | Cell 2   | Cell 3   |
| Cell 4   | Cell 5   | Cell 6   |
```

### Column Alignment

```markdown
| Left     | Center   | Right    |
|:---------|:--------:|---------:|
| Left     | Center   | Right    |
```

## Blockquotes

```markdown
> This is a blockquote.
> It can span multiple lines.
>
> And have multiple paragraphs.
```

### Nested Blockquotes

```markdown
> Outer quote
>> Nested quote
>>> Deeply nested
```

## Horizontal Rules

```markdown
---

***

___
```

## Links

```markdown
[Link text](https://example.com)
[Link with title](https://example.com "Title")
```

**Note**: Links are converted to plain text in DOCX output.

## Images

```markdown
![Alt text](image.png)
![Alt text](image.png "Optional title")
```

**Note**: Images are currently not embedded during conversion. Use the python-docx API directly for images.

## Extended Syntax

### Task Lists

```markdown
- [x] Completed task
- [ ] Incomplete task
```

**Note**: Converted to regular bullet lists with markers.

### Strikethrough

```markdown
~~Strikethrough text~~
```

**Note**: Limited support in DOCX conversion.

## Security Report Examples

### Finding Template

```markdown
### Finding: SQL Injection in Login Form

**Severity**: Critical
**CVSS Score**: 9.8
**Status**: Open

#### Description

The login form is vulnerable to SQL injection attacks through the username parameter.

#### Evidence

```sql
username: ' OR '1'='1' --
password: anything
```

#### Impact

- Authentication bypass
- Data exfiltration
- Potential remote code execution

#### Remediation

1. Use parameterized queries
2. Implement input validation
3. Apply principle of least privilege

#### References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- CWE-89: SQL Injection
```

### Executive Summary Template

```markdown
# Executive Summary

## Assessment Overview

| Attribute | Value |
|-----------|-------|
| Client | {{CLIENT_NAME}} |
| Date Range | {{START_DATE}} - {{END_DATE}} |
| Scope | {{SCOPE}} |
| Methodology | {{METHODOLOGY}} |

## Key Findings

A total of **{{TOTAL_FINDINGS}}** vulnerabilities were identified:

| Severity | Count |
|----------|-------|
| Critical | {{CRITICAL_COUNT}} |
| High | {{HIGH_COUNT}} |
| Medium | {{MEDIUM_COUNT}} |
| Low | {{LOW_COUNT}} |

## Risk Summary

> The overall security posture is considered **{{RISK_LEVEL}}** based on the findings.

## Recommendations

1. **Immediate** - Address critical findings within 24-48 hours
2. **Short-term** - Remediate high severity findings within 1-2 weeks
3. **Medium-term** - Address medium findings within 30 days
```

## Best Practices

### For Security Reports

1. **Use consistent heading levels**
   - H1: Report title
   - H2: Major sections (Executive Summary, Findings, Appendix)
   - H3: Individual findings or subsections
   - H4: Finding details (Description, Impact, Remediation)

2. **Use tables for structured data**
   - Finding summaries
   - Risk matrices
   - Timeline of events

3. **Use code blocks for technical details**
   - Proof of concept code
   - Log excerpts
   - Configuration examples

4. **Use blockquotes for key callouts**
   - Critical warnings
   - Important notes
   - Recommendations

### For Readability

1. Keep paragraphs short (3-4 sentences)
2. Use bullet points for lists of 3+ items
3. Include visual breaks between sections
4. Be consistent with formatting throughout
