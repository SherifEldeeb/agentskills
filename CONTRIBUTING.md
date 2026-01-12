# Contributing to Cybersecurity Agent Skills

Thank you for your interest in contributing! This document provides guidelines for contributing new skills or improving existing ones.

## Types of Contributions

### New Skills

We welcome new skills in these categories:

**Baseline Skills**
- Document processing (new formats)
- Data transformation utilities
- Research and gathering tools
- Visualization and reporting

**Cybersecurity Domain Skills**
- Security operations workflows
- Incident response procedures
- Threat intelligence processes
- Compliance and governance
- Vulnerability management

### Improvements to Existing Skills

- Bug fixes
- New capabilities
- Documentation improvements
- Performance optimizations
- Security enhancements

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/agentskills.git
cd agentskills
```

### 2. Create a Branch

```bash
git checkout -b feature/skill-name
# or
git checkout -b fix/issue-description
```

### 3. Use the Template

For new skills, start with the template:

```bash
cp -r templates/skill-template skills/baseline/my-new-skill
# or
cp -r templates/skill-template skills/cybersecurity/my-new-skill
```

## Skill Development Checklist

Before submitting your skill, ensure:

### Required

- [ ] `SKILL.md` exists with valid YAML frontmatter
- [ ] `name` field matches directory name
- [ ] `description` field is 1-1024 characters
- [ ] Description includes WHEN to use the skill
- [ ] Instructions are clear and actionable

### Recommended

- [ ] Examples included for each capability
- [ ] Edge cases documented
- [ ] Scripts have proper error handling
- [ ] Dependencies documented in requirements.txt
- [ ] No hardcoded paths or credentials

### Security

- [ ] Input validation implemented
- [ ] No arbitrary code execution
- [ ] File paths sanitized
- [ ] Sensitive data handling documented

## Naming Conventions

### Skill Names

- Use lowercase letters, numbers, and hyphens
- Be descriptive but concise
- Examples: `docx`, `incident-response`, `threat-intelligence`

### File Names

- Scripts: `snake_case.py` or `kebab-case.sh`
- References: `UPPERCASE.md` for main docs, `lowercase.md` for supplementary
- Assets: descriptive names, lowercase

## Commit Messages

Use clear, descriptive commit messages:

```
feat(docx): add markdown-to-docx conversion

- Implement markdown parsing with marked
- Apply template styles from reference DOCX
- Support heading levels 1-6
- Handle code blocks and tables
```

### Prefixes

- `feat`: New feature or capability
- `fix`: Bug fix
- `docs`: Documentation only
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

## Pull Request Process

### 1. Create PR

- Use a descriptive title
- Reference any related issues
- Complete the PR template

### 2. PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] New skill
- [ ] Enhancement to existing skill
- [ ] Bug fix
- [ ] Documentation

## Skill Category
- [ ] Baseline
- [ ] Cybersecurity

## Checklist
- [ ] SKILL.md is valid
- [ ] Scripts tested locally
- [ ] Documentation updated
- [ ] No breaking changes (or documented)

## Testing Done
Describe how you tested these changes.

## Screenshots (if applicable)
```

### 3. Review Process

1. Automated checks run on PR
2. Maintainer reviews code and documentation
3. Feedback addressed
4. Approval and merge

## Code Review Guidelines

### For Reviewers

- Verify SKILL.md frontmatter is valid
- Check that instructions are clear
- Test scripts if possible
- Ensure security best practices
- Provide constructive feedback

### For Contributors

- Respond to feedback promptly
- Ask for clarification if needed
- Update PR based on feedback
- Keep discussions focused

## Style Guide

### SKILL.md

```yaml
---
name: example-skill
description: |
  One clear sentence about what this does.
  Second sentence about when to use it.
license: Apache-2.0
metadata:
  author: your-name
  version: "1.0.0"
  category: baseline
---
```

### Python

```python
#!/usr/bin/env python3
"""Module docstring."""

from typing import Optional
from pathlib import Path


def function_name(param: str, optional: Optional[int] = None) -> str:
    """
    Brief description.

    Args:
        param: Description of param
        optional: Description of optional param

    Returns:
        Description of return value
    """
    pass
```

### Markdown Documentation

- Use ATX-style headers (`#`, `##`, etc.)
- One sentence per line for easier diffs
- Code blocks with language identifiers
- Tables for structured information

## Community Standards

### Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn
- Focus on the work, not the person

### Getting Help

- Open an issue for questions
- Tag with `question` label
- Search existing issues first

## Recognition

Contributors are recognized in:

- README acknowledgments
- Skill metadata (author field)
- Release notes

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

---

Thank you for contributing to Cybersecurity Agent Skills!
