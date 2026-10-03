#!/usr/bin/env python3
"""Read-only skill inventory and narrow structural diagnostics; no code execution/network."""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import unquote


def inspect(roots):
    entries, issues, names = [], [], {}
    for root in roots:
        root = root.expanduser().absolute()
        if not root.is_dir():
            issues.append({'kind': 'missing-root', 'path': str(root)})
            continue
        for skill in sorted(root.iterdir()):
            if not skill.is_dir() or skill.name.startswith('.'):
                continue
            entry = skill / 'SKILL.md'
            if skill.is_symlink() or entry.is_symlink():
                issues.append({'kind': 'symlink-not-followed', 'path': str(skill)})
                continue
            if not entry.is_file():
                issues.append({'kind': 'missing-entrypoint', 'path': str(skill)})
                continue
            text = entry.read_text(encoding='utf-8', errors='replace')
            front = re.match(r'\A---\r?\n(.*?)\r?\n---(?:\r?\n|$)', text, re.S)
            header = front.group(1) if front else ''
            fields = {}
            for key in ('name', 'description'):
                match = re.search(r'^' + key + r':\s*(\S.*)$', header, re.M)
                if match:
                    fields[key] = match.group(1).strip().strip('\"\'')
                else:
                    issues.append({'kind': 'missing-frontmatter-' + key, 'path': str(entry)})
            name = fields.get('name', skill.name)
            names.setdefault(name, []).append(str(entry))
            entries.append({'name': name, 'path': str(entry)})
            if name != skill.name:
                issues.append({'kind': 'name-directory-mismatch', 'path': str(entry)})
            # Only inspect this entrypoint's explicit Markdown links. References can
            # contain example paths or code; the semantic reviewer checks those.
            for target in re.findall(r'(?<!!)\[[^\]\n]*\]\(([^\s)]+)\)', text):
                target = target.strip('<>')
                if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target) or target.startswith('#'):
                    continue
                raw = unquote(target.split('#', 1)[0])
                if not raw or any(x in raw for x in ('{', '}', '<', '>')):
                    continue
                path = Path(raw) if raw.startswith('/') else entry.parent / raw
                if not path.exists():
                    issues.append({'kind': 'missing-entrypoint-link', 'path': str(entry), 'target': raw})
            if re.search(r'(?:/Users/[^/\s]+/|/home/[^/\s]+/)', text):
                issues.append({'kind': 'owner-path-candidate', 'path': str(entry)})
    for name, paths in names.items():
        if len(paths) > 1:
            issues.append({'kind': 'duplicate-name', 'name': name, 'paths': paths})
    return {'scope': 'entrypoint structure only; not YAML validation, security or behavior proof',
            'skills': entries, 'issues': issues}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, action='append', required=True)
    args = parser.parse_args()
    result = inspect(args.root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result['issues'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
