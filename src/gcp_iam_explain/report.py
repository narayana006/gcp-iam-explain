"""Text and JSON rendering."""

from __future__ import annotations

import json
from collections import Counter

from .analyze import SEVERITIES, Finding, Policy, explain_binding


def render_text(policy: Policy, findings: list[Finding], explain: bool = True) -> str:
    lines = []
    meta = []
    if policy.version is not None:
        meta.append(f"version {policy.version}")
    if policy.etag:
        meta.append(f"etag {policy.etag}")
    head = f"Policy: {policy.source}"
    lines.append(head + (f"  ({', '.join(meta)})" if meta else ""))
    n_members = sum(len(b.members) for b in policy.bindings)
    lines.append(f"{len(policy.bindings)} binding(s), {n_members} member entr{'y' if n_members == 1 else 'ies'}")
    if policy.audit_configs:
        svcs = ", ".join(a.get("service", "?") for a in policy.audit_configs)
        lines.append(f"Audit logging configured for: {svcs}")
    for b in (policy.bindings if explain else []):
        e = explain_binding(b)
        lines.append("")
        lines.append(f"{b.role}")
        lines.append(f"  {e['role_description']}")
        if b.condition:
            title = b.condition.get("title", "untitled")
            lines.append(f"  Only when condition '{title}' is true (not evaluated here):")
            lines.append(f"    {b.condition.get('expression', '')}")
        if not b.members:
            lines.append("  (no members)")
        for m in e["members"]:
            lines.append(f"  - {m['description']}")
    lines.append("")
    if findings:
        lines.append(f"Findings ({len(findings)}):")
        for f in sorted(findings, key=lambda f: -SEVERITIES.index(f.severity)):
            who = f" {f.member}" if f.member else ""
            cond = f" [conditional: {f.condition}]" if f.condition else ""
            lines.append(f"  {f.severity.upper():8} {f.code:17} {f.role}{who}{cond}")
            lines.append(f"           {f.message}")
    else:
        lines.append("Findings: none")
    return "\n".join(lines)


def summary(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in reversed(SEVERITIES)}


def render_json(policies: list[Policy], findings: list[Finding]) -> str:
    out = {
        "policies": [
            {
                "source": p.source,
                "version": p.version,
                "etag": p.etag,
                "bindings": [explain_binding(b) for b in p.bindings],
            }
            for p in policies
        ],
        "findings": [f.to_dict() for f in findings],
        "summary": summary(findings),
    }
    return json.dumps(out, indent=2)
