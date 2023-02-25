"""Load IAM allow policies and run the risk checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from .members import Principal, parse_member
from .roles import (
    BASIC_ROLES,
    IAM_ADMIN_ROLES,
    IMPERSONATION_ROLES,
    describe_role,
    is_admin_like,
)

SEVERITIES = ["low", "medium", "high", "critical"]


class PolicyError(ValueError):
    pass


@dataclass
class Binding:
    role: str
    members: list[Principal]
    condition: dict[str, Any] | None = None

    @property
    def condition_label(self) -> str | None:
        if not self.condition:
            return None
        return self.condition.get("title") or self.condition.get("expression") or "untitled condition"


@dataclass
class Policy:
    source: str
    bindings: list[Binding]
    version: int | None = None
    etag: str | None = None
    audit_configs: list[dict] = field(default_factory=list)


@dataclass
class Finding:
    severity: str
    code: str
    role: str
    member: str | None
    message: str
    condition: str | None = None
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in
                ("severity", "code", "source", "role", "member", "condition", "message")}


def _policy_from_obj(obj: dict, source: str) -> Policy:
    if not isinstance(obj, dict):
        raise PolicyError(f"{source}: expected a JSON object with 'bindings'")
    raw_bindings = obj.get("bindings", [])
    if not isinstance(raw_bindings, list):
        raise PolicyError(f"{source}: 'bindings' must be a list")
    bindings = []
    for i, b in enumerate(raw_bindings):
        if not isinstance(b, dict) or "role" not in b:
            raise PolicyError(f"{source}: binding #{i} has no 'role'")
        members = b.get("members") or []
        bindings.append(Binding(b["role"], [parse_member(m) for m in members], b.get("condition")))
    return Policy(source, bindings, obj.get("version"), obj.get("etag"), obj.get("auditConfigs", []))


def load_policies(text: str, source: str) -> list[Policy]:
    """Accept a single policy object (get-iam-policy output) or a list of
    `gcloud asset search-all-iam-policies` results (objects with resource + policy)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{source}: not valid JSON ({exc}); use --format=json with gcloud") from exc
    if isinstance(data, dict) and "policy" in data and "bindings" not in data:
        data = [data]
    if isinstance(data, list):
        out = []
        for i, item in enumerate(data):
            if not isinstance(item, dict) or "policy" not in item:
                raise PolicyError(f"{source}: list item #{i} is not a search-all-iam-policies result")
            out.append(_policy_from_obj(item["policy"], item.get("resource") or f"{source}[{i}]"))
        return out
    if isinstance(data, dict) and ("bindings" in data or "etag" in data):
        return [_policy_from_obj(data, source)]
    raise PolicyError(f"{source}: no IAM policy found (expected 'bindings')")


@dataclass
class Options:
    allowed_domains: set[str] = field(default_factory=set)
    max_admins: int = 3
    ignore: set[str] = field(default_factory=set)


def _domain_allowed(domain: str, allowed: Iterable[str]) -> bool:
    return any(domain == a or domain.endswith("." + a) for a in allowed)


def check_policy(policy: Policy, opts: Options | None = None) -> list[Finding]:
    opts = opts or Options()
    findings: list[Finding] = []

    def add(sev, code, b, member, msg):
        if code not in opts.ignore:
            findings.append(Finding(sev, code, b.role, member, msg, b.condition_label, policy.source))

    for b in policy.bindings:
        admin = is_admin_like(b.role)
        for p in b.members:
            if p.is_public:
                sev = "critical" if (admin or b.role in BASIC_ROLES) else "high"
                who = "anyone on the internet" if p.kind == "allUsers" else "any Google account holder"
                add(sev, "PUBLIC_MEMBER", b, p.raw, f"{b.role} is granted to {who}")
            if p.deleted:
                add("low", "DELETED_MEMBER", b, p.raw,
                    "binding refers to a deleted principal; remove it")
            if p.kind in ("projectOwner", "projectEditor", "projectViewer"):
                add("low", "CONVENIENCE_VALUE", b, p.raw,
                    "convenience value grants access to everyone holding a basic role on the project")
            if opts.allowed_domains and p.domain and not p.is_google_service_account \
                    and not _domain_allowed(p.domain, opts.allowed_domains):
                sev = "high" if (admin or b.role in BASIC_ROLES) else "medium"
                add(sev, "EXTERNAL_MEMBER", b, p.raw,
                    f"{p.kind} from domain '{p.domain}' is outside the allowed domains")
            if b.role in ("roles/owner", "roles/editor"):
                add("high", "BASIC_ROLE", b, p.raw,
                    f"basic role {b.role} is very broad; prefer predefined or custom roles")
            elif b.role == "roles/viewer":
                add("medium", "BASIC_ROLE", b, p.raw,
                    "basic role roles/viewer reads almost everything; prefer narrower roles")
            if b.role in IMPERSONATION_ROLES:
                add("high", "IMPERSONATION", b, p.raw,
                    f"{b.role} lets this principal act as service accounts; on a project, "
                    "folder or organization it covers every service account below it")
            if b.role in IAM_ADMIN_ROLES:
                add("medium", "IAM_ADMIN", b, p.raw,
                    f"{b.role} can change IAM policies (grant itself or others more access)")
        live = [p for p in b.members if not p.deleted]
        if admin and len(live) > opts.max_admins:
            add("medium", "ADMIN_SPRAWL", b, None,
                f"admin-level role {b.role} is held by {len(live)} principals (more than {opts.max_admins})")
    return findings


def explain_binding(b: Binding) -> dict[str, Any]:
    return {
        "role": b.role,
        "role_description": describe_role(b.role),
        "condition": b.condition,
        "members": [{"member": p.raw, "kind": p.kind, "description": p.describe()} for p in b.members],
    }


def severity_at_least(sev: str, threshold: str) -> bool:
    return SEVERITIES.index(sev) >= SEVERITIES.index(threshold)
