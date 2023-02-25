"""Parse IAM principal identifiers (the strings in a binding's ``members`` list)."""

from __future__ import annotations

import re
from dataclasses import dataclass

GKE_KSA = re.compile(r"^(?P<project>[^.\[]+)\.svc\.id\.goog\[(?P<ns>[^/\]]+)/(?P<ksa>[^\]]+)\]$")
WORKFORCE = re.compile(r"^//iam\.googleapis\.com/locations/global/workforcePools/(?P<pool>[^/]+)/(?P<rest>.*)$")
WORKLOAD = re.compile(
    r"^//iam\.googleapis\.com/projects/(?P<proj>[^/]+)/locations/global/"
    r"workloadIdentityPools/(?P<pool>[^/]+)/(?P<rest>.*)$"
)

CONVENIENCE = {"projectOwner", "projectEditor", "projectViewer"}


@dataclass(frozen=True)
class Principal:
    raw: str
    kind: str  # allUsers, allAuthenticatedUsers, user, group, serviceAccount, domain,
    # principal, principalSet, projectOwner, projectEditor, projectViewer, unknown
    ident: str
    deleted: bool = False
    uid: str | None = None

    @property
    def is_public(self) -> bool:
        return self.kind in ("allUsers", "allAuthenticatedUsers")

    @property
    def domain(self) -> str | None:
        """Email/organization domain this principal belongs to, if it has one."""
        if self.kind == "domain":
            return self.ident.lower()
        if self.kind in ("user", "group", "serviceAccount") and "@" in self.ident:
            return self.ident.rsplit("@", 1)[1].lower()
        return None

    @property
    def is_google_service_account(self) -> bool:
        d = self.domain or ""
        return self.kind == "serviceAccount" and (d == "gserviceaccount.com" or d.endswith(".gserviceaccount.com"))

    def describe(self) -> str:
        prefix = "deleted " if self.deleted else ""
        suffix = f" (uid {self.uid})" if self.uid else ""
        if self.kind == "allUsers":
            return "anyone on the internet, signed in or not (allUsers)"
        if self.kind == "allAuthenticatedUsers":
            return "anyone signed in with a Google account (allAuthenticatedUsers)"
        if self.kind == "user":
            return f"{prefix}user {self.ident}{suffix}"
        if self.kind == "group":
            return f"{prefix}Google group {self.ident}{suffix}"
        if self.kind == "serviceAccount":
            m = GKE_KSA.match(self.ident)
            if m:
                return (f"Kubernetes service account {m['ns']}/{m['ksa']} "
                        f"via workload identity pool {m['project']}.svc.id.goog")
            return f"{prefix}service account {self.ident}{suffix}"
        if self.kind == "domain":
            return f"every account in the Google Workspace / Cloud Identity domain {self.ident}"
        if self.kind in CONVENIENCE:
            role = self.kind[len("project"):].lower()
            return f"every principal with the basic {role} role on project {self.ident}"
        if self.kind in ("principal", "principalSet"):
            return prefix + _describe_federated(self.kind, self.ident)
        return f"unrecognized principal {self.raw}"


def _describe_federated(kind: str, ident: str) -> str:
    m = WORKFORCE.match(ident)
    source = None
    if m:
        source, rest = f"workforce pool '{m['pool']}'", m["rest"]
    else:
        m = WORKLOAD.match(ident)
        if m:
            source, rest = f"workload identity pool '{m['pool']}' (project {m['proj']})", m["rest"]
    if source is None:
        return f"{kind}://{ident.lstrip('/')}"
    if kind == "principal" and rest.startswith("subject/"):
        return f"identity with subject '{rest[len('subject/'):]}' in {source}"
    if rest == "*":
        return f"all identities in {source}"
    if rest.startswith("group/"):
        return f"identities in group '{rest[len('group/'):]}' of {source}"
    if rest.startswith("attribute."):
        name, _, value = rest[len("attribute."):].partition("/")
        return f"identities with attribute {name}='{value}' in {source}"
    return f"{kind} {rest} in {source}"


def parse_member(raw: str) -> Principal:
    s = raw.strip()
    if s in ("allUsers", "allAuthenticatedUsers"):
        return Principal(raw, s, s)
    deleted = False
    if s.startswith("deleted:"):
        deleted, s = True, s[len("deleted:"):]
    uid = None
    if "?uid=" in s:
        s, uid = s.split("?uid=", 1)
    for kind in ("principalSet", "principal"):
        if s.startswith(kind + "://"):
            return Principal(raw, kind, s[len(kind) + 1:], deleted, uid)
    kind, sep, ident = s.partition(":")
    if not sep:
        return Principal(raw, "unknown", s, deleted, uid)
    if kind in ("user", "group", "serviceAccount", "domain") or kind in CONVENIENCE:
        return Principal(raw, kind, ident, deleted, uid)
    return Principal(raw, "unknown", s, deleted, uid)
