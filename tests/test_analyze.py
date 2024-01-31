import json

import pytest

from gcp_iam_explain.analyze import Options, PolicyError, check_policy, load_policies
from gcp_iam_explain.roles import describe_role, is_admin_like


def policy(bindings, **extra):
    return load_policies(json.dumps({"bindings": bindings, "etag": "BwX=", **extra}), "t")[0]


def codes(findings):
    return sorted({f.code for f in findings})


def test_load_single_policy_metadata():
    p = policy([{"role": "roles/viewer", "members": ["user:a@example.com"]}], version=3)
    assert p.version == 3 and p.etag == "BwX=" and len(p.bindings) == 1


def test_load_policy_without_bindings():
    p = load_policies('{"etag": "ACAB"}', "empty")[0]
    assert p.bindings == []
    assert check_policy(p) == []


def test_load_search_all_iam_policies_list():
    data = [{"resource": "//cloudresourcemanager.googleapis.com/projects/acme-prod-1234",
             "policy": {"bindings": [{"role": "roles/owner", "members": ["user:a@example.com"]}]}}]
    pols = load_policies(json.dumps(data), "f")
    assert pols[0].source.endswith("projects/acme-prod-1234")


@pytest.mark.parametrize("text", ["not json", "[1, 2]", '{"foo": 1}',
                                  '{"bindings": [{"members": []}]}', '{"bindings": {}}'])
def test_load_errors(text):
    with pytest.raises(PolicyError):
        load_policies(text, "bad")


def test_public_member_severity_depends_on_role():
    f = check_policy(policy([{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]))
    assert [(x.code, x.severity) for x in f] == [("PUBLIC_MEMBER", "high")]
    f = check_policy(policy([{"role": "roles/storage.admin", "members": ["allAuthenticatedUsers"]}]))
    assert f[0].severity == "critical"


def test_basic_roles():
    f = check_policy(policy([
        {"role": "roles/owner", "members": ["user:a@example.com"]},
        {"role": "roles/viewer", "members": ["user:b@example.com"]},
    ]))
    sev = {(x.role, x.severity) for x in f if x.code == "BASIC_ROLE"}
    assert sev == {("roles/owner", "high"), ("roles/viewer", "medium")}


def test_external_domains_only_when_configured():
    b = [{"role": "roles/storage.objectViewer",
          "members": ["user:x@gmail.com", "user:y@eu.example.com", "domain:partner.example.org",
                      "serviceAccount:1-compute@developer.gserviceaccount.com"]}]
    assert check_policy(policy(b)) == []
    f = check_policy(policy(b), Options(allowed_domains={"example.com"}))
    assert sorted(x.member for x in f) == ["domain:partner.example.org", "user:x@gmail.com"]
    assert all(x.severity == "medium" for x in f)


def test_external_member_on_admin_role_is_high():
    f = check_policy(policy([{"role": "roles/compute.admin", "members": ["user:x@gmail.com"]}]),
                     Options(allowed_domains={"example.com"}))
    assert [(x.code, x.severity) for x in f] == [("EXTERNAL_MEMBER", "high")]


def test_impersonation_iam_admin_deleted_convenience():
    f = check_policy(policy([
        {"role": "roles/iam.serviceAccountTokenCreator", "members": ["group:g@example.com"]},
        {"role": "roles/resourcemanager.projectIamAdmin", "members": ["user:a@example.com"]},
        {"role": "roles/run.invoker", "members": ["deleted:user:z@example.com?uid=9"]},
        {"role": "roles/storage.legacyBucketReader", "members": ["projectViewer:acme-prod-1234"]},
    ]))
    assert codes(f) == ["CONVENIENCE_VALUE", "DELETED_MEMBER", "IAM_ADMIN", "IMPERSONATION"]


def test_admin_sprawl_counts_live_members_only():
    members = [f"user:u{i}@example.com" for i in range(3)] + ["deleted:user:old@example.com?uid=1"]
    f = check_policy(policy([{"role": "roles/compute.admin", "members": members}]))
    assert "ADMIN_SPRAWL" not in codes(f)
    f = check_policy(policy([{"role": "roles/compute.admin", "members": members}]), Options(max_admins=2))
    assert "ADMIN_SPRAWL" in codes(f)


def test_condition_carried_on_findings_and_ignore():
    b = [{"role": "roles/owner", "members": ["user:a@example.com"],
          "condition": {"title": "temp", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}]
    f = check_policy(policy(b))
    assert f[0].condition == "temp"
    assert check_policy(policy(b), Options(ignore={"BASIC_ROLE"})) == []


def test_role_helpers():
    assert is_admin_like("roles/compute.instanceAdmin.v1")
    assert is_admin_like("roles/owner")
    assert not is_admin_like("roles/viewer")
    assert not is_admin_like("projects/acme/roles/myAdmin")
    assert describe_role("projects/acme/roles/deployer").startswith("custom role")
    assert describe_role("roles/made.up") == "predefined role (not in the bundled table)"
