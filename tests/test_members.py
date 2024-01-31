from gcp_iam_explain.members import parse_member


def test_public_members():
    p = parse_member("allUsers")
    assert p.kind == "allUsers" and p.is_public
    assert "internet" in p.describe()
    assert parse_member("allAuthenticatedUsers").is_public


def test_user_group_domain():
    u = parse_member("user:alice@Example.com")
    assert u.kind == "user" and u.domain == "example.com"
    assert parse_member("group:ops@example.com").describe() == "Google group ops@example.com"
    d = parse_member("domain:example.com")
    assert d.domain == "example.com" and "domain example.com" in d.describe()


def test_deleted_member_with_uid():
    p = parse_member("deleted:serviceAccount:old@acme-prod-1234.iam.gserviceaccount.com?uid=42")
    assert p.deleted and p.kind == "serviceAccount" and p.uid == "42"
    assert p.ident == "old@acme-prod-1234.iam.gserviceaccount.com"
    assert p.describe().startswith("deleted service account")


def test_google_service_accounts():
    assert parse_member("serviceAccount:1-compute@developer.gserviceaccount.com").is_google_service_account
    assert parse_member("serviceAccount:x@acme-prod-1234.iam.gserviceaccount.com").is_google_service_account
    assert not parse_member("user:x@gserviceaccount.com.evil.example").is_google_service_account


def test_gke_workload_identity_member():
    p = parse_member("serviceAccount:acme-prod-1234.svc.id.goog[payments/api]")
    assert "Kubernetes service account payments/api" in p.describe()
    assert p.domain is None


def test_federated_principals():
    p = parse_member("principal://iam.googleapis.com/locations/global/workforcePools/corp/subject/jdoe")
    assert p.kind == "principal"
    assert p.describe() == "identity with subject 'jdoe' in workforce pool 'corp'"
    s = parse_member("principalSet://iam.googleapis.com/projects/123/locations/global/"
                     "workloadIdentityPools/github/attribute.repository/org/repo")
    assert s.kind == "principalSet"
    assert "attribute repository='org/repo'" in s.describe()
    assert "all identities" in parse_member(
        "principalSet://iam.googleapis.com/locations/global/workforcePools/corp/*").describe()
    g = parse_member("principalSet://iam.googleapis.com/locations/global/workforcePools/corp/group/eng")
    assert "group 'eng'" in g.describe()


def test_convenience_and_unknown():
    p = parse_member("projectViewer:acme-prod-1234")
    assert p.kind == "projectViewer"
    assert "basic viewer role on project acme-prod-1234" in p.describe()
    assert parse_member("weird").kind == "unknown"
    assert parse_member("foo:bar").kind == "unknown"
