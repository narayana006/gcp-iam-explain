# gcp-iam-explain

Explain a Google Cloud IAM allow policy in plain English and flag basic roles, public members, external domains and other risky bindings.

**Status:** v0.1. Works today, offline: per-binding explanation of who has which role (and under which condition), nine risk checks, text and JSON output, CI-friendly exit codes. It reads JSON you already exported; it never calls Google Cloud.

## Install

```bash
pip install git+https://github.com/narayana006/gcp-iam-explain
```

Python 3.10+; no runtime dependencies.

## Quick start

Export a policy with gcloud (JSON output is required), then explain it:

```bash
gcloud storage buckets get-iam-policy gs://acme-public-assets --format=json > bucket-policy.json
gcp-iam-explain bucket-policy.json
```

Running it on the bundled example (`examples/bucket-policy.json`, hand-written and illustrative):

```text
$ gcp-iam-explain examples/bucket-policy.json
Policy: examples/bucket-policy.json  (etag CAI=)
3 binding(s), 4 member entries

roles/storage.legacyBucketOwner
  predefined role (not in the bundled table)
  - every principal with the basic editor role on project acme-prod-1234
  - every principal with the basic owner role on project acme-prod-1234

roles/storage.legacyBucketReader
  predefined role (not in the bundled table)
  - every principal with the basic viewer role on project acme-prod-1234

roles/storage.objectViewer
  Storage Object Viewer: read and list objects
  - anyone on the internet, signed in or not (allUsers)

Findings (4):
  HIGH     PUBLIC_MEMBER     roles/storage.objectViewer allUsers
           roles/storage.objectViewer is granted to anyone on the internet
  LOW      CONVENIENCE_VALUE roles/storage.legacyBucketOwner projectEditor:acme-prod-1234
           convenience value grants access to everyone holding a basic role on the project
  LOW      CONVENIENCE_VALUE roles/storage.legacyBucketOwner projectOwner:acme-prod-1234
           convenience value grants access to everyone holding a basic role on the project
  LOW      CONVENIENCE_VALUE roles/storage.legacyBucketReader projectViewer:acme-prod-1234
           convenience value grants access to everyone holding a basic role on the project
$ echo $?
1
```

A larger project policy with a condition, a deleted member, workload identity principals and an outside contractor:

```text
$ gcp-iam-explain examples/project-policy.json --allowed-domains example.com --findings-only
Policy: examples/project-policy.json  (version 3, etag BwYKk4l2Uq0=)
10 binding(s), 16 member entries
Audit logging configured for: storage.googleapis.com

Findings (12):
  HIGH     BASIC_ROLE        roles/owner group:platform-admins@example.com
           basic role roles/owner is very broad; prefer predefined or custom roles
  ...
  HIGH     EXTERNAL_MEMBER   roles/storage.admin user:carol@partner-example.net [conditional: expires-2025-12-31]
           user from domain 'partner-example.net' is outside the allowed domains
  ...
  HIGH     PUBLIC_MEMBER     roles/run.invoker allAuthenticatedUsers
           roles/run.invoker is granted to any Google account holder
  MEDIUM   BASIC_ROLE        roles/viewer domain:example.com
           basic role roles/viewer reads almost everything; prefer narrower roles
  MEDIUM   ADMIN_SPRAWL      roles/compute.admin
           admin-level role roles/compute.admin is held by 4 principals (more than 3)
  LOW      DELETED_MEMBER    roles/run.admin deleted:user:dave@example.com?uid=123456789012345678901
           binding refers to a deleted principal; remove it
```

(Some lines elided with `...`; run the command to see all 12.)

## Input

Any of these, as files or on stdin (`-`, the default):

| Source | Command |
| --- | --- |
| Project | `gcloud projects get-iam-policy PROJECT_ID --format=json` |
| Folder | `gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json` |
| Organization | `gcloud organizations get-iam-policy ORG_ID --format=json` |
| Bucket | `gcloud storage buckets get-iam-policy gs://BUCKET --format=json` |
| Many resources | `gcloud asset search-all-iam-policies --scope=projects/PROJECT_ID --format=json` (a list of results; each result's `resource` becomes the policy name) |

The tool reads the allow policy fields `bindings[].role`, `bindings[].members`, `bindings[].condition` (`title`, `description`, `expression`), `version`, `etag` and `auditConfigs[].service`. YAML (the gcloud default output) is rejected with a hint to add `--format=json`.

Principals understood: `allUsers`, `allAuthenticatedUsers`, `user:`, `group:`, `serviceAccount:` (including GKE workload identity `PROJECT.svc.id.goog[NAMESPACE/KSA]`), `domain:`, `deleted:...?uid=...`, workforce and workload identity federation `principal://` / `principalSet://` identifiers, and the Cloud Storage convenience values `projectOwner:`, `projectEditor:`, `projectViewer:`.

## Checks

| Code | Severity | What it flags |
| --- | --- | --- |
| `PUBLIC_MEMBER` | critical if the role is basic or admin-level, else high | `allUsers` or `allAuthenticatedUsers` |
| `BASIC_ROLE` | high (owner, editor), medium (viewer) | each member of `roles/owner`, `roles/editor`, `roles/viewer` |
| `EXTERNAL_MEMBER` | high on basic/admin roles, else medium | user, group, service account or `domain:` member whose domain is not in `--allowed-domains` (only when that option is set; Google-managed `*.gserviceaccount.com` service accounts are skipped) |
| `IMPERSONATION` | high | `roles/iam.serviceAccountUser`, `roles/iam.serviceAccountTokenCreator`, `roles/iam.workloadIdentityUser` |
| `IAM_ADMIN` | medium | roles that can change IAM policies: Project IAM Admin, Folder Admin, Folder IAM Admin, Organization Administrator, Security Admin |
| `ADMIN_SPRAWL` | medium | an admin-level role (owner, editor, or a predefined role id with an `...Admin` segment) held by more than `--max-admins` live principals |
| `DELETED_MEMBER` | low | `deleted:` principals left in a binding |
| `CONVENIENCE_VALUE` | low | `projectOwner:` / `projectEditor:` / `projectViewer:` on a bucket |

Conditions are displayed but **not evaluated**: a finding on a conditional binding is tagged `[conditional: TITLE]` and keeps its severity.

## Usage

```text
gcp-iam-explain [FILE ...] [--format text|json] [--allowed-domains example.com,example.org]
                [--max-admins N] [--ignore CODE] [--fail-on low|medium|high|critical|never]
                [--findings-only]
```

- `--allowed-domains`: comma-separated; subdomains match (`eu.example.com` is allowed by `example.com`).
- `--ignore CODE`: drop a check, repeatable (`--ignore DELETED_MEMBER --ignore BASIC_ROLE`).
- `--format json`: one document with every policy's explained bindings, all findings and a severity summary.

Exit codes: `0` no finding at or above `--fail-on` (default `high`), `1` at least one such finding, `2` bad input (missing file, not JSON, no policy).

## Required permissions

The tool itself needs none. To export policies you need the matching read permission, for example `resourcemanager.projects.getIamPolicy`, `resourcemanager.folders.getIamPolicy`, `resourcemanager.organizations.getIamPolicy`, `storage.buckets.getIamPolicy`, or `cloudasset.assets.searchAllIamPolicies` for the Cloud Asset search (the Security Reviewer role, `roles/iam.securityReviewer`, covers the resource manager ones).

## Features

- [x] Plain-English explanation of every binding and principal type
- [x] Conditions shown (title and CEL expression), not evaluated
- [x] Basic roles, public members, external domains, impersonation roles, IAM admin roles, deleted members, admin sprawl, bucket convenience values
- [x] Bundled descriptions for 46 common predefined roles; unknown and custom roles shown as-is
- [x] Text and JSON output, `--fail-on` exit codes for CI
- [x] Reads `gcloud asset search-all-iam-policies` output for many resources at once
- [ ] Expand custom roles using `gcloud iam roles describe` output
- [ ] Policy diff between two exports (what an `etag` change granted or removed)
- [ ] Deny policies and principal access boundary policies

## Limitations

- Only the allow policy you give it is analysed. Inherited bindings from folders and the organization, deny policies, and IAM conditions are not combined or evaluated, so this is not an effective-access calculator.
- The role table is a small hand-picked subset with short descriptions; it does not list permissions. Custom roles are not expanded.
- Group membership is not resolved: `group:` and `domain:` members may contain many people.
- `ADMIN_SPRAWL` decides "admin-level" from the role id, so custom roles are never counted.
- The examples in `examples/` are hand-written and illustrative (fictional project `acme-prod-1234`, domain `example.com`), not captured from a real project.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Contributing

Issues and pull requests are welcome. Please include a test with any new check, and a sample policy (with fictional identifiers) if you are reporting a parsing problem.

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
