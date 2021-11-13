# gcp-iam-explain

Explain a Google Cloud IAM policy in plain English and flag basic roles, public members, external domains and risky bindings.

## Planned scope

Offline on JSON from `gcloud projects/folders/organizations get-iam-policy --format=json` (and bucket policies). Per binding: who (user/group/serviceAccount/domain/allUsers/allAuthenticatedUsers/principal://), role, condition (shown, not evaluated). Flags: basic roles (owner/editor/viewer), allUsers/allAuthenticatedUsers, members outside --allowed-domains, service account user/token creator roles (impersonation), deleted: members, admin roles on many members. A small bundled table of well-known roles with descriptions (only ones you are sure of); unknown roles shown as-is. CI exit codes.
