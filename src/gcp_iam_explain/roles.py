"""A small table of well-known predefined roles and helpers to classify roles.

Only roles whose meaning is well established are listed. Anything else is
shown by name only; custom roles are labelled as such.
"""

from __future__ import annotations

KNOWN_ROLES: dict[str, str] = {
    "roles/owner": "Owner (basic role): full control of most resources, including managing IAM and billing for the resource",
    "roles/editor": "Editor (basic role): create, change and delete most resources, but not manage IAM",
    "roles/viewer": "Viewer (basic role): read-only access to most resources",
    "roles/browser": "Browser: see the resource hierarchy (projects, folders); no access to resources inside",
    "roles/resourcemanager.projectIamAdmin": "Project IAM Admin: change the IAM policy of the project",
    "roles/resourcemanager.folderAdmin": "Folder Admin: full control of folders, including their IAM policies",
    "roles/resourcemanager.folderIamAdmin": "Folder IAM Admin: change the IAM policy of folders",
    "roles/resourcemanager.organizationAdmin": "Organization Administrator: manage IAM policies for the organization, folders and projects",
    "roles/iam.securityAdmin": "Security Admin: get and set any IAM policy",
    "roles/iam.securityReviewer": "Security Reviewer: list all resources and their IAM policies",
    "roles/iam.roleAdmin": "Role Administrator: create and manage custom roles",
    "roles/iam.serviceAccountAdmin": "Service Account Admin: create and manage service accounts",
    "roles/iam.serviceAccountUser": "Service Account User: run operations as (attach) service accounts",
    "roles/iam.serviceAccountTokenCreator": "Service Account Token Creator: impersonate service accounts (mint access/ID tokens, sign blobs and JWTs)",
    "roles/iam.serviceAccountKeyAdmin": "Service Account Key Admin: create and manage service account keys",
    "roles/iam.workloadIdentityUser": "Workload Identity User: impersonate service accounts from federated or GKE workloads",
    "roles/storage.admin": "Storage Admin: full control of buckets and objects",
    "roles/storage.objectAdmin": "Storage Object Admin: full control of objects",
    "roles/storage.objectViewer": "Storage Object Viewer: read and list objects",
    "roles/storage.objectCreator": "Storage Object Creator: create objects (no read, overwrite or delete)",
    "roles/storage.objectUser": "Storage Object User: read, create, change and delete objects",
    "roles/compute.admin": "Compute Admin: full control of Compute Engine resources",
    "roles/compute.instanceAdmin.v1": "Compute Instance Admin (v1): full control of VM instances",
    "roles/compute.networkAdmin": "Compute Network Admin: manage networking resources (not firewall rules or SSL certificates)",
    "roles/compute.securityAdmin": "Compute Security Admin: manage firewall rules and SSL certificates",
    "roles/compute.viewer": "Compute Viewer: read-only access to Compute Engine resources",
    "roles/container.admin": "Kubernetes Engine Admin: full control of GKE clusters and their Kubernetes API objects",
    "roles/container.developer": "Kubernetes Engine Developer: access Kubernetes API objects inside clusters",
    "roles/container.viewer": "Kubernetes Engine Viewer: read-only access to GKE resources",
    "roles/bigquery.admin": "BigQuery Admin: manage all BigQuery resources and data",
    "roles/bigquery.dataEditor": "BigQuery Data Editor: read and change table data and metadata",
    "roles/bigquery.dataViewer": "BigQuery Data Viewer: read table data and metadata",
    "roles/bigquery.jobUser": "BigQuery Job User: run jobs, including queries",
    "roles/secretmanager.admin": "Secret Manager Admin: full control of secrets",
    "roles/secretmanager.secretAccessor": "Secret Manager Secret Accessor: read secret payloads",
    "roles/cloudsql.client": "Cloud SQL Client: connect to Cloud SQL instances",
    "roles/cloudsql.admin": "Cloud SQL Admin: full control of Cloud SQL resources",
    "roles/run.invoker": "Cloud Run Invoker: invoke Cloud Run services",
    "roles/run.admin": "Cloud Run Admin: full control of Cloud Run resources",
    "roles/pubsub.publisher": "Pub/Sub Publisher: publish messages to topics",
    "roles/pubsub.subscriber": "Pub/Sub Subscriber: consume messages from subscriptions",
    "roles/logging.viewer": "Logs Viewer: read logs (except Data Access audit logs)",
    "roles/logging.admin": "Logging Admin: full control of Cloud Logging",
    "roles/monitoring.viewer": "Monitoring Viewer: read-only access to Cloud Monitoring",
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": "Cloud KMS CryptoKey Encrypter/Decrypter: encrypt and decrypt with keys",
    "roles/billing.admin": "Billing Account Administrator: manage billing accounts",
}

BASIC_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}

# Roles that let the holder act as service accounts. Granted at project level they
# apply to every service account in the project.
IMPERSONATION_ROLES = {
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.workloadIdentityUser",
}

# Roles that can change who has access (set IAM policies).
IAM_ADMIN_ROLES = {
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.folderAdmin",
    "roles/resourcemanager.folderIamAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/iam.securityAdmin",
}


def is_custom(role: str) -> bool:
    return role.startswith(("projects/", "organizations/"))


def is_admin_like(role: str) -> bool:
    """Owner/editor, or a predefined role whose id has an '...admin' segment."""
    if role in ("roles/owner", "roles/editor") or role in IAM_ADMIN_ROLES:
        return True
    if not role.startswith("roles/"):
        return False
    return any(seg.lower().endswith("admin") for seg in role[len("roles/"):].split("."))


def describe_role(role: str) -> str:
    if role in KNOWN_ROLES:
        return KNOWN_ROLES[role]
    if is_custom(role):
        return "custom role (permissions not shown; check with gcloud iam roles describe)"
    return "predefined role (not in the bundled table)"
