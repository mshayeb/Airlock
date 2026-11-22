#!/usr/bin/env bash
# Idempotent setup for keyless GitHub Actions -> Google Cloud Build via Workload Identity Federation.
# Conforms to spec.md Zero-Secret Policy (no static JSON service-account keys generated).

set -euo pipefail

: "${GCP_PROJECT_ID:?Set GCP_PROJECT_ID (e.g., export GCP_PROJECT_ID=my-airlock-ci)}"
: "${GITHUB_ORG:?Set GITHUB_ORG (e.g., export GITHUB_ORG=my-org)}"
: "${GITHUB_REPO:?Set GITHUB_REPO (e.g., export GITHUB_REPO=Airlock)}"
GCP_REGION="${GCP_REGION:-us-west1}"
POOL_ID="${POOL_ID:-github-pool}"
PROVIDER_ID="${PROVIDER_ID:-github-oidc}"
SA_NAME="${SA_NAME:-airlock-github-ci}"
SA_EMAIL="${SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

echo "==> [1/5] Enabling Google Cloud APIs in project ${GCP_PROJECT_ID}..."
gcloud services enable \
  cloudbuild.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  artifactregistry.googleapis.com \
  compute.googleapis.com \
  --project="${GCP_PROJECT_ID}"

PROJECT_NUMBER="$(gcloud projects describe "${GCP_PROJECT_ID}" --format='value(projectNumber)')"

echo "==> [2/5] Creating least-privilege CI service account ${SA_EMAIL}..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${GCP_PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="Airlock GitHub Actions Cloud Build CI" \
    --project="${GCP_PROJECT_ID}"
fi

for role in \
  roles/cloudbuild.builds.editor \
  roles/logging.logWriter \
  roles/serviceusage.serviceUsageConsumer \
  roles/storage.objectAdmin; do
  gcloud projects add-iam-policy-binding "${GCP_PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${role}" \
    --condition=None >/dev/null
done

echo "==> [3/5] Creating Workload Identity Pool (${POOL_ID})..."
if ! gcloud iam workload-identity-pools describe "${POOL_ID}" \
  --location="global" --project="${GCP_PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam workload-identity-pools create "${POOL_ID}" \
    --location="global" \
    --display-name="GitHub Actions Pool" \
    --project="${GCP_PROJECT_ID}"
fi

echo "==> [4/5] Creating OIDC Provider (${PROVIDER_ID}) scoped to ${GITHUB_ORG}/${GITHUB_REPO}..."
if ! gcloud iam workload-identity-pools providers describe "${PROVIDER_ID}" \
  --location="global" --workload-identity-pool="${POOL_ID}" --project="${GCP_PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_ID}" \
    --location="global" \
    --workload-identity-pool="${POOL_ID}" \
    --display-name="GitHub Actions OIDC" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
    --attribute-condition="assertion.repository == '${GITHUB_ORG}/${GITHUB_REPO}'" \
    --project="${GCP_PROJECT_ID}"
fi

echo "==> [5/5] Binding Workload Identity User role..."
PRINCIPAL_SET="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.repository/${GITHUB_ORG}/${GITHUB_REPO}"
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
  --project="${GCP_PROJECT_ID}" \
  --role="roles/iam.workloadIdentityUser" \
  --member="${PRINCIPAL_SET}" >/dev/null

WIF_PROVIDER="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"

cat <<EOF

[SEALED] Google Cloud Workload Identity Federation configured for ${GITHUB_ORG}/${GITHUB_REPO}.

Add these Repository Variables in GitHub -> Settings -> Secrets and variables -> Actions -> Variables:
  GCP_PROJECT_ID=${GCP_PROJECT_ID}
  GCP_REGION=${GCP_REGION}
  GCP_WORKLOAD_IDENTITY_PROVIDER=${WIF_PROVIDER}
  GCP_CI_SERVICE_ACCOUNT=${SA_EMAIL}

(Optional) For Cloud Build GitHub App direct triggers, connect your repo in GCP Console and run:
  gcloud builds triggers create github \\
    --name="airlock-main-ci" \\
    --repo-owner="${GITHUB_ORG}" \\
    --repo-name="${GITHUB_REPO}" \\
    --branch-pattern="^main\$" \\
    --build-config="cloudbuild.yaml" \\
    --region="${GCP_REGION}" \\
    --project="${GCP_PROJECT_ID}"
EOF
