# Google Cloud ↔ GitHub CI Integration

Airlock integrates GitHub and Google Cloud using **keyless Workload Identity Federation (WIF)** (`google-github-actions/auth@v2`) and **Google Cloud Build** ([`cloudbuild.yaml`](../../cloudbuild.yaml)), preserving the Zero-Secret invariant in [`spec.md`](../../spec.md) (no static GCP service-account JSON keys stored in GitHub Secrets).

---

## Architecture

1. **Stage 1 (`smoke` in GitHub Actions):** Runs fast `<5s` `pytest -m smoke` checks (`airlock version`, `airlock doctor`, `airlock init`, SDK imports) on `ubuntu-latest`.
2. **Stage 2 (`more-tests` in GitHub Actions):** Only runs after `smoke` passes; executes `cargo test --workspace` and `pytest` tiers (`unit` -> `integration` -> `security`) across Linux (`ubuntu-latest`) and Apple Silicon macOS (`macos-15`).
3. **Stage 3 (`gcp-cloud-build` in GitHub Actions or Cloud Build App Trigger):** Exchanges a short-lived GitHub OIDC token for GCP credentials and submits [`cloudbuild.yaml`](../../cloudbuild.yaml) to Google Cloud Build.

---

## One-Time Setup

Run [`setup-github-gcp-ci.sh`](setup-github-gcp-ci.sh) with `gcloud` authenticated as a project owner/IAM admin:

```sh
export GCP_PROJECT_ID="your-gcp-project-id"
export GCP_REGION="us-west1"
export GITHUB_ORG="your-github-org-or-user"
export GITHUB_REPO="Airlock"

sh infra/gcp/setup-github-gcp-ci.sh
```

Then add the printed **Repository Variables** in GitHub (**Settings → Secrets and variables → Actions → Variables**):

| Variable | Example Value | Required |
|---|---|---|
| `GCP_PROJECT_ID` | `your-gcp-project-id` | Yes (to enable Stage 3) |
| `GCP_REGION` | `us-west1` | Optional (defaults to `us-west1`) |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/123456789/locations/global/workloadIdentityPools/github-pool/providers/github-oidc` | Yes (to enable Stage 3) |
| `GCP_CI_SERVICE_ACCOUNT` | `airlock-github-ci@your-gcp-project-id.iam.gserviceaccount.com` | Yes (to enable Stage 3) |
| `GCP_KVM_WORKER_POOL` | `projects/your-gcp-project-id/locations/us-central1/workerPools/airlock-kvm` | Optional (for `/dev/kvm` Firecracker M1+ tests) |

> **Note:** Until those repository variables are set, Stages 1 (`smoke`) and 2 (`more-tests`) still run on every push/PR, and Stage 3 (`gcp-cloud-build`) skips cleanly.

---

## Optional: Nested-KVM GCE Self-Hosted Runner for Milestone M1+ (Firecracker)

Standard Cloud Build container workers do not expose `/dev/kvm` (`airlock doctor --json` reports `linux_kvm: BLOCKED`, exit `70`). To test live Firecracker microVMs on Google Cloud in Milestone M1+:

1. Create a Compute Engine VM (`n2-standard-8` or `c3-standard-8`) with nested virtualization enabled:
   ```sh
   gcloud compute instances create airlock-kvm-runner \
     --project="$GCP_PROJECT_ID" \
     --zone="${GCP_REGION}-a" \
     --machine-type=n2-standard-8 \
     --image-family=debian-12 \
     --image-project=debian-cloud \
     --enable-nested-virtualization \
     --boot-disk-size=100GB
   ```
2. Provision `erofs-utils` (`mkfs.erofs`), `firecracker`, `jailer`, `/dev/kvm` permissions (`kvm` group + udev rule), and register an `--ephemeral` GitHub Actions self-hosted runner (`[self-hosted, linux, x64, airlock-kvm]`):
   ```sh
   export GCP_PROJECT_ID="airlock-515421"
   export GCP_ZONE="us-west1-a"
   export VM_NAME="airlock-kvm-runner"
   export GITHUB_REPO_FULL="mshayeb/Airlock"

   sh infra/gcp/provision-kvm-runner.sh
   ```
3. The provisioning script verifies the transition directly on `airlock-kvm-runner`:
   - Before adding `ghrunner` to the `kvm` group: `airlock doctor --json` outputs `"check":"linux_kvm","status":"BLOCKED"` (exit `70`).
   - After granting `/dev/kvm` access (`usermod -aG kvm ghrunner`): `airlock doctor --json` outputs `"check":"linux_kvm","status":"ALLOW"`, `"firecracker":"ALLOW"`, `"jailer":"ALLOW"`, and `"mkfs.erofs":"ALLOW"` (exit `0`).
4. Trigger the `kvm-self-hosted` job in [`.github/workflows/ci-gcp.yml`](../../.github/workflows/ci-gcp.yml) via `workflow_dispatch` (`run_kvm_runner=true`) or by setting repository variable `ENABLE_KVM_RUNNER=true`.
