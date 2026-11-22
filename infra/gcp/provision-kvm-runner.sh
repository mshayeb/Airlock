#!/usr/bin/env bash
# Idempotently provision a nested-KVM GCE VM (`erofs-utils`, `firecracker`, `jailer`,
# `/dev/kvm` udev + `kvm` group access), verify `airlock doctor --json` transitions
# `linux_kvm` from [BLOCKED] to [ALLOW], and register an ephemeral GitHub Actions runner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

GCP_PROJECT_ID="${GCP_PROJECT_ID:-airlock-515421}"
GCP_ZONE="${GCP_ZONE:-us-west1-a}"
VM_NAME="${VM_NAME:-airlock-kvm-runner}"
GITHUB_REPO_FULL="${GITHUB_REPO_FULL:-mshayeb/Airlock}"
FIRECRACKER_VERSION="${FIRECRACKER_VERSION:-v1.10.1}"

RUNNER_VERSION="${RUNNER_VERSION:-}"
if [ -z "$RUNNER_VERSION" ]; then
  RUNNER_VERSION="$(gh api /repos/actions/runner/releases/latest --jq '.tag_name | ltrimstr("v")' 2>/dev/null || echo "2.322.0")"
fi

SRC_TAR="/tmp/airlock-src-$$.tgz"
cleanup() {
  rm -f "$SRC_TAR"
}
trap cleanup EXIT

echo "==> [1/4] Packaging Airlock source archive and uploading to ${VM_NAME} (${GCP_PROJECT_ID}/${GCP_ZONE})..."
COPYFILE_DISABLE=1 tar -czf "$SRC_TAR" -C "$REPO_ROOT" --exclude=target --exclude=.git --exclude=reports .
gcloud compute scp --quiet \
  --project="${GCP_PROJECT_ID}" \
  --zone="${GCP_ZONE}" \
  "$SRC_TAR" "${VM_NAME}:/tmp/airlock-src.tgz"

echo "==> [2/4] Minting short-lived GitHub Actions runner registration token for ${GITHUB_REPO_FULL}..."
REG_TOKEN="$(gh api --method POST -H 'Accept: application/vnd.github+json' \
  "/repos/${GITHUB_REPO_FULL}/actions/runners/registration-token" --jq .token)"

echo "==> [3/4] Provisioning erofs-utils, firecracker, jailer, /dev/kvm access, and ephemeral runner on ${VM_NAME}..."
{
  printf 'FIRECRACKER_VERSION=%q\nRUNNER_VERSION=%q\nGITHUB_REPO_FULL=%q\nVM_NAME=%q\nREG_TOKEN=%q\n' \
    "$FIRECRACKER_VERSION" "$RUNNER_VERSION" "$GITHUB_REPO_FULL" "$VM_NAME" "$REG_TOKEN"
  cat <<'REMOTE_EOF'
set -euo pipefail

echo "--- Installing OS dependencies & erofs-utils ---"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  erofs-utils curl jq tar ca-certificates git build-essential pkg-config \
  libssl-dev python3 python3-venv python3-pytest util-linux acl

echo "--- Installing Firecracker & Jailer (${FIRECRACKER_VERSION}) ---"
FC_ARCH="$(uname -m)"
FC_TGZ="/tmp/firecracker-${FIRECRACKER_VERSION}-${FC_ARCH}.tgz"
if [ ! -x /usr/local/bin/firecracker ] || [ ! -x /usr/local/bin/jailer ]; then
  curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${FC_ARCH}.tgz" -o "$FC_TGZ"
  FC_TMP="/tmp/fc-extract"
  rm -rf "$FC_TMP"
  mkdir -p "$FC_TMP"
  tar -xzf "$FC_TGZ" -C "$FC_TMP"
  sudo install -m 0755 "$FC_TMP/release-${FIRECRACKER_VERSION}-${FC_ARCH}/firecracker-${FIRECRACKER_VERSION}-${FC_ARCH}" /usr/local/bin/firecracker
  sudo install -m 0755 "$FC_TMP/release-${FIRECRACKER_VERSION}-${FC_ARCH}/jailer-${FIRECRACKER_VERSION}-${FC_ARCH}" /usr/local/bin/jailer
  rm -rf "$FC_TMP" "$FC_TGZ"
fi
command -v mkfs.erofs
dpkg-query -W -f='erofs-utils ${Version}\n' erofs-utils
firecracker --version
jailer --version

echo "--- Ensuring system-wide Rust toolchain in /opt/rust ---"
if [ ! -x /opt/rust/bin/cargo ]; then
  sudo mkdir -p /opt/rust
  sudo env RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust sh -c \
    'curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path'
  sudo chmod -R a+rX /opt/rust
fi
for bin in cargo rustc rustdoc rustup; do
  cat <<WRAP | sudo tee "/usr/local/bin/${bin}" >/dev/null
#!/bin/sh
export RUSTUP_HOME=/opt/rust
exec /opt/rust/bin/${bin} "\$@"
WRAP
  sudo chmod 0755 "/usr/local/bin/${bin}"
done
cargo --version
rustc --version
rustdoc --version

echo "--- Configuring ghrunner user and /dev/kvm udev rules ---"
if ! id -u ghrunner >/dev/null 2>&1; then
  sudo useradd -m -s /bin/bash ghrunner
fi
cat <<'UDEV' | sudo tee /etc/udev/rules.d/99-airlock-kvm.rules >/dev/null
KERNEL=="kvm", GROUP="kvm", MODE="0660"
UDEV
sudo udevadm control --reload-rules || true
sudo udevadm trigger --subsystem-match=misc || true
if [ -e /dev/kvm ]; then
  sudo chgrp kvm /dev/kvm
  sudo chmod 0660 /dev/kvm
  ls -la /dev/kvm
else
  echo "ERROR: /dev/kvm is absent on ${VM_NAME}; verify --enable-nested-virtualization." >&2
  exit 1
fi

# Temporarily ensure ghrunner lacks kvm access so we observe the authentic BEFORE [BLOCKED] state.
sudo gpasswd -d ghrunner kvm >/dev/null 2>&1 || true

echo "--- Building airlock CLI on ${VM_NAME} ---"
sudo rm -rf /home/ghrunner/airlock-src
sudo mkdir -p /home/ghrunner/airlock-src
sudo tar -xzf /tmp/airlock-src.tgz -C /home/ghrunner/airlock-src
sudo chown -R ghrunner:ghrunner /home/ghrunner/airlock-src
rm -f /tmp/airlock-src.tgz

sudo -u ghrunner -H bash -lc 'cd /home/ghrunner/airlock-src && cargo build -p airlock-cli && cargo test --workspace'

echo "--- BEFORE granting kvm group: airlock doctor --json ---"
sudo -u ghrunner -H id
set +e
sudo -u ghrunner -H /home/ghrunner/airlock-src/target/debug/airlock doctor --json
BEFORE_EXIT=$?
set -e
echo "BEFORE_EXIT=${BEFORE_EXIT}"

echo "--- Granting ghrunner and $USER access to /dev/kvm (kvm group) ---"
sudo usermod -aG kvm ghrunner
sudo usermod -aG kvm "$USER"

echo "--- AFTER granting kvm group: airlock doctor --json ---"
sudo -u ghrunner -H id
set +e
sudo -u ghrunner -H /home/ghrunner/airlock-src/target/debug/airlock doctor --json
AFTER_EXIT=$?
set -e
echo "AFTER_EXIT=${AFTER_EXIT}"
if [ "$AFTER_EXIT" -ne 0 ]; then
  echo "ERROR: Expected airlock doctor to exit 0 after granting kvm group, got $AFTER_EXIT" >&2
  exit "$AFTER_EXIT"
fi

echo "--- Installing and registering ephemeral GitHub Actions runner (${RUNNER_VERSION}) ---"
RUNNER_DIR="/home/ghrunner/actions-runner"
sudo mkdir -p "$RUNNER_DIR"
sudo chown -R ghrunner:ghrunner "$RUNNER_DIR"

if [ -x "$RUNNER_DIR/svc.sh" ]; then
  (cd "$RUNNER_DIR" && sudo ./svc.sh stop >/dev/null 2>&1 || true)
  (cd "$RUNNER_DIR" && sudo ./svc.sh uninstall >/dev/null 2>&1 || true)
fi

if [ ! -x "$RUNNER_DIR/config.sh" ]; then
  RUNNER_ARCH="x64"
  if [ "$(uname -m)" = "aarch64" ]; then
    RUNNER_ARCH="arm64"
  fi
  RUNNER_TGZ="/tmp/actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
  curl -fsSL "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz" -o "$RUNNER_TGZ"
  sudo -u ghrunner -H tar -xzf "$RUNNER_TGZ" -C "$RUNNER_DIR"
  rm -f "$RUNNER_TGZ"
  sudo "$RUNNER_DIR/bin/installdependencies.sh" >/dev/null
fi

cd "$RUNNER_DIR"
sudo rm -f "$RUNNER_DIR/.runner" "$RUNNER_DIR/.credentials" "$RUNNER_DIR/.credentials_rsaparams" "$RUNNER_DIR/.service"
sudo -u ghrunner -H ./config.sh \
  --url "https://github.com/${GITHUB_REPO_FULL}" \
  --token "${REG_TOKEN}" \
  --name "${VM_NAME}" \
  --labels "airlock-kvm" \
  --work "_work" \
  --ephemeral \
  --unattended \
  --replace

sudo ./svc.sh install ghrunner
sudo ./svc.sh start
sudo ./svc.sh status || true
REMOTE_EOF
} | gcloud compute ssh "${VM_NAME}" \
  --quiet \
  --project="${GCP_PROJECT_ID}" \
  --zone="${GCP_ZONE}" \
  --command="bash -s"

echo "==> [4/4] Verifying ${VM_NAME} registration status in GitHub Actions..."
for attempt in 1 2 3 4 5; do
  runner_json="$(gh api "/repos/${GITHUB_REPO_FULL}/actions/runners" \
    --jq ".runners[] | select(.name == \"${VM_NAME}\") | {name, status, busy, labels: [.labels[].name]}" 2>/dev/null || true)"
  if echo "$runner_json" | grep -q '"status":"online"'; then
    echo "$runner_json"
    exit 0
  fi
  sleep 3
done

gh api "/repos/${GITHUB_REPO_FULL}/actions/runners" \
  --jq '.runners[] | {name, status, busy, labels: [.labels[].name]}'
