# Airlock Cookbook

Practical, copy-pasteable recipes for getting started with **Airlock** — from building the CLI and inspecting your host to wiring `airlock.toml` policies, agent harness adapters, tamper-evident audit checks, and progressive `pytest` CI on GitHub + Google Cloud.

> **Terminology note:** Airlock isolates untrusted workloads inside a **Chamber** (`[SEALED]`), replaces raw `.env` secrets with session-bound **Phantom Tokens**, governs egress through the host **Broker** according to declared **Capabilities**, and validates changes at the **Commit Gate**.

---

## Contents
- [Recipe 1 — 5-Minute Quickstart (Build, Doctor & Init)](#recipe-1--5-minute-quickstart-build-doctor--init)
- [Recipe 2 — Authoring `airlock.toml` Policies](#recipe-2--authoring-airlocktoml-policies)
- [Recipe 3 — Using the Python SDK (`airlock-sdk`)](#recipe-3--using-the-python-sdk-airlock-sdk)
- [Recipe 4 — Integrating Agent Harnesses (`LangGraph`, `Claude`, `OpenAI`, `OpenHands`)](#recipe-4--integrating-agent-harnesses-langgraph-claude-openai-openhands)
- [Recipe 5 — Using the TypeScript SDK (`@airlock/sdk`)](#recipe-5--using-the-typescript-sdk-airlocksdk)
- [Recipe 6 — Verifying the Tamper-Evident Audit Trail](#recipe-6--verifying-the-tamper-evident-audit-trail)
- [Recipe 7 — Running Progressive `pytest` Stages & Google Cloud ↔ GitHub CI](#recipe-7--running-progressive-pytest-stages--google-cloud--github-ci)
- [Recipe 8 — Diagnosing `[BLOCKED]` & `[REVIEW]` Events Safely](#recipe-8--diagnosing-blocked--review-events-safely)

---

## Recipe 1 — 5-Minute Quickstart (Build, Doctor & Init)

Build the Rust workspace and (on Apple Silicon macOS) the signed `Virtualization.framework` helper:

```sh
# 1. Build the CLI and run Rust unit tests
cargo build -p airlock-cli
cargo test --workspace

# 2. On Apple Silicon macOS: build and sign the Virtualization helper
sh "macos/airlock-vz-helper/build.sh"

# 3. Check host readiness (plain screen-reader mode or JSON)
./target/debug/airlock doctor --plain
./target/debug/airlock doctor --json
```

Generate a least-privilege `airlock.toml` in any project directory (`airlock init` auto-detects `Cargo.toml`, `package.json`, and `pyproject.toml`):

```sh
./target/debug/airlock init /path/to/your-repo
```

> **Tip:** Re-running `airlock init` never overwrites an existing `airlock.toml` (exits `78`) unless you pass `--force`.

---

## Recipe 2 — Authoring `airlock.toml` Policies

Start from [`airlock.toml.example`](../airlock.toml.example) and grant **only** the destinations, HTTP methods, and Git branches an agent task needs.

### 2A. Branch-Scoped GitHub Pull Requests + Budgeted LLM Calls

```toml
version = "1"

[chamber]
target = "local"
profile = "standard"
vcpus = 2
memory_mib = 4096
ttl_seconds = 3600

[workspace]
synthesize_env_from_example = true
protected_paths = [".git/**", ".github/workflows/**", "airlock.toml", "Dockerfile", "Makefile"]

[[capabilities]]
id = "github_agent_pr"
type = "git_http"
provider = "github_app"
hosts = ["github.com", "api.github.com"]
allow_methods = ["GET", "POST"]
allow_paths = [
  "/org/app.git/info/refs*",
  "/org/app.git/git-upload-pack",
  "/org/app.git/git-receive-pack",
  "/repos/org/app/pulls*"
]
allowed_branches = ["refs/heads/agent/*"]
allow_force_push = false
env_var = "GITHUB_TOKEN"
rate_limit_rpm = 60

[[capabilities]]
id = "llm_vertex_gemini"
type = "http"
provider = "oidc:gcp_vertex"
hosts = ["us-central1-aiplatform.googleapis.com"]
allow_methods = ["POST"]
allow_paths = ["/v1/projects/*/locations/us-central1/publishers/google/models/*"]
inject_header = "Authorization"
max_budget_usd = 5.00
rate_limit_rpm = 30
```

### 2B. High-Sensitivity Offline Mode (Zero Egress)

For proprietary repositories where no package downloads or external calls are permitted (`spec.md` §12 `C4`), omit all `[[capabilities]]` blocks:

```toml
version = "1"

[chamber]
target = "local"
profile = "standard"

[workspace]
synthesize_env_from_example = false
protected_paths = [".git/**", ".github/workflows/**", "airlock.toml"]

[commit_gate]
mode = "interactive"
secret_scan = "block"
```

Every outbound request from the Chamber will fail closed at the Broker and emit a `[BLOCKED]` record in `audit.jsonl`.

---

## Recipe 3 — Using the Python SDK (`airlock-sdk`)

Install in editable mode with dev dependencies:

```sh
pip install -e "sdks/python[dev]"
```

Run commands inside a context-managed Chamber, inspect the CoW diff, commit safely, or roll back:

```python
from airlock_sdk import AirlockClient

client = AirlockClient(target="local")  # uses ~/.local/state/airlock/airlockd.sock

with client.chamber("/path/to/your-repo") as ch:
    # Guest receives only phantom tokens (airlock-phantom:cap_...), never raw secrets.
    res = ch.exec("pytest -q", agent_step_id="step_run_tests")
    print("exit:", res.exit_code)
    print(res.stdout)

    # Inspect CoW upper changes before touching the host working tree.
    diff = ch.diff()
    if not diff["protected_paths"] and not diff["secret_findings"]:
        ch.commit(approve_protected=False)
    else:
        print("[REVIEW] Protected or flagged changes:", diff)

    # If a commit needs to be reverted atomically:
    # ch.undo()
```

---

## Recipe 4 — Integrating Agent Harnesses (`LangGraph`, `Claude`, `OpenAI`, `OpenHands`)

All four first-party adapters implement the `SandboxProvider` protocol (`run_shell`, `read_file`, `write_file`) and forward `step_id` so every tool action links to `audit.jsonl`.

```python
from airlock_sdk import (
    AirlockClient,
    ClaudeAgentSandbox,
    LangGraphSandbox,
    OpenAIAgentSandbox,
    OpenHandsSandbox,
)

client = AirlockClient(target="local")

with client.chamber("/path/to/your-repo") as ch:
    # 1. LangGraph tool node
    lg = LangGraphSandbox(ch)
    lg.write_file("src/hello.py", "print('sealed')\n", step_id="lg_node_write")
    print(lg.run_shell("python3 src/hello.py", step_id="lg_node_run").stdout)

    # 2. Claude Agent SDK / OpenAI Agents SDK
    claude_box = ClaudeAgentSandbox(ch)
    openai_box = OpenAIAgentSandbox(ch)
    _ = claude_box.read_file("src/hello.py", step_id="claude_read")
    _ = openai_box.run_shell("git status -s", step_id="oai_git_status")

    # 3. OpenHands action adapter
    oh = OpenHandsSandbox(ch)
    action_result = oh.execute_action("cargo test --workspace", step_id="oh_step_4")
    print(action_result)
```

---

## Recipe 5 — Using the TypeScript SDK (`@airlock/sdk`)

```ts
import { AirlockClient } from "@airlock/sdk";

const client = new AirlockClient({
  baseUrl: process.env.AIRLOCK_URL ?? "http://localhost:7641",
  bearerToken: process.env.AIRLOCK_OIDC_TOKEN,
});

const chamber = await client.createChamber({
  workspace: "/path/to/your-repo",
  target: "remote",
});

try {
  const res = await chamber.runShell("npm test", "ts_step_01");
  console.log({ exitCode: res.exitCode, stdout: res.stdout });
} finally {
  await chamber.close();
}
```

---

## Recipe 6 — Verifying the Tamper-Evident Audit Trail

Every Chamber records an append-only, secret-scrubbed, SHA-256 hash-chained `audit.jsonl`. Verify integrity with `airlock logs --verify`:

```sh
./target/debug/airlock logs --verify ~/.local/state/airlock/audit/chmb_01/audit.jsonl
./target/debug/airlock logs --verify ~/.local/state/airlock/audit/chmb_01/audit.jsonl --json
```

Expected outputs:
- Unmodified chain: exits `0` with `[SEALED] Hash chain verified (...)`.
- Modified or truncated line: exits `79` with `[BLOCKED] event_hash tamper detected at line ...`.

---

## Recipe 7 — Running Progressive `pytest` Stages & Google Cloud ↔ GitHub CI

Airlock separates tests into four explicit `pytest` markers defined in [`pytest.ini`](../pytest.ini) so CI always runs the fast smoke gate first before launching matrix or cloud builds:

```sh
# Stage 1: Fast smoke gate (<5s) — CLI version, doctor, init, SDK imports
./scripts/ci-pytest.sh --stage smoke

# Stage 2+: Unit -> AF_UNIX Integration -> Security & Accessibility Acceptance (AT-11/13/14)
./scripts/ci-pytest.sh --stage more

# Run everything in one shot with JUnit XML reports
JUNIT_DIR=reports ./scripts/ci-pytest.sh --stage all
```

### Connecting GitHub Actions to Google Cloud Build (Keyless WIF)

1. Run the one-time setup script ([`infra/gcp/setup-github-gcp-ci.sh`](../infra/gcp/setup-github-gcp-ci.sh)) to configure Workload Identity Federation:
   ```sh
   export GCP_PROJECT_ID="your-gcp-project-id"
   export GITHUB_ORG="your-github-org"
   export GITHUB_REPO="Airlock"
   sh infra/gcp/setup-github-gcp-ci.sh
   ```
2. Add the printed `GCP_PROJECT_ID`, `GCP_WORKLOAD_IDENTITY_PROVIDER`, and `GCP_CI_SERVICE_ACCOUNT` values in GitHub **Settings → Secrets and variables → Actions → Variables**.
3. Every PR/push to `main` runs `.github/workflows/ci-gcp.yml` (`smoke` -> `more-tests` across Linux + macOS -> `gcp-cloud-build` executing `cloudbuild.yaml`). See [`infra/gcp/README.md`](../infra/gcp/README.md) for optional nested-KVM Compute Engine Firecracker runners.

---

## Recipe 8 — Diagnosing `[BLOCKED]` & `[REVIEW]` Events Safely

| Signal | Meaning | Recommended Fix |
|---|---|---|
| `[BLOCKED] POLICY_REF_DENIED` | Guest pushed to `main`/`master` or outside `allowed_branches` | Push to `refs/heads/agent/<branch>` instead of `main`. |
| `[BLOCKED] SSRF_BLOCKED` | Outbound domain resolved to loopback, RFC 1918, or `169.254.169.254` | Remove private/IMDS URL; external public endpoints only. |
| `[BLOCKED] CAPABILITY_REPLAY_DETECTED` | Phantom token used outside its originating `(chamber_id, vsock_cid)` | Re-run inside the active Chamber; never share phantom tokens across VMs. |
| `[REVIEW] protected_paths` | Diff modifies `.git/**`, `.github/workflows/**`, `Dockerfile`, or `Makefile` | Inspect diff line-by-line at Commit Gate before approving. |
| `[REVIEW] workspace_path_hygiene` | Working directory ends with whitespace (e.g. `Airlock `) | Rename directory (`mv "Airlock " Airlock`) to avoid third-party tool issues. |
