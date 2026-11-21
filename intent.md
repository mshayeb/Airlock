Searched most common AI agentic platforms and sandboxes 2025 2026 E2B Modal Daytona Firecracker gVisor
Searched AI agent sandboxing security research papers 2025 2026 CaMeL IsolateGPT capability security information flow control
Searched local vs remote sandbox for coding agents seatbelts bubblewrap Landlock microVM WebAssembly 2026
Searched most popular AI agent frameworks platforms 2025 2026 LangGraph CrewAI Claude Agent SDK OpenAI Agents SDK Google ADK OpenHands sandbox
Searched AI agent sandbox credential proxy secretless egress control eBPF Progent AgentSpec MCP security 2025 2026

### 1. Most Common Agentic Platforms & Their Sandboxes

Modern agent stacks separate the **orchestration layer** (how agents plan, loop, and delegate) from the **execution sandbox** (where code, shell commands, browsers, and tools actually run).

| Agentic Platform / Harness | Primary Role | Commonly Paired Sandboxes |
| :--- | :--- | :--- |
| **LangGraph** (LangChain) | Stateful, graph-based enterprise orchestration | E2B, Modal, Daytona, Docker/Kata, custom K8s |
| **Claude Agent SDK / Claude Code** | Long-horizon coding & file-driven agents | Local OS sandbox (`Seatbelt` / `bubblewrap` via `sandbox-runtime`), remote microVMs (E2B, Daytona, Coder) |
| **OpenAI Agents SDK / Codex CLI** | Handoff-based API loops & local/cloud coding | Local OS (`Seatbelt` / `Landlock`), OpenAI hosted containers / Code Interpreter, E2B |
| **Google ADK** | Hierarchical GCP/Vertex AI orchestration | Vertex AI Code Execution, gVisor / Cloud Run sandboxes, Cloud Hypervisor |
| **CrewAI** | Role-based multi-agent automation | Docker containers, E2B, Modal, serverless sandboxes |
| **OpenHands** (fka OpenDevin) | Autonomous SWE harness | Docker/container runtimes, Remote microVMs (Daytona, E2B, Modal) |
| **Cloud Coding Platforms** (Devin, Coder, etc.) | Full persistent dev workspaces for agents | Firecracker/Kata microVMs, isolated K8s pods, cloud VMs |

#### Sandbox Techniques Across Local, Remote, and API Modes

| Layer / Technique | Representative Tools | Isolation Boundary | Cold Start | Compatibility | Main Weakness |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Local OS Confinement** | macOS `Seatbelt` (`sandbox-exec`), Linux `bubblewrap`, `Landlock`, `seccomp-bpf` | Shared host kernel; restricted FS/syscalls | ~0 ms | Native local binaries | Shared kernel; often grants broad read access to `$HOME`; easy to misconfigure |
| **Local Lightweight VMs** | Apple Virtualization (`Tart`, `Lima`), local KVM/Firecracker | Dedicated guest kernel | ~0.5–2 s | Full Linux/macOS | Higher RAM/disk overhead; file-sync ergonomics |
| **User-Space App Kernels** | **gVisor** (used by Modal, Cloud Run) | Intercepted syscalls in Go user-space | ~50–150 ms | High (good GPU passthrough) | Syscall performance overhead; occasional Linux edge-case incompatibilities |
| **Remote MicroVMs** | **Firecracker** (E2B, Fly.io Sprites), **Cloud Hypervisor** (Modal VMs), **Kata Containers** | Hardware virtualization (KVM) + dedicated guest kernel | ~50–250 ms | Full Linux userland (Docker, apt, npm, git) | Network latency, cloud cost, no native access to local uncommitted state |
| **Managed Cloud Workspaces** | **Daytona**, **Blaxel**, **Coder**, **Vercel / Cloudflare Sandbox** | MicroVMs or hardened containers + snapshot/fork | ~100 ms–2 s | Full dev environments (some support desktop UI) | Security still depends on egress/credential architecture, not just VM boundary |
| **Language / Edge Isolates** | **Wasm / WASI** (`Wasmtime`, `Pyodide`), **V8 Isolates** (Cloudflare Workers) | Memory-safe software fault isolation; deny-by-default capabilities | <1 ms | Restricted (must compile to Wasm/JS) | Cannot run arbitrary Linux CLI tools, compilers, or native C extensions |

---

### 2. Comparison of the Most Promising Security Research (2025–2026)

Recent research has shifted away from brittle prompt-level guardrails toward **structural isolation, capability-based security, and Information Flow Control (IFC)**:

| Research / Approach | Core Mechanism | Threat Mitigated | Enforcement Layer | Key Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **CaMeL** (*Google DeepMind / ETH Zurich, 2025*) | Strict separation of **control flow vs. data flow** using a Dual-LLM architecture (privileged planner + quarantined reader) and capability-tagged values. | Indirect prompt injection hijacking tool calls or exfiltrating private data. | Agent harness / interpreter | Assumes structured tool calls; breaks down when the agent drops into an arbitrary bash shell or writes/executes free-form code. |
| **FIDES** (*Microsoft Research, 2025*) | Formal **Information Flow Control (IFC)** and dynamic taint tracking (confidentiality + integrity labels) with selective hide/reveal & endorsement primitives. | Data exfiltration and low-integrity data influencing high-impact actions. | Planner & memory loop | Hard to maintain taint fidelity across OS processes, filesystems, and external binaries; risk of over-tainting (label creep). |
| **IsolateGPT** (*NDSS 2025*) | **Hub-and-spoke execution isolation** isolating third-party LLM apps/tools into separate spokes with mediated inter-spoke messaging. | Cross-app data leakage, privilege escalation, and rogue plugin interference. | Multi-agent / plugin runtime | ~20–30% latency overhead; focuses on app-level boundaries rather than OS/network-level code execution. |
| **Declarative Policy Runtimes** (*Progent, AgentSpec*) | Formal manifests specifying per-task tool privileges, argument schemas, and runtime invariants. | Over-privileged tool use and unauthorized state mutations. | Tool / MCP gateway | Static or coarse policies struggle with dynamic coding tasks where needed tools/packages aren't known upfront. |
| **Kernel eBPF Enforcement** (*Meta Sentinel, Grimlock, MCPGuard-Dynamic*) | **eBPF LSM hooks**, cgroups, and socket redirection to enforce syscall/file/egress policies and track process-level taint inside the kernel. | Sandbox escapes, rogue local MCP servers, unauthorized network exfiltration. | Linux kernel | Linux-only; lacks high-level semantic awareness of *why* the LLM made a request unless coupled to the harness. |
| **Secretless / Credential Proxies** (*Industry pattern: OpenShell, Action Gateways*) | Zero raw secrets inside the sandbox; an external egress proxy injects short-lived, scoped credentials on the wire. | Secret theft (`~/.ssh`, `.env`, API keys) via prompt injection or supply-chain attacks. | Network egress boundary | Still allows a hijacked agent to *misuse* an authorized API (confused deputy) unless paired with action-level policy. |

---

### 3. What Is Missing (The Critical Gaps)

1. **The Semantic–OS Disconnect ("Blind Isolation")**
   Infrastructure sandboxes (Firecracker, gVisor, Seatbelt) protect the *host* from the agent, but are blind to *intent and data sensitivity*. If a prompt-injected agent inside a Firecracker VM reads a malicious `README.md` and uses its legitimate GitHub token to exfiltrate source code or push a backdoor, the VM did nothing "wrong." Conversely, CaMeL and FIDES enforce semantic IFC in the *planner*, but lose all tracking the moment the agent executes a bash command.
2. **Ambient Authority & Secret Exposure**
   Most local sandboxes mount `$HOME` or inherit environment variables/SSH agents; most remote sandboxes inject static API keys as env vars. Even with short-lived tokens, once a secret enters the sandbox memory, any compromised dependency or shell command can steal it.
3. **No Unified Local ↔ Remote ↔ API Security Model**
   Teams use `Seatbelt`/`bubblewrap` locally, Firecracker remotely, and Wasm/HTTP proxies for API tools—each with completely different policy formats, trust boundaries, and audit logs. A safe workflow locally often becomes unsafe remotely (or vice versa).
4. **Unsandboxed MCP & Tool Supply Chains**
   Model Context Protocol (MCP) servers frequently run as unsandboxed local subprocesses with full user privileges, and tool outputs/descriptions can poison agent context without isolation between tools.
5. **Taint & Capability Loss Across Snapshots/Forks**
   Pause/resume/fork (E2B, Daytona) is a killer feature for agents, but **capability leases and taint labels are not persisted with snapshots**. Resuming an old snapshot can silently revive stale permissions or lose track of tainted files.
6. **Covert & Allowed-Channel Exfiltration**
   Domain allowlists alone fail when allowed domains (GitHub Gists, Slack, npm/PyPI, or even the LLM API itself) can be abused to leak sensitive repo data or secrets.

---

### 4. Proposed Sandbox Architecture to Fill the Gaps

To close the gap between **OS/VM isolation** and **semantic IFC/capability security**, a next-generation agent sandbox should be designed as a **5-layer Capability- & Taint-Aware Unified Sandbox** that runs identically across **local, remote, and API** modes.

```text
┌────────────────────────────────────────────────────────────────────────────┐
│  Layer 4: Agent Harness & Policy Engine (CaMeL/FIDES + Declarative Policy) │
│  - Control/Data separation (Trusted Planner vs. Quarantined Reader)        │
│  - Portable Policy Manifest (FS views, API caps, budgets, HITL gates)      │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │ Opaque Capability Handles + Taint Context
┌───────────────────────────────▼────────────────────────────────────────────┐
│  Layer 2: Secretless Capability Broker & Egress Proxy (Host / Control Plane)│
│  - Zero secrets inside sandbox; injects scoped, short-lived creds on wire  │
│  - Semantic egress inspection (blocks tainted data -> untrusted sinks)     │
│  - Per-MCP-server isolated spokes (IsolateGPT pattern) + schema validation │
└───────────────┬─────────────────────────────────────────┬──────────────────┘
                │ vsock / Unix socket (no direct internet)│
┌───────────────▼───────────────────────────┐   ┌─────────▼──────────────────┐
│  Layer 1 & 3: Pluggable Compute + Kernel  │   │  Layer 1 (API/Plugin Mode) │
│  - Local:  Apple VZ / KVM microVM + CoW   │   │  - Wasm / WASI (Wasmtime)  │
│            (fallback: Landlock/Seatbelt)  │   │  - V8 Isolates (<1ms)      │
│  - Remote: Firecracker / Kata / gVisor    │   │  - Deny-by-default caps    │
│  - Kernel: eBPF LSM + FUSE CoW tainting   │   └────────────────────────────┘
│  - Layer 5: Atomic CoW Diff + Audit Log   │
└───────────────────────────────────────────┘
```

#### How Each Layer Closes a Specific Gap

1. **Unified Pluggable Compute Substrate (Local ↔ Remote ↔ API Parity)**
   * **One runtime interface, one policy file** across all three modes:
     * **Local:** Ephemeral microVM (Apple Virtualization Framework on macOS; Firecracker/Cloud Hypervisor on Linux) mounting only the target repo via a **Copy-on-Write (CoW) overlay**—zero visibility into `$HOME`, `~/.ssh`, or browser cookies. Fall back to `Landlock`/`Seatbelt` only for read-only/low-risk commands.
     * **Remote:** Firecracker/Kata microVMs (or gVisor for GPU workloads) with **policy- and taint-aware snapshots** so forked sessions inherit exact taint labels and re-validate capability leases on resume.
     * **API / Stateless Tools:** Wasm/WASI (`Wasmtime`) or V8 Isolates for sub-millisecond, memory-safe execution of lightweight tools and untrusted parsers.
2. **Secretless Capability Broker (Eliminates Ambient Authority)**
   * The sandbox has **no direct internet access** (no raw TCP/UDP/DNS egress). All network traffic exits through a host-side proxy over `vsock` or a Unix socket.
   * No `.env` files, API keys, or SSH keys ever enter the sandbox. Instead, the agent holds **opaque, action-scoped capability tokens** (e.g., `cap:git:push:branch=agent/*`, `cap:http:POST:api.github.com/repos/org/app/pulls`).
   * The broker validates the capability, inspects arguments/payloads, injects real short-lived credentials on the wire, and enforces rate/spend limits.
3. **Cross-Boundary Taint & IFC Enforcement (Bridges CaMeL/FIDES ↔ OS Kernel)**
   * Data entering the sandbox is labeled by **confidentiality** (`public`, `internal`, `secret`) and **integrity** (`trusted_user`, `verified_repo`, `untrusted_web`).
   * Inside Linux microVMs, an **eBPF LSM + FUSE/overlayfs tracker** propagates coarse-grained taint across files and child processes.
   * **Deterministic rules enforced at the broker:**
     * *Confidentiality:* If a process/session has read `secret`-labeled files, outbound egress is blocked to any sink not explicitly cleared for that label (preventing exfiltration even through allowed domains like `curl` or `npm`).
     * *Integrity:* If the agent reads `untrusted_web` content (e.g., an external web page or untrusted PR comment), mutating high-impact capabilities (merging PRs, modifying CI workflows, running production API calls) are automatically **downgraded to require HITL approval or quarantined declassification**.
4. **Isolated MCP Spokes (Fixes Tool Supply-Chain Risk)**
   * Following the **IsolateGPT** model, each MCP server runs in its own lightweight sandbox (Wasm or micro-container) with its own minimal capability slice rather than sharing the host or the main agent's shell.
   * Tool definitions are pinned/hashed to prevent rug-pull tool poisoning, and all arguments/outputs pass through strict schema validation and taint tagging before re-entering the LLM context.
5. **Atomic CoW Commits, Rollback & Verifiable Audit Trail**
   * All filesystem edits happen in an ephemeral CoW layer. Before changes are committed back to the developer's real working tree or pushed to a remote repo, an automated **egress/diff gate** runs secret scanning, policy checks, and—when integrity rules trigger—presents a concise human-in-the-loop diff approval.
   * Every syscall anomaly, capability invocation, taint transition, and proxied API call is logged as an immutable trace linked to the agent's reasoning step.

---

### Practical Rollout Path (If Building Today)
* **Phase 1 (Immediate wins):** Pair **Firecracker (remote) / Apple VZ or KVM (local)** with a **secretless egress proxy** (zero keys in sandbox, `vsock`-only networking, CoW workspace overlay). This alone eliminates >80% of real-world agent blast radius.
* **Phase 2 (Tool & MCP isolation):** Isolate every MCP server into its own capability-scoped spoke (Wasm or container) and adopt a single declarative policy manifest across local and remote runs.
* **Phase 3 (Semantic IFC + Kernel Taint):** Connect **eBPF LSM file/process tainting** inside the VM to **CaMeL/FIDES-style planner rules** at the broker so indirect prompt injections cannot exfiltrate data or trigger unapproved high-impact actions.