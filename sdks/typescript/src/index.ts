/**
 * Airlock Phase 1 TypeScript SDK (`FR-INT-4`, `FR-INT-5`).
 */

export type ChamberTarget = "local" | "remote";

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  agentStepId?: string;
}

export interface ChamberOptions {
  workspace: string;
  target?: ChamberTarget;
  manifestPath?: string;
}

export interface SandboxProvider {
  runShell(command: string, agentStepId?: string): Promise<ExecResult>;
}

export class AirlockClient {
  constructor(
    private readonly config: {
      baseUrl?: string;
      socketPath?: string;
      bearerToken?: string;
    } = {},
  ) {}

  async createChamber(opts: ChamberOptions): Promise<ChamberHandle> {
    const baseUrl = this.config.baseUrl ?? "http://localhost:7641";
    const res = await fetch(`${baseUrl}/v1/chambers`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        workspace: opts.workspace,
        target: opts.target ?? "local",
        manifest_path: opts.manifestPath ?? null,
      }),
    });
    if (!res.ok) {
      throw new Error(`Airlock createChamber failed: ${res.status}`);
    }
    const json = (await res.json()) as { chamber_id: string };
    return new ChamberHandle(baseUrl, json.chamber_id, this.headers());
  }

  private headers(): Record<string, string> {
    const out: Record<string, string> = { "Content-Type": "application/json" };
    if (this.config.bearerToken) {
      out.Authorization = `Bearer ${this.config.bearerToken}`;
    }
    return out;
  }
}

export class ChamberHandle implements SandboxProvider {
  constructor(
    private readonly baseUrl: string,
    public readonly chamberId: string,
    private readonly headers: Record<string, string>,
  ) {}

  async runShell(command: string, agentStepId?: string): Promise<ExecResult> {
    const res = await fetch(`${this.baseUrl}/v1/chambers/${this.chamberId}/exec`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({
        command: ["/bin/sh", "-lc", command],
        cwd: "/workspace",
        agent_step_id: agentStepId ?? null,
      }),
    });
    if (!res.ok) {
      throw new Error(`Airlock exec failed: ${res.status}`);
    }
    const data = (await res.json()) as { exit_code: number; stdout: string; stderr: string };
    return {
      exitCode: data.exit_code,
      stdout: data.stdout,
      stderr: data.stderr,
      agentStepId,
    };
  }

  async close(): Promise<void> {
    await fetch(`${this.baseUrl}/v1/chambers/${this.chamberId}`, {
      method: "DELETE",
      headers: this.headers,
    });
  }
}
