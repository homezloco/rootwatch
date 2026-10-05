/**
 * `rootwatch mcp` — stdio MCP server backed by the REST v1 client.
 * Drop into agent configs:
 *   { "mcpServers": { "rootwatch": { "command": "rootwatch", "args": ["mcp"],
 *     "env": { "ROOTWATCH_URL": "…", "ROOTWATCH_TOKEN": "rw_…" } } } }
 *
 * All protocol traffic is on stdout — never print logs there.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ApiClient, CLI_VERSION, CliError, type ApiResult } from "./client.js";
import { resolveAuth } from "./config.js";

// Exported for the CLI↔MCP tool-parity test (A7) — this list must match
// server/mcp.ts's TOOLS exactly (tests/tool-parity.test.ts enforces it).
export const TOOLS: Tool[] = [
  {
    name: "get_security_score",
    description: "Computed org security score (one number + breakdown).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_compliance_status",
    description:
      "Compliance check results for the organization. Optional framework filter (case-insensitive, e.g. 'PCI-DSS', 'HIPAA'). Returns rows plus a summary.",
    inputSchema: {
      type: "object",
      properties: {
        framework: {
          type: "string",
          description: "Filter by compliance framework (case-insensitive)",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_security_events",
    description: "Security events, newest first. Optional severity/status filters.",
    inputSchema: {
      type: "object",
      properties: {
        severity: { type: "string", description: "critical|high|medium|low" },
        status: { type: "string" },
        limit: { type: "number", description: "max results (default 50)" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_vulnerabilities",
    description: "Tracked vulnerabilities, open first. Optional filters.",
    inputSchema: {
      type: "object",
      properties: {
        severity: { type: "string" },
        status: { type: "string", description: "e.g. open" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_listening_ports",
    description: "TCP/UDP ports currently listening on the monitored host.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "list_listeners",
    description:
      "Enriched inventory of processes listening on TCP/UDP ports: identity, class, risk, and stoppability. Requires the 'read' scope and the local_scanning capability on the server.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "stop_listener",
    description:
      "Stop a listening process by pid (guarded — refusals and elevated_required are reported in the result). Requires the 'write' scope.",
    inputSchema: {
      type: "object",
      properties: {
        pid: { type: "number", description: "PID of the listener process" },
        confirmSystem: {
          type: "boolean",
          description: "Confirm stopping a system/root-owned process",
        },
        disable: {
          type: "boolean",
          description:
            "Also disable the boot-survival mechanism (systemd unit → systemctl disable --now)",
        },
      },
      required: ["pid"],
      additionalProperties: false,
    },
  },
  {
    name: "get_host_info",
    description: "Host inventory: hostname, OS, kernel, IPs, uptime.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "list_projects",
    description: "Projects reported by CLI/CI scans.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_project_findings",
    description: "Findings for the organization, optionally filtered by project slug or id.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: { type: "number", description: "project id" },
        projectSlug: { type: "string", description: "project slug" },
        severity: { type: "string" },
        status: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "run_security_checks",
    description: "Run the host security rule engine now. Requires 'scan' scope.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_system_status",
    description: "Stored system-status rows for the monitored host (component health cards).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "update_vulnerability",
    description:
      "Update a vulnerability's status (Open|In Progress|Resolved|Accepted) and optional assignee. Requires 'write' scope.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Vulnerability id" },
        status: {
          type: "string",
          description: "New status: Open | In Progress | Resolved | Accepted",
        },
        assignedTo: { type: "number", description: "Optional user id to assign" },
      },
      required: ["id", "status"],
      additionalProperties: false,
    },
  },
  {
    name: "list_remediations",
    description: "Remediation proposals and their states. Optional status/risk filters.",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "e.g. proposed, approved, succeeded" },
        risk: { type: "string", description: "safe | guarded | critical" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "propose_remediations",
    description: "Generate remediation proposals from open findings. Requires 'scan' scope.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "approve_remediation",
    description: "Approve a proposed remediation. Requires 'admin' scope.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Remediation action id" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "execute_remediation",
    description:
      "Execute an approved remediation on the host. ssh/firewall categories need confirmRemote. Requires 'admin' scope.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number", description: "Remediation action id" },
        confirmRemote: {
          type: "boolean",
          description: "Acknowledge remote-lockout risk for ssh/firewall plans",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "rollback_remediation",
    description:
      "Roll back a succeeded remediation that recorded a rollback plan. Requires 'admin' scope.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "number", description: "Remediation action id" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "list_devices",
    description:
      "Fleet devices reporting health to this control plane: hostname, OS, last-seen, checks, firewall.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "approve_enrollment",
    description:
      "Approve a pending device enrollment code — mints the write-scope token the agent claims. Requires 'admin' scope.",
    inputSchema: {
      type: "object",
      properties: {
        code: { type: "string", description: "Enrollment code, e.g. RW-4K7M-9Q2P" },
      },
      required: ["code"],
      additionalProperties: false,
    },
  },
  {
    name: "create_api_token",
    description: "Mint an org API token (rw_… returned once). Requires 'admin' scope.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Token label, e.g. 'laptop-reporter'" },
        scopes: {
          type: "array",
          items: { type: "string" },
          description: "Subset of read|write|scan|admin — defaults to ['read']",
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
  },
  {
    name: "create_enrollment_invite",
    description:
      "Mint a pre-authorized device pairing credential (code:secret) for the one-line install command. Requires 'admin' scope.",
    inputSchema: {
      type: "object",
      properties: {
        controlUrl: { type: "string", description: "Control-plane URL to embed" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_capabilities",
    description: "Deployment mode and capability flags for the server. Requires 'read' scope.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "list_device_vulns",
    description:
      "Org-wide fleet CVEs (device package-inventory matches: osv/CVE/EPSS/KEV) with device hostnames. Requires 'read' scope.",
    inputSchema: {
      type: "object",
      properties: {
        deviceId: { type: "number", description: "Filter to a single device id" },
        status: { type: "string", description: "e.g. open, resolved" },
        limit: { type: "number", description: "max results (<= 100, default 100)" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "get_device_report",
    description: "Latest report snapshot for one device id. Requires 'read' scope.",
    inputSchema: {
      type: "object",
      properties: {
        deviceId: { type: "number", description: "Device id (see list_devices)" },
      },
      required: ["deviceId"],
      additionalProperties: false,
    },
  },
  {
    name: "queue_device_command",
    description:
      "Queue a remote action a device picks up on its next report: 'refresh' or 'stop-listener' (payload.pid integer > 1). Requires 'admin' scope.",
    inputSchema: {
      type: "object",
      properties: {
        deviceId: { type: "number", description: "Device id (see list_devices)" },
        type: { type: "string", description: "refresh | stop-listener" },
        payload: { type: "object", description: "stop-listener requires {pid: integer > 1}" },
      },
      required: ["deviceId", "type"],
      additionalProperties: false,
    },
  },
];

export const jsonResult = (data: unknown): CallToolResult => {
  const result = data as Partial<ApiResult<unknown>> | null;
  const payload =
    result && typeof result.status === "number" && "data" in result && "meta" in result
      ? result.data
      : data;
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
};

function pickQuery(
  args: Record<string, unknown>,
  keys: string[],
): Record<string, string | number | undefined> {
  const q: Record<string, string | number | undefined> = {};
  for (const k of keys) {
    const v = args[k];
    if (typeof v === "string" || typeof v === "number") q[k] = v;
  }
  return q;
}

export async function runMcpServer(profileFlag?: string): Promise<void> {
  const auth = resolveAuth(profileFlag);
  if (!auth.token) {
    throw new CliError("no API token — set ROOTWATCH_TOKEN or run `rootwatch login`", {
      code: "unauthorized",
    });
  }
  const client = new ApiClient(auth.url, auth.token);

  const server = new Server(
    { name: "rootwatch", version: CLI_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    try {
      switch (request.params.name) {
        case "get_security_score":
          return jsonResult(await client.get("/score"));
        case "get_compliance_status":
          return jsonResult(await client.get("/compliance", pickQuery(args, ["framework"])));
        case "list_security_events":
          return jsonResult(
            await client.get("/events", pickQuery(args, ["severity", "status", "limit"])),
          );
        case "list_vulnerabilities":
          return jsonResult(
            await client.get("/vulnerabilities", pickQuery(args, ["severity", "status", "limit"])),
          );
        case "list_listening_ports":
          return jsonResult(await client.get("/ports"));
        case "list_listeners":
          return jsonResult(await client.get("/listeners"));
        case "stop_listener": {
          const pid = Number(args.pid);
          if (!Number.isInteger(pid) || pid <= 0) {
            throw new McpError(ErrorCode.InvalidParams, "A positive integer 'pid' is required");
          }
          return jsonResult(
            await client.post(`/listeners/${pid}/stop`, {
              confirm: true,
              confirmSystem: args.confirmSystem === true,
              disable: args.disable === true,
            }),
          );
        }
        case "get_host_info": {
          const current = await client.get<{ host: unknown }>("/hosts/current");
          return jsonResult(current.data.host);
        }
        case "list_projects":
          return jsonResult(await client.get("/projects"));
        case "get_project_findings": {
          const project = args.projectSlug ?? args.projectId;
          const path =
            project === undefined
              ? "/findings"
              : `/projects/${encodeURIComponent(String(project))}/findings`;
          return jsonResult(
            await client.get(path, pickQuery(args, ["severity", "status", "limit"])),
          );
        }
        case "run_security_checks":
          return jsonResult(await client.post("/scans/security-checks", {}));
        case "get_system_status": {
          // Read the same stored statuses as the direct MCP tool, without live-collector side effects.
          return jsonResult(await client.get("/system-status"));
        }
        case "update_vulnerability": {
          const id = Number(args.id);
          if (!Number.isInteger(id) || id <= 0) {
            throw new McpError(ErrorCode.InvalidParams, "A positive integer 'id' is required");
          }
          const body: Record<string, unknown> = { status: args.status };
          if (typeof args.assignedTo === "number") body.assignedTo = args.assignedTo;
          return jsonResult(await client.patch(`/vulnerabilities/${id}`, body));
        }
        case "list_remediations":
          return jsonResult(
            await client.get("/remediations", pickQuery(args, ["status", "risk", "limit"])),
          );
        case "propose_remediations":
          return jsonResult(await client.post("/remediations/propose", {}));
        case "approve_remediation": {
          const id = Number(args.id);
          if (!Number.isInteger(id) || id <= 0) {
            throw new McpError(ErrorCode.InvalidParams, "A positive integer 'id' is required");
          }
          return jsonResult(await client.post(`/remediations/${id}/approve`, {}));
        }
        case "execute_remediation": {
          const id = Number(args.id);
          if (!Number.isInteger(id) || id <= 0) {
            throw new McpError(ErrorCode.InvalidParams, "A positive integer 'id' is required");
          }
          return jsonResult(
            await client.post(`/remediations/${id}/execute`, {
              confirmRemote: args.confirmRemote === true,
            }),
          );
        }
        case "rollback_remediation": {
          const id = Number(args.id);
          if (!Number.isInteger(id) || id <= 0) {
            throw new McpError(ErrorCode.InvalidParams, "A positive integer 'id' is required");
          }
          return jsonResult(await client.post(`/remediations/${id}/rollback`, {}));
        }
        case "list_devices":
          return jsonResult(await client.get("/devices"));
        case "approve_enrollment": {
          const code = String(args.code ?? "").trim();
          if (!code) {
            throw new McpError(ErrorCode.InvalidParams, "'code' is required");
          }
          return jsonResult(await client.post(`/enroll/${encodeURIComponent(code)}/approve`, {}));
        }
        case "create_api_token": {
          const name = String(args.name ?? "").trim();
          if (!name) {
            throw new McpError(ErrorCode.InvalidParams, "'name' is required");
          }
          const body: Record<string, unknown> = { name };
          if (Array.isArray(args.scopes)) body.scopes = args.scopes;
          return jsonResult(await client.post("/tokens", body));
        }
        case "create_enrollment_invite": {
          const body: Record<string, unknown> = {};
          if (typeof args.controlUrl === "string" && args.controlUrl) {
            body.controlUrl = args.controlUrl;
          }
          return jsonResult(await client.post("/enroll/bootstrap", body));
        }
        case "get_capabilities":
          return jsonResult(await client.get("/capabilities"));
        case "list_device_vulns":
          return jsonResult(
            await client.get(
              "/devices/vulnerabilities",
              pickQuery(args, ["deviceId", "status", "limit"]),
            ),
          );
        case "get_device_report": {
          const deviceId = Number(args.deviceId);
          if (!Number.isInteger(deviceId) || deviceId <= 0) {
            throw new McpError(
              ErrorCode.InvalidParams,
              "A positive integer 'deviceId' is required",
            );
          }
          return jsonResult(await client.get(`/devices/${deviceId}/report`));
        }
        case "queue_device_command": {
          const deviceId = Number(args.deviceId);
          if (!Number.isInteger(deviceId) || deviceId <= 0) {
            throw new McpError(
              ErrorCode.InvalidParams,
              "A positive integer 'deviceId' is required",
            );
          }
          const body: Record<string, unknown> = { type: args.type };
          if (args.payload && typeof args.payload === "object") body.payload = args.payload;
          return jsonResult(await client.post(`/devices/${deviceId}/commands`, body));
        }
        default:
          throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
      }
    } catch (e) {
      if (e instanceof McpError) throw e;
      throw new McpError(ErrorCode.InternalError, e instanceof Error ? e.message : String(e));
    }
  });

  await server.connect(new StdioServerTransport());
}
