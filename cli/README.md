# @rootwatch/cli — `rootwatch` / `rw`

Terminal control panel, local project scanner, and CI gate for RootWatch.
Talks to any RootWatch instance over the versioned `/api/v1` REST API with
org-scoped Bearer tokens (`rw_…`).

## Install

```bash
npm install -g @rootwatch/cli   # or: npx @rootwatch/cli …
```

From source:

```bash
cd cli && npm install && npm run build
./dist/index.js --help
# or link the binary onto your PATH:
npm link
```

## Connect

```bash
rootwatch login --url https://rootwatch.dev --token rw_xxxxxxxx
rootwatch whoami
rootwatch doctor                  # connectivity + token-scope self-check
```

Tokens are created in the web app under **Org Settings → API tokens**.
Recommended scopes: `read` for status/commands, plus `scan` for
`scan remote` and `write` for `scan local` ingest.

Config lives at `~/.config/rootwatch/config.json` (mode `0600`), supports
named profiles (`--profile staging`), and honors env overrides for CI:
`ROOTWATCH_URL`, `ROOTWATCH_TOKEN`, `ROOTWATCH_PROFILE`.

## Commands

```
rootwatch status                    score + host metrics in the terminal
rootwatch score                     security score rollup
rootwatch events [--severity high] [--status new] [--limit 50] [--watch]
rootwatch vulns [--open] [--severity critical] [--limit 50]
rootwatch listeners ls              listener inventory (alias: ports)
rootwatch listeners stop <pid>      stop a listener (guarded; --yes/--force)
rootwatch hosts                     host inventory
rootwatch scan remote               run server-side security checks now
rootwatch scan [path]               scan a local project (see below)
rootwatch mcp                       run an MCP stdio server over /api/v1
rootwatch org tokens list|create|revoke   (requires admin scope)
rootwatch doctor                    self-check; exits 1 on failure
```

Global flags: `--json` (machine output), `--profile <name>`.

## Local project scanning

`rootwatch scan .` audits the current project and reports findings into your
org's dashboard (requires the `write` scope):

- **Secrets** — AWS keys, GitHub PATs, OpenAI-style keys, private key
  blocks, generic credential assignments. Only file:line + rule id are
  uploaded — never the secret value.
- **Dependencies** — `npm audit` results mapped to findings.
- **Repo hygiene** — committed `.env`, `.gitignore` gaps, `DEBUG=true`,
  permissive CORS.

Findings land under a `projects`/`findings` entity in the dashboard and are
readable via `GET /api/v1/projects/:slug/findings` and the MCP
`list_projects` / `get_project_findings` tools.

## CI usage

```bash
export ROOTWATCH_URL=https://rootwatch.dev
export ROOTWATCH_TOKEN=rw_xxxxxxxx
rootwatch scan --fail-on high     # exits 1 if any finding ≥ High
```

Exit codes: `0` ok · `1` findings above threshold / API failure · `2` usage error.

## MCP for agents

```bash
rootwatch mcp
```

…runs an MCP server on stdio exposing `get_security_score`,
`list_security_events`, `list_vulnerabilities`, `list_listening_ports`,
`list_listeners`, `stop_listener`, `get_host_info`, `list_projects`,
`get_project_findings`, and `run_security_checks`. Point any MCP-capable
client (Claude Desktop, Cursor,
Windsurf…) at it:

```json
{
  "mcpServers": {
    "rootwatch": {
      "command": "rootwatch",
      "args": ["mcp"],
      "env": {
        "ROOTWATCH_URL": "https://rootwatch.dev",
        "ROOTWATCH_TOKEN": "rw_xxxxxxxx"
      }
    }
  }
}
```
