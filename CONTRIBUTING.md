# Contributing

RootWatch's development trunk is a private monorepo
(`homezloco/rootwatch-cloud`). This repo is a public mirror of the
client-side components, synced from the trunk on each release — history
here is a flattened snapshot, not the real commit history.

## Issues

Bug reports and feature requests are welcome on this repo. Name the
component (`agent/`, `cli/`, `desktop/`, `packaging/`, `scripts/`) and the
version or commit you're running.

## Pull requests

PRs against this repo are welcome. Maintainers review here and backport
accepted changes into the private trunk — they'll land in this repo on the
next mirror rather than via a direct merge of the PR, so authorship is
preserved in the commit message.

Bugs that require server-side changes (API behavior, dashboard) can't be
fixed from this repo — file them as issues and maintainers will pick them
up in the trunk.

## Development

Each component is self-contained:

```bash
# agent — zero-dep Node 18+, no build step
node agent/agent.mjs --help

# cli — TypeScript, builds to cli/dist
cd cli && npm install && npm run build && npm run check

# desktop — Electron; tests run under plain node:test
cd desktop && npm install && npm test && npm run dist:dir
```

## Rules that apply here too

- Real data only — collectors and scanners must degrade to honest
  `unsupported`/`refused` answers, never fabricated results.
- No shell across privilege boundaries — argv allowlists + `execFile`/`exec`.
- Never emit secret values in findings, logs, or command output.
