# HardyOS: notes for Claude Code sessions

HardyOS is a custom Debian 13 based NAS/server OS with a Go control plane and a
React web desktop. Read `docs/architecture.md` and `docs/decisions.md` before
large changes.

## Ground rules

- Only `hardyd-priv` runs as root, and it exposes a fixed allowlist of
  operations over `/run/hardyos/priv.sock`. Never add a generic "run command"
  operation. New privileged work = a new named op with validated arguments.
- Every state-changing API call goes through the job system and audit log
  (from Phase 1 PR 2 onward).
- `api/openapi.yaml` is the source of truth. After changing it, run
  `make gen` to regenerate the TypeScript client, and keep Go handlers in sync.
- Destructive storage operations (pool destroy, disk wipe, dataset destroy)
  require an explicit confirmation field in the request and must never run
  from tests against real disks. Tests use file-backed vdevs or fakes.
- Architecture-neutral: no x86-only code in Go or web. CPU-specific features
  are optional capabilities detected at runtime.
- x86_64 is the only build target for now; keep GOARCH out of source files.

## Layout

- `daemon/cmd/{hardyd,hardyd-priv,hardyctl}`: binaries
- `daemon/internal/...`: packages (api, priv, version, ...)
- `web/apps/shell`: the web desktop; `web/packages/sdk`: app SDK;
  `web/packages/api-client`: generated from the OpenAPI spec
- `os/`: live-build config and ISO build script (runs in Docker)
- `packaging/`: nfpm configs and systemd units

## Commands

- `make test`: Go tests (`go test ./...`) and web typecheck + tests
- `make build`: Go binaries into `dist/bin`, web build into `web/apps/shell/dist`
- `make deb`: Debian packages into `dist/`
- `make iso`: full ISO (needs Docker with `--privileged`)

## Workflow

- Work on a branch and open a pull request; CI must pass before merge.
- Style: `gofmt`, `go vet`; TypeScript strict mode.
- UI follows the mockups: dark glass panels, blue accent `#3B7BFF`,
  Plus Jakarta Sans for UI text, JetBrains Mono for numbers.
