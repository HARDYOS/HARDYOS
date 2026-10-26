# HardyOS

A self-hosted NAS and server OS for family and friends: ZFS storage, a
macOS-style web desktop, Docker apps, VMs, and one login for everything.

**Status:** Phase 0–1 (foundations and core OS) in progress. Not ready for real data.

## Repository layout

| Path | What lives there |
| --- | --- |
| `daemon/` | Go control plane: `hardyd` (API server), `hardyd-priv` (root helper), `hardyctl` (CLI) |
| `web/` | React + TypeScript web desktop (`apps/shell`), the app SDK (`packages/sdk`), and the generated API client |
| `api/` | OpenAPI spec, the single source of truth for the HTTP API |
| `os/` | Live ISO and installed-system image build (Debian 13 + OpenZFS) |
| `packaging/` | Debian packages (built with nfpm) and systemd units |
| `apps/` | `.hardyapp` files: one-click Docker apps for the App Center (see `docs/apps.md`) |
| `docs/` | Architecture, decisions, and developer setup |
| `scripts/` | Developer helper scripts |

## Quick start (development)

Requirements: Go 1.26+ (fetched automatically by newer Go toolchains), Node 22+, pnpm 9+.

```sh
make dev-priv     # root helper on .dev/priv.sock (privileged ops need root)
make dev-daemon   # hardyd on http://localhost:8080 (plain HTTP in dev only)
make dev-web      # web desktop on http://localhost:5173, proxied to hardyd
make test         # Go and web tests
```

Building the ISO (WSL2 or any Linux machine with Docker): see
[docs/dev-setup.md](docs/dev-setup.md).

```sh
make iso          # writes dist/hardyos-<version>-amd64.iso
```

## Docs

- [Architecture](docs/architecture.md)
- [Decisions](docs/decisions.md)
- [Developer setup (WSL2 + VMware Workstation)](docs/dev-setup.md)

## License

Proprietary, all rights reserved. See [LICENSE](LICENSE).
