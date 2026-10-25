# Decisions

Settled choices, newest last. Change one by adding a row that supersedes it.

| # | Date | Decision | Why |
| --- | --- | --- | --- |
| 1 | 2026-10-24 | Base on Debian 13 (trixie) stable, custom installer ISO | Proven kernel and drivers; effort goes into the product |
| 2 | 2026-10-24 | x86_64 first, code kept architecture-neutral | ARM64 can become a second build target later |
| 3 | 2026-10-24 | OpenZFS for storage, optional special vdev, SLOG and L2ARC | Checksums, snapshots, RAIDZ expansion, replication |
| 4 | 2026-10-24 | Go for the control plane | Linux, Docker and libvirt libraries; single static binary |
| 5 | 2026-10-24 | React + TypeScript web desktop, macOS-style layout | Large ecosystem; familiar dock and menu bar |
| 6 | 2026-10-24 | Split daemon: unprivileged `hardyd` + root `hardyd-priv` with a fixed op allowlist | Limits what a bug or compromise in the API can do |
| 7 | 2026-10-24 | ZFS boot environments for updates and rollback | Roll back to any previous version, same as TrueNAS |
| 8 | 2026-10-24 | Fully web-based installer with a one-time code on the console | Install headless servers from any browser |
| 9 | 2026-10-24 | Local admin accounts in Phase 1, migrated to Samba AD later, plus a break-glass admin | Works before AD and Authentik exist |
| 10 | 2026-10-24 | Integrate Samba 4 (AD DC), Authentik (SSO), RustFS (S3); build everything else | Ownership of the product, reuse of hard infrastructure |
| 11 | 2026-10-24 | GitHub + Actions for code and CI; ISOs built locally in WSL2 via Docker | Private repo: save Actions minutes for tests |
| 12 | 2026-10-24 | Pull requests for every change, CI must pass | Reviewable history |
| 13 | 2026-10-24 | Proprietary license, all rights reserved | Family use; can open source later |
| 14 | 2026-10-24 | Fonts bundled with the web desktop (no Google Fonts at runtime) | The NAS must work fully offline |
