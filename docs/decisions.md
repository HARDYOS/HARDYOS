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
| 15 | 2026-10-24 | SQLite (pure-Go driver) for control-plane state, at /var/lib/hardyos until a pool exists | No cgo, builds for any arch; moves to tank/system later |
| 16 | 2026-10-24 | HTTPS by default with a self-signed certificate; HTTP redirects | Session cookies are Secure; ACME and uploaded certs come later |
| 17 | 2026-10-24 | Argon2id passwords, hashed session tokens, SameSite=Strict cookies plus an X-HardyOS-Request header for CSRF | Standard, simple, no tokens in JavaScript |
| 18 | 2026-10-24 | First admin is a break-glass local account; `hardyctl reset-password` / `create-admin` work on the database directly as root | Recovery never depends on the web UI or directory services |
| 19 | 2026-10-24 | Parse `zpool`/`zfs` text output (-H/-p) rather than JSON output | Works on every OpenZFS 2.x; verified against real ZFS in CI |
| 20 | 2026-10-24 | Pool encryption via per-pool key files (auto-unlock at boot) | Protects removed disks without a passphrase prompt at every boot; passphrase mode can come later |
| 21 | 2026-10-24 | Special-vdev parity lower than the data vdevs is a warning, not an error | 2-way special mirrors are common and reasonable; the user decides |
| 22 | 2026-10-24 | Installer copies the live image (unsquashfs) instead of downloading packages | Installs work offline and install exactly the tested image |
| 23 | 2026-10-24 | Kernels on each disk's ESP, GRUB never reads ZFS; one grub.cfg entry per boot environment | Full ZFS features on rpool, no bpool, same layout for UEFI and BIOS, every mirror disk boots alone |
| 24 | 2026-10-24 | `/var/lib/hardyos` is a separate dataset shared by all boot environments | Accounts and settings survive switching boot environments; database migrations stay forward-only |
| 25 | 2026-10-24 | The installer creates the first admin and passes only the password hash to root | No setup race on first boot; the plain password never leaves hardyd |
| 26 | 2026-10-24 | Install steps are registered only on the live ISO | An installed system has no API that can repartition boot disks |
| 27 | 2026-10-25 | Accent colors follow the HardyOS logo: cyan solid accent, cyan-to-violet gradient for primary actions with near-black text | Matches the brand; white text fails contrast on cyan, near-black passes at least 6:1 across the gradient |
| 28 | 2026-10-25 | Updates are whole signed system images (ed25519), installed into a new boot environment | Atomic: a version is either fully there or not; the same image as the ISO; no package-by-package upgrades to go wrong |
| 29 | 2026-10-25 | The release signing key stays on Cade's release computer; servers trust compiled-in public keys | Matches building releases locally; a GitHub account compromise can't ship updates |
| 30 | 2026-10-25 | New versions boot once via GRUB `next_entry` and become the default only after hardyd confirms health | A version that can't start falls back by itself, even after a kernel panic or power cycle |
| 31 | 2026-10-25 | Settings are snapshotted right before restarting into an update and restored if it fails | The old version never meets a database migrated by a version that didn't work |
| 32 | 2026-10-25 | Network settings stay on ifupdown (no NetworkManager or systemd-networkd), rendered from one settings file | Debian's default for servers, already used by the installer; plain files are easy to inspect and restore |
| 33 | 2026-10-25 | Network changes undo themselves unless confirmed within 3 minutes | A wrong address or gateway can't lock anyone out of a headless server |
