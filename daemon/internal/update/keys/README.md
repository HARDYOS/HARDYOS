# Trusted release keys

Public keys in this directory (`*.pub`) are compiled into HardyOS. A server
installs an update only when its manifest is signed by one of them.

Create the release key once, on the computer that builds releases:

```sh
make release-key
```

That writes the private key to `~/.config/hardyos/release.key` (keep it safe
and backed up; never commit it) and the public key to
`daemon/internal/update/keys/release.pub`. Commit the public key.

For testing, a server also trusts keys in `/etc/hardyos/trusted-keys.d/*.pub`
(root-owned, carried over between versions).
