# File sharing (Windows, Mac, Linux, Time Machine)

The shared folders (Control Panel › **Shared Folders**, see
[shares.md](shares.md)) can be opened from the family's computers over SMB,
the protocol Windows and macOS use natively. People sign in with their
**domain account** (Control Panel › Domain), and each folder's "Who can use
it" rules decide what they can do.

## Setting it up

Control Panel › **File Services**.

- **This server runs the domain.** Nothing to do: creating the domain (or
  making this server another domain controller) also connects the file
  server to it. If that step failed, File Services shows **Join the
  domain**: enter the domain Administrator's password.
- **The domain runs elsewhere** (another HardyOS server, or Windows
  Server). Point this server's DNS at the domain's DNS servers (Control
  Panel › Network), then in File Services enter the domain's name (like
  `home.yourname.net`), an administrator account and its password.
- The password is used once to add the server to the domain and isn't
  kept.
- **SMB sharing** turns sharing on or off for the whole server. Each
  shared folder has its own switch too (Shared Folders › Edit ›
  *Windows and Mac file sharing*), on for new folders.
- **Leave the domain** stops sharing. With the Administrator password the
  server's computer account is removed from the domain as well; without
  it the server just forgets the domain. Files and their permissions stay.

The server's name on the network is its host name in capitals
(`HARDYOS`), shown at the top of File Services.

## Who can do what

The rules you set on a shared folder apply over SMB and on disk:

| Rule | Over SMB |
| --- | --- |
| Everyone | every domain account (`HOME\Domain Users`) |
| A group (`HOME\Family`) | its members |
| A person (`HOME\alice`) | that account |
| Read only | open and copy files |
| Read and write | also create, change and delete |
| No access | can't open the folder at all, whatever else applies |

- **Administrators** (Domain Admins, and the HardyOS Admins group) can
  always read and write every shared folder.
- No rules means administrators only.
- A person's own rule wins over their groups' rules on disk: if Everyone
  may write but alice is set to read only, alice can open the folder but
  not change it.
- Rules naming a HardyOS account (not a domain one) don't apply over SMB;
  File Services points them out.
- **Guest access** lets people on the network open the folder read-only
  without signing in (guest connections are `nobody`).

## Connecting

Replace `HARDYOS` with your server's name and `Media` with the folder's
name. File Services lists the exact addresses for every folder.

### Windows

- File Explorer › address bar: `\\HARDYOS\Media`, or right-click
  **This PC › Map network drive**, pick a letter, enter
  `\\HARDYOS\Media` and tick *Reconnect at sign-in*.
- PCs joined to the domain sign in by themselves. Others ask: use
  `HOME\yourname` and your domain password.
- **Previous Versions**: right-click a file or folder › Properties ›
  Previous Versions lists the folder's automatic snapshots; open, copy
  or restore an older copy from there.

### Mac

- Finder › **Go › Connect to Server** (⌘K): `smb://hardyos.home.yourname.net/Media`
  (or `smb://<the server's address>/Media`). The server also shows under
  **Network** in Finder's sidebar.
- Sign in as **Registered User** with `yourname` and your domain password
  (domain: `HOME` if asked). Tick *Remember this password in my keychain*.

### Time Machine (Mac backups)

1. In Shared Folders, edit a folder (Backups is a good one), turn on
   **Time Machine** and optionally set the most each Mac may use. Give the
   folder a quota too, so backups can't fill the pool.
2. On the Mac: System Settings › General › **Time Machine** › Add Backup
   Disk, and pick the folder on your server (it's advertised on the
   network). Sign in with a domain account that may write to it.

Time Machine folders have no recycle bin (Time Machine deletes old backups
itself).

### Linux

- File managers (GNOME Files, Dolphin): `smb://hardyos.home.yourname.net/Media`.
- Terminal, with `cifs-utils` installed:

  ```
  sudo mkdir -p /mnt/media
  sudo mount -t cifs //hardyos.home.yourname.net/Media /mnt/media \
    -o username=yourname,domain=HOME,uid=$(id -u),gid=$(id -g)
  ```

  For Linux machines that should mount by address only, NFS is available
  per folder too (Shared Folders › Edit › NFS).

## Recycle bin

With a folder's **Recycle bin** on, files deleted over SMB go to a hidden
`.recycle` folder inside it, under the name of the person who deleted them,
with their folders kept. Open `\\HARDYOS\Media\.recycle` to get one back
(type the address; it's hidden). Files that have been there for 30 days
are removed automatically.

## Home folders

File Services › **Home folders** gives every domain account its own
private folder on the pool you choose, with an optional quota. It appears
as the person's name on the network (`\\HARDYOS\alice`) and as **Home** in
the File Manager. Folders are made for new accounts within ten minutes;
turned-off or deleted accounts keep their folder (an administrator can
delete it).

## How it works (for administrators)

- The server runs its own Samba file server (`smbd` and `winbind`) as a
  member of the domain, separate from the domain controller's Samba.
  HardyOS writes `/etc/samba/smb.conf` itself: changes made by hand are
  replaced.
- Domain accounts get the same Linux user and group IDs on every HardyOS
  server (100000 + their RID), so file ownership survives moving a pool.
- Permissions are POSIX ACLs on the folders, set by HardyOS from the
  rules. Changing permissions from Windows' Security tab works for files
  you own, but HardyOS sets the folder's top again from its rules.
- Logs: in the Terminal, `journalctl -u smbd -u winbind` and
  `/var/log/samba/`.
