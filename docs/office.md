# Office: documents, spreadsheets, presentations and notes

HardyOS opens Word, Excel and PowerPoint files (and their OpenDocument
cousins, CSV and plain text) in an editor window on the desktop. Several
people can edit one file at once, with comments and tracked changes, and
every save goes back into the shared folder as the person who made it.
Notes is a small built-in app for Markdown notes and a family or team wiki.

Phase 7 part B. Decisions 250-262; the design is in
[architecture.md](architecture.md#office).

## Turning it on

Control Panel › Office › **Turn on the office suite**. HardyOS installs the
OnlyOffice Document Server (Community Edition 9.4, about 1.5 GB to download;
4 GB of memory recommended) from its own app catalog, gives it a secret only
HardyOS and the Document Server know, starts it and waits until it answers.
The first start takes a few minutes. If no app is installed yet, choose the
pool apps go on.

The Document Server is an app like the others (App Store › My apps shows
it, with its logs, updates and snapshots), but it's installed and set up
only from Control Panel › Office: the App Store refuses to install it on
its own, and its secret can't be changed from the app's settings.

**Turn off** stops it (its data stays). While people are editing, HardyOS
asks first: what they haven't saved is lost.

Settings:

- **Largest document**: files bigger than this (default 100 MB) download
  instead of opening, and saves bigger than this are refused.
- **Extra fonts**: a shared folder with `.ttf`, `.otf` or `.ttc` files. It's
  given to the Document Server read only, which reads it when it starts (the
  save restarts it).

### The 20-editor limit

The free Community Edition allows **20 people editing at the same time**,
across all documents. Control Panel › Office shows how many are editing and
which documents are open. When 20 are editing, the next person's document
opens read only, with a note saying why; it works again as soon as someone
closes theirs. Viewing doesn't count.

## Opening documents

In the File Manager:

- **Double-click** a `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.odp`,
  `.rtf`, `.csv` or `.txt` file to open it in the editor. Older `.doc`,
  `.xls` and `.ppt` files open read only (save a copy as `.docx` and so on to
  edit them). With the office suite off, double-click previews or downloads
  as before.
- Right-click: **Open in editor** or **Open read only**.
- **New document** (toolbar, or right-click in an empty part of a folder):
  a document, spreadsheet or presentation, made empty in that folder and
  opened.

Each file opens in its own window. If you can read a file but not change
it, it opens read only and says so. Home folders are each person's own: two
people opening "plan.docx" in their own Home edit two different files.

### Working together

Everyone who opens the same file while it's open joins the same editing
session: you see each other's cursors and names (HardyOS display names;
people from share links show as "Name (guest)"), changes appear as they're
typed, and comments, chat and tracked changes (Review tab) work as in
OnlyOffice. The editor saves on its own a few seconds after the last person
closes the file, and when someone presses Save.

### Saving and versions

- A save is written as the **last person who changed the file**, through the
  same file worker as the File Manager, so the folder's permissions apply.
  If that person can no longer change the file (their access was taken away,
  their account turned off, the link they used was turned off), the save is
  refused and recorded; the Document Server keeps the edits, and Control
  Panel › Office shows the document with the error.
- If the file was **changed somewhere else** while it was open (over SMB,
  by another app), the editor's version is saved next to it as
  "Plan (edited by Alice 2026-10-27 1504).docx" instead of over the other
  change. The same happens if the file was moved or deleted meanwhile.
- **Older versions** come from the folder's snapshots: right-click ›
  Previous versions in the File Manager, or Previous Versions in Windows.
  Turn on hourly snapshots for folders where people edit a lot. OnlyOffice's
  own version history isn't kept (decision 257); saves don't go to the
  recycle bin either.
- Every opening (`office.open`) and save (`files.write`) is in the audit log
  (Control Panel › Security), with who did it.

## Share links for editing

A share link to a document (or a folder) can let people without an account
open documents in their browser:

- **People can: View only** (the default) opens documents read only in the
  browser editor.
- **Edit in their browser** must be chosen on purpose. At most 5 people
  edit through one link at once (more open it read only). Download and Print
  are offered only on edit links without a download limit. Their changes are
  saved over the shared copy, as you (the person who made the link), so you
  must still be allowed to change the file. Consider a password and a short
  expiry. Only files the editor can save (and folders) can be shared for
  editing.

Visitors are asked for a name to show the others in the document (brackets
and quotes are left out). Turning a link off puts its visitors out of the
document straight away. Everything else about links stays the same: expiry,
password, and the audit log (`office.open` and `files.write` by "link #3 of alice
(visitor: Sam)"). Turning a link off or letting it expire stops its editors
saving.

From outside the home network the editor works at `files.<base>` (Control
Panel › Remote Access), like the link pages themselves.

## Notes

Notes (in the dock) keeps Markdown notes as `.md` files in a folder you
choose: `Home/Notes` by default, or a shared folder as a family or team
wiki. Because they're ordinary files, the folder's permissions decide who
can read and edit, they show in the File Manager, keep older versions in
Previous Versions and are backed up with the folder.

- **+** makes a note; the list is newest first and can be filtered.
- Write, Both (side by side) or Read. Notes save a moment after you stop
  typing (Ctrl+S saves at once).
- `[[Shopping list]]` links to the note of that name in the same folder
  (and makes it if it isn't there); `[[Shopping list|the list]]` shows other
  words. Links to web pages open in a new tab. Task lists (`- [ ] milk`),
  headings, lists, quotes, code and emphasis are shown; HTML in a note is
  shown as text, never run.
- If someone else saved the note after you opened it, nothing is written:
  choose **Save mine as a copy**, **Load theirs** or **Keep mine**.

## Checking it by hand

The CI job "Office" runs the real Document Server and checks the one-time
document download, the JWT and a save through a callback. A real browser
editing session isn't automated; after changes, check on a test server:

1. Turn the office suite on; open a `.docx` from the File Manager. The
   window's address (Open frame in new tab) is `https://<server>:44250/...`,
   never the desktop's own.
2. Open the same file as a second person in another browser: both cursors
   and names show; type in both.
3. Close both; within a few seconds the file's modified time changes and the
   audit log has `files.write` by the last person who typed.
4. Make an edit link, open it from another device: "Name (guest)" shows; the
   save is recorded as "link #N of you (visitor: Name)".
5. The Document Server publishes no port: `docker ps` shows none for it,
   and on the server `sudo -u nobody curl http://<its address>/healthcheck`
   is refused (only hardyd may connect).

## For developers

- `daemon/internal/office`: JWTs, document keys, sessions, the internal
  listener (downloads, callbacks), the proxy and its gate cookie, the editor
  page, blank documents. `integration_test.go` is the gated test the CI job
  runs (`HARDYOS_OFFICE_INTEGRATION=1`, see its comment for the variables).
- `daemon/internal/api/handlers_office.go`: Control Panel › Office, opening,
  new documents, share link editors, the two listeners and the jobs
  (`office.enable`, `office.disable`, `office.settings`).
- `apps/catalog/onlyoffice`: the app package (image pinned by digest).
- Web: `apps/office` (editor window, helpers), `apps/notes`,
  `control-panel/Office.tsx`, File Manager and share link dialog changes.
