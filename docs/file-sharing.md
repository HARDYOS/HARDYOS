# File sharing

How the family reaches the files on the NAS. The design is in
[plans/file-sharing.md](plans/file-sharing.md); shared folders themselves
are in [shares.md](shares.md).

## File Manager

The **File Manager** app (in the dock and on the desktop) opens the shared
folders you may use, plus your own **Home** folder, in the web desktop.
Everything you do happens as you: you see and change only what your access
allows, exactly as over the network.

![File Manager in grid view with two photos selected](images/files/file-manager-grid.png)

### Finding your way

- **Places** on the left: Home, then the shared folders you can use
  (marked *read only* where you can only look). Hidden system folders such
  as the recycle bin and snapshots never show.
- **Breadcrumbs** at the top take you back to any folder on the way; the up
  arrow (or **Backspace**) goes up one.
- **List** or **grid** view (the switch at the top right; grid shows photo
  thumbnails). Click a column heading in the list to sort by name, date or
  size; click it again to reverse. Folders always come first. The File
  Manager remembers your choice.
- **Filter** narrows the current folder to names containing what you type.
- On a phone or in a narrow window the places become a strip along the
  top and the buttons shrink to icons.

### Selecting and the keyboard

- Click to select, **Ctrl/Cmd+click** to add or remove one, **Shift+click**
  to select a range. **Ctrl/Cmd+A** selects everything, **Esc** clears.
- **Arrow keys** move (with Shift they extend the selection), **Enter**
  opens a folder or previews a file, **Space** previews, **Backspace** goes
  up, **Delete** deletes, **F2** renames.
- **Right-click** an item for everything you can do with it; right-click
  empty space for New folder and Upload.

### Working with files

- **Upload**: drag files from your computer onto the window, or use
  **Upload**. Files go up in pieces with a progress bar each; the cross
  cancels one. Nothing is ever replaced: a name that's taken gets " (2)".
  Dragging a whole folder isn't supported yet; make the folder and drop its
  files in.
- **Download** a file, or select folders or several items and get them as
  one zip.
- **New folder**, **Rename** (F2), **Move to…** and **Copy to…** (pick any
  folder you can change, in any shared folder or Home), **Properties**.
- **Delete** says what will happen: in a folder with a recycle bin, items
  go there and are kept for 30 days (an administrator can get them back);
  without one they are gone for good unless a snapshot still has them.
- **Quick preview** (Enter, Space or double-click): photos, PDFs, text
  files (the first 256 KB), video and music. The arrows (or ← →) step
  through the folder; Esc closes.

### Previous versions

Select a file or folder and choose **Previous versions**. The panel lists
the older copies kept by the folder's automatic snapshots (hourly, daily,
weekly, monthly). **Download** saves that old copy; **Restore** puts it
back next to the current one (named "… (restored <date>)" when the name is
taken), so restoring never loses anything.

![Previous versions of a text file](images/files/file-manager-versions.png)

### Share links

Select one file or folder and choose **Share link** to give it to someone
without an account. You can share what you're allowed to change;
administrators can share anything.

- **Works for** 1, 7 (the default), 30 or 90 days.
- **Password** (at least 6 characters): tell it to people some other way.
- **Let people add files** (folders only): visitors can upload into the
  folder, never change or delete anything. Their files never replace
  yours.
- **Download limit**: the link stops after that many downloads.

The link is shown **once**: copy it then. HardyOS keeps only a fingerprint
of it, so nobody (not even an administrator) can read it back later.

The person opening it gets a simple HardyOS page outside the desktop: the
folder's files (and its subfolders) to download one by one or all as a
zip, or the one file, plus the upload box when allowed.

![A shared folder opened from a link](images/files/share-link-page.png)

A link stops working when it expires, when it is turned off, when its
download limit is reached, and also when the person who made it loses
access to what it points at, or their account is disabled or deleted:
files are always read as that person.

**Links I've shared** (under Sharing in the File Manager) lists your links
with their status, expiry and download count; **Turn off** stops one at
once. Administrators also see **All links** and can turn off anyone's.

![Links I've shared](images/files/file-manager-links.png)

Links work on your home network now; reaching them from outside comes
with remote access (the reverse proxy). Every link made, used (downloads,
uploads, wrong passwords) and turned off is in the Log Center.

### For developers

- Web: `web/apps/shell/src/apps/files/` (`FileManager.tsx`, dialogs,
  `Uploads.tsx` for the chunked upload queue, `Preview.tsx`,
  `Versions.tsx`, `SharedLinks.tsx`, pure helpers in `paths.ts` and
  `selection.ts`). Tests mock the API with a stubbed `fetch`.
- It consumes the files API (`/api/v1/files/*`, part C of the plan) and the
  share link API (`/api/v1/sharelinks`). Both are in `api/openapi.yaml`.
- Share links: `daemon/internal/sharelinks` (store, public pages,
  rate limiter; `linktest` has a fake `files.Access` over a temp dir) and
  `daemon/internal/api/handlers_sharelinks.go`. See
  [architecture.md](architecture.md#file-manager-and-share-links).
