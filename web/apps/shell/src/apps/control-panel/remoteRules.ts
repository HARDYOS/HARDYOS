// Addresses and commands for SFTP and WebDAV (File Services and the shared
// folder dialog), kept apart so they can be tested on their own.

/** The WebDAV address of the whole tree, or of one folder in it. */
export function davURL(host: string, folder?: string): string {
  const base = `https://${host}/dav/`;
  return folder ? base + encodeURIComponent(folder) + "/" : base;
}

/** Windows' own name for a WebDAV folder (\\host@SSL\dav\Folder). */
export function davWindowsPath(host: string, folder?: string): string {
  const m = /^(.*):(\d+)$/.exec(host);
  const name = m ? m[1] : host;
  const port = m && m[2] !== "443" ? `@${m[2]}` : "";
  return `\\\\${name}@SSL${port}\\dav${folder ? "\\" + folder : ""}`;
}

/** The sftp:// address of a folder for a domain account. */
export function sftpURL(host: string, netbios: string, folder?: string): string {
  const user = encodeURIComponent(`${netbios}\\yourname`);
  return `sftp://${user}@${host}/${folder ? encodeURIComponent(folder) + "/" : ""}`;
}

/** The command line for OpenSSH's sftp client (quoted for a shell). */
export function sftpCommand(host: string, netbios: string): string {
  return `sftp '${netbios}\\yourname@${host}'`;
}

/** An rclone remote for the WebDAV tree. */
export function rcloneConfig(host: string, netbios: string): string {
  return [
    "rclone config create hardyos webdav \\",
    `  url=${davURL(host)} vendor=other \\`,
    `  user='${netbios}\\yourname' pass="$(rclone obscure 'your password')"`,
  ].join("\n");
}
