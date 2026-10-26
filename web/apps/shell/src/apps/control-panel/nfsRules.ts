/** NFS client rules, checked like the server does (shares.CheckServices). */

function ipv4(a: string): boolean {
  const parts = a.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function ipv6(a: string): boolean {
  if (!a.includes(":") || /[^0-9A-Fa-f:.]/.test(a)) return false;
  try {
    return new URL(`http://[${a}]/`).hostname !== "";
  } catch {
    return false;
  }
}

/** Why an NFS client entry can't be used, or null when it's fine. */
export function nfsClientProblem(client: string): string | null {
  const c = client.trim();
  if (c === "") return "Enter an address like 192.168.1.50 or a network like 192.168.1.0/24.";
  const [addr = "", bits, extra] = c.split("/");
  if (extra !== undefined) return `${c} isn't an address or network.`;
  const v4 = ipv4(addr);
  const v6 = !v4 && ipv6(addr);
  if (!v4 && !v6) return `${c} isn't an address or network like 192.168.1.0/24 (names aren't accepted).`;
  if (bits === undefined) {
    if (v4 ? addr === "0.0.0.0" : /^[0:]+$/.test(addr)) return `${c} isn't a computer's address.`;
    return null;
  }
  const max = v4 ? 32 : 128;
  if (!/^\d{1,3}$/.test(bits) || Number(bits) > max) return `The network size after / must be 1 to ${max}.`;
  if (Number(bits) === 0) return "NFS can't be opened to every address; name a network like 192.168.1.0/24.";
  return null;
}

/** The shell commands that mount a folder exported at path from host. */
export function mountCommands(host: string, path: string, id: string): { linux: string; fstab: string; mac: string; finder: string } {
  const h = host.includes(":") ? `[${host}]` : host;
  return {
    linux: `sudo mkdir -p /mnt/${id}\nsudo mount -t nfs ${h}:${path} /mnt/${id}`,
    fstab: `${h}:${path}  /mnt/${id}  nfs  defaults,_netdev  0  0`,
    mac: `mkdir -p ~/${id}\nsudo mount -t nfs -o resvport,rw ${h}:${path} ~/${id}`,
    finder: `nfs://${h}${path}`,
  };
}
