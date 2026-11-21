# Hostnames

Control Panel › Hostnames gives every app its own address under your base
domain, with a certificate every browser trusts:

| Address | Opens |
| --- | --- |
| `https://nas.home.example.net` | the desktop (its name from Remote Access) |
| `https://sso.home.example.net` | HardyOS sign-in |
| `https://files.home.example.net` | share links |
| `https://office.home.example.net` | the office editor |
| `https://photos.home.example.net` | Photos (Immich) |
| `https://mail.home.example.net` | webmail, plus mail-app settings and calendars |
| `https://<app>.home.example.net` | any other app with a web page |

Each app then runs on its own origin: its cookies, storage and scripts are
apart from the desktop's and from every other app's. Without hostnames,
apps open on ports of the server's own address, which browsers treat as one
site (see [apps.md](apps.md)).

## Setting it up

1. **A Cloudflare API token.** In Cloudflare, My Profile › API Tokens ›
   Create Token › Custom token: permission **Zone › DNS › Edit**, zone
   resources **Include › Specific zone ›** the zone your base domain is in.
   Nothing else.
2. Paste it with the base domain (Remote Access's, if you set one there).
   HardyOS checks it with Cloudflare. Only the system's root helper keeps
   it, encrypted; the desktop never shows it again ("set, last verified").
3. Turn on **Use hostnames**. HardyOS gets a `*.<base>` certificate from
   Let's Encrypt by adding a temporary `_acme-challenge` record in
   Cloudflare (about a minute), and renews it by itself 30 days before it
   expires. **Test certificate** uses Let's Encrypt's staging server while
   you try things out.
4. **Make the names reach this server at home** (below), then open the
   desktop at `https://nas.<base>`. Apps opened from there open at their
   own names; the desktop offers to switch when you use it at its address.

## Names at home

Public DNS sends `*.<base>` to NetBird's reverse proxy (Remote Access), which
only has what you published. At home, devices should go straight to this
server. Choose one:

- **This server's domain controller.** If HardyOS runs your domain
  (Control Panel › Domain) and devices use it for DNS, **Add the names**
  puts an A record for each name in its DNS (in the domain's own zone if the
  base domain is the domain or inside it, otherwise in a new zone for the
  base domain on the DC, which then answers for every name under it at
  home). Names another record already uses are left alone, and **Remove
  them** only removes what HardyOS added.
- **Your router.** Add the listed records as local DNS entries (Pi-hole,
  OpenWrt and dnsmasq take the `address=/name/ip` lines shown).
- **Over NetBird**, the same names work at the server's NetBird address for
  devices whose DNS points there.

Devices that can't resolve the names keep working at the server's address:
apps there still open on their ports. Old port addresses used with a name
under the base redirect to the new ones.

## Turning it off

Turn off **Use hostnames**, or **Forget token** (type the base domain):
the certificate is removed and apps open on ports again. DNS records stay
in Cloudflare and on the domain controller until you remove them.

## For later

hardyd-priv can also set one A, AAAA or CNAME record under the base domain
(`dns.record.set`, only records it made itself). A later release uses it to
point names at this server instead of NetBird's proxy.
