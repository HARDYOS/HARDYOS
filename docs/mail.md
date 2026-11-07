# Mail server

HardyOS runs the family's mail at home: a mailbox for every domain account,
webmail in the desktop, IMAP and SMTP for phones and computers, calendars and
contacts (with a shared family calendar and address book), spam filtering
and optional virus scanning. Control Panel › Mail sets it up; the **Mail**
app in the dock is where each person reads mail (webmail) and finds how to
set up their devices.

Architecture: [architecture.md › Mail server](architecture.md#mail-server);
decisions 239-249.

```
                      internet
                         │  MX → mail.<base> (the VPS's public address)
                         ▼
   ┌──────────────────── VPS (vpn.hardynetworks.net) ────────────────────┐
   │ Postfix :25   relay for your domains, checks recipients with home,  │
   │               queues up to 14 days while home is offline            │
   │ HAProxy :993 :465 :587   TCP to home with the PROXY protocol        │
   │ NetBird server + reverse proxy :443 (https://mail.<base>)           │
   └──────────────┬──────────────────────────────────────────────────────┘
                  │ WireGuard (NetBird)
                  ▼
   ┌──────────────────────────── HardyOS ────────────────────────────────┐
   │ Postfix :2525 (VPS only)  :10465/:10587 (PROXY, VPS only)           │
   │         :465/:587 (LAN)  ── Rspamd (spam, DKIM) ── Dovecot LMTP     │
   │ Dovecot :993 (LAN)  :10993 (PROXY, VPS only)  ── mailboxes on       │
   │                                                  <pool>/mail        │
   │ hardyd: sign-ins (127.0.0.1:44250), /dav-mail/ → Radicale,          │
   │         autoconfig/autodiscover, Control Panel › Mail               │
   │ Roundcube (App Store) in the desktop, signed in by HardyOS          │
   └──────────────┬──────────────────────────────────────────────────────┘
                  │ SMTP + STARTTLS (verified)
                  ▼
           Amazon SES  ──►  the rest of the world
```

## Before you start

- **A pool** for the mail (a dataset `<pool>/mail` is made on it).
- **The domain controller** (Control Panel › Domain): mailboxes belong to
  domain accounts, and people sign in to mail with their domain password.
- **NetBird** (Control Panel › Remote Access): this server must be on the
  same NetBird network as the VPS. Note the VPS's NetBird address (the
  NetBird dashboard › Peers, or `netbird status` on the VPS).
- **The VPS** (Debian or Ubuntu, root access) with TCP 25, 465, 587 and 993
  open in its provider's firewall. Many providers block port 25 for new
  accounts until you ask.
- **Amazon SES** in a region near you, with an IAM user for HardyOS (see
  below). New SES accounts are in the *sandbox* (they only send to verified
  addresses) until you request production access in the AWS console.
- **Cloudflare** for your domains' DNS (optional, but needed for Let's
  Encrypt certificates and for publishing the records automatically).

## Setting it up

1. **Control Panel › Mail › Domains & DNS**: add your mail domain(s), like
   `example.net`. The first one becomes the domain for new mailboxes.
2. **Setup**: choose the pool, the mail server's name (like
   `mail.hardynetworks.net`; mail apps connect to it and the MX points to
   it), the VPS's NetBird address and its public IPv4 address. Enter the SES
   region, access key ID and secret access key, and (for Let's Encrypt) a
   Cloudflare token. Optionally set **Notifications from** (an address at
   your domain) so HardyOS's alerts can be sent through this server. Turn
   **Mail server** on and press **Save and apply**.
3. **VPS**: copy or download the script and run it on the VPS as root
   (`sudo bash hardyos-mail-relay.sh`). Then press **Check now**: HardyOS
   connects to the VPS's public address like a sender would and confirms
   that port 25 relays home and ports 993 and 465 reach this server.
4. **Domains & DNS**: publish the listed records (automatically with
   **Publish in Cloudflare**, or by hand at your DNS provider), then
   **Check DNS**. With SES, press **Verify with SES** first so its Easy DKIM
   records are listed too. HardyOS checks the records every day and warns
   you when one goes missing.
5. **Certificate**: with Let's Encrypt, press **Get a new one now**. It
   renews by itself 30 days before expiry.
6. **App Store**: install **Mail (Roundcube)** for webmail in the desktop.

Every domain account gets a mailbox within two minutes (Control Panel ›
Mail › Mailboxes › **Check for new accounts** does it at once).

### The IAM user for SES

Create an IAM user with an access key and this policy (replace the region
and account ID):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["ses:SendRawEmail", "ses:SendEmail"], "Resource": "*" },
    { "Effect": "Allow",
      "Action": ["ses:GetAccount", "ses:GetEmailIdentity", "ses:CreateEmailIdentity", "ses:PutEmailIdentityMailFromAttributes"],
      "Resource": "*" }
  ]
}
```

HardyOS derives the SES SMTP password from the secret access key (AWS's
documented conversion) and uses the same key for the SES API (domain
verification, the sandbox state). The secret key is sealed in hardyd's
database; only the derived SMTP password reaches the root helper, which
keeps it in a root-only Postfix file.

### The Cloudflare token

Cloudflare › My Profile › API Tokens › Create Token › *Edit zone DNS*:
permission **Zone › DNS › Edit**, zone resources **only your mail domains'
zones** (and the zone of the mail server's name). HardyOS checks the token
when you save it, keeps it sealed and never shows it again. It only adds
records and changes the ones it owns (its DKIM record, the single SPF and
DMARC records, its MX), marks what it creates with the comment `hardyos`,
merges its senders into an existing SPF record instead of replacing it, and
never deletes a record it didn't create (Let's Encrypt challenge records are
removed after use).

## DNS records

For each domain HardyOS lists:

| Record | Why |
| --- | --- |
| `A mail.<base>` → VPS | The MX may not point to a CNAME; an A record also overrides NetBird's wildcard. |
| `MX <domain>` → `mail.<base>` | Mail for the domain goes to the VPS. |
| `TXT <domain>` `v=spf1 mx include:amazonses.com -all` | The VPS (bounces) and SES may send for the domain. |
| `TXT <selector>._domainkey.<domain>` | HardyOS's DKIM key (made by the root helper, never leaves it). |
| `TXT _dmarc.<domain>` | Policy for mail that fails SPF and DKIM; reports to postmaster@. |
| `CNAME <token>._domainkey.<domain>` ×3 | SES Easy DKIM and domain verification. |
| `MX` and `TXT bounce.<domain>` | SES's custom MAIL FROM (SPF aligns for DMARC). |
| `SRV _submissions/_submission/_imaps._tcp` | Mail apps find the server (RFC 6186/8314); `_imap`, `_pop3`, `_pop3s` say "not offered". |
| `SRV _autodiscover._tcp` | Outlook finds `https://mail.<base>/autodiscover/autodiscover.xml`. |
| `SRV`/`TXT _caldavs/_carddavs._tcp` | Calendar and contacts apps find `/dav-mail/`. |
| `CNAME autoconfig.<domain>` | Thunderbird; works only if a certificate covers that name (otherwise Thunderbird uses the SRV records or the MX's own domain). |
| `TXT _mta-sts`, `_smtp._tls` (optional) | MTA-STS and TLS reports; needs the policy served at `https://mta-sts.<domain>` and a trusted certificate on the VPS's port 25. |

## Mailboxes

- Addresses come from the account's first name (`alice@`) or its account
  name, at the domain for new mailboxes; a taken address gets a number.
  Administrators can change the address, add aliases (they deliver to the
  mailbox and may be sent from) and set a size limit.
- **Group addresses** (like `family@`) deliver to several mailboxes; anyone
  in the group may send from them.
- `postmaster@` and `abuse@` of every domain go to the postmaster mailbox.
- People sign in to mail apps with their **full mail address and domain
  password**. Turning a domain account off (or deleting it) stops its mail
  sign-ins at once and ends open sessions; its mail keeps arriving. A
  mailbox can also be turned off by itself.
- Deleting a mailbox deletes every message in it and needs its address
  typed again; it's only possible once the account is turned off or
  deleted from the domain.

## Devices

The Mail app's **Set up my phone or computer** has step-by-step guides:

- **iPhone, iPad, Mac**: a configuration profile (mail, calendars and
  contacts at once). It holds no password; the device asks while
  installing. It isn't signed, so iOS calls it *Unverified*.
- **Thunderbird** finds its settings itself (autoconfig, SRV, or the MX's
  domain); **Outlook** through autodiscover.
- **Android**: the Gmail app (IMAP) and DAVx⁵ for calendars and contacts.
- Settings by hand: IMAP `mail.<base>:993` SSL/TLS, SMTP `mail.<base>:465`
  SSL/TLS (or 587 STARTTLS), user name = the address.

At home, devices reach the server directly (the same ports on the server's
LAN address); outside, through the VPS. The certificate is for
`mail.<base>`, so use that name in both places (a DNS override on your
router to the server's LAN address keeps home traffic home).

## Calendars and contacts

Radicale keeps calendars and contacts on the mail dataset. hardyd serves
them at `https://mail.<base>/dav-mail/` (and on the desktop's address):
each request signs in with the person's mail address and domain password,
which hardyd checks (with the same limits as mail sign-ins) before talking
to Radicale on 127.0.0.1. The **family calendar** and **family address
book** (`/dav-mail/family/calendar/`, `/dav-mail/family/contacts/`) are
shared by everyone with a mailbox. Apple's profile adds them; other apps add
them by URL (most apps only discover a person's own collections).

## Spam and viruses

Rspamd scores every message. From the junk score (6 by default) mail goes
to the **Junk** folder; moving a message into Junk or out of it teaches the
filter. Nothing is rejected at home: mail arrives through the VPS, which
has already accepted it, so a rejection would make the VPS bounce to a
sender that is often forged. **ClamAV** (optional, about 1.5 GB of memory)
marks infected mail, which goes to Junk.

Limits: per person 200 messages an hour by default (a stolen password can't
send a flood), the largest message 50 MB, and Postfix's per-address
connection and rate limits.

## Security

- No program of the mail server runs as root except the ones that start as
  root and drop to their own users (Postfix's and Dovecot's masters);
  mailboxes belong to `hardyos-vmail`, Rspamd runs as `_rspamd`, Radicale as
  `radicale`, Redis as `redis` (on a Unix socket only).
- **No open relay**: there's no port 25 at home; the relay port (2525)
  accepts only mail for your domains and only from the VPS's NetBird
  address; submission (465, 587 and the forwarded 10465, 10587) needs TLS
  and a sign-in, and people may only send from their own addresses. CI runs
  these checks against the real programs (`scripts/mail-integration.sh`).
- **PROXY protocol** headers (the real client address the VPS passes on) are
  believed only from the VPS: Dovecot by `haproxy_trusted_networks`, Postfix
  because an nftables table lets only the VPS's NetBird address reach those
  ports at all.
- **Sign-ins** are checked by hardyd: domain passwords with this server's own
  domain controller (like a desktop sign-in), webmail tokens against the
  desktop session they were made for. Wrong passwords from the internet
  block the address for an hour after 10 failures in 15 minutes and slow
  down further guesses at that mailbox; sign-ins from the LAN, NetBird or
  the server itself are only ever slowed down and never share a counter
  with the internet, so an attacker can't lock anyone at home out.
- **Secrets**: the SES secret key, the Cloudflare token, the notification
  sign-in and the Dovecot ↔ hardyd secret are sealed in hardyd's database.
  DKIM keys and the TLS key are made by the root helper on the mail dataset
  (DKIM `0640 root:_rspamd`, TLS `0600 root`) and never reach hardyd.
- **Webmail** only opens through HardyOS's window proxy (Roundcube listens
  on 127.0.0.1), signed in with a token that lasts as long as the person's
  desktop session.

## Backups

Mail lives in `<pool>/mail` (mailboxes, calendars, DKIM keys, the TLS
certificate); settings backups keep the configuration and sealed secrets.
Cloud backups (Backup & Restore) and replication to another HardyOS server
don't offer the mail dataset as an item yet: both know shared folders, apps
and VMs (and cloud backups the system), and a "Mail" kind needs its own
restore rules (into a stopped mail server, never over live mailboxes), its
own rebuild step and its place in both UIs. That's the follow-up; until
then, snapshots of the pool keep older states of the mail dataset.

## Troubleshooting

- **Control Panel › Mail › Setup** shows each service's state; **Queue**
  shows waiting mail and why it waits ("outgoing mail isn't set up yet"
  means SES isn't configured; SES errors are quoted).
- Alerts (Control Panel › Notifications, category *mail*): `mail.service`
  (a service stopped), `mail.queue` (mail waiting over an hour), `mail.ses`
  (SES refuses mail), `mail.dns` (a required record missing or wrong),
  `mail.certificate` (expired or expiring), `mail.signin` (an internet
  address was blocked).
- On the VPS: `journalctl -u postfix -u haproxy`, `postqueue -p` (mail held
  while home is offline), `postqueue -f` to retry.
- On HardyOS (Terminal): `journalctl -u postfix -u dovecot -u rspamd`,
  `doveadm who`, `postqueue -p`.
