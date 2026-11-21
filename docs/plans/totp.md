# Two-factor sign-in (TOTP) — plan

Phase 9, branch `phase9/totp`, decisions 440-449, migration `0090_totp.sql`.
Amended after the security review of PR #38 (H1, M1-M4, L1-L8).

Owner's choice (2026-11-21): authenticator-app codes (RFC 6238). Administrators
must enroll (forced at their next sign-in after a short grace period that
admins can see); other people may; and **everyone** needs a second factor when
signing in from outside (the published desktop, published apps' sign-in, and
the sign-in provider at `sso.<base>`). WebAuthn passkeys are out of scope; the
code leaves a clean place for them (below).

## 1. What "outside" means

A request is from outside when it came in through the app gateway (any
published service, public or NetBird-only: NetBird's proxy terminates it), or
when its client address isn't inside. Inside is only:

- hardyd's own loopback;
- the networks of this server's LAN interfaces (IPv6 global prefixes on them
  included, so a home with global IPv6 still counts as home);
- NetBird peers (100.64.0.0/10, or NetBird's own network).

Docker's networks (the default bridge, compose bridges, the app and webmail
networks), libvirt's and the domain controller's shim are outside.

**The router's own address** is on the LAN, so it counts as inside: a server
running in a VM behind NAT sees every client that way. But it is also how
hairpin NAT (a device at home using the public address) and a port forward the
router masquerades show up, and those could let the internet look like home.
So Control Panel › Security warns when a request came from the router, and the
docs say not to forward ports to HardyOS.

## 2. Factors and storage

- TOTP: SHA-1, 6 digits, 30 s, the current step and one either side. A code is
  accepted only for a step later than the last one accepted (`last_step`,
  compare-and-set), so the same code (or an older one) can't be used twice.
- Secrets: 20 random bytes, sealed with secretbox (purpose `totp`, AAD bound to
  the user id and to active/pending), never returned after enrollment. A
  pending setup is tied to the sign-in challenge or desktop session that
  started it.
- 10 recovery codes per enrollment, 80 bits each (`xxxx-xxxx-xxxx-xxxx`),
  stored as SHA-256, single use. Not sealed, so they still work after a restore
  without keys.
- App passwords: per device, named, scoped (`files` = WebDAV, `mail` = IMAP and
  SMTP, `calendars` = CalDAV/CardDAV), 100 bits, stored as SHA-256, revocable,
  last use recorded; domain accounts only. Revoked when the domain says the
  password changed.

## 3. Where each sign-in path stands

| Path | Behaviour |
| --- | --- |
| Desktop (`POST /auth/login`) | Password, then (when needed) `POST /auth/login/2fa` with a challenge token, or forced enrollment (`/auth/login/enroll`, `/auth/login/enroll/confirm`). Sessions record `mfa`. |
| Desktop session use | A session without `mfa` is refused from outside; an administrator past the grace period gets only the 2FA endpoints until enrolled. App windows and VM consoles use the same gate. |
| Sign-in provider (`sso.<base>`, `/oidc`) | Same rules on server-rendered, script-free pages: a code page, and an enrollment page whose QR code is inline SVG. Its browser sessions record `mfa`; an existing sign-in (its own or the desktop's) is reused only if it meets the rule for where the browser is now. `amr` gets `otp`/`mfa`. Grants record whether the browser was outside. A grant without a second factor doesn't refresh from outside, if its browser was outside, or while the person must enroll. |
| Published apps (gateway) | Only with HardyOS sign-in in front (which goes through the provider); an app can't be published without it (`signin_required`), and one published that way before is refused at the gateway. The exception is Photos, whose sign-in is HardyOS's own (Sign in with HardyOS on, Immich passwords off). Sessions an app keeps on its own after that are the app's. |
| WebDAV (`/dav/`) | An app password (scope `files`) always works. The account's own password works only from inside, only without 2FA, and not while an admin must enroll; this is checked again after Kerberos succeeds. |
| Mail (IMAP/SMTP via Dovecot), calendars (`/dav-mail/`) | Same rule (scopes `mail`, `calendars`), with the source classified as in section 1. Webmail keeps its `hwm1.` tokens. |
| SFTP, SMB, Kerberos, LDAP | Samba/winbind check the domain password themselves: unaffected (HardyOS-web-level 2FA only). HardyOS doesn't publish SFTP or SMB outside. |
| Terminal / recovery-kit re-auth | Unchanged (password re-entry inside an MFA-gated session). |

Setting up or replacing an authenticator, on any path, ends everything signed
in before. That covers desktop sessions and app windows, WebDAV's remembered
sign-ins, Office sessions, HardyOS sign-in sessions, and every app grant and
refresh token. The browser that did it gets a fresh two-factor session.

## 4. Enrolling from outside

The safer design was picked. By default people enroll from home (account menu
› Two-factor sign-in, or forced enrollment on the LAN). For someone who can't
get home, an administrator can issue a **one-time setup code** for that person
(24 h, stored hashed, audited). It is used up the moment it's accepted (one
compare-and-clear), and the setup it unlocks belongs to that sign-in only.

From outside, a correct password plus that code is the only way to reach
enrollment. A password alone never is: it would let whoever stole the password
enroll their own authenticator.

## 5. Limits and lockout

- **Pauses.** Wrong codes count per account and origin: at home one bucket,
  from outside per address (IPv6 per /64). Each attempt is reserved atomically
  before the code is checked. 5 in 15 minutes pause that origin for 15
  minutes. Recovery codes and enrollment/setup codes have their own buckets.
  So nothing from outside blocks home, and nothing blocks a recovery code.
- **Rolling budget.** Wrong codes from outside also go into a 60-day budget
  that a right code doesn't reset (a recovery code does, until the budget runs
  out). At 20, authenticator codes stop working from outside; at home they
  still work, and recovery codes work everywhere. Only a password change or an
  administrator's reset lifts the stop; re-enrolling doesn't. This caps a
  guesser who has the password at about 60 in a million per 60 days.
- **Notifications.** Pauses, every 5 wrong codes from outside, and the stop
  notify administrators (Notifications, `security.2fa`) and the person (a
  notice in their account menu), and are audited.
- **Shared challenges.** The desktop and the provider share the challenges
  (10 minutes, 5 tries, at most 3 open per person and origin).
- Password limits stay as they are (decision 156 buckets from the internet).

## 6. Administration and recovery

- **Users & Groups** in Control Panel shows each account's 2FA state, the
  grace deadline and recovery codes left, with two actions:
  - **Reset two-factor:** type the username to confirm; audited. It signs the
    person out everywhere, revokes app sign-ins and (with a tick, on by
    default) app passwords. An admin must re-enroll at the next sign-in.
  - **Setup code:** issues the one-time code from section 4.
- **Security** in Control Panel holds the administrators' grace period (0-30
  days, default 7) and the router warning.
- **Lost authenticator:**
  - a recovery code;
  - another administrator's reset;
  - as root on the console, `hardyctl reset-2fa <user>` (the same
    revocations; `-keep-app-passwords` to keep them).

  A bare-metal restore from the recovery kit brings the master key back, so
  authenticators keep working. A restore without keys leaves recovery codes
  and `hardyctl reset-2fa`.
- Two-factor changes are synchronous and audited under decision 69's exception
  (no job). Enrollment starts are audited too.

## 7. Passkeys later

`auth.MFA.Verify` takes a typed factor (`FactorTOTP`, `FactorRecovery`). A
`FactorWebAuthn` and a `user_webauthn` table slot in beside them, and the
challenge's `step` already tells the sign-in pages what to ask for.
