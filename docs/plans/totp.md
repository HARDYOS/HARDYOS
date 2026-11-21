# Two-factor sign-in (TOTP) — plan

Phase 9, branch `phase9/totp`, decisions 440-449, migration `0090_totp.sql`.

Owner's choice (2026-11-21): authenticator-app codes (RFC 6238). Administrators
must enroll (forced at their next sign-in after a short grace period that
admins can see); other people may; and **everyone** needs a second factor when
signing in from outside (the published desktop, published apps' sign-in, and
the sign-in provider at `sso.<base>`). WebAuthn passkeys are out of scope; the
code leaves a clean place for them (below).

## 1. What "outside" means

A request is from outside when it came in through the app gateway (any
published service, public or NetBird-only: NetBird's proxy terminates it), or
when its client address is not inside (loopback, RFC 1918, link-local,
unique-local, CGNAT/NetBird 100.64.0.0/10). The mail server already counts
connections that came through the VPS as the internet's; it keeps doing so.

## 2. Factors and storage

- TOTP: SHA-1, 6 digits, 30 s, the current step and one either side. A code is
  accepted only for a step later than the last one accepted (`last_step`,
  updated with a compare-and-set), so the same code (or an older one) can't be
  used twice.
- Secrets: 20 random bytes, sealed with secretbox (purpose `totp`, AAD bound to
  the user id and to active/pending), never returned after enrollment.
- 10 recovery codes per enrollment, 80 bits each (`xxxx-xxxx-xxxx-xxxx`),
  stored as SHA-256, single use (compare-and-set on `used_at`). They are not
  sealed, so they still work after a restore without keys.
- App passwords: per device, named, scoped (`files` = WebDAV, `mail` = IMAP and
  SMTP, `calendars` = CalDAV/CardDAV), 100 bits, stored as SHA-256, revocable,
  last use recorded; domain accounts only (local accounts can't use WebDAV or
  mail). Revoked when the domain says the password changed.

## 3. Where each sign-in path stands

| Path | Behaviour |
| --- | --- |
| Desktop (`POST /auth/login`) | Password, then (when needed) `POST /auth/login/2fa` with a challenge token, or forced enrollment (`/auth/login/enroll`, `/auth/login/enroll/confirm`). Sessions record `mfa`. |
| Desktop session use | A session without `mfa` is refused from outside; an administrator past the grace period gets only the 2FA endpoints until enrolled. App windows and VM consoles follow the same gate. |
| Sign-in provider (`sso.<base>`, `/oidc`) | Same rules on server-rendered, script-free pages: a code page, and an enrollment page whose QR code is inline SVG. Its browser sessions record `mfa`; an existing sign-in is reused only if it satisfies the rule for where the browser is now. `amr` gets `otp`. A refresh token from outside whose sign-in had no second factor ends that sign-in. |
| Published apps (gateway) | Sign in through the provider: covered. |
| WebDAV (`/dav/`) | App password (scope `files`) always works; the account password only from inside and only for accounts without 2FA. |
| Mail (IMAP/SMTP via Dovecot), calendars (`/dav-mail/`) | Same rule (scopes `mail`, `calendars`); webmail keeps its `hwm1.` tokens. |
| SFTP, SMB, Kerberos, LDAP | Samba/winbind check the domain password themselves: unaffected (HardyOS-web-level 2FA only). SFTP and SMB are not published outside by HardyOS. |
| Terminal / recovery-kit re-auth | Unchanged (password re-entry inside an MFA-gated session). |

## 4. Enrolling from outside

Safer design picked: by default people enroll from home (Settings ›
Two-factor sign-in, or forced enrollment on the LAN). An administrator can
issue a **one-time setup code** for one person (24 h, single use, stored
hashed, audited). From outside, a correct password plus that code is the only
way to reach enrollment; a password alone never is (it would let whoever stole
the password enroll their own authenticator).

## 5. Limits and lockout

- Per account: 5 wrong codes in 15 minutes locks code entry for 15 minutes (all
  sign-in paths share it), and each challenge allows 5 tries.
- 20 wrong authenticator codes in a row (persisted) stops authenticator codes
  for that account until a recovery code or an administrator's reset; caps an
  attacker who knows the password at about 60 in a million.
- Password limits stay as they are (decision 156 buckets from the internet).

## 6. Administration and recovery

- Control Panel › Users shows each account's 2FA state, the grace deadline and
  recovery codes left; **Reset two-factor** (type the username to confirm;
  audited; signs the person out everywhere; an admin must re-enroll at next
  sign-in) and **Setup code**.
- Control Panel › Security: the administrators' grace period (0-30 days,
  default 7).
- Lost authenticator: a recovery code; another administrator's reset; or, as
  root on the console, `hardyctl reset-2fa <user>`. A bare-metal restore from
  the recovery kit brings the master key back, so authenticators keep working;
  a restore without keys leaves recovery codes and `hardyctl reset-2fa`.

## 7. Passkeys later

`auth.MFA.Verify` takes a typed factor (`FactorTOTP`, `FactorRecovery`); a
`FactorWebAuthn` and a `user_webauthn` table slot in beside them, and the
challenge's `step` already tells the sign-in pages what to ask for.
