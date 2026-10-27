import type { MailManualSettings } from "@hardy/api-client";

/** The catalog app that is the desktop's webmail (Roundcube). */
export const WEBMAIL_APP_ID = "roundcube";

export type DeviceKind = "iphone" | "android" | "thunderbird" | "outlook" | "other";

export interface DeviceGuide {
  steps: string[];
  note?: string;
}

/** Plain-language steps for each kind of device. */
export function deviceGuides(s: MailManualSettings): Record<DeviceKind, DeviceGuide> {
  const imap = `${s.imapHost}, port ${s.imapPort}, SSL/TLS`;
  const smtp = `${s.smtpHost}, port ${s.smtpPort}, SSL/TLS`;
  return {
    iphone: {
      steps: [
        "Download the profile below on the iPhone, iPad or Mac (or AirDrop it there).",
        "Open Settings › General › VPN & Device Management (on a Mac: System Settings › Privacy & Security › Profiles) and install “Mail for " + s.address + "”.",
        "Enter your domain password when asked. Mail, Calendar and Contacts are set up together.",
      ],
      note: "The profile isn't signed, so the device calls it “Unverified”. It only names this server; your password stays on the device.",
    },
    android: {
      steps: [
        "Gmail app: Settings › Add account › Other, enter " + s.address + ", choose Personal (IMAP).",
        "Password: your domain password. Incoming server: " + imap + ". Outgoing server: " + smtp + ".",
        "Calendars and contacts: install DAVx⁵, choose “Login with URL and user name”, URL " + s.davUrl + ", your address and password.",
      ],
    },
    thunderbird: {
      steps: [
        "Thunderbird › Account Settings › Account Actions › Add Mail Account.",
        "Enter your name, " + s.address + " and your domain password. Thunderbird finds the settings by itself.",
        "If it asks, choose IMAP: incoming " + imap + ", outgoing " + smtp + ", authentication “Normal password”.",
        "Calendars: New Calendar › On the network, URL " + s.davUrl + ".",
      ],
    },
    outlook: {
      steps: [
        "Outlook › Add account, enter " + s.address + ".",
        "Choose IMAP when asked (Advanced setup). Incoming " + imap + ", outgoing " + smtp + ".",
        "User name for both: " + s.username + ". Password: your domain password.",
      ],
      note: "New Outlook for Windows adds IMAP accounts too. Outlook can't show CalDAV calendars; use the webmail or another app for the family calendar.",
    },
    other: {
      steps: ["Use IMAP for incoming mail and SMTP with sign-in for sending, with the settings below. Sign in with your full address and your domain password."],
    },
  };
}
