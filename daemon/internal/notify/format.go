package notify

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"
)

// message is one event ready for a channel: who it's from and where its
// link goes.
type message struct {
	Event
	Server    string // this server's name
	ServerURL string // https://… of the desktop, or ""
	Note      string // e.g. "3 similar alerts were held back"
}

// url is the absolute link for the event, if the server's address is known.
func (m message) url() string {
	if m.ServerURL == "" {
		return ""
	}
	u := strings.TrimSuffix(m.ServerURL, "/") + "/"
	if m.Link != "" {
		u += "#open=" + escapeFragment(m.Link)
	}
	return u
}

func escapeFragment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("-._~/:", r):
			b.WriteRune(r)
		default:
			for _, c := range []byte(string(r)) {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
	}
	return b.String()
}

func (m message) body() string {
	b := m.Body
	if m.Note != "" {
		if b != "" {
			b += "\n\n"
		}
		b += m.Note
	}
	return b
}

var sevLabel = map[string]string{SeverityInfo: "Info", SeverityWarning: "Warning", SeverityCritical: "Critical"}

// Colors: the accent for info, amber for warnings, red for critical.
var sevColor = map[string]int{SeverityInfo: 0x22D3EE, SeverityWarning: 0xF59E0B, SeverityCritical: 0xEF4444}

func (m message) subject() string {
	s := fmt.Sprintf("[%s] %s", m.Server, m.Title)
	if m.Severity != SeverityInfo {
		s = fmt.Sprintf("[%s] %s: %s", m.Server, sevLabel[m.Severity], m.Title)
	}
	return oneLine(s)
}

func (m message) footer() string {
	return fmt.Sprintf("%s · %s · %s", m.Server, sevLabel[m.Severity], m.Kind)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Alert text carries names others chose (file, app, VM and disk names): it
// must never become a link or formatting in a chat app. Only HardyOS's own
// link (the server address) is a real link.

// discordMarkdown are the characters Discord's markdown gives meaning.
var discordMarkdown = strings.NewReplacer(
	`\`, `\\`, "*", `\*`, "_", `\_`, "~", `\~`, "`", "\\`", "|", `\|`, ">", `\>`, "<", `\<`,
	"[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`, "#", `\#`, "-", `\-`, "@", "@\u200b",
	// Break bare URLs so they aren't linked.
	"://", ":\u200b//",
)

// discordEscape makes untrusted text literal in a Discord embed.
func discordEscape(s string) string { return discordMarkdown.Replace(s) }

// discordPayload: an embed with the severity's color.
func discordPayload(m message) []byte {
	embed := map[string]any{
		"title":       trunc(discordEscape(m.Title), 256),
		"description": trunc(discordEscape(m.body()), 4000),
		"color":       sevColor[m.Severity],
		"timestamp":   m.Time.UTC().Format(time.RFC3339),
		"footer":      map[string]string{"text": trunc(m.footer(), 2048)},
	}
	if u := m.url(); u != "" {
		embed["url"] = u
	}
	b, _ := json.Marshal(map[string]any{
		"username":         "HardyOS",
		"embeds":           []any{embed},
		"allowed_mentions": map[string]any{"parse": []string{}}, // never ping @everyone from alert text
	})
	return b
}

// slackEscape escapes the three characters Slack's mrkdwn treats specially.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func slackPayload(m message) []byte {
	icon := map[string]string{SeverityInfo: ":information_source:", SeverityWarning: ":warning:", SeverityCritical: ":rotating_light:"}[m.Severity]
	blocks := []any{
		map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": trunc(m.Title, 150), "emoji": true}},
	}
	if b := m.body(); b != "" {
		// verbatim: no automatic links or mentions in the alert's own text.
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": trunc(slackEscape(b), 3000), "verbatim": true}})
	}
	ctx := icon + " " + slackEscape(m.footer())
	if u := m.url(); u != "" {
		ctx += " · <" + u + "|Open HardyOS>"
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn", "text": trunc(ctx, 3000)}}})
	b, _ := json.Marshal(map[string]any{"text": trunc(m.subject(), 3000), "blocks": blocks})
	return b
}

// teamsPayload is an Adaptive Card message, which both Teams' Workflows
// ("Post to a channel when a webhook request is received") and the older
// Office 365 connectors accept.
func teamsPayload(m message) []byte {
	color := map[string]string{SeverityInfo: "Accent", SeverityWarning: "Warning", SeverityCritical: "Attention"}[m.Severity]
	// RichTextBlock text runs are plain text: TextBlock would read the
	// alert's text as markdown (links included).
	run := func(text string, extra map[string]any) map[string]any {
		r := map[string]any{"type": "TextRun", "text": text}
		for k, v := range extra {
			r[k] = v
		}
		return map[string]any{"type": "RichTextBlock", "inlines": []any{r}}
	}
	body := []any{run(m.Title, map[string]any{"weight": "Bolder", "size": "Medium", "color": color})}
	if b := m.body(); b != "" {
		body = append(body, run(trunc(b, 4000), nil))
	}
	body = append(body, run(m.footer(), map[string]any{"isSubtle": true, "size": "Small"}))
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
	}
	if u := m.url(); u != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open HardyOS", "url": u}}
	}
	b, _ := json.Marshal(map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     card,
		}},
	})
	return b
}

// webhookPayload is the generic JSON for any other endpoint.
func webhookPayload(m message) []byte {
	b, _ := json.Marshal(map[string]any{
		"kind":     m.Kind,
		"severity": m.Severity,
		"title":    m.Title,
		"body":     m.body(),
		"link":     m.Link,
		"url":      m.url(),
		"time":     m.Time.UTC().Format(time.RFC3339),
		"server":   m.Server,
		"source":   "hardyos",
	})
	return b
}

// textBody is the plain-text email.
func textBody(m message) string {
	var b strings.Builder
	b.WriteString(m.Title + "\n\n")
	if body := m.body(); body != "" {
		b.WriteString(body + "\n\n")
	}
	fmt.Fprintf(&b, "Severity: %s\nServer: %s\nTime: %s\nKind: %s\n", sevLabel[m.Severity], m.Server, m.Time.Local().Format("Mon 2 Jan 2006 15:04 MST"), m.Kind)
	if u := m.url(); u != "" {
		b.WriteString("\nOpen HardyOS: " + u + "\n")
	}
	b.WriteString("\n-- \nSent by HardyOS. Change where alerts go in Control Panel > Notifications.\n")
	return b.String()
}

// htmlBody is the HTML email: a dark card in HardyOS's colors with inline
// styles (mail clients drop stylesheets).
func htmlBody(m message) string {
	sev := map[string]string{SeverityInfo: "#22D3EE", SeverityWarning: "#F59E0B", SeverityCritical: "#EF4444"}[m.Severity]
	paras := ""
	for _, p := range strings.Split(m.body(), "\n") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		paras += `<p style="margin:0 0 10px;color:#C9D2E3;font-size:14px;line-height:1.5">` + html.EscapeString(p) + `</p>`
	}
	button := ""
	if u := m.url(); u != "" {
		button = `<p style="margin:18px 0 0"><a href="` + html.EscapeString(u) + `" style="display:inline-block;padding:9px 16px;border-radius:9px;background:#22D3EE;background-image:linear-gradient(90deg,#00F0FF,#8B5CFF);color:#05070D;font-weight:700;text-decoration:none;font-size:14px">Open HardyOS</a></p>`
	}
	return `<!doctype html><html><body style="margin:0;padding:24px;background:#05070D;font-family:'Plus Jakarta Sans',Segoe UI,Helvetica,Arial,sans-serif">` +
		`<div style="max-width:560px;margin:0 auto;background:#0F1524;border:1px solid #1F2A40;border-radius:14px;overflow:hidden">` +
		`<div style="height:4px;background:` + sev + `"></div><div style="padding:22px 24px">` +
		`<p style="margin:0 0 6px;color:` + sev + `;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase">` + html.EscapeString(sevLabel[m.Severity]) + ` · ` + html.EscapeString(m.Server) + `</p>` +
		`<h1 style="margin:0 0 14px;color:#F4F7FF;font-size:19px;line-height:1.3">` + html.EscapeString(m.Title) + `</h1>` + paras + button +
		`<p style="margin:20px 0 0;color:#6B7895;font-size:12px;font-family:'JetBrains Mono',Consolas,monospace">` + html.EscapeString(m.Time.Local().Format("2006-01-02 15:04 MST")+" · "+m.Kind) + `</p>` +
		`</div></div><p style="max-width:560px;margin:12px auto 0;color:#6B7895;font-size:12px">Sent by HardyOS. Change where alerts go in Control Panel › Notifications.</p></body></html>`
}
