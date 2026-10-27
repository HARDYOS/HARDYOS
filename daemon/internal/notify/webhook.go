package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// sendError is a failed delivery; Temporary ones are retried.
type sendError struct {
	Msg       string
	Temporary bool
}

func (e *sendError) Error() string { return e.Msg }

func temporary(err error) bool {
	var se *sendError
	if errors.As(err, &se) {
		return se.Temporary
	}
	return false
}

// scrubURL removes the request URL from net/http's errors: a webhook URL
// carries its token, and errors end up in the channel's status and logs.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", strings.ToLower(ue.Op), ue.Err)
	}
	return err
}

// postJSON posts body to rawURL with the guarded client and reports the
// outcome. extra headers are added (SES signs its request).
func postJSON(ctx context.Context, client *http.Client, rawURL string, body []byte, sign func(*http.Request) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return &sendError{Msg: "invalid URL"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HardyOS-alerts/1")
	if sign != nil {
		if err := sign(req); err != nil {
			return &sendError{Msg: err.Error()}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		err = scrubURL(err)
		var le *LocalAddressError
		if errors.As(err, &le) || errors.Is(err, errRedirect) {
			return &sendError{Msg: err.Error()}
		}
		return &sendError{Msg: err.Error(), Temporary: true}
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	msg := fmt.Sprintf("the service answered %s", resp.Status)
	if s := strings.TrimSpace(oneLine(string(snippet))); s != "" {
		msg += ": " + clip(s, 300)
	}
	return &sendError{Msg: msg, Temporary: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500}
}

func (d *Dispatcher) sendWebhook(ctx context.Context, ch *channelRow, m message) error {
	if ch.secrets.URL == "" {
		return &sendError{Msg: "the webhook URL is missing; enter it again"}
	}
	// Check again: the stored URL must still be acceptable for its type.
	if _, err := checkWebhookURL(ch.Type, ch.secrets.URL, ch.Config.AllowAnyHost); err != nil && !d.allowLocal {
		return &sendError{Msg: err.Error()}
	}
	var body []byte
	switch ch.Type {
	case TypeDiscord:
		body = discordPayload(m)
	case TypeSlack:
		body = slackPayload(m)
	case TypeTeams:
		body = teamsPayload(m)
	default:
		body = webhookPayload(m)
	}
	return postJSON(ctx, d.client(), ch.secrets.URL, body, nil)
}
