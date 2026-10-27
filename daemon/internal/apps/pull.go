package apps

// Downloading images through Docker's own API, so an install can show how
// far a big download has got (`docker compose pull --quiet` says nothing
// until it's done).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DockerSocket is where the engine listens (Debian's docker.socket).
const DockerSocket = "/run/docker.sock"

// PullProgress is how far an image download has got.
type PullProgress struct {
	// Current and Total are bytes over the layers seen so far (Total grows
	// as Docker learns each layer's size).
	Current int64 `json:"current"`
	Total   int64 `json:"total"`
	Layers  int   `json:"layers"`
	// Active is false before the download starts and once it ends.
	Active bool `json:"active"`
}

type layerProgress struct {
	current, total int64
	done           bool
}

type pullState struct {
	mu     sync.Mutex
	layers map[string]*layerProgress
	active bool
}

func (p *pullState) snapshot() PullProgress {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := PullProgress{Active: p.active, Layers: len(p.layers)}
	for _, l := range p.layers {
		out.Total += l.total
		if l.done {
			out.Current += l.total
		} else {
			out.Current += min(l.current, l.total)
		}
	}
	return out
}

// pullEvent is one line of Docker's /images/create stream.
type pullEvent struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	ProgressDetail struct {
		Current int64 `json:"current"`
		Total   int64 `json:"total"`
	} `json:"progressDetail"`
	Error       string `json:"error"`
	ErrorDetail struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
}

// layerStatus: the statuses Docker sends about a layer (the others, like
// "Pulling from <name>" or "Digest: ...", are about the whole image).
func layerStatus(s string) bool {
	switch s {
	case "Pulling fs layer", "Waiting", "Downloading", "Verifying Checksum", "Download complete",
		"Pull complete", "Already exists", "Retrying":
		return true
	}
	return strings.HasPrefix(s, "Extracting") || strings.HasPrefix(s, "Retrying")
}

func (p *pullState) note(ev pullEvent) {
	if ev.ID == "" || !layerStatus(ev.Status) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.layers[ev.ID]
	if l == nil {
		l = &layerProgress{}
		p.layers[ev.ID] = l
	}
	switch {
	case ev.Status == "Downloading":
		if ev.ProgressDetail.Total > 0 {
			l.total = ev.ProgressDetail.Total
		}
		l.current = ev.ProgressDetail.Current
	case ev.Status == "Download complete", ev.Status == "Pull complete", ev.Status == "Already exists",
		strings.HasPrefix(ev.Status, "Extracting"), ev.Status == "Verifying Checksum":
		l.done = true
	}
}

func pullKey(id, service string) string { return id + "/" + service }

func (m *Manager) pullState(id, service string) *pullState {
	m.pullsMu.Lock()
	defer m.pullsMu.Unlock()
	if m.pulls == nil {
		m.pulls = map[string]*pullState{}
	}
	st := m.pulls[pullKey(id, service)]
	if st == nil {
		st = &pullState{layers: map[string]*layerProgress{}}
		m.pulls[pullKey(id, service)] = st
	}
	return st
}

// PullStatus reports how far the download of an app service's image has got.
func (m *Manager) PullStatus(id, service string) PullProgress {
	if ValidID(id) != nil {
		return PullProgress{}
	}
	m.pullsMu.Lock()
	st := m.pulls[pullKey(id, service)]
	m.pullsMu.Unlock()
	if st == nil {
		return PullProgress{}
	}
	return st.snapshot()
}

// splitImageRef splits an image reference into the name and the tag (or
// digest) Docker's API wants separately. An empty tag would make Docker pull
// every tag of the image, so "latest" is the default, as for docker pull.
func splitImageRef(ref string) (name, tag string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		return ref[:i], ref[i+1:]
	}
	return ref, "latest"
}

var errNoEngineAPI = errors.New("docker's API isn't reachable")

// apiPull downloads image through the engine's API, recording progress in
// st. errNoEngineAPI means the socket isn't there (the caller falls back to
// the CLI).
func (m *Manager) apiPull(ctx context.Context, image string, st *pullState) error {
	sock := m.sys(DockerSocket)
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		ResponseHeaderTimeout: 2 * time.Minute,
	}}
	defer client.CloseIdleConnections()
	st.mu.Lock()
	st.layers = map[string]*layerProgress{} // a retry starts again
	st.mu.Unlock()
	name, tag := splitImageRef(image)
	q := url.Values{"fromImage": {name}, "tag": {tag}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) && ne.Op == "dial" {
			return errNoEngineAPI
		}
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(res.Body).Decode(&e)
		if e.Message == "" {
			e.Message = res.Status
		}
		return fmt.Errorf("downloading %s: %s", image, e.Message)
	}
	st.mu.Lock()
	st.active = true
	st.mu.Unlock()
	defer func() {
		st.mu.Lock()
		st.active = false
		st.mu.Unlock()
	}()
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var ev pullEvent
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		if ev.Error != "" || ev.ErrorDetail.Message != "" {
			msg := ev.ErrorDetail.Message
			if msg == "" {
				msg = ev.Error
			}
			return fmt.Errorf("downloading %s: %s", image, msg)
		}
		st.note(ev)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("downloading %s: %w", image, err)
	}
	return nil
}
