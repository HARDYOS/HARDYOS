// Package fence is the node side of fencing (docs/plans/cluster.md section
// 7.2): the watchdog feeder that runs inside hardyd-priv (root), the node
// fence agent that runs in hardyd, and the out-of-band power fencer
// interface (later).
//
// The feeder owns /dev/watchdog0. It pets the device itself, once a
// second, only while the deadline hardyd last gave is in the future
// (monotonic clock). A hung hardyd, a hung hardyd-priv or a lost quorum
// lease all end the same way: no pets, and the hardware resets the server
// after the watchdog timeout. Closing the device without the magic
// character (hardyd-priv crashing) keeps the watchdog running.
package fence

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
)

// Device is an open watchdog device.
type Device interface {
	// SetTimeout asks for a timeout in seconds; the device answers with the
	// one it uses.
	SetTimeout(seconds int) (int, error)
	Keepalive() error
	// Close closes the device; magic writes the magic close character
	// first (stopping the watchdog where the driver allows it).
	Close(magic bool) error
}

// Watchdog kinds (cluster.ComputeInfo.Watchdog).
const (
	KindHardware = "hardware"
	KindSoftdog  = "softdog"
	KindNone     = ""
)

// Opener opens the watchdog device and says which kind it is.
type Opener func() (Device, string, error)

// ErrNoWatchdog: the server has no watchdog device.
var ErrNoWatchdog = errors.New("this server has no watchdog device")

// Status is the feeder's state, for hardyd and the Cluster app.
type Status struct {
	Armed bool   `json:"armed"`
	Kind  string `json:"kind"`
	// TimeoutSec is the device's timeout while armed.
	TimeoutSec int `json:"timeoutSec,omitempty"`
	// PettingFor is how long root keeps petting without hearing from
	// hardyd again (0: it has stopped).
	PettingForMs int64     `json:"pettingForMs"`
	LastPet      time.Time `json:"lastPet,omitzero"`
	Problem      string    `json:"problem,omitempty"`
}

// Feeder pets the watchdog for hardyd, within the deadline it was given.
type Feeder struct {
	Open Opener
	// Detect reports the server's watchdog kind without opening it.
	Detect func() string
	// Now is the clock (monotonic; tests fake it).
	Now func() time.Time
	// Interval between pets (default 1 s).
	Interval time.Duration
	// MaxValid bounds a single Pet's validity (default 2 minutes, the
	// largest quorum lease).
	MaxValid time.Duration

	mu      sync.Mutex
	dev     Device
	kind    string
	timeout int
	until   time.Time
	lastPet time.Time
	problem string
	stop    chan struct{}
	done    chan struct{}
}

func (f *Feeder) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Feeder) interval() time.Duration {
	if f.Interval > 0 {
		return f.Interval
	}
	return time.Second
}

func (f *Feeder) maxValid() time.Duration {
	if f.MaxValid > 0 {
		return f.MaxValid
	}
	return 2 * time.Minute
}

// Arm opens the device with the timeout and starts the petting loop. The
// deadline starts at now: nothing more is petted until hardyd's first Pet.
// Arming an armed feeder only changes the timeout.
func (f *Feeder) Arm(timeout time.Duration) (string, error) {
	secs := int((timeout + time.Second - 1) / time.Second)
	if secs < 5 || secs > 60 {
		return "", fmt.Errorf("the watchdog timeout is 5-60 s, not %s", timeout)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dev == nil {
		if f.Open == nil {
			return "", ErrNoWatchdog
		}
		dev, kind, err := f.Open()
		if err != nil {
			return "", err
		}
		f.dev, f.kind = dev, kind
		f.until = f.now()
		f.stop, f.done = make(chan struct{}), make(chan struct{})
		go f.loop(f.stop, f.done)
	}
	got, err := f.dev.SetTimeout(secs)
	if err != nil {
		f.problem = err.Error()
		return f.kind, fmt.Errorf("setting the watchdog timeout: %w", err)
	}
	if got != secs {
		// The device rounds; a longer timeout than asked breaks F >= Q+W+10.
		if got > secs {
			f.problem = fmt.Sprintf("the watchdog uses %d s instead of %d s", got, secs)
			return f.kind, errors.New(f.problem)
		}
	}
	f.timeout = got
	if err := f.dev.Keepalive(); err != nil {
		f.problem = err.Error()
		return f.kind, err
	}
	f.lastPet = f.now()
	f.problem = ""
	return f.kind, nil
}

// Pet lets root keep petting for validFor more (from now). The deadline
// only ever comes from here: root never extends it by itself.
func (f *Feeder) Pet(validFor time.Duration) error {
	if validFor <= 0 {
		return errors.New("a pet needs a positive validity")
	}
	if validFor > f.maxValid() {
		validFor = f.maxValid()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dev == nil {
		return errors.New("the watchdog isn't armed")
	}
	now := f.now()
	f.until = now.Add(validFor)
	if err := f.dev.Keepalive(); err != nil {
		f.problem = err.Error()
		return err
	}
	f.lastPet = now
	return nil
}

// Expire stops petting at once: the server resets within the timeout
// unless hardyd disarms first.
func (f *Feeder) Expire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.until = time.Time{}
}

// Disarm stops the loop and closes the device with the magic character.
// hardyd only disarms with no HA workload running here (its fence agent
// is DISARMED).
func (f *Feeder) Disarm() error {
	f.mu.Lock()
	dev, stop, done := f.dev, f.stop, f.done
	f.dev, f.stop, f.done = nil, nil, nil
	f.until = time.Time{}
	f.timeout = 0
	f.mu.Unlock()
	if dev == nil {
		return nil
	}
	close(stop)
	<-done
	return dev.Close(true)
}

// Status reports the feeder's state.
func (f *Feeder) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := Status{Armed: f.dev != nil, Kind: f.kind, TimeoutSec: f.timeout, LastPet: f.lastPet, Problem: f.problem}
	if f.dev == nil {
		if f.Detect != nil {
			st.Kind = f.Detect()
		}
		return st
	}
	if left := f.until.Sub(f.now()); left > 0 {
		st.PettingForMs = left.Milliseconds()
	}
	return st
}

// Tick pets the device once if the deadline is still ahead (the loop calls
// it every Interval; tests call it directly).
func (f *Feeder) Tick() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dev == nil {
		return
	}
	now := f.now()
	if !now.Before(f.until) {
		return
	}
	if err := f.dev.Keepalive(); err != nil {
		f.problem = err.Error()
		return
	}
	f.lastPet = now
}

func (f *Feeder) loop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	t := time.NewTicker(f.interval())
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			f.Tick()
		}
	}
}

// ---- detecting the kind ---------------------------------------------------------

// softdogIdentities are what the software watchdog calls itself.
var softdogIdentities = []string{"Software Watchdog", "softdog"}

// DetectKind reads /sys/class/watchdog/watchdog0/identity under root:
// "softdog" for the software watchdog, "hardware" for anything else, ""
// when there's no watchdog.
func DetectKind(root fs.FS) string {
	b, err := fs.ReadFile(root, "sys/class/watchdog/watchdog0/identity")
	if err != nil {
		return KindNone
	}
	id := strings.TrimSpace(string(b))
	for _, s := range softdogIdentities {
		if strings.EqualFold(id, s) {
			return KindSoftdog
		}
	}
	if id == "" {
		return KindNone
	}
	return KindHardware
}

// SystemOpener opens /dev/watchdog0 (the kind from sysfs).
func SystemOpener() (Device, string, error) {
	kind := DetectKind(os.DirFS("/"))
	if kind == KindNone {
		return nil, "", ErrNoWatchdog
	}
	d, err := openDevice("/dev/watchdog0")
	if err != nil {
		return nil, "", err
	}
	return d, kind, nil
}
