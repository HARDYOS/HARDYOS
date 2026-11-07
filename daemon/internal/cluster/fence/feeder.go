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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
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
	// Instance changes every time hardyd-priv starts: hardyd notices a
	// restart (which closed the device without the magic character).
	Instance string `json:"instance"`
	// NoWayOut: the driver can't be stopped once opened (the magic close
	// doesn't disarm it); the agent then keeps it petted instead.
	NoWayOut bool `json:"noWayOut,omitempty"`
	// Leases: root checks leader-signed lease statements (keys pinned).
	Leases bool `json:"leases,omitempty"`
	// KeySet is the cluster.KeySetHash of the pinned keys.
	KeySet string `json:"keySet,omitempty"`
}

// Feeder pets the watchdog for hardyd, within the deadline it was given.
type Feeder struct {
	Open Opener
	// Detect reports the server's watchdog kind without opening it.
	Detect func() string
	// Now is the clock (default CLOCK_BOOTTIME, which counts through a
	// suspend; tests fake it).
	Now func() time.Time
	// Mono is the monotonic clock (CLOCK_MONOTONIC, which stops while
	// suspended): when the two drift apart the server was suspended and
	// every deadline is void (decision 392). Default MonoNow.
	Mono func() time.Time
	// NoWayOut reports whether the device can't be stopped (default: the
	// driver's sysfs flag).
	NoWayOut func() bool
	// Running reports whether any cluster workload runs here (root's own
	// view: vms and apps ClusterStatus). Disarming is refused while one
	// does, and once lease keys are pinned an unsigned pet is accepted
	// only while none does. nil: nothing is checked (tests).
	Running func(ctx context.Context) (bool, error)
	// Verifier checks lease statements (default ES256Leases).
	Verifier LeaseVerifier
	// SelfFenceGrace is how long after root's own self-fence a disarm is
	// accepted with non-HA workloads still running (default 2 minutes).
	SelfFenceGrace time.Duration
	// Interval between pets (default 1 s).
	Interval time.Duration
	// MaxValid bounds a single Pet's validity (default 2 minutes, the
	// largest quorum lease).
	MaxValid time.Duration

	mu        sync.Mutex
	dev       Device
	kind      string
	timeout   int
	until     time.Time
	lastPet   time.Time
	problem   string
	stop      chan struct{}
	done      chan struct{}
	instance  string
	nowayout  bool
	keys      *LeaseKeys
	selfFence time.Time
	// the clocks at the last tick (suspend detection)
	lastBoot, lastMono time.Time
}

func (f *Feeder) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return BootNow()
}

func (f *Feeder) mono() time.Time {
	if f.Mono != nil {
		return f.Mono()
	}
	if f.Now != nil {
		return f.Now() // a faked clock: no suspends
	}
	return MonoNow()
}

func (f *Feeder) instanceID() string {
	if f.instance == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		f.instance = hex.EncodeToString(b)
	}
	return f.instance
}

// suspendedLocked notices a suspend since the last call: the boot clock
// ran on while the monotonic one stood still.
func (f *Feeder) suspendedLocked() bool {
	b, m := f.now(), f.mono()
	defer func() { f.lastBoot, f.lastMono = b, m }()
	if f.lastBoot.IsZero() {
		return false
	}
	return b.Sub(f.lastBoot)-m.Sub(f.lastMono) > time.Second
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
		f.nowayout = f.NoWayOut != nil && f.NoWayOut()
		f.until = f.now()
		f.lastBoot = time.Time{}
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
	return f.PetLease(context.Background(), validFor, nil)
}

// ErrLeaseNeeded: root has lease keys pinned and a cluster workload runs,
// so a pet must carry a leader-signed statement.
var ErrLeaseNeeded = errors.New("a pet must carry the leader's signed lease statement while cluster workloads run here")

// PinKeys pins the keys lease statements are checked with. While the
// watchdog is armed the keys change only for the same cluster and node and
// with a statement, signed by a key already pinned and still within its
// lease, whose key set hash is the new set's: the cluster's leader vouches
// for a server that joined or left.
func (f *Feeder) PinKeys(k LeaseKeys) error {
	if k.Cluster == "" || k.Node == "" || len(k.Voters) == 0 || len(k.Voters) > 64 {
		return errors.New("lease keys need the cluster, this server and 1-64 servers that may lead")
	}
	for id, key := range k.Voters {
		if _, err := cluster.ParsePublicKey(key); err != nil {
			return fmt.Errorf("%s's key: %w", id, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys != nil && f.dev != nil {
		if k.Cluster != f.keys.Cluster || k.Node != f.keys.Node {
			return errors.New("the watchdog is armed: its lease keys stay for this cluster and server")
		}
		if len(k.Lease) == 0 {
			return errors.New("the watchdog is armed: new lease keys need the leader's statement for them")
		}
		st, _, err := CheckLease(k.Lease, f.keys, time.Now())
		if err != nil {
			return fmt.Errorf("the watchdog is armed: %w", err)
		}
		if st.Keys != k.Hash() {
			return errors.New("the watchdog is armed: the leader's statement doesn't vouch for these keys")
		}
	}
	c := k
	c.Lease = nil
	c.Voters = map[string][]byte{}
	for id, key := range k.Voters {
		c.Voters[id] = append([]byte(nil), key...)
	}
	f.keys = &c
	return nil
}

// PetLease is Pet with the leader's signed statement: with keys pinned,
// the deadline is what the statement grants on root's clock (never more
// than validFor), and while a cluster workload runs a pet without a valid
// statement is refused.
func (f *Feeder) PetLease(ctx context.Context, validFor time.Duration, statement []byte) error {
	if validFor <= 0 {
		return errors.New("a pet needs a positive validity")
	}
	if validFor > f.maxValid() {
		validFor = f.maxValid()
	}
	f.mu.Lock()
	keys := f.keys
	armed := f.dev != nil
	f.mu.Unlock()
	if !armed {
		return errors.New("the watchdog isn't armed")
	}
	if keys != nil {
		if len(statement) > 0 {
			v := f.Verifier
			if v == nil {
				f.mu.Lock()
				if f.Verifier == nil {
					f.Verifier = &ES256Leases{}
				}
				v = f.Verifier
				f.mu.Unlock()
			}
			granted, err := v.Verify(statement, keys, time.Now())
			if err != nil {
				return fmt.Errorf("%w: %v", ErrLeaseNeeded, err)
			}
			validFor = min(validFor, granted)
		} else if f.Running != nil {
			running, err := f.Running(ctx)
			if err != nil || running {
				return ErrLeaseNeeded
			}
		}
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

// ErrStillRunning: root refuses to disarm while cluster workloads run.
var ErrStillRunning = errors.New("cluster workloads still run on this server: the watchdog stays armed")

// ErrNoWayOut: the driver can't be disarmed once opened.
var ErrNoWayOut = errors.New("this watchdog can't be stopped once started (nowayout): it stays armed and petted")

// SelfFenced records that root finished a self-fence now: for a while a
// disarm is accepted with the node's non-HA workloads still running.
func (f *Feeder) SelfFenced() {
	f.mu.Lock()
	f.selfFence = f.now()
	f.mu.Unlock()
}

// DisarmChecked disarms only when root sees no cluster workload running
// (or right after its own self-fence of the HA ones), and never a
// nowayout device (decisions 389 and 391).
func (f *Feeder) DisarmChecked(ctx context.Context) error {
	f.mu.Lock()
	armed, nowayout, sf := f.dev != nil, f.nowayout, f.selfFence
	f.mu.Unlock()
	if !armed {
		return nil
	}
	if nowayout {
		return ErrNoWayOut
	}
	grace := f.SelfFenceGrace
	if grace <= 0 {
		grace = 2 * time.Minute
	}
	if f.Running != nil && (sf.IsZero() || f.now().Sub(sf) > grace) {
		running, err := f.Running(ctx)
		if err != nil {
			return fmt.Errorf("%w (root couldn't list them: %v)", ErrStillRunning, err)
		}
		if running {
			return ErrStillRunning
		}
	}
	return f.Disarm()
}

// Disarm stops the loop and closes the device with the magic character.
// hardyd only disarms with no HA workload running here (its fence agent
// is DISARMED); the operation goes through DisarmChecked.
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
	st := Status{Armed: f.dev != nil, Kind: f.kind, TimeoutSec: f.timeout, LastPet: f.lastPet, Problem: f.problem,
		Instance: f.instanceID(), NoWayOut: f.nowayout, Leases: f.keys != nil}
	if f.keys != nil {
		st.KeySet = f.keys.Hash()
	}
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
	if f.suspendedLocked() {
		// Suspended: whatever deadline hardyd gave was measured before;
		// the cluster may have declared this server dead meanwhile.
		f.until = time.Time{}
		f.problem = "the server was suspended; the watchdog isn't petted until hardyd renews the lease"
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

// DetectNoWayOut reads the device's nowayout flag (the driver's or the
// watchdog core's).
func DetectNoWayOut(root fs.FS) bool {
	for _, p := range []string{"sys/class/watchdog/watchdog0/nowayout", "sys/module/watchdog/parameters/nowayout"} {
		if b, err := fs.ReadFile(root, p); err == nil {
			v := strings.TrimSpace(string(b))
			if v == "1" || v == "Y" || v == "y" {
				return true
			}
		}
	}
	return false
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
