package cloudbackup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResticArgvHasNoSecrets(t *testing.T) {
	dir := tmp(t)
	log := filepath.Join(dir, "log")
	script := filepath.Join(dir, "restic")
	body := "#!/bin/sh\n" +
		"{ echo \"ARGS $*\"; env | sort; echo \"FD3 $(cat /dev/fd/3)\"; } >> " + log + "\n" +
		"exit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Restic{Binary: script, CacheDir: filepath.Join(dir, "cache"), Resolver: staticResolver{}}
	repo := &Repo{Target: Target{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com", Bucket: "bucket", LimitUploadKiB: 100},
		Creds: Credentials{AccessKey: "AKIDSECRETACCESS", SecretKey: "VERYSECRETKEY", RepoPassword: "repo-password-1234567890"}}
	if _, err := r.Exists(context.Background(), repo); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Backup(context.Background(), repo, ResticBackup{Stdin: strings.NewReader("x"), StdinName: "s.raw", Tags: []string{"task=t"}}, nil); err == nil {
		t.Fatal("a backup without a summary was accepted")
	}
	b, _ := os.ReadFile(log)
	out := string(b)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "ARGS ") {
			for _, secret := range []string{"AKIDSECRETACCESS", "VERYSECRETKEY", "repo-password", "s3.example.com"} {
				if strings.Contains(line, secret) {
					t.Fatalf("%q on the command line: %s", secret, line)
				}
			}
		}
	}
	for _, want := range []string{"AWS_ACCESS_KEY_ID=AKIDSECRETACCESS", "AWS_SECRET_ACCESS_KEY=VERYSECRETKEY", "RESTIC_REPOSITORY=s3:https://s3.example.com/bucket",
		"RESTIC_PASSWORD_FILE=/dev/fd/3", "FD3 repo-password-1234567890", "HTTPS_PROXY=http://127.0.0.1:", "--limit-upload 100"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "RESTIC_PASSWORD=") {
		t.Error("the password is in the environment")
	}
	// Nothing from the caller's environment leaks in.
	if strings.Contains(out, "GOPATH=") || strings.Contains(out, "GOROOT=") {
		t.Error("restic inherited the caller's environment")
	}
	// Bad arguments never reach restic.
	for _, a := range []ResticBackup{
		{Path: "relative"},
		{Path: "/x/../etc"},
		{Stdin: strings.NewReader(""), StdinName: "../x"},
		{Path: "/ok", Tags: []string{"--password=x"}},
		{Path: "/ok", Excludes: []string{"a/b"}},
	} {
		if _, err := r.Backup(context.Background(), repo, a, nil); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
}

func TestCancelKillsRestic(t *testing.T) {
	dir := tmp(t)
	pidFile := filepath.Join(dir, "pid")
	script := filepath.Join(dir, "restic")
	// restic that ignores SIGINT and starts a child: both must go.
	body := "#!/bin/sh\ntrap '' INT\nsleep 300 &\necho $! > " + pidFile + "\nwait\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Restic{Binary: script, CacheDir: filepath.Join(dir, "cache"), KillGrace: time.Second}
	repo := &Repo{Target: Target{ID: "x", Name: "x", Kind: KindLocal, Path: "/nowhere"}, Creds: Credentials{RepoPassword: "p"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := r.run(ctx, repo, call{args: []string{"check"}}); done <- err }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		sleepMS(50)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("a cancelled run reported success")
	}
	b, _ := os.ReadFile(pidFile)
	pid := strings.TrimSpace(string(b))
	if pid == "" {
		t.Fatal("the child never started")
	}
	if _, err := os.Stat("/proc/" + pid); err == nil {
		st, _ := os.ReadFile("/proc/" + pid + "/stat")
		if !strings.Contains(string(st), ") Z ") {
			t.Fatalf("the child %s survived the cancel", pid)
		}
	}
}
