package ports

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNoPortIsUsedTwice(t *testing.T) {
	seen := map[int]string{}
	for name, p := range Fixed {
		if p < 1 || p > 65535 {
			t.Errorf("%s: %d isn't a valid port", name, p)
		}
		if other, dup := seen[p]; dup {
			t.Errorf("%s and %s both use %d", name, other, p)
		}
		seen[p] = name
		if p >= AppProxyBase && p < AppProxyBase+AppProxyCount {
			t.Errorf("%s (%d) is inside the app window proxy range %d-%d", name, p, AppProxyBase, AppProxyBase+AppProxyCount-1)
		}
		if p >= MigrateFirst && p < MigrateFirst+MigrateCount {
			t.Errorf("%s (%d) is inside the live migration range %d-%d", name, p, MigrateFirst, MigrateFirst+MigrateCount-1)
		}
	}
	if !Reserved(MailRelay) || Reserved(AppProxyBase) {
		t.Fatal("Reserved")
	}
}

// TestNoPortNumbersOutsideRegistry walks the daemon's Go code: a constant
// or variable whose name says it's a port must not be a bare number
// anywhere but here, so two packages can't pick the same one unnoticed.
func TestNoPortNumbersOutsideRegistry(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	here, _ := filepath.Abs(".")
	fset := token.NewFileSet()
	var bad []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "vendor" || strings.HasPrefix(n, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || filepath.Dir(p) == here {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) || !portName(name.Name) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.INT {
						continue
					}
					if n, err := strconv.Atoi(lit.Value); err == nil && n > 0 && n <= 65535 {
						rel, _ := filepath.Rel(root, p)
						bad = append(bad, rel+": "+name.Name+" = "+lit.Value)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bad {
		t.Errorf("%s: take the port from internal/ports instead", b)
	}
}

func portName(n string) bool {
	l := strings.ToLower(n)
	if !strings.Contains(l, "port") {
		return false
	}
	for _, not := range []string{"report", "transport", "export", "import", "support", "portal", "passport", "portable"} {
		if strings.Contains(l, not) {
			return false
		}
	}
	return true
}

// Game streaming slots (decision 506): slot 0 is Sunshine's standard set,
// no two slots share a port, no slot reaches into another fixed port,
// the app proxy range or the migration range, and every slot's ports are
// reserved.
func TestStreamingSlots(t *testing.T) {
	s0 := StreamingSlot(0)
	if s0.Base != SunshineHTTP || s0.WebUI != SunshineWebUI {
		t.Fatalf("slot 0 %+v", s0)
	}
	if !equalSets(s0.TCP, SunshineTCP) || !equalSets(s0.UDP, SunshineUDP) {
		t.Fatalf("slot 0's ports aren't Sunshine's own: %+v", s0)
	}
	sunshine := map[int]bool{SunshineHTTPS: true, SunshineHTTP: true, SunshineWebUI: true, SunshineRTSP: true, SunshineVideo: true,
		SunshineControl: true, SunshineAudio: true, SunshineMic: true}
	owner := map[string]int{}
	for s := 0; s < StreamingSlots; s++ {
		set := StreamingSlot(s)
		if got, ok := StreamingSlotOfBase(set.Base); !ok || got != s {
			t.Errorf("slot %d's base %d maps back to %d", s, set.Base, got)
		}
		all := append(append([]int{set.WebUI}, set.TCP...), set.UDP...)
		for i, p := range all {
			proto := "tcp"
			if i > len(set.TCP) {
				proto = "udp"
			}
			key := proto + strconv.Itoa(p)
			if o, dup := owner[key]; dup && o != s {
				t.Errorf("slots %d and %d share %s", o, s, key)
			}
			owner[key] = s
			if !Reserved(p) {
				t.Errorf("slot %d's port %d isn't reserved", s, p)
			}
			if p >= AppProxyBase && p < AppProxyBase+AppProxyCount || p >= MigrateFirst && p < MigrateFirst+MigrateCount || p > 65535 {
				t.Errorf("slot %d's port %d is in another range", s, p)
			}
			for name, f := range Fixed {
				if f == p && !sunshine[p] {
					t.Errorf("slot %d's port %d is %s's", s, p, name)
				}
			}
		}
	}
	if _, ok := StreamingSlotOfBase(SunshineHTTP + 1); ok {
		t.Fatal("a base between slots")
	}
	if len(StreamingWebUIPorts()) != StreamingSlots {
		t.Fatal("web UI ports")
	}
}

func equalSets(a, b []int) bool {
	m := map[int]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestOwnedPorts(t *testing.T) {
	for _, p := range []int{NetBirdStandbyHTTP, NetBirdStandbyHTTPS, NetBirdStandbySTUN} {
		if OwnedBy(p) != NetBirdStandbyApp || !Reserved(p) {
			t.Errorf("%d: owner %q reserved %v", p, OwnedBy(p), Reserved(p))
		}
	}
	if OwnedBy(AppGateway) != "" || OwnedBy(HTTPS) != "" {
		t.Fatal("only the standby's ports are owned")
	}
	for p := range owned {
		inFixed := false
		for _, v := range Fixed {
			inFixed = inFixed || v == p
		}
		if !inFixed {
			t.Errorf("owned port %d isn't in Fixed", p)
		}
	}
}

func TestPortName(t *testing.T) {
	for n, want := range map[string]bool{"DefaultPort": true, "PortRelay": true, "InternalPort": true, "DefaultOfficePort": true,
		"maxReports": false, "Transport": false, "ImportTimeout": false} {
		if portName(n) != want {
			t.Errorf("%s: %v", n, !want)
		}
	}
}
