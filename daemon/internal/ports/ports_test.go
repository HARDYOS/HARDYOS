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

func TestFixedPortsAreUnique(t *testing.T) {
	seen := map[int]string{}
	names := map[string]bool{}
	for _, e := range Fixed {
		if e.Port < 1 || e.Port > 65535 {
			t.Errorf("%s: port %d out of range", e.Name, e.Port)
		}
		if prev, ok := seen[e.Port]; ok {
			t.Errorf("port %d is both %s and %s", e.Port, prev, e.Name)
		}
		if names[e.Name] {
			t.Errorf("%s is listed twice", e.Name)
		}
		seen[e.Port], names[e.Name] = e.Name, true
	}
	for i, r := range Ranges {
		for j, o := range Ranges {
			if i < j && r.First < o.First+o.Count && o.First < r.First+r.Count {
				t.Errorf("ranges %s and %s overlap", r.Name, o.Name)
			}
		}
		for _, e := range Fixed {
			if e.Port >= r.First && e.Port < r.First+r.Count && !r.SkipsFixed {
				t.Errorf("%s (%d) is inside %s, whose allocator doesn't skip fixed ports", e.Name, e.Port, r.Name)
			}
		}
	}
	if !Reserved(MailRelay) || Reserved(AppProxyFirst) {
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

func TestPortName(t *testing.T) {
	for n, want := range map[string]bool{"DefaultPort": true, "PortRelay": true, "InternalPort": true, "DefaultOfficePort": true,
		"maxReports": false, "Transport": false, "ImportTimeout": false} {
		if portName(n) != want {
			t.Errorf("%s: %v", n, !want)
		}
	}
}
