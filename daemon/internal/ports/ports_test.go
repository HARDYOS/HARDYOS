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

func TestPortName(t *testing.T) {
	for n, want := range map[string]bool{"DefaultPort": true, "PortRelay": true, "InternalPort": true, "DefaultOfficePort": true,
		"maxReports": false, "Transport": false, "ImportTimeout": false} {
		if portName(n) != want {
			t.Errorf("%s: %v", n, !want)
		}
	}
}
