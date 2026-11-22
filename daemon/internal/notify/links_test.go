package notify

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// linkList is the list the web desktop's link handler is tested against
// (web/apps/shell/src/links.test.ts). Both sides read the same file.
const linkList = "../../../web/apps/shell/src/notification-links.json"

// Types whose Link field ends up as a notification's link.
var linkCarriers = map[string]bool{"Event": true, "Notification": true, "Condition": true}

// TestEveryEmittedLinkIsKnown walks the daemon's source, finds every Link
// given to an Event, Notification or Condition, and checks it against
// notification-links.json, so a link the desktop can't open (such as
// "control-panel/mail" when the handler expects "control/...") fails here.
func TestEveryEmittedLinkIsKnown(t *testing.T) {
	raw, err := os.ReadFile(linkList)
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Links []string }
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	match := func(where string, v linkValue) {
		for _, p := range list.Links {
			i := strings.IndexByte(p, '{')
			if (!v.dynamic && i < 0 && p == v.text) || (v.dynamic && i >= 0 && p[:i] == v.text && v.text != "") {
				used[p] = true
				return
			}
		}
		if v.dynamic {
			t.Errorf("%s: link %q+... isn't in %s", where, v.text, filepath.Base(linkList))
		} else {
			t.Errorf("%s: link %q isn't in %s", where, v.text, filepath.Base(linkList))
		}
	}

	fset := token.NewFileSet()
	found := 0
	root := filepath.Join("..", "..")
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == "oidc") {
			// oidc's pages have a Link field of their own (a page's button).
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || !linkCarriers[typeName(cl.Type)] {
				return true
			}
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Link" {
					continue
				}
				where := fset.Position(kv.Pos()).String()
				if sel, ok := kv.Value.(*ast.SelectorExpr); ok && sel.Sel.Name == "Link" {
					continue // passes another event's link on
				}
				vals, ok := resolve(kv.Value, 0)
				if !ok {
					t.Errorf("%s: can't tell what this Link is; use a string, \"prefix/\"+x, or a local variable or constant set to one", where)
					continue
				}
				for _, v := range vals {
					found++
					match(where, v)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 20 {
		t.Fatalf("found only %d links; the source walk is broken", found)
	}
	for _, p := range list.Links {
		if !used[p] {
			t.Errorf("%s lists %q but nothing in the daemon emits it", filepath.Base(linkList), p)
		}
	}
}

type linkValue struct {
	text    string
	dynamic bool // text is a prefix; the rest is filled in at run time
}

func typeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

func resolve(e ast.Expr, depth int) ([]linkValue, bool) {
	if depth > 4 {
		return nil, false
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return nil, false
		}
		s, err := strconv.Unquote(x.Value)
		return []linkValue{{text: s}}, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return nil, false
		}
		left, ok := resolve(x.X, depth+1)
		if !ok || len(left) != 1 || left[0].dynamic {
			return nil, false
		}
		return []linkValue{{text: left[0].text, dynamic: true}}, true
	case *ast.Ident:
		if x.Obj == nil {
			return nil, false
		}
		switch d := x.Obj.Decl.(type) {
		case *ast.AssignStmt:
			for i, l := range d.Lhs {
				if id, ok := l.(*ast.Ident); ok && id.Name == x.Name && i < len(d.Rhs) {
					return resolve(d.Rhs[i], depth+1)
				}
			}
		case *ast.ValueSpec:
			for i, n := range d.Names {
				if n.Name == x.Name && i < len(d.Values) {
					return resolve(d.Values[i], depth+1)
				}
			}
		}
	}
	return nil, false
}
