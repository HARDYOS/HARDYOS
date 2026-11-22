package qrsvg

import (
	"regexp"
	"strings"
	"testing"

	"rsc.io/qr"
)

func TestEncode(t *testing.T) {
	text := "otpauth://totp/HardyOS%20%28nas%29:HOME%5Calice?algorithm=SHA1&digits=6&issuer=HardyOS+%28nas%29&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	c, err := Encode(text)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := qr.Encode(text, qr.M)
	if c.Size != raw.Size+2*quiet || c.Size < 21+2*quiet {
		t.Fatalf("size %d", c.Size)
	}
	// Only path commands and numbers: nothing that could break out of an
	// attribute or element.
	if !regexp.MustCompile(`^[Mhvz0-9 -]+$`).MatchString(c.Path) {
		t.Fatal("unexpected characters in the path")
	}
	// The top-left finder pattern's first row is seven dark modules.
	if !strings.HasPrefix(c.Path, "M4 4h7v1h-7z") {
		t.Fatalf("finder pattern missing: %.40s", c.Path)
	}
	svg := c.SVG(200)
	if !strings.HasPrefix(svg, "<svg ") || !strings.Contains(svg, `width="200"`) || strings.Contains(svg, "<script") {
		t.Fatal(svg[:80])
	}
}
