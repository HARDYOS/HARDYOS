// Package qrsvg draws QR codes as SVG paths (rsc.io/qr does the encoding),
// so the desktop and the sign-in provider's script-free pages can show the
// authenticator enrollment code without images from anywhere else.
package qrsvg

import (
	"fmt"
	"strconv"
	"strings"

	"rsc.io/qr"
)

// quiet is the margin of light modules the QR standard asks for.
const quiet = 4

// Code is a QR code as one SVG path: dark modules on a light square of
// Size modules (quiet zone included).
type Code struct {
	Size int    `json:"size"`
	Path string `json:"path"`
}

// Encode makes the QR code for text (error correction level M).
func Encode(text string) (*Code, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; {
			if !c.Black(x, y) {
				x++
				continue
			}
			run := 1
			for x+run < c.Size && c.Black(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run
		}
	}
	return &Code{Size: c.Size + 2*quiet, Path: b.String()}, nil
}

// SVG is the code as a complete <svg> element. It holds only numbers and
// fixed markup, so it is safe to put in a page as it is.
func (c *Code) SVG(pixels int) string {
	s := strconv.Itoa(c.Size)
	px := strconv.Itoa(pixels)
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ` + s + ` ` + s + `" width="` + px + `" height="` + px +
		`" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="` + s + `" height="` + s +
		`" fill="#fff"/><path fill="#000" d="` + c.Path + `"/></svg>`
}
