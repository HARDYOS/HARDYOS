package sharelinks

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/files"
)

func TestIsResume(t *testing.T) {
	mod := time.Date(2026, 10, 1, 12, 0, 0, 500, time.UTC)
	fe := &files.Entry{Name: "film.mp4", Size: 1000, Modified: mod}
	cases := []struct {
		rng, ifRange string
		resume, bad  bool
	}{
		{rng: "", resume: false},
		{rng: "bytes=500-", resume: true},
		{rng: "bytes=500-999", resume: true},
		{rng: "bytes= 500-", resume: true},
		{rng: "bytes=1-", resume: true},
		{rng: "bytes=-100", resume: true},
		{rng: "bytes=,500-", resume: true},
		// Byte 0, written any way, is a new download.
		{rng: "bytes=0-"},
		{rng: "bytes= 0-"},
		{rng: "bytes=\t0-"},
		{rng: "bytes=0 -"},
		{rng: "bytes=00-"},
		{rng: "bytes=0-0"},
		{rng: "bytes=-1000"},
		{rng: "bytes=-5000"},
		// More than one range is a new download, whatever the ranges.
		{rng: "bytes=1-,0-"},
		{rng: "bytes=1-, 0-"},
		{rng: "bytes=500-600,700-800"},
		{rng: "bytes=500-,500-"},
		// If-Range that ServeContent would answer with the whole file.
		{rng: "bytes=500-", ifRange: `"etag"`},
		{rng: "bytes=500-", ifRange: "Wed, 01 Oct 2026 11:00:00 GMT"},
		{rng: "bytes=500-", ifRange: "nonsense"},
		{rng: "bytes=500-", ifRange: "Thu, 01 Oct 2026 12:00:00 GMT", resume: true},
		// Not ranges ServeContent would serve: refused (416).
		{rng: "Bytes=500-", bad: true},
		{rng: "bytes=x-", bad: true},
		{rng: "bytes=+0-", bad: true},
		{rng: "bytes=5-1", bad: true},
		{rng: "bytes=-", bad: true},
		{rng: "bytes=--5", bad: true},
		{rng: "bytes=500", bad: true},
		{rng: "items=0-", bad: true},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/s/x/download", nil)
		if c.rng != "" {
			r.Header.Set("Range", c.rng)
		}
		if c.ifRange != "" {
			r.Header.Set("If-Range", c.ifRange)
		}
		ranges, err := parseRange(c.rng)
		if (err != nil) != c.bad {
			t.Errorf("parseRange(%q) err = %v, want bad=%v", c.rng, err, c.bad)
			continue
		}
		if err != nil {
			continue
		}
		if got := isResume(r, ranges, fe); got != c.resume {
			t.Errorf("isResume(%q, If-Range %q) = %v, want %v", c.rng, c.ifRange, got, c.resume)
		}
	}
	// Two Range headers: a new download.
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Range", "bytes=500-")
	r.Header.Add("Range", "bytes=0-")
	ranges, _ := parseRange(r.Header.Get("Range"))
	if isResume(r, ranges, fe) {
		t.Error("two Range headers count as a resume")
	}
}

func TestUploadNameAndZipName(t *testing.T) {
	for raw, want := range map[string]string{
		"photo.jpg":            "photo.jpg",
		`C:\Users\me\cv.pdf`:   "cv.pdf",
		"../../etc/passwd":     "passwd",
		"  spaced.txt ":        "spaced.txt",
		"a.tar.gz":             "a.tar.gz",
		"résumé.docx":          "résumé.docx",
		".env":                 "",
		".htaccess":            "",
		"dir/.hidden":          "",
		".recycle":             "",
		".hardyos-upload-abcd": "",
		"bad\x01name.txt":      "",
		"tab\tname.txt":        "",
		"new\nline.txt":        "",
		"del\x7f.txt":          "",
		"c1\u0085.txt":         "",
		"bad\xffutf8.txt":      "",
		"..":                   "",
		"":                     "",
	} {
		got, ok := uploadName(raw)
		if want == "" && ok {
			t.Errorf("uploadName(%q) = %q, want refused", raw, got)
		} else if want != "" && got != want {
			t.Errorf("uploadName(%q) = %q %v, want %q", raw, got, ok, want)
		}
	}
	for in, want := range map[string]string{
		"plain.txt":        "plain.txt",
		`a\b.txt`:          "a_b.txt",
		"c:d.txt":          "c_d.txt",
		"C:":               "C_",
		"tab\tname":        "tab_name",
		"nul\x00x":         "nul_x",
		"bell\x07\x1b.txt": "bell__.txt",
		"résumé ☃.txt":     "résumé ☃.txt",
	} {
		if got := ZipName(in); got != want {
			t.Errorf("ZipName(%q) = %q, want %q", in, got, want)
		}
	}
}
