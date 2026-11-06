package office

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"path"
	"strconv"
	"strings"
	"time"
)

// Format is a file type the editor opens.
type Format struct {
	Ext string `json:"ext"`
	// DocumentType is the Document Server's editor: word, cell or slide.
	DocumentType string `json:"documentType"`
	// Editable: the editor can save it back in the same format. ODF, CSV
	// and plain text are "lossy" in the Document Server (formatting it
	// doesn't support is dropped on save); the editor warns about it.
	Editable bool `json:"editable"`
	Lossy    bool `json:"lossy"`
}

// Formats are the types the File Manager opens in the editor.
var Formats = []Format{
	{Ext: "docx", DocumentType: "word", Editable: true},
	{Ext: "xlsx", DocumentType: "cell", Editable: true},
	{Ext: "pptx", DocumentType: "slide", Editable: true},
	{Ext: "odt", DocumentType: "word", Editable: true, Lossy: true},
	{Ext: "ods", DocumentType: "cell", Editable: true, Lossy: true},
	{Ext: "odp", DocumentType: "slide", Editable: true, Lossy: true},
	{Ext: "csv", DocumentType: "cell", Editable: true, Lossy: true},
	{Ext: "txt", DocumentType: "word", Editable: true, Lossy: true},
	{Ext: "rtf", DocumentType: "word", Editable: true, Lossy: true},
	// Older binary formats open read only.
	{Ext: "doc", DocumentType: "word"},
	{Ext: "xls", DocumentType: "cell"},
	{Ext: "ppt", DocumentType: "slide"},
}

// FormatOf returns the format of a file name, by extension.
func FormatOf(name string) (Format, bool) {
	ext := strings.TrimPrefix(strings.ToLower(path.Ext(name)), ".")
	for _, f := range Formats {
		if f.Ext == ext {
			return f, true
		}
	}
	return Format{}, false
}

// MaxKeyLength is the Document Server's limit on a document key.
const MaxKeyLength = 128

// DeriveKey is a document key: the Document Server's name for one version
// of one file being edited. Everyone who opens the file while a session is
// open gets the same key (so they edit together); a new session after the
// file changed gets a new one. It's an HMAC under a key only hardyd has, so
// a key can't be guessed from the file's name and time, and nonce makes
// two sessions on the same unchanged file distinct (a session that ended
// with an error isn't resumed by accident). 40 characters from [A-Za-z0-9_-],
// all allowed in a key.
func DeriveKey(secret []byte, share, filePath string, size int64, modified time.Time, nonce string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("hardyos-office-key\x00"))
	m.Write([]byte(share))
	m.Write([]byte{0})
	m.Write([]byte(filePath))
	m.Write([]byte{0})
	m.Write([]byte(strconv.FormatInt(size, 10)))
	m.Write([]byte{0})
	m.Write([]byte(strconv.FormatInt(modified.UnixNano(), 10)))
	m.Write([]byte{0})
	m.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))[:40]
}

// ValidKey reports whether s could be a key DeriveKey made.
func ValidKey(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
