package nbstandby

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Snapshots are kept sealed (decision 422): a stream of AES-256-GCM chunks
// under a key made for that one file from root's own key (HMAC of a random
// file id), so the nonce can simply count chunks. Each chunk's additional
// data names the file and whether it is the last one: chunks can't be
// reordered, moved to another file, dropped from the end or followed by
// anything.

const (
	sealMagic = "HNBSNAP1"
	chunkSize = 1 << 20
	fileIDLen = 16
)

var errTruncated = errors.New("the sealed snapshot is cut short")

func fileKey(root []byte, id []byte) (cipher.AEAD, error) {
	if len(root) != 32 {
		return nil, errors.New("the sealing key must be 32 bytes")
	}
	m := hmac.New(sha256.New, root)
	m.Write([]byte("hardyos nbstandby file key v1\x00"))
	m.Write(id)
	blk, err := aes.NewCipher(m.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func chunkAAD(id []byte, final bool) []byte {
	a := append([]byte("hardyos nbstandby chunk v1\x00"), id...)
	if final {
		return append(a, 1)
	}
	return append(a, 0)
}

func chunkNonce(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

// gcmSeal seals a small secret (root's SSH key seed) with AES-256-GCM.
func gcmSeal(key, plain, aad []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, aad), nil
}

func gcmOpen(key, sealed, aad []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("damaged")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}

// SealWriter seals everything written to it; Close writes the last chunk.
type SealWriter struct {
	w      io.Writer
	g      cipher.AEAD
	id     []byte
	buf    []byte
	n      uint64
	closed bool
	err    error
}

// NewSealWriter starts a sealed stream on w with the root key key.
func NewSealWriter(w io.Writer, key []byte) (*SealWriter, error) {
	id := make([]byte, fileIDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	g, err := fileKey(key, id)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(append([]byte(sealMagic), id...)); err != nil {
		return nil, err
	}
	return &SealWriter{w: w, g: g, id: id, buf: make([]byte, 0, chunkSize)}, nil
}

func (s *SealWriter) flush(final bool) error {
	ct := s.g.Seal(nil, chunkNonce(s.n), s.buf, chunkAAD(s.id, final))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	if _, err := s.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(ct); err != nil {
		return err
	}
	s.n++
	s.buf = s.buf[:0]
	return nil
}

func (s *SealWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.closed {
		return 0, errors.New("write after close")
	}
	total := len(p)
	for len(p) > 0 {
		room := chunkSize - len(s.buf)
		take := min(room, len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		// A full chunk is written only once more data follows, so the
		// last chunk (written by Close) is never empty unless the stream is.
		if len(s.buf) == chunkSize && len(p) > 0 {
			if err := s.flush(false); err != nil {
				s.err = err
				return total - len(p), err
			}
		}
	}
	return total, nil
}

// Close writes the final chunk. It doesn't close the underlying writer.
func (s *SealWriter) Close() error {
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.err != nil {
		return s.err
	}
	s.err = s.flush(true)
	return s.err
}

type openReader struct {
	r     *bufio.Reader
	g     cipher.AEAD
	id    []byte
	n     uint64
	plain []byte
	done  bool
	err   error
}

// OpenReader reads a stream SealWriter made; any change, truncation or
// trailing data is an error (only after the final chunk does Read return
// io.EOF).
func OpenReader(r io.Reader, key []byte) (io.Reader, error) {
	br := bufio.NewReader(r)
	hdr := make([]byte, len(sealMagic)+fileIDLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, errors.New("not a sealed snapshot")
	}
	if string(hdr[:len(sealMagic)]) != sealMagic {
		return nil, errors.New("not a sealed snapshot")
	}
	id := hdr[len(sealMagic):]
	g, err := fileKey(key, id)
	if err != nil {
		return nil, err
	}
	return &openReader{r: br, g: g, id: id}, nil
}

func (o *openReader) next() error {
	var hdr [4]byte
	if _, err := io.ReadFull(o.r, hdr[:]); err != nil {
		return errTruncated
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < uint32(o.g.Overhead()) || n > chunkSize+uint32(o.g.Overhead()) {
		return errors.New("the sealed snapshot is damaged")
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(o.r, ct); err != nil {
		return errTruncated
	}
	nonce := chunkNonce(o.n)
	if p, err := o.g.Open(nil, nonce, ct, chunkAAD(o.id, false)); err == nil {
		o.plain, o.n = p, o.n+1
		return nil
	}
	p, err := o.g.Open(nil, nonce, ct, chunkAAD(o.id, true))
	if err != nil {
		return fmt.Errorf("the sealed snapshot doesn't open with this server's key (or was changed)")
	}
	if _, err := o.r.ReadByte(); err != io.EOF {
		return errors.New("the sealed snapshot has data after its end")
	}
	o.plain, o.n, o.done = p, o.n+1, true
	return nil
}

func (o *openReader) Read(p []byte) (int, error) {
	for len(o.plain) == 0 {
		if o.err != nil {
			return 0, o.err
		}
		if o.done {
			return 0, io.EOF
		}
		if err := o.next(); err != nil {
			o.err = err
			return 0, err
		}
	}
	n := copy(p, o.plain)
	o.plain = o.plain[n:]
	return n, nil
}
