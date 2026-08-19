// Package canon provides the single canonical-encoding primitive that every
// hashed or signed structure in VERITY is built from.
//
// It exists because the alternative — each package concatenating its own
// fields into a buffer — is a reliable source of subtle, exploitable bugs.
// Two rules prevent them, and centralising them here means they are
// enforced once rather than remembered five times:
//
//   - Domain separation. Every encoding starts with a unique label, so a
//     byte string produced for one purpose (a quote) can never be
//     reinterpreted as a valid byte string for another (a decision).
//   - Length prefixing. Every variable-length field is preceded by its
//     length, so distinct values cannot concatenate into identical
//     encodings. Without it, {"a\x00b", "c"} and {"a", "b\x00c"} hash the
//     same — and a hash collision between two different policies is exactly
//     the substitution that measurement is supposed to make impossible.
//   - Type tagging. Every field is preceded by a byte naming its type, so
//     values of different types cannot collide either. Length prefixes
//     alone are not enough: the integer 0 and the empty string both encode
//     as eight zero bytes. Position within a fixed schema would disambiguate
//     them, but that makes injectivity depend on an invariant held by every
//     caller rather than by this package, and the cost of not depending on
//     it is one byte per field.
//
// The zero value is not usable; start with New.
package canon

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// Field type tags. Their values are arbitrary but must stay stable: they
// are inputs to every measurement, quote, decision, and checkpoint digest
// the system produces.
const (
	tagOctets uint8 = 'o' // length-prefixed bytes or string
	tagUint   uint8 = 'u'
	tagBool   uint8 = 'b'
	tagList   uint8 = 'l'
	tagRaw32  uint8 = 'r'
)

// Hasher accumulates canonically framed fields. Methods chain.
type Hasher struct {
	h hash.Hash
}

// New starts an encoding in the given domain. The domain is written as an
// ordinary tagged, length-prefixed field, so no domain can be a prefix of
// another and no content can make up the difference.
func New(domain string) *Hasher {
	w := &Hasher{h: sha256.New()}
	return w.String(domain)
}

// Uint64 appends a fixed-width integer.
func (w *Hasher) Uint64(v uint64) *Hasher {
	return w.tag(tagUint).uint(v)
}

// Bool appends a boolean.
func (w *Hasher) Bool(v bool) *Hasher {
	b := byte(0)
	if v {
		b = 1
	}
	w.tag(tagBool).h.Write([]byte{b})
	return w
}

// Bytes appends a length-prefixed byte field. It frames identically to
// String: both are octet strings, and the distinction is a Go one.
func (w *Hasher) Bytes(b []byte) *Hasher {
	w.tag(tagOctets).uint(uint64(len(b))).h.Write(b)
	return w
}

// String appends a length-prefixed string field.
func (w *Hasher) String(s string) *Hasher {
	return w.Bytes([]byte(s))
}

// Strings appends a counted sequence of string fields. The count is
// committed to, so a list cannot be confused with a shorter list followed
// by other fields.
func (w *Hasher) Strings(ss []string) *Hasher {
	w.tag(tagList).uint(uint64(len(ss)))
	for _, s := range ss {
		w.String(s)
	}
	return w
}

// Raw32 appends a fixed 32-byte value, such as a nested digest.
func (w *Hasher) Raw32(b [32]byte) *Hasher {
	w.tag(tagRaw32).h.Write(b[:])
	return w
}

func (w *Hasher) tag(t uint8) *Hasher {
	w.h.Write([]byte{t})
	return w
}

func (w *Hasher) uint(v uint64) *Hasher {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.h.Write(b[:])
	return w
}

// Sum returns the 32-byte digest of everything appended so far.
func (w *Hasher) Sum() [32]byte {
	var out [32]byte
	w.h.Sum(out[:0])
	return out
}

// SumBytes is Sum as a slice, for callers handing the digest straight to a
// signing function.
func (w *Hasher) SumBytes() []byte {
	out := w.Sum()
	return out[:]
}
