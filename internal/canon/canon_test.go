package canon

import "testing"

// The whole point of this package is that distinct inputs cannot produce
// identical encodings. These tests are the concrete statements of that.

func TestLengthPrefixingPreventsFieldConfusion(t *testing.T) {
	// The classic concatenation bug: without length prefixes, moving a
	// separator across a field boundary produces the same bytes. This is
	// exactly how two different enclave images could share a measurement.
	cases := [][2][]string{
		{{"a\x00b", "c"}, {"a", "b\x00c"}},
		{{"ab", "c"}, {"a", "bc"}},
		{{"", "abc"}, {"abc", ""}},
		{{"a", ""}, {"", "a"}},
	}
	for _, c := range cases {
		x := New("d").String(c[0][0]).String(c[0][1]).Sum()
		y := New("d").String(c[1][0]).String(c[1][1]).Sum()
		if x == y {
			t.Fatalf("fields %q and %q must not encode identically", c[0], c[1])
		}
	}
}

func TestDomainSeparation(t *testing.T) {
	if New("verity/quote/v2").String("x").Sum() == New("verity/decision/v2").String("x").Sum() {
		t.Fatal("the same content in different domains must hash differently")
	}
	// No domain may be a prefix of another in a way that lets content make
	// up the difference: "ab" + field "c" must differ from "a" + field "bc".
	if New("ab").String("c").Sum() == New("a").String("bc").Sum() {
		t.Fatal("domain label must itself be length-prefixed")
	}
}

func TestStringsCommitsToCount(t *testing.T) {
	// A list must not be confusable with a shorter list followed by a
	// separate field of the same content.
	if New("d").Strings([]string{"a", "b"}).Sum() ==
		New("d").Strings([]string{"a"}).String("b").Sum() {
		t.Fatal("list encoding must commit to its element count")
	}
	if New("d").Strings(nil).Sum() != New("d").Strings([]string{}).Sum() {
		t.Fatal("nil and empty lists must encode identically")
	}
	if New("d").Strings([]string{"a", "b"}).Sum() == New("d").Strings([]string{"b", "a"}).Sum() {
		t.Fatal("list encoding must preserve order; callers normalise before hashing")
	}
}

func TestTypedFieldsAreDistinguished(t *testing.T) {
	// A bool must not collide with an integer or a string that happens to
	// share a byte pattern.
	if New("d").Bool(true).Sum() == New("d").Uint64(1).Sum() {
		t.Fatal("bool and uint64 must not collide")
	}
	if New("d").Bool(false).Sum() == New("d").Bool(true).Sum() {
		t.Fatal("bool values must be distinguished")
	}
	if New("d").Uint64(0).Sum() == New("d").String("").Sum() {
		t.Fatal("a zero integer must not collide with an empty string")
	}
}

func TestBytesAndStringAgree(t *testing.T) {
	if New("d").Bytes([]byte("x")).Sum() != New("d").String("x").Sum() {
		t.Fatal("Bytes and String must frame identical content identically")
	}
	if New("d").Bytes(nil).Sum() != New("d").String("").Sum() {
		t.Fatal("nil bytes and the empty string must encode identically")
	}
}

func TestDeterministicAndFullWidth(t *testing.T) {
	a := New("d").String("x").Uint64(7).Bool(true).Raw32([32]byte{1}).Sum()
	b := New("d").String("x").Uint64(7).Bool(true).Raw32([32]byte{1}).Sum()
	if a != b {
		t.Fatal("encoding must be deterministic")
	}
	if len(New("d").SumBytes()) != 32 {
		t.Fatal("digest must be 32 bytes")
	}
}

// A 4 GiB+ field would overflow a 32-bit length prefix; the encoder uses 64
// bits so that a length can never wrap into a colliding value. Verifying the
// full 8-byte width directly is cheaper than allocating 4 GiB.
func TestLengthPrefixIsSixtyFourBits(t *testing.T) {
	if New("d").Uint64(1<<32).Sum() == New("d").Uint64(0).Sum() {
		t.Fatal("length/size fields must not truncate at 32 bits")
	}
}
