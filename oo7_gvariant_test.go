package keyring

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Golden vectors serialised by GLib's GVariant implementation, e.g. in Python:
//
//	GLib.Variant('(uayutua(a{say}ay))', ...).get_data_as_bytes()
//
// GLib emits dictionary entries in the order given, which only equals the
// sorted order this encoder uses for some of the item vectors, so those cases
// say whether the encoding must match byte for byte.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOO7GVariantKeyringVectors(t *testing.T) {
	cases := []struct {
		name   string
		golden string
		file   oo7File
	}{
		{
			name:   "empty",
			golden: "200000000101010101010101010101010101010101010101010101010101010101010101a086010000f15365000000000000000024",
			file: oo7File{
				salt:           bytes.Repeat([]byte{1}, 32),
				iterationCount: 100000,
				modifiedTime:   1700000000,
			},
		},
		{
			name:   "one item",
			golden: "04000000aabbccdda08601000000000001f1536500000000030000006b657900010204736572766963650003080711101112131708",
			file: oo7File{
				salt:           []byte{0xaa, 0xbb, 0xcc, 0xdd},
				iterationCount: 100000,
				modifiedTime:   1700000001,
				usageCount:     3,
				items: []oo7EncryptedItem{{
					hashedAttributes: map[string][]byte{"key": {1, 2}, "service": {3}},
					blob:             []byte{0x10, 0x11, 0x12},
				}},
			},
		},
		{
			name:   "two items with empty members",
			golden: "02000000000100000700000000000000090000000000000001000000006100ff02040005010806",
			file: oo7File{
				salt:           []byte{0, 1},
				iterationCount: 7,
				modifiedTime:   9,
				usageCount:     1,
				items: []oo7EncryptedItem{
					{hashedAttributes: map[string][]byte{}, blob: []byte{}},
					{hashedAttributes: map[string][]byte{"a": {0xff}}, blob: []byte{0}},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			golden := mustHex(t, tc.golden)
			encoded := tc.file.marshal()
			if got := encoded[len(oo7FileHeader)+2:]; !bytes.Equal(got, golden) {
				t.Fatalf("encoding mismatch\n got %x\nwant %x", got, golden)
			}
			decoded, err := parseOO7File(encoded)
			if err != nil {
				t.Fatal(err)
			}
			assertOO7FileEqual(t, decoded, &tc.file)
		})
	}
}

func TestOO7GVariantItemVectors(t *testing.T) {
	bigAttrs := map[string]string{}
	for _, k := range []string{"k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10", "k11"} {
		bigAttrs[k] = strings.Repeat("v", 20)
	}
	cases := []struct {
		name   string
		golden string
		exact  bool
		item   oo7Item
	}{
		{
			name:   "simple",
			golden: "6b6579006c6c616d6173000473657276696365006b657972696e672d7465737400080c226c6c616d617300000000000000f153650000000001f15365000000006c6c616d6173206172652067726561742b24",
			exact:  true,
			item: oo7Item{
				attributes: map[string]string{"key": "llamas", "service": "keyring-test"},
				label:      "llamas",
				created:    1700000000,
				modified:   1700000001,
				secret:     []byte("llamas are great"),
			},
		},
		{
			name:   "empty",
			golden: "0000000000000000000000000000000000000000000000000100",
			exact:  true,
			item:   oo7Item{attributes: map[string]string{}, secret: []byte{}},
		},
		{
			name: "two byte offsets",
			golden: "6b3000767676767676767676767676767676767676767600036b3100767676767676767676767676767676767676767600036b3200767676767676767676767676767676767676767600036b3300767676767676767676767676767676767676767600036b3400767676767676767676767676767676767676767600036b3500767676767676767676767676767676767676767600036b3600767676767676767676767676767676767676767600036b3700767676767676767676767676767676767676767600036b3800767676767676767676767676767676767676767600036b3900767676767676767676767676767676767676767600036b313000767676767676767676767676767676767676767600046b31310076767676767676767676767676767676767676760004190032004b0064007d009600af00c800e100" +
				"fa0014012e014c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c00000000000000000100000000000000020000000000000078787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787879014601",
			item: oo7Item{
				attributes: bigAttrs,
				label:      strings.Repeat("L", 50),
				created:    1,
				modified:   2,
				secret:     bytes.Repeat([]byte("x"), 300),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			golden := mustHex(t, tc.golden)
			if encoded := tc.item.marshal(); tc.exact && !bytes.Equal(encoded, golden) {
				t.Fatalf("encoding mismatch\n got %x\nwant %x", encoded, golden)
			}
			decoded, err := parseOO7Item(golden)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.item
			want.attributes = withDefaultContentType(want.attributes)
			assertOO7ItemEqual(t, decoded, &want)

			// Whatever the dictionary order on disk, re-encoding must round-trip.
			again, err := parseOO7Item(decoded.marshal())
			if err != nil {
				t.Fatal(err)
			}
			assertOO7ItemEqual(t, again, &want)
		})
	}
}

func TestOO7ParseFileRejectsMalformedData(t *testing.T) {
	f, err := newOO7File()
	if err != nil {
		t.Fatal(err)
	}
	good := f.marshal()
	cases := map[string]func([]byte) []byte{
		"wrong header":        func(b []byte) []byte { b[0] = 'X'; return b },
		"unsupported version": func(b []byte) []byte { b[len(oo7FileHeader)] = 2; return b },
		"truncated":           func(b []byte) []byte { return b[:len(oo7FileHeader)+2+3] },
		"salt size mismatch":  func(b []byte) []byte { b[len(oo7FileHeader)+2] = 31; return b },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOO7File(mutate(append([]byte(nil), good...))); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestOO7GVariantRejectsMalformedData(t *testing.T) {
	cases := map[string][]byte{
		"truncated string":            {'a', 'b'},
		"interior nul in string":      {'a', 0, 'b', 0},
		"offset beyond data":          {'k', 0, 'v', 0, 0x09, 0x0a},
		"array offset beyond data":    {'k', 0, 'v', 0, 0x02, 0xff},
		"struct offsets out of order": {'k', 0, 'v', 0, 0x20},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := gvDecodeStringDict(data); err == nil {
				t.Fatalf("expected an error decoding %x", data)
			}
		})
	}
}

func withDefaultContentType(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs)+1)
	for k, v := range attrs {
		out[k] = v
	}
	if _, ok := out[oo7ContentTypeAttribute]; !ok {
		out[oo7ContentTypeAttribute] = oo7DefaultContentType
	}
	return out
}

func assertOO7FileEqual(t *testing.T, got, want *oo7File) {
	t.Helper()
	if !bytes.Equal(got.salt, want.salt) || got.iterationCount != want.iterationCount ||
		got.modifiedTime != want.modifiedTime || got.usageCount != want.usageCount {
		t.Fatalf("header mismatch: got %+v want %+v", got, want)
	}
	if len(got.items) != len(want.items) {
		t.Fatalf("got %d items, want %d", len(got.items), len(want.items))
	}
	for i := range want.items {
		if !bytes.Equal(got.items[i].blob, want.items[i].blob) {
			t.Fatalf("item %d blob mismatch: got %x want %x", i, got.items[i].blob, want.items[i].blob)
		}
		if len(got.items[i].hashedAttributes) != len(want.items[i].hashedAttributes) {
			t.Fatalf("item %d attribute count mismatch", i)
		}
		for k, v := range want.items[i].hashedAttributes {
			if !bytes.Equal(got.items[i].hashedAttributes[k], v) {
				t.Fatalf("item %d attribute %q mismatch", i, k)
			}
		}
	}
}

func assertOO7ItemEqual(t *testing.T, got, want *oo7Item) {
	t.Helper()
	if got.label != want.label || got.created != want.created || got.modified != want.modified ||
		!bytes.Equal(got.secret, want.secret) {
		t.Fatalf("item mismatch: got %+v want %+v", got, want)
	}
	if len(got.attributes) != len(want.attributes) {
		t.Fatalf("attribute mismatch: got %v want %v", got.attributes, want.attributes)
	}
	for k, v := range want.attributes {
		if got.attributes[k] != v {
			t.Fatalf("attribute %q: got %q want %q", k, got.attributes[k], v)
		}
	}
}
