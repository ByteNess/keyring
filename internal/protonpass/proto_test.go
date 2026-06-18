package protonpass

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildMetadata encodes a Metadata{name, note} sub-message and interleaves an
// unknown varint field (item_uuid-ish) to prove the parser skips what it doesn't model.
func buildMetadata(name, note string) []byte {
	var m []byte
	m = protowire.AppendTag(m, fieldMetadataName, protowire.BytesType)
	m = protowire.AppendBytes(m, []byte(name))
	m = protowire.AppendTag(m, 9, protowire.VarintType) // unknown field, must be skipped
	m = protowire.AppendVarint(m, 42)
	m = protowire.AppendTag(m, fieldMetadataNote, protowire.BytesType)
	m = protowire.AppendBytes(m, []byte(note))
	return m
}

// buildItem encodes an Item{metadata}, plus an unknown content sub-message and a
// fixed32 field, so the top-level walk also exercises skipping.
func buildItem(name, note string) []byte {
	var item []byte
	item = protowire.AppendTag(item, 2, protowire.BytesType) // Item.content, unmodeled
	item = protowire.AppendBytes(item, []byte("ignored-content"))
	item = protowire.AppendTag(item, fieldItemMetadata, protowire.BytesType)
	item = protowire.AppendBytes(item, buildMetadata(name, note))
	item = protowire.AppendTag(item, 7, protowire.Fixed32Type) // unknown, must be skipped
	item = protowire.AppendFixed32(item, 0xdeadbeef)
	return item
}

func TestParseItemMetadata(t *testing.T) {
	const title = "aws-vault/dev"
	const blob = `{"AccessKeyID":"AKIA","SecretAccessKey":"s3cr3t"}`

	got, err := ParseItemMetadata(buildItem(title, blob))
	if err != nil {
		t.Fatalf("ParseItemMetadata: %v", err)
	}
	if got.Name != title {
		t.Errorf("Name = %q, want %q", got.Name, title)
	}
	if got.Note != blob {
		t.Errorf("Note = %q, want %q", got.Note, blob)
	}
}

func TestParseItemMetadataEmptyNote(t *testing.T) {
	got, err := ParseItemMetadata(buildItem("title-only", ""))
	if err != nil {
		t.Fatalf("ParseItemMetadata: %v", err)
	}
	if got.Name != "title-only" || got.Note != "" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestParseItemMetadataMissing(t *testing.T) {
	// An Item with no metadata field is an error.
	var item []byte
	item = protowire.AppendTag(item, 2, protowire.BytesType)
	item = protowire.AppendBytes(item, []byte("only-content"))
	if _, err := ParseItemMetadata(item); err == nil {
		t.Fatal("ParseItemMetadata must fail when metadata is absent")
	}
}

func TestParseItemMetadataTruncated(t *testing.T) {
	good := buildItem("t", "n")
	if _, err := ParseItemMetadata(good[:len(good)-1]); err == nil {
		t.Fatal("ParseItemMetadata must fail on truncated input")
	}
}
