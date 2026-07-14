package protonpass

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// Field numbers from Proton Pass's item-v1.proto (the wire contract, re-declared
// clean-room from the documented schema, not generated):
//
//	message Item     { Metadata metadata = 1; Content content = 2; ... }
//	message Metadata { string name = 1; string note = 2; string item_uuid = 3; ... }
//	message Content  { oneof content { ItemNote note = 2; ... } }
//	message ItemNote {}   // empty marker; the note text lives in Metadata.note
//
// aws-vault keys items by metadata.name and stores its blob in metadata.note.
const (
	fieldItemMetadata     = 1
	fieldItemContent      = 2
	fieldMetadataName     = 1
	fieldMetadataNote     = 2
	fieldMetadataItemUUID = 3
	fieldContentNote      = 2
)

// ItemMetadata is the subset of a decrypted Item the backend uses: the title and
// the note payload.
type ItemMetadata struct {
	Name string
	Note string
}

// ParseItemMetadata extracts Metadata.name and Metadata.note from a decrypted Item
// protobuf (the plaintext returned by OpenItemContent). Unknown fields and other
// content types are skipped.
func ParseItemMetadata(item []byte) (ItemMetadata, error) {
	meta, found, err := bytesField(item, fieldItemMetadata)
	if err != nil {
		return ItemMetadata{}, fmt.Errorf("item: read metadata: %w", err)
	}
	if !found {
		return ItemMetadata{}, errors.New("item: missing metadata field")
	}

	name, _, err := bytesField(meta, fieldMetadataName)
	if err != nil {
		return ItemMetadata{}, fmt.Errorf("metadata: read name: %w", err)
	}
	note, _, err := bytesField(meta, fieldMetadataNote)
	if err != nil {
		return ItemMetadata{}, fmt.Errorf("metadata: read note: %w", err)
	}
	return ItemMetadata{Name: string(name), Note: string(note)}, nil
}

// EncodeItem serializes a note-type item-v1 Item protobuf: metadata.name (title),
// metadata.note (the blob), and metadata.item_uuid, plus a Content oneof selecting
// the empty ItemNote variant. It is the inverse of ParseItemMetadata.
func EncodeItem(meta ItemMetadata, itemUUID string) []byte {
	var m []byte
	m = protowire.AppendTag(m, fieldMetadataName, protowire.BytesType)
	m = protowire.AppendBytes(m, []byte(meta.Name))
	m = protowire.AppendTag(m, fieldMetadataNote, protowire.BytesType)
	m = protowire.AppendBytes(m, []byte(meta.Note))
	m = protowire.AppendTag(m, fieldMetadataItemUUID, protowire.BytesType)
	m = protowire.AppendBytes(m, []byte(itemUUID))

	// Content { note = 2: ItemNote {} } — an empty submessage selecting the note type.
	var content []byte
	content = protowire.AppendTag(content, fieldContentNote, protowire.BytesType)
	content = protowire.AppendBytes(content, nil)

	var item []byte
	item = protowire.AppendTag(item, fieldItemMetadata, protowire.BytesType)
	item = protowire.AppendBytes(item, m)
	item = protowire.AppendTag(item, fieldItemContent, protowire.BytesType)
	item = protowire.AppendBytes(item, content)
	return item
}

// bytesField returns the last length-delimited field number `num` in msg. found is
// false (with a nil slice) when the field is absent.
func bytesField(msg []byte, num protowire.Number) (value []byte, found bool, err error) {
	for len(msg) > 0 {
		fieldNum, typ, tagLen := protowire.ConsumeTag(msg)
		if tagLen < 0 {
			return nil, false, protowire.ParseError(tagLen)
		}
		msg = msg[tagLen:]

		if typ == protowire.BytesType {
			v, vLen := protowire.ConsumeBytes(msg)
			if vLen < 0 {
				return nil, false, protowire.ParseError(vLen)
			}
			if fieldNum == num {
				value, found = v, true // keep the last occurrence (proto3 semantics)
			}
			msg = msg[vLen:]
			continue
		}

		skip := protowire.ConsumeFieldValue(fieldNum, typ, msg)
		if skip < 0 {
			return nil, false, protowire.ParseError(skip)
		}
		msg = msg[skip:]
	}
	return value, found, nil
}
