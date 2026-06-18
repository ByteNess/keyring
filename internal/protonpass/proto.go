package protonpass

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// Field numbers from Proton Pass's item-v1.proto (the wire contract, re-declared
// clean-room from the documented schema, not generated):
//
//	message Item     { Metadata metadata = 1; ... }
//	message Metadata { string name = 1; string note = 2; ... }
//
// aws-vault keys items by metadata.name and stores its blob in metadata.note.
const (
	fieldItemMetadata = 1
	fieldMetadataName = 1
	fieldMetadataNote = 2
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
