package keyring

// Minimal GVariant (GLib serialisation format, little-endian) encoder and
// decoder. It covers exactly the shapes the oo7 keyring file format uses:
// fixed-size integers, nul-terminated strings, byte arrays, dictionaries
// keyed by string, arrays of variable-sized structures and structures.
//
// Serialisation rules (see the GVariant specification):
//   - members are padded to their alignment relative to the container start;
//   - a structure stores a framing offset for every variable-sized member
//     except the last, in reverse member order, after the body;
//   - an array of variable-sized elements stores a framing offset for every
//     element, in element order, after the body;
//   - framing offsets are 1, 2, 4 or 8 bytes wide, chosen from the total
//     container size.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

var errOO7GVariant = errors.New("oo7: malformed gvariant data")

// gvMember is a serialised structure member.
type gvMember struct {
	data  []byte
	align int
	fixed bool
}

// gvMemberType describes a structure member for decoding. size is -1 for a
// variable-sized member.
type gvMemberType struct {
	align int
	size  int
}

var (
	gvTypeU32    = gvMemberType{align: 4, size: 4}
	gvTypeU64    = gvMemberType{align: 8, size: 8}
	gvTypeString = gvMemberType{align: 1, size: -1}
	gvTypeBytes  = gvMemberType{align: 1, size: -1}
)

func gvAlignUp(pos, align int) int {
	return (pos + align - 1) &^ (align - 1)
}

func gvPad(buf []byte, align int) []byte {
	for len(buf)%align != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// gvOffsetSize returns the framing offset width for a container of size bytes.
func gvOffsetSize(size int) int {
	switch {
	case size <= 0xff:
		return 1
	case size <= 0xffff:
		return 2
	case size <= 0xffffffff:
		return 4
	default:
		return 8
	}
}

// gvChooseOffsetSize picks the smallest width such that the body plus the
// offsets still fits in the width's range.
func gvChooseOffsetSize(bodySize, offsets int) int {
	for _, n := range []int{1, 2, 4} {
		if gvOffsetSize(bodySize+offsets*n) <= n {
			return n
		}
	}
	return 8
}

func gvReadOffset(data []byte, pos, size int) int {
	switch size {
	case 1:
		return int(data[pos])
	case 2:
		return int(binary.LittleEndian.Uint16(data[pos:]))
	case 4:
		return int(binary.LittleEndian.Uint32(data[pos:]))
	default:
		return int(binary.LittleEndian.Uint64(data[pos:]))
	}
}

func gvAppendOffset(buf []byte, v, size int) []byte {
	switch size {
	case 1:
		return append(buf, byte(v))
	case 2:
		return binary.LittleEndian.AppendUint16(buf, uint16(v))
	case 4:
		return binary.LittleEndian.AppendUint32(buf, uint32(v))
	default:
		return binary.LittleEndian.AppendUint64(buf, uint64(v))
	}
}

func gvAppendOffsets(body []byte, ends []int, reverse bool) []byte {
	size := gvChooseOffsetSize(len(body), len(ends))
	if reverse {
		for i := len(ends) - 1; i >= 0; i-- {
			body = gvAppendOffset(body, ends[i], size)
		}
		return body
	}
	for _, end := range ends {
		body = gvAppendOffset(body, end, size)
	}
	return body
}

func gvU32(v uint32) []byte {
	return binary.LittleEndian.AppendUint32(nil, v)
}

func gvU64(v uint64) []byte {
	return binary.LittleEndian.AppendUint64(nil, v)
}

func gvString(s string) []byte {
	return append([]byte(s), 0)
}

// gvEncodeStruct serialises a structure from its already serialised members.
func gvEncodeStruct(members []gvMember) []byte {
	var body []byte
	var ends []int
	for i, m := range members {
		body = gvPad(body, m.align)
		body = append(body, m.data...)
		if !m.fixed && i < len(members)-1 {
			ends = append(ends, len(body))
		}
	}
	return gvAppendOffsets(body, ends, true)
}

// gvEncodeArray serialises an array of variable-sized elements.
func gvEncodeArray(elems [][]byte, align int) []byte {
	if len(elems) == 0 {
		return nil
	}
	var body []byte
	ends := make([]int, 0, len(elems))
	for _, e := range elems {
		body = gvPad(body, align)
		body = append(body, e...)
		ends = append(ends, len(body))
	}
	return gvAppendOffsets(body, ends, false)
}

// gvEncodeStringDict serialises a{ss} with the keys sorted for determinism.
func gvEncodeStringDict(m map[string]string) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	elems := make([][]byte, 0, len(keys))
	for _, k := range keys {
		elems = append(elems, gvEncodeStruct([]gvMember{
			{data: gvString(k), align: 1},
			{data: gvString(m[k]), align: 1},
		}))
	}
	return gvEncodeArray(elems, 1)
}

// gvEncodeBytesDict serialises a{say} with the keys sorted for determinism.
func gvEncodeBytesDict(m map[string][]byte) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	elems := make([][]byte, 0, len(keys))
	for _, k := range keys {
		elems = append(elems, gvEncodeStruct([]gvMember{
			{data: gvString(k), align: 1},
			{data: m[k], align: 1},
		}))
	}
	return gvEncodeArray(elems, 1)
}

// gvDecodeStruct splits a serialised structure into its members.
func gvDecodeStruct(data []byte, types []gvMemberType) ([][]byte, error) {
	variable := 0
	for i, t := range types {
		if t.size < 0 && i < len(types)-1 {
			variable++
		}
	}
	offsetSize := gvOffsetSize(len(data))
	if len(data) < variable*offsetSize {
		return nil, errOO7GVariant
	}
	offsetsStart := len(data) - variable*offsetSize

	members := make([][]byte, 0, len(types))
	pos, k := 0, 0
	for i, t := range types {
		start := gvAlignUp(pos, t.align)
		var end int
		switch {
		case t.size >= 0:
			end = start + t.size
		case i == len(types)-1:
			end = offsetsStart
		default:
			end = gvReadOffset(data, offsetsStart+(variable-1-k)*offsetSize, offsetSize)
			k++
		}
		if start > end || end > offsetsStart {
			return nil, errOO7GVariant
		}
		members = append(members, data[start:end])
		pos = end
	}
	return members, nil
}

// gvDecodeArray splits a serialised array of variable-sized elements.
func gvDecodeArray(data []byte, align int) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	offsetSize := gvOffsetSize(len(data))
	if len(data) < offsetSize {
		return nil, errOO7GVariant
	}
	lastEnd := gvReadOffset(data, len(data)-offsetSize, offsetSize)
	if lastEnd > len(data)-offsetSize || (len(data)-lastEnd)%offsetSize != 0 {
		return nil, errOO7GVariant
	}
	n := (len(data) - lastEnd) / offsetSize
	offsetsStart := len(data) - n*offsetSize

	elems := make([][]byte, 0, n)
	pos := 0
	for i := 0; i < n; i++ {
		start := gvAlignUp(pos, align)
		end := gvReadOffset(data, offsetsStart+i*offsetSize, offsetSize)
		if start > end || end > offsetsStart {
			return nil, errOO7GVariant
		}
		elems = append(elems, data[start:end])
		pos = end
	}
	return elems, nil
}

func gvDecodeString(data []byte) (string, error) {
	if len(data) == 0 || data[len(data)-1] != 0 {
		return "", errOO7GVariant
	}
	for _, b := range data[:len(data)-1] {
		if b == 0 {
			return "", errOO7GVariant
		}
	}
	return string(data[:len(data)-1]), nil
}

func gvDecodeU32(data []byte) (uint32, error) {
	if len(data) != 4 {
		return 0, errOO7GVariant
	}
	return binary.LittleEndian.Uint32(data), nil
}

func gvDecodeU64(data []byte) (uint64, error) {
	if len(data) != 8 {
		return 0, errOO7GVariant
	}
	return binary.LittleEndian.Uint64(data), nil
}

func gvDecodeStringDict(data []byte) (map[string]string, error) {
	entries, err := gvDecodeArray(data, 1)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		parts, err := gvDecodeStruct(e, []gvMemberType{gvTypeString, gvTypeString})
		if err != nil {
			return nil, err
		}
		k, err := gvDecodeString(parts[0])
		if err != nil {
			return nil, err
		}
		v, err := gvDecodeString(parts[1])
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", errOO7GVariant, k)
		}
		m[k] = v
	}
	return m, nil
}

func gvDecodeBytesDict(data []byte) (map[string][]byte, error) {
	entries, err := gvDecodeArray(data, 1)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]byte, len(entries))
	for _, e := range entries {
		parts, err := gvDecodeStruct(e, []gvMemberType{gvTypeString, gvTypeBytes})
		if err != nil {
			return nil, err
		}
		k, err := gvDecodeString(parts[0])
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", errOO7GVariant, k)
		}
		m[k] = append([]byte(nil), parts[1]...)
	}
	return m, nil
}
