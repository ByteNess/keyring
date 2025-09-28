package keyring

import (
	"encoding/json"
	"testing"
)

func DeepCopy(t *testing.T, src, dst any) {
	data, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatal(err)
	}
}

func NewOPItemFieldValue(t *testing.T, key string, data []byte) string {
	item := Item{
		Key:  key,
		Data: data,
	}

	bytes, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}

	return string(bytes)
}
