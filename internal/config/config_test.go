package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeToken(t *testing.T) {
	token, err := DecodeToken(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	if token[0] != 1 || token[31] != 1 {
		t.Fatal("wrong token")
	}
	if _, err := DecodeToken("abcd"); err == nil {
		t.Fatal("accepted short token")
	}
}

func TestStrictJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:1080","unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClient(path); err == nil {
		t.Fatal("accepted unknown field")
	}
}
