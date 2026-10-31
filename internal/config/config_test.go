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

func TestLoadServerConnectionLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	data := `{
		"listen":"127.0.0.1:8443",
		"certificate_file":"server.crt",
		"private_key_file":"server.key",
		"token_sha256":["` + strings.Repeat("01", 32) + `"],
		"max_connections":12,
		"max_handshakes":3,
		"max_udp_associations":4
	}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConnections != 12 || cfg.MaxHandshakes != 3 || cfg.MaxUDPAssociations != 4 {
		t.Fatalf("limits = %d/%d/%d", cfg.MaxConnections, cfg.MaxHandshakes, cfg.MaxUDPAssociations)
	}
}
