package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("duration must be a string")
	}
	v, err := time.ParseDuration(s)
	if err != nil || v <= 0 {
		return fmt.Errorf("invalid positive duration %q", s)
	}
	*d = Duration(v)
	return nil
}
func (d Duration) Value(fallback time.Duration) time.Duration {
	if d == 0 {
		return fallback
	}
	return time.Duration(d)
}

type Server struct {
	Listen                   string   `json:"listen"`
	CertificateFile          string   `json:"certificate_file"`
	PrivateKeyFile           string   `json:"private_key_file"`
	TokenSHA256              []string `json:"token_sha256"`
	AllowPrivateDestinations bool     `json:"allow_private_destinations"`
	HandshakeTimeout         Duration `json:"handshake_timeout"`
	DialTimeout              Duration `json:"dial_timeout"`
	IOTimeout                Duration `json:"io_timeout"`
	UDPIdleTimeout           Duration `json:"udp_idle_timeout"`
	ShutdownTimeout          Duration `json:"shutdown_timeout"`
}

type Client struct {
	Listen           string   `json:"listen"`
	ServerAddress    string   `json:"server_address"`
	ServerName       string   `json:"server_name"`
	RootCAFile       string   `json:"root_ca_file"`
	Token            string   `json:"token"`
	HandshakeTimeout Duration `json:"handshake_timeout"`
	IOTimeout        Duration `json:"io_timeout"`
	UDPIdleTimeout   Duration `json:"udp_idle_timeout"`
	ShutdownTimeout  Duration `json:"shutdown_timeout"`
}

func LoadServer(path string) (Server, error) { var c Server; err := load(path, &c); return c, err }
func LoadClient(path string) (Client, error) { var c Client; err := load(path, &c); return c, err }

func load(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	return nil
}

func DecodeToken(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(out) {
		return out, errors.New("token must be 64 hexadecimal characters")
	}
	copy(out[:], b)
	return out, nil
}

func DecodeTokenHashes(values []string) ([][32]byte, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one token_sha256 value is required")
	}
	out := make([][32]byte, len(values))
	for i, value := range values {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("token_sha256[%d] must be 64 hexadecimal characters", i)
		}
		copy(out[i][:], b)
	}
	return out, nil
}
