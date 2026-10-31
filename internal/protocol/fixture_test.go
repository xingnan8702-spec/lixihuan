package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type protocolFixture struct {
	Version  int             `json:"version"`
	TokenHex string          `json:"tokenHex"`
	Vectors  []fixtureVector `json:"vectors"`
}

type fixtureVector struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Domain     string `json:"domain"`
	Host       string `json:"host"`
	Port       uint16 `json:"port"`
	Message    string `json:"message"`
	PayloadHex string `json:"payloadHex"`
	WireHex    string `json:"wireHex"`
}

func TestSharedProtocolV1Fixtures(t *testing.T) {
	fixture := loadProtocolFixture(t)
	if fixture.Version != Version {
		t.Fatalf("fixture version %d, protocol version %d", fixture.Version, Version)
	}
	tokenBytes := decodeFixtureHex(t, fixture.TokenHex)
	if len(tokenBytes) != TokenSize {
		t.Fatalf("fixture token has %d bytes", len(tokenBytes))
	}
	var token [TokenSize]byte
	copy(token[:], tokenBytes)

	for _, vector := range fixture.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			wire := decodeFixtureHex(t, vector.WireHex)
			body, err := ReadFrame(bytes.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			var encoded []byte
			switch vector.Kind {
			case "request_udp":
				request, err := ParseAuthRequest(body)
				if err != nil {
					t.Fatal(err)
				}
				if request.Command != CommandUDPAssociate || request.Token != token || request.Target != nil {
					t.Fatalf("unexpected UDP request: %+v", request)
				}
				encoded, err = request.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
			case "request_tcp_domain":
				request, err := ParseAuthRequest(body)
				if err != nil {
					t.Fatal(err)
				}
				if request.Command != CommandTCPConnect || request.Token != token || request.Target == nil ||
					request.Target.Type != AddressDomain || request.Target.Domain != vector.Domain || request.Target.Port != vector.Port {
					t.Fatalf("unexpected TCP request: %+v", request)
				}
				encoded, err = request.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
			case "response_ok", "response_forbidden":
				response, err := ParseResponse(body)
				if err != nil {
					t.Fatal(err)
				}
				expectedStatus := StatusOK
				if vector.Kind == "response_forbidden" {
					expectedStatus = StatusForbidden
				}
				if response.Status != expectedStatus || response.Message != vector.Message {
					t.Fatalf("unexpected response: %+v", response)
				}
				encoded, err = response.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
			case "datagram_ipv4", "datagram_ipv6", "datagram_domain":
				datagram, err := ParseDatagram(body)
				if err != nil {
					t.Fatal(err)
				}
				expectedPayload := decodeFixtureHex(t, vector.PayloadHex)
				if datagram.Target.Port != vector.Port || !bytes.Equal(datagram.Payload, expectedPayload) {
					t.Fatalf("unexpected datagram: %+v", datagram)
				}
				if vector.Domain != "" {
					if datagram.Target.Type != AddressDomain || datagram.Target.Domain != vector.Domain {
						t.Fatalf("unexpected domain target: %+v", datagram.Target)
					}
				} else {
					expectedIP := netip.MustParseAddr(vector.Host)
					if datagram.Target.IP != expectedIP {
						t.Fatalf("target IP %s, want %s", datagram.Target.IP, expectedIP)
					}
				}
				encoded, err = datagram.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown fixture kind %q", vector.Kind)
			}

			var roundTrip bytes.Buffer
			if err := WriteFrame(&roundTrip, encoded); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(roundTrip.Bytes(), wire) {
				t.Fatalf("encoded wire %x, want %x", roundTrip.Bytes(), wire)
			}
		})
	}
}

func loadProtocolFixture(t *testing.T) protocolFixture {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate fixture test")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "protocol-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture protocolFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func decodeFixtureHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid fixture hex %q: %v", value, err)
	}
	return decoded
}
