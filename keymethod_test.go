package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestOVPNStringEncoding(t *testing.T) {
	var b bytes.Buffer
	if err := writeOVPNString(&b, "abc"); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 4, 'a', 'b', 'c', 0}
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("encoded %x want %x", b.Bytes(), want)
	}
	got, err := readOVPNString(bytes.NewReader(b.Bytes()), 20)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Fatalf("got %q", got)
	}

	b.Reset()
	if err := writeOVPNString(&b, ""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Bytes(), []byte{0, 0}) {
		t.Fatalf("empty encoded %x", b.Bytes())
	}
}

func TestOpenVPNLegacyPRFVector(t *testing.T) {
	var client, server keySource
	for i := 0; i < 48; i++ {
		client.PreMaster[i] = byte(i)
	}
	for i := 0; i < 32; i++ {
		client.Random1[i] = byte(48 + i)
		server.Random1[i] = byte(80 + i)
		client.Random2[i] = byte(112 + i)
		server.Random2[i] = byte(144 + i)
	}
	var csid, ssid sessionID
	for i := 0; i < 8; i++ {
		csid[i] = byte(i)
		ssid[i] = byte(8 + i)
	}

	master, keys := deriveOpenVPNKeys(client, server, csid, ssid)
	if got := hex.EncodeToString(master[:]); got != "326bae7a6685734d8d5b05e10eef57f046d7678ab1fe3a61716e237ca0d74c1b3d0d72cb5f1b30c2ae5aaf7fd091f857" {
		t.Fatalf("master mismatch: %s", got)
	}
	raw := make([]byte, 0, 256)
	raw = append(raw, keys.ClientCipher[:]...)
	raw = append(raw, keys.ClientHMAC[:]...)
	raw = append(raw, keys.ServerCipher[:]...)
	raw = append(raw, keys.ServerHMAC[:]...)
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != "db79febaeafe6fcef09b82b6c94de985a023af4c4f983756535e12f4efd2ee7c" {
		t.Fatalf("key block mismatch: %s", got)
	}
	if got := hex.EncodeToString(keys.ClientCipher[:32]); got != "7ecb09a427d591e8654127a282ed2d57ceb90e02046accfa56ff7238d4fb3012" {
		t.Fatalf("client AES key mismatch: %s", got)
	}
	if got := hex.EncodeToString(keys.ServerCipher[:32]); got != "4fc2ca8870663352936673fb150ba5a760c7afbfb3cfd20ca3ad2b478b8ae60c" {
		t.Fatalf("server AES key mismatch: %s", got)
	}
}

func TestClientKeyMethodShape(t *testing.T) {
	var src keySource
	for i := range src.PreMaster {
		src.PreMaster[i] = byte(i)
	}
	ep := Endpoint{Protocol: "udp"}
	raw, err := marshalClientKeyMethod(src, ep)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 117 {
		t.Fatalf("too short: %d", len(raw))
	}
	if !bytes.Equal(raw[:4], []byte{0, 0, 0, 0}) || raw[4] != 2 {
		t.Fatalf("bad header: %x", raw[:5])
	}
	if !bytes.Equal(raw[5:53], src.PreMaster[:]) {
		t.Fatal("pre-master location mismatch")
	}
}
