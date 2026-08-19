package main

import (
	"bytes"
	"testing"
)

func TestDataV2AESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	hmacKey := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range hmacKey {
		hmacKey[i] = byte(0x80 + i)
	}
	plaintext := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	packet, err := encryptDataV2(327, 0, 1, key, hmacKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if packet[0]>>3 != 9 {
		t.Fatalf("opcode=%d", packet[0]>>3)
	}
	got, err := decryptDataV2(packet, key, hmacKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.PeerID != 327 || got.PacketID != 1 || got.KeyID != 0 {
		t.Fatalf("bad metadata: %#v", got)
	}
	if !bytes.Equal(got.Payload, plaintext) {
		t.Fatalf("payload mismatch %x != %x", got.Payload, plaintext)
	}

	packet[len(packet)-1] ^= 1
	if _, err := decryptDataV2(packet, key, hmacKey); err == nil {
		t.Fatal("tampered packet unexpectedly authenticated")
	}
}
