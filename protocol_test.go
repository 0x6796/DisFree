package main

import (
	"bytes"
	"testing"
)

func TestControlResetRoundTrip(t *testing.T) {
	client := sessionID{1, 2, 3, 4, 5, 6, 7, 8}
	server := sessionID{8, 7, 6, 5, 4, 3, 2, 1}
	in := controlPacket{Opcode: opControlHardResetServerV2, SessionID: server, AckIDs: []uint32{0}, RemoteSessionID: &client, PacketID: 0}
	raw, err := in.marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseControlPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Opcode != in.Opcode || out.SessionID != server || out.PacketID != 0 {
		t.Fatalf("round trip mismatch: %#v", out)
	}
	if out.RemoteSessionID == nil || *out.RemoteSessionID != client {
		t.Fatalf("remote session mismatch: %#v", out.RemoteSessionID)
	}
	if len(out.AckIDs) != 1 || out.AckIDs[0] != 0 {
		t.Fatalf("ack mismatch: %v", out.AckIDs)
	}
}

func TestAckEncoding(t *testing.T) {
	local := sessionID{1, 1, 1, 1, 1, 1, 1, 1}
	remote := sessionID{2, 2, 2, 2, 2, 2, 2, 2}
	raw, err := (controlPacket{Opcode: opAckV1, SessionID: local, AckIDs: []uint32{42}, RemoteSessionID: &remote}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1+8+1+4+8 {
		t.Fatalf("unexpected ACK length: %d", len(raw))
	}
	out, err := parseControlPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Opcode != opAckV1 || len(out.AckIDs) != 1 || out.AckIDs[0] != 42 {
		t.Fatalf("bad ACK decode: %#v", out)
	}
}

func TestControlPayloadRoundTrip(t *testing.T) {
	sid := sessionID{9, 9, 9, 9, 9, 9, 9, 9}
	payload := []byte("tls-record")
	raw, err := (controlPacket{Opcode: opControlV1, SessionID: sid, PacketID: 7, Payload: payload}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseControlPacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.PacketID != 7 || !bytes.Equal(out.Payload, payload) {
		t.Fatalf("payload mismatch: %#v", out)
	}
}
