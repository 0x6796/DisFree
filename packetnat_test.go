package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func testIPv4UDP(src, dst net.IP, sp, dp uint16, payload []byte) []byte {
	p := make([]byte, 20+8+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	binary.BigEndian.PutUint16(p[20:22], sp)
	binary.BigEndian.PutUint16(p[22:24], dp)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	_ = recalcIPv4TransportChecksums(p)
	return p
}

func testIPv4TCPSYN(src, dst net.IP, sp, dp, mss uint16) []byte {
	p := make([]byte, 20+24)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 6
	copy(p[12:16], src.To4())
	copy(p[16:20], dst.To4())
	tcp := p[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sp)
	binary.BigEndian.PutUint16(tcp[2:4], dp)
	tcp[12] = 6 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mss)
	_ = recalcIPv4TransportChecksums(p)
	return p
}

func TestParseAndRewriteUDP(t *testing.T) {
	local := net.IPv4(192, 168, 1, 10)
	remote := net.IPv4(162, 159, 128, 233)
	p := testIPv4UDP(local, remote, 50000, 443, []byte("voice"))
	k, err := parseIPv4Flow(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if k.Protocol != 17 || k.LocalPort != 50000 || k.RemotePort != 443 {
		t.Fatalf("bad tuple: %+v", k)
	}
	vpnIP := net.IPv4(10, 42, 0, 77)
	if err := rewriteIPv4Source(p, vpnIP); err != nil {
		t.Fatal(err)
	}
	if got := net.IP(p[12:16]).String(); got != "10.42.0.77" {
		t.Fatalf("source = %s", got)
	}
	if err := rewriteIPv4Destination(p, local); err != nil {
		t.Fatal(err)
	}
}

func TestClampTCPMSS(t *testing.T) {
	p := testIPv4TCPSYN(net.IPv4(192, 168, 1, 10), net.IPv4(1, 1, 1, 1), 50001, 443, 1460)
	changed, err := clampTCPMSS(p, 1180)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected MSS change")
	}
	if got := binary.BigEndian.Uint16(p[42:44]); got != 1180 {
		t.Fatalf("MSS=%d", got)
	}
}
