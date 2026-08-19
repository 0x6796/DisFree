package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	opControlSoftResetV1       = 3
	opControlV1                = 4
	opAckV1                    = 5
	opDataV1                   = 6
	opControlHardResetClientV2 = 7
	opControlHardResetServerV2 = 8
	opDataV2                   = 9
)

type sessionID [8]byte

func newSessionID() (sessionID, error) {
	var sid sessionID
	_, err := rand.Read(sid[:])
	return sid, err
}

func (s sessionID) String() string { return fmt.Sprintf("%x", s[:]) }

type controlPacket struct {
	Opcode          uint8
	KeyID           uint8
	SessionID       sessionID
	AckIDs          []uint32
	RemoteSessionID *sessionID
	PacketID        uint32
	Payload         []byte
}

func (p controlPacket) marshal() ([]byte, error) {
	if p.Opcode == 0 || p.Opcode > 31 {
		return nil, fmt.Errorf("invalid opcode %d", p.Opcode)
	}
	if p.KeyID > 7 {
		return nil, fmt.Errorf("invalid key id %d", p.KeyID)
	}
	if len(p.AckIDs) > 255 {
		return nil, errors.New("too many ACK ids")
	}
	if len(p.AckIDs) > 0 && p.RemoteSessionID == nil {
		return nil, errors.New("ACK ids require remote session id")
	}

	var b bytes.Buffer
	b.Grow(1 + 8 + 1 + 4*len(p.AckIDs) + 8 + 4 + len(p.Payload))
	b.WriteByte((p.Opcode << 3) | (p.KeyID & 0x07))
	b.Write(p.SessionID[:])
	b.WriteByte(byte(len(p.AckIDs)))
	for _, ack := range p.AckIDs {
		if err := binary.Write(&b, binary.BigEndian, ack); err != nil {
			return nil, err
		}
	}
	if len(p.AckIDs) > 0 {
		b.Write(p.RemoteSessionID[:])
	}
	if p.Opcode != opAckV1 {
		if err := binary.Write(&b, binary.BigEndian, p.PacketID); err != nil {
			return nil, err
		}
		b.Write(p.Payload)
	}
	return b.Bytes(), nil
}

func parseControlPacket(raw []byte) (controlPacket, error) {
	var p controlPacket
	if len(raw) < 10 {
		return p, fmt.Errorf("control packet too short: %d", len(raw))
	}
	p.Opcode = raw[0] >> 3
	p.KeyID = raw[0] & 0x07
	copy(p.SessionID[:], raw[1:9])

	pos := 9
	ackCount := int(raw[pos])
	pos++
	if ackCount > 64 {
		return p, fmt.Errorf("unreasonable ACK count %d", ackCount)
	}
	if len(raw) < pos+ackCount*4 {
		return p, errors.New("truncated ACK array")
	}
	p.AckIDs = make([]uint32, ackCount)
	for i := 0; i < ackCount; i++ {
		p.AckIDs[i] = binary.BigEndian.Uint32(raw[pos : pos+4])
		pos += 4
	}
	if ackCount > 0 {
		if len(raw) < pos+8 {
			return p, errors.New("truncated remote session id")
		}
		var remote sessionID
		copy(remote[:], raw[pos:pos+8])
		pos += 8
		p.RemoteSessionID = &remote
	}
	if p.Opcode == opAckV1 {
		if pos != len(raw) {
			p.Payload = append([]byte(nil), raw[pos:]...)
		}
		return p, nil
	}
	if len(raw) < pos+4 {
		return p, errors.New("truncated packet id")
	}
	p.PacketID = binary.BigEndian.Uint32(raw[pos : pos+4])
	pos += 4
	p.Payload = append([]byte(nil), raw[pos:]...)
	return p, nil
}

type wireProbe struct {
	Endpoint      Endpoint
	Latency       time.Duration
	ClientSID     sessionID
	ServerSID     sessionID
	ServerPacket  uint32
	ServerAckedUs bool
	Err           error
}

func openVPNResetUDP(ctx context.Context, ep Endpoint, timeout time.Duration) wireProbe {
	result := wireProbe{Endpoint: ep}
	if strings.ToLower(ep.Protocol) != "udp" {
		result.Err = errors.New("wire probe currently requires UDP")
		return result
	}

	clientSID, err := newSessionID()
	if err != nil {
		result.Err = err
		return result
	}
	result.ClientSID = clientSID

	reset, err := (controlPacket{Opcode: opControlHardResetClientV2, KeyID: 0, SessionID: clientSID, PacketID: 0}).marshal()
	if err != nil {
		result.Err = err
		return result
	}

	d := net.Dialer{}
	connRaw, err := d.DialContext(ctx, "udp", ep.Address())
	if err != nil {
		result.Err = err
		return result
	}
	conn := connRaw.(*net.UDPConn)
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	start := time.Now()
	if _, err := conn.Write(reset); err != nil {
		result.Err = err
		return result
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	result.Latency = time.Since(start)
	if err != nil {
		result.Err = err
		return result
	}

	resp, err := parseControlPacket(buf[:n])
	if err != nil {
		result.Err = fmt.Errorf("parse server reset: %w", err)
		return result
	}
	if resp.Opcode != opControlHardResetServerV2 {
		result.Err = fmt.Errorf("unexpected opcode %d", resp.Opcode)
		return result
	}
	if resp.KeyID != 0 {
		result.Err = fmt.Errorf("unexpected key id %d", resp.KeyID)
		return result
	}
	if len(resp.AckIDs) == 0 {
		result.Err = errors.New("server reset did not ACK client reset")
		return result
	}
	for _, id := range resp.AckIDs {
		if id == 0 {
			result.ServerAckedUs = true
			break
		}
	}
	if !result.ServerAckedUs {
		result.Err = fmt.Errorf("server ACK list does not contain client packet 0: %v", resp.AckIDs)
		return result
	}
	if resp.RemoteSessionID == nil || *resp.RemoteSessionID != clientSID {
		result.Err = errors.New("server returned wrong remote session id")
		return result
	}

	result.ServerSID = resp.SessionID
	result.ServerPacket = resp.PacketID

	ack, err := (controlPacket{Opcode: opAckV1, KeyID: 0, SessionID: clientSID, AckIDs: []uint32{resp.PacketID}, RemoteSessionID: &resp.SessionID}).marshal()
	if err != nil {
		result.Err = err
		return result
	}
	if _, err := conn.Write(ack); err != nil {
		result.Err = fmt.Errorf("send reset ACK: %w", err)
		return result
	}
	return result
}

func probeOpenVPNWire(ctx context.Context, s *Service, timeout time.Duration) []wireProbe {
	var eps []Endpoint
	for _, ep := range endpoints(s, "openvpn") {
		if ep.Protocol == "udp" {
			eps = append(eps, ep)
		}
	}
	results := make([]wireProbe, len(eps))
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func(i int, ep Endpoint) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = wireProbe{Endpoint: ep, Err: ctx.Err()}
				return
			}
			results[i] = openVPNResetUDP(ctx, ep, timeout)
		}(i, ep)
	}
	wg.Wait()
	sort.SliceStable(results, func(i, j int) bool {
		iok, jok := results[i].Err == nil, results[j].Err == nil
		if iok != jok {
			return iok
		}
		return results[i].Latency < results[j].Latency
	})
	return results
}

func cmdWire(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wire", flag.ContinueOnError)
	top := fs.Int("top", 10, "best protocol-confirmed endpoints to show")
	timeout := fs.Duration("timeout", 2500*time.Millisecond, "UDP protocol timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := newAPI().service(ctx)
	if err != nil {
		return err
	}
	results := probeOpenVPNWire(ctx, s, *timeout)
	if len(results) == 0 {
		return errors.New("no UDP OpenVPN endpoints advertised")
	}

	okCount, shown := 0, 0
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		okCount++
		if shown < *top {
			shown++
			fmt.Printf("%2d. %-12s %-24s %-21s %7s UDP/%d sid=%s\n", shown, r.Endpoint.Location, r.Endpoint.Host, r.Endpoint.IP, r.Latency.Round(time.Millisecond), r.Endpoint.Port, r.ServerSID.String()[:8])
		}
	}
	if okCount == 0 {
		var sample []string
		for _, r := range results {
			if r.Err != nil && len(sample) < 4 {
				sample = append(sample, fmt.Sprintf("%s UDP/%d: %v", r.Endpoint.Host, r.Endpoint.Port, r.Err))
			}
		}
		return fmt.Errorf("no gateway completed OpenVPN reset handshake (%s)", strings.Join(sample, "; "))
	}
	fmt.Printf("\n%d/%d UDP endpoints completed the OpenVPN reset handshake.\n", okCount, len(results))
	fmt.Println("No TUN interface or host route was changed.")
	return nil
}
