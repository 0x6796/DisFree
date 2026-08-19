package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

type controlUDPConn struct {
	udp       *net.UDPConn
	localSID  sessionID
	remoteSID sessionID
	muWrite   sync.Mutex
	nextID    uint32
	muRead    sync.Mutex
	readBuf   bytes.Buffer
}

func dialControlUDP(ctx context.Context, ep Endpoint, timeout time.Duration) (*controlUDPConn, time.Duration, error) {
	if ep.Protocol != "udp" {
		return nil, 0, errors.New("control TLS probe currently requires UDP")
	}
	sid, err := newSessionID()
	if err != nil {
		return nil, 0, err
	}
	reset, err := (controlPacket{Opcode: opControlHardResetClientV2, SessionID: sid, PacketID: 0}).marshal()
	if err != nil {
		return nil, 0, err
	}
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "udp", ep.Address())
	if err != nil {
		return nil, 0, err
	}
	udp := raw.(*net.UDPConn)
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = udp.SetDeadline(deadline)
	start := time.Now()
	if _, err := udp.Write(reset); err != nil {
		udp.Close()
		return nil, 0, err
	}
	buf := make([]byte, 4096)
	n, err := udp.Read(buf)
	latency := time.Since(start)
	if err != nil {
		udp.Close()
		return nil, latency, err
	}
	resp, err := parseControlPacket(buf[:n])
	if err != nil {
		udp.Close()
		return nil, latency, err
	}
	if resp.Opcode != opControlHardResetServerV2 {
		udp.Close()
		return nil, latency, fmt.Errorf("expected server hard reset, got opcode %d", resp.Opcode)
	}
	if resp.RemoteSessionID == nil || *resp.RemoteSessionID != sid {
		udp.Close()
		return nil, latency, errors.New("server reset session-id mismatch")
	}
	ack, err := (controlPacket{Opcode: opAckV1, SessionID: sid, AckIDs: []uint32{resp.PacketID}, RemoteSessionID: &resp.SessionID}).marshal()
	if err != nil {
		udp.Close()
		return nil, latency, err
	}
	if _, err := udp.Write(ack); err != nil {
		udp.Close()
		return nil, latency, err
	}
	_ = udp.SetDeadline(time.Time{})
	return &controlUDPConn{udp: udp, localSID: sid, remoteSID: resp.SessionID, nextID: 1}, latency, nil
}

func (c *controlUDPConn) sendAck(id uint32) error {
	raw, err := (controlPacket{Opcode: opAckV1, SessionID: c.localSID, AckIDs: []uint32{id}, RemoteSessionID: &c.remoteSID}).marshal()
	if err != nil {
		return err
	}
	_, err = c.udp.Write(raw)
	return err
}

func (c *controlUDPConn) Write(p []byte) (int, error) {
	c.muWrite.Lock()
	defer c.muWrite.Unlock()
	total := 0
	const maxPayload = 1000
	for len(p) > 0 {
		n := len(p)
		if n > maxPayload {
			n = maxPayload
		}
		chunk := p[:n]
		raw, err := (controlPacket{Opcode: opControlV1, SessionID: c.localSID, PacketID: c.nextID, Payload: chunk}).marshal()
		if err != nil {
			return total, err
		}
		if _, err := c.udp.Write(raw); err != nil {
			return total, err
		}
		c.nextID++
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *controlUDPConn) Read(p []byte) (int, error) {
	c.muRead.Lock()
	defer c.muRead.Unlock()
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}
	buf := make([]byte, 8192)
	for {
		n, err := c.udp.Read(buf)
		if err != nil {
			return 0, err
		}
		pkt, err := parseControlPacket(buf[:n])
		if err != nil {
			continue
		}
		if pkt.SessionID != c.remoteSID {
			continue
		}
		switch pkt.Opcode {
		case opAckV1:
			continue
		case opControlV1:
			if pkt.RemoteSessionID != nil && *pkt.RemoteSessionID != c.localSID {
				continue
			}
			if err := c.sendAck(pkt.PacketID); err != nil {
				return 0, err
			}
			if len(pkt.Payload) == 0 {
				continue
			}
			c.readBuf.Write(pkt.Payload)
			return c.readBuf.Read(p)
		case opControlSoftResetV1:
			return 0, errors.New("server requested control-channel rekey during TLS probe")
		default:
			continue
		}
	}
}

func (c *controlUDPConn) Close() error                       { return c.udp.Close() }
func (c *controlUDPConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *controlUDPConn) RemoteAddr() net.Addr               { return c.udp.RemoteAddr() }
func (c *controlUDPConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *controlUDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *controlUDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

func loadOrFetchIdentity(ctx context.Context, path string) (*Identity, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		id, parseErr := parseIdentity(raw)
		if parseErr == nil && time.Now().Before(id.Leaf.NotAfter.Add(-24*time.Hour)) {
			return id, nil
		}
	}
	id, err := newAPI().identity(ctx)
	if err != nil {
		return nil, err
	}
	if err := saveIdentity(id, path); err != nil {
		return nil, err
	}
	return id, nil
}

type lowLatencyCandidate struct {
	Endpoint Endpoint
	Samples  []time.Duration
	Median   time.Duration
	Best     time.Duration
}

func medianLatency(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	v := append([]time.Duration(nil), samples...)
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}

func bestWireEndpoint(ctx context.Context, s *Service, timeout time.Duration) (Endpoint, error) {
	// Stage 1: probe every advertised UDP endpoint once using the real
	// OpenVPN reset exchange, then keep only the fastest finalists.
	rs := probeOpenVPNWire(ctx, s, timeout)
	const finalists = 5
	candidates := make([]lowLatencyCandidate, 0, finalists)
	for _, r := range rs {
		if r.Err != nil {
			continue
		}
		candidates = append(candidates, lowLatencyCandidate{
			Endpoint: r.Endpoint,
			Samples:  []time.Duration{r.Latency},
			Best:     r.Latency,
		})
		if len(candidates) == finalists {
			break
		}
	}
	if len(candidates) == 0 {
		return Endpoint{}, errors.New("no protocol-confirmed UDP endpoint")
	}

	// Stage 2: take two extra samples for each finalist (3 total). For VoIP,
	// use the median RTT so one lucky or spiky packet cannot choose the server.
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for sample := 0; sample < 2; sample++ {
				r := openVPNResetUDP(ctx, candidates[i].Endpoint, timeout)
				if r.Err != nil {
					continue
				}
				candidates[i].Samples = append(candidates[i].Samples, r.Latency)
				if candidates[i].Best == 0 || r.Latency < candidates[i].Best {
					candidates[i].Best = r.Latency
				}
			}
			candidates[i].Median = medianLatency(candidates[i].Samples)
		}(i)
	}
	wg.Wait()

	// Prefer candidates that answered at least 2/3 measurements, then the
	// lowest median RTT. Best single RTT is only a tie-breaker.
	sort.SliceStable(candidates, func(i, j int) bool {
		iStable := len(candidates[i].Samples) >= 2
		jStable := len(candidates[j].Samples) >= 2
		if iStable != jStable {
			return iStable
		}
		if candidates[i].Median != candidates[j].Median {
			return candidates[i].Median < candidates[j].Median
		}
		return candidates[i].Best < candidates[j].Best
	})
	return candidates[0].Endpoint, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func cmdTLSProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tlsprobe", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 8*time.Second, "overall TLS control-channel timeout")
	identityPath := fs.String("identity", defaultIdentityPath(), "client certificate/key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := newAPI().service(ctx)
	if err != nil {
		return err
	}
	ep, err := bestWireEndpoint(ctx, s, 1800*time.Millisecond)
	if err != nil {
		return err
	}
	id, err := loadOrFetchIdentity(ctx, *identityPath)
	if err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	cc, resetLatency, err := dialControlUDP(probeCtx, ep, *timeout)
	if err != nil {
		return fmt.Errorf("control reset: %w", err)
	}
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(*timeout))
	trust, err := loadProviderTrust(probeCtx)
	if err != nil {
		return fmt.Errorf("provider trust: %w", err)
	}
	tc := tls.Client(cc, trust.tlsConfigForGateway(ep, id))
	if err := tc.HandshakeContext(probeCtx); err != nil {
		return fmt.Errorf("TLS over OpenVPN control channel: %w", err)
	}
	st := tc.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return errors.New("TLS completed without peer certificate")
	}
	leaf := st.PeerCertificates[0]
	fmt.Printf("Gateway:       %s (%s) %s UDP/%d\n", ep.Host, ep.Location, ep.IP, ep.Port)
	fmt.Printf("Reset RTT:     %s\n", resetLatency.Round(time.Millisecond))
	fmt.Printf("TLS:           %s\n", tlsVersionName(st.Version))
	fmt.Printf("Cipher suite:  0x%04x\n", st.CipherSuite)
	fmt.Printf("Server cert:   %s\n", leaf.Subject.String())
	fmt.Printf("Issuer:        %s\n", leaf.Issuer.String())
	fmt.Printf("Cert validity: %s -> %s\n", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	fmt.Printf("Peer chain:    %d certificate(s)\n", len(st.PeerCertificates))
	fmt.Println("TLS control channel established in pure Go.")
	fmt.Printf("Provider CA:   %s\n", trust.CA.Subject.String())
	fmt.Printf("CA SHA-256:    %x\n", trust.Fingerprint)
	fmt.Println("Gateway certificate verified against provider.json-pinned CA.")
	fmt.Println("No TUN interface or host route was changed.")
	_ = cc.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_ = tc.Close()
	return nil
}

var _ net.Conn = (*controlUDPConn)(nil)
var _ io.Reader = (*controlUDPConn)(nil)
