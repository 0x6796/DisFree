package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type pushedSession struct {
	IPv4    net.IP
	Netmask net.IP
	DNS     net.IP
	PeerID  uint32
	Cipher  string
}

func parsePushedSession(opts []string) (pushedSession, error) {
	var s pushedSession
	ifcfg := strings.Fields(findPushOption(opts, "ifconfig"))
	if len(ifcfg) >= 2 {
		s.IPv4 = net.ParseIP(ifcfg[0]).To4()
		s.Netmask = net.ParseIP(ifcfg[1]).To4()
	}
	for _, o := range opts {
		f := strings.Fields(o)
		if len(f) >= 3 && f[0] == "dhcp-option" && strings.EqualFold(f[1], "DNS") {
			if ip := net.ParseIP(f[2]).To4(); ip != nil {
				s.DNS = ip
				break
			}
		}
	}
	peer := findPushOption(opts, "peer-id")
	if peer != "" {
		v, err := strconv.ParseUint(strings.TrimSpace(peer), 10, 24)
		if err != nil {
			return s, fmt.Errorf("peer-id: %w", err)
		}
		s.PeerID = uint32(v)
	}
	s.Cipher = findPushOption(opts, "cipher")
	if s.IPv4 == nil {
		return s, errors.New("PUSH_REPLY has no usable IPv4 ifconfig")
	}
	if s.DNS == nil {
		return s, errors.New("PUSH_REPLY has no IPv4 DNS server")
	}
	if peer == "" {
		return s, errors.New("PUSH_REPLY has no peer-id")
	}
	if s.Cipher != "AES-256-GCM" {
		return s, fmt.Errorf("unsupported negotiated cipher %q", s.Cipher)
	}
	return s, nil
}

func checksum16(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildDNSQuery(name string) ([]byte, uint16, error) {
	var idbuf [2]byte
	if _, err := rand.Read(idbuf[:]); err != nil {
		return nil, 0, err
	}
	txid := binary.BigEndian.Uint16(idbuf[:])
	if txid == 0 {
		txid = 1
	}

	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], txid)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)      // one question
	name = strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid DNS label %q", label)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 1) // A
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	return msg, txid, nil
}

func buildIPv4UDP(src, dst net.IP, srcPort, dstPort uint16, payload []byte, ipID uint16) ([]byte, error) {
	src4, dst4 := src.To4(), dst.To4()
	if src4 == nil || dst4 == nil {
		return nil, errors.New("IPv4 packet requires IPv4 addresses")
	}
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	if total > 65535 {
		return nil, errors.New("packet too large")
	}

	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], ipID)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], checksum16(pkt[:20]))

	u := pkt[20:28]
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], dstPort)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(u[6:8], 0) // legal for IPv4 UDP
	copy(pkt[28:], payload)
	return pkt, nil
}

type dnsReplyProof struct {
	SourceIP   net.IP
	SourcePort uint16
	DestPort   uint16
	TxID       uint16
	RCode      uint8
	Answers    uint16
}

func parseIPv4DNSReply(pkt []byte, wantTxID, wantDestPort uint16) (dnsReplyProof, error) {
	var p dnsReplyProof
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		return p, errors.New("not an IPv4 packet")
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return p, errors.New("invalid IPv4 header length")
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl+8 || total > len(pkt) {
		return p, errors.New("invalid IPv4 total length")
	}
	if pkt[9] != 17 {
		return p, errors.New("not UDP")
	}
	p.SourceIP = net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	udp := pkt[ihl:total]
	p.SourcePort = binary.BigEndian.Uint16(udp[0:2])
	p.DestPort = binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8+12 || udpLen > len(udp) {
		return p, errors.New("invalid UDP length/DNS payload")
	}
	dns := udp[8:udpLen]
	p.TxID = binary.BigEndian.Uint16(dns[0:2])
	flags := binary.BigEndian.Uint16(dns[2:4])
	p.RCode = uint8(flags & 0x0f)
	p.Answers = binary.BigEndian.Uint16(dns[6:8])
	if p.SourcePort != 53 {
		return p, fmt.Errorf("response source port %d is not DNS", p.SourcePort)
	}
	if p.DestPort != wantDestPort {
		return p, fmt.Errorf("response destination port %d != %d", p.DestPort, wantDestPort)
	}
	if p.TxID != wantTxID {
		return p, fmt.Errorf("DNS transaction %d != %d", p.TxID, wantTxID)
	}
	if flags&0x8000 == 0 {
		return p, errors.New("DNS packet is not a response")
	}
	return p, nil
}

func cmdDataProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dataprobe", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 22*time.Second, "overall data-channel test timeout")
	identityPath := fs.String("identity", defaultIdentityPath(), "client certificate/key path")
	queryName := fs.String("name", "example.com", "DNS name to query through the encrypted data channel")
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := newAPI().service(ctx)
	if err != nil {
		return err
	}
	ep, err := bestWireEndpoint(ctx, svc, 1800*time.Millisecond)
	if err != nil {
		return err
	}
	id, err := loadOrFetchIdentity(ctx, *identityPath)
	if err != nil {
		return err
	}
	trust, err := loadProviderTrust(ctx)
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

	tc := tls.Client(cc, trust.tlsConfigForGateway(ep, id))
	if err := tc.HandshakeContext(probeCtx); err != nil {
		return fmt.Errorf("TLS control channel: %w", err)
	}
	defer tc.Close()

	clientSrc, err := randomClientKeySource()
	if err != nil {
		return err
	}
	km, err := marshalClientKeyMethod(clientSrc, ep)
	if err != nil {
		return err
	}
	if _, err := tc.Write(km); err != nil {
		return fmt.Errorf("send key-method 2: %w", err)
	}
	serverRec, err := readServerKeyMethod(tc)
	if err != nil {
		return fmt.Errorf("read key-method 2: %w", err)
	}
	master, keys := deriveOpenVPNKeys(clientSrc, serverRec.Source, cc.localSID, cc.remoteSID)

	if _, err := tc.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return fmt.Errorf("send PUSH_REQUEST: %w", err)
	}
	br := bufio.NewReaderSize(tc, 64<<10)
	pushMsgs, err := readPushReply(br)
	if err != nil {
		return fmt.Errorf("PUSH_REPLY: %w", err)
	}
	opts := flattenPushOptions(pushMsgs)
	ps, err := parsePushedSession(opts)
	if err != nil {
		return err
	}

	dnsPayload, txid, err := buildDNSQuery(*queryName)
	if err != nil {
		return err
	}
	srcPort := uint16(40000 + (txid % 20000))
	inner, err := buildIPv4UDP(ps.IPv4, ps.DNS, srcPort, 53, dnsPayload, txid)
	if err != nil {
		return err
	}
	encrypted, err := encryptDataV2(ps.PeerID, 0, 1, keys.ClientCipher[:32], keys.ClientHMAC[:], inner)
	if err != nil {
		return err
	}

	// From this point on we use the same connected UDP socket directly. For
	// this short probe we can ignore control-channel retransmits/keepalives and
	// wait specifically for an authenticated P_DATA_V2 reply.
	if err := cc.udp.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	sentAt := time.Now()
	if _, err := cc.udp.Write(encrypted); err != nil {
		return fmt.Errorf("send P_DATA_V2: %w", err)
	}

	buf := make([]byte, 65535)
	var proof dnsReplyProof
	var dataMeta decryptedDataV2
	var dataRTT time.Duration
	decryptFailures := 0
	for i := 0; i < 40; i++ {
		n, err := cc.udp.Read(buf)
		if err != nil {
			return fmt.Errorf("wait data-channel DNS reply: %w", err)
		}
		if n < 1 || int(buf[0]>>3) != openVPNDataV2Opcode {
			continue
		}
		dec, err := decryptDataV2(buf[:n], keys.ServerCipher[:32], keys.ServerHMAC[:])
		if err != nil {
			decryptFailures++
			continue
		}
		if len(dec.Payload) == 0 || dec.Payload[0]>>4 != 4 {
			continue
		} // e.g. VPN keepalive
		p, err := parseIPv4DNSReply(dec.Payload, txid, srcPort)
		if err != nil {
			continue
		}
		dataMeta, proof, dataRTT = dec, p, time.Since(sentAt)
		break
	}
	if proof.TxID == 0 {
		return fmt.Errorf("no matching DNS reply decrypted (GCM failures=%d)", decryptFailures)
	}

	fmt.Printf("Gateway:          %s (%s) %s UDP/%d\n", ep.Host, ep.Location, ep.IP, ep.Port)
	fmt.Printf("Control RTT:      %s\n", resetLatency.Round(time.Millisecond))
	fmt.Printf("Virtual IPv4:     %s\n", ps.IPv4)
	fmt.Printf("VPN DNS:          %s\n", ps.DNS)
	fmt.Printf("Peer ID:          %d\n", ps.PeerID)
	fmt.Printf("Cipher:           %s\n", ps.Cipher)
	fmt.Printf("Data packet:      P_DATA_V2 id=%d peer=%d\n", dataMeta.PacketID, dataMeta.PeerID)
	fmt.Printf("Encrypted DNS:    %s -> %s:53 (%s)\n", *queryName, proof.SourceIP, dataRTT.Round(time.Millisecond))
	fmt.Printf("DNS response:     rcode=%d answers=%d txid=%d\n", proof.RCode, proof.Answers, proof.TxID)
	fmt.Println("REAL encrypted data-channel traffic succeeded in pure Go.")
	fmt.Println("The test packet was constructed in memory; no TUN interface or host route was changed.")

	for i := range clientSrc.PreMaster {
		clientSrc.PreMaster[i] = 0
	}
	for i := range master {
		master[i] = 0
	}
	keys = dataKeyBlock{}
	return nil
}
