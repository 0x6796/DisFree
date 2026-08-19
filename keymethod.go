package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
)

const (
	keyMethod2         = 2
	maxCipherKeyLength = 64
	maxHMACKeyLength   = 64
	keyWireSize        = maxCipherKeyLength + maxHMACKeyLength
)

type keySource struct {
	PreMaster [48]byte
	Random1   [32]byte
	Random2   [32]byte
}

type keyMethodRecord struct {
	Source   keySource
	Options  string
	Username string
	Password string
	PeerInfo string
}

type dataKeyBlock struct {
	ClientCipher [maxCipherKeyLength]byte
	ClientHMAC   [maxHMACKeyLength]byte
	ServerCipher [maxCipherKeyLength]byte
	ServerHMAC   [maxHMACKeyLength]byte
}

func randomClientKeySource() (keySource, error) {
	var k keySource
	if _, err := rand.Read(k.PreMaster[:]); err != nil {
		return k, err
	}
	if _, err := rand.Read(k.Random1[:]); err != nil {
		return k, err
	}
	if _, err := rand.Read(k.Random2[:]); err != nil {
		return k, err
	}
	return k, nil
}

func writeOVPNString(w io.Writer, s string) error {
	if s == "" {
		return binary.Write(w, binary.BigEndian, uint16(0))
	}
	if strings.IndexByte(s, 0) >= 0 {
		return errors.New("OpenVPN string contains NUL")
	}
	n := len(s) + 1
	if n > 0xffff {
		return errors.New("OpenVPN string too long")
	}
	if err := binary.Write(w, binary.BigEndian, uint16(n)); err != nil {
		return err
	}
	if _, err := io.WriteString(w, s); err != nil {
		return err
	}
	_, err := w.Write([]byte{0})
	return err
}

func readOVPNString(r io.Reader, max int) (string, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	if int(n) > max {
		return "", fmt.Errorf("OpenVPN string length %d exceeds %d", n, max)
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	if b[len(b)-1] != 0 {
		return "", errors.New("OpenVPN string missing trailing NUL")
	}
	return string(b[:len(b)-1]), nil
}

func clientOptionsString(ep Endpoint) string {
	proto := "UDPv4"
	if strings.EqualFold(ep.Protocol, "tcp") {
		proto = "TCPv4_CLIENT"
	}
	// OCC mismatches are warnings in OpenVPN; these values describe the
	// actual DisFree data path we are implementing and intentionally avoid
	// advertising features we do not support yet.
	return fmt.Sprintf("V4,dev-type tun,link-mtu 1550,tun-mtu 1500,proto %s,cipher AES-256-GCM,auth SHA512,keysize 256,key-method 2,tls-client", proto)
}

func clientPeerInfo() string {
	// IV_PROTO=6 => DATA_V2 (bit 1) + REQUEST_PUSH (bit 2).
	// Do not advertise TLS key exporter / epoch / dyn-tls-crypt until those
	// code paths exist in DisFree.
	return "IV_VER=DisFree_0.5\nIV_PLAT=linux\nIV_MTU=1500\nIV_CIPHERS=AES-256-GCM\nIV_PROTO=6\n"
}

func marshalClientKeyMethod(src keySource, ep Endpoint) ([]byte, error) {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.BigEndian, uint32(0)); err != nil {
		return nil, err
	}
	b.WriteByte(keyMethod2)
	b.Write(src.PreMaster[:])
	b.Write(src.Random1[:])
	b.Write(src.Random2[:])
	if err := writeOVPNString(&b, clientOptionsString(ep)); err != nil {
		return nil, err
	}
	if err := writeOVPNString(&b, ""); err != nil {
		return nil, err
	}
	if err := writeOVPNString(&b, ""); err != nil {
		return nil, err
	}
	if err := writeOVPNString(&b, clientPeerInfo()); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func readServerKeyMethod(r io.Reader) (keyMethodRecord, error) {
	var rec keyMethodRecord
	var zero uint32
	if err := binary.Read(r, binary.BigEndian, &zero); err != nil {
		return rec, err
	}
	if zero != 0 {
		return rec, fmt.Errorf("key-method prefix is %d, expected 0", zero)
	}
	var method [1]byte
	if _, err := io.ReadFull(r, method[:]); err != nil {
		return rec, err
	}
	if method[0]&0x07 != keyMethod2 {
		return rec, fmt.Errorf("server key method=%d", method[0])
	}

	// The server half contains random1/random2 only. pre_master is client-only.
	if _, err := io.ReadFull(r, rec.Source.Random1[:]); err != nil {
		return rec, err
	}
	if _, err := io.ReadFull(r, rec.Source.Random2[:]); err != nil {
		return rec, err
	}
	var err error
	if rec.Options, err = readOVPNString(r, 8192); err != nil {
		return rec, fmt.Errorf("server options: %w", err)
	}
	if rec.Username, err = readOVPNString(r, 1024); err != nil {
		return rec, fmt.Errorf("server username: %w", err)
	}
	if rec.Password, err = readOVPNString(r, 1024); err != nil {
		return rec, fmt.Errorf("server password: %w", err)
	}
	if rec.PeerInfo, err = readOVPNString(r, 16384); err != nil {
		return rec, fmt.Errorf("server peer-info: %w", err)
	}
	return rec, nil
}

func pHash(newHash func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n)
	a := append([]byte(nil), seed...)
	for len(out) < n {
		macA := hmac.New(newHash, secret)
		_, _ = macA.Write(a)
		a = macA.Sum(nil)

		mac := hmac.New(newHash, secret)
		_, _ = mac.Write(a)
		_, _ = mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:n]
}

func tls10PRF(secret, seed []byte, n int) []byte {
	// TLS 1.0 PRF: P_MD5(S1, seed) XOR P_SHA1(S2, seed), with the middle
	// byte shared when the secret length is odd.
	half := (len(secret) + 1) / 2
	s1 := secret[:half]
	s2 := secret[len(secret)-half:]
	a := pHash(md5.New, s1, seed, n)
	b := pHash(sha1.New, s2, seed, n)
	out := make([]byte, n)
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func deriveOpenVPNKeys(client, server keySource, clientSID, serverSID sessionID) ([48]byte, dataKeyBlock) {
	var master [48]byte
	seedMaster := make([]byte, 0, len("OpenVPN master secret")+64)
	seedMaster = append(seedMaster, []byte("OpenVPN master secret")...)
	seedMaster = append(seedMaster, client.Random1[:]...)
	seedMaster = append(seedMaster, server.Random1[:]...)
	copy(master[:], tls10PRF(client.PreMaster[:], seedMaster, len(master)))

	seedKeys := make([]byte, 0, len("OpenVPN key expansion")+64+16)
	seedKeys = append(seedKeys, []byte("OpenVPN key expansion")...)
	seedKeys = append(seedKeys, client.Random2[:]...)
	seedKeys = append(seedKeys, server.Random2[:]...)
	seedKeys = append(seedKeys, clientSID[:]...)
	seedKeys = append(seedKeys, serverSID[:]...)
	raw := tls10PRF(master[:], seedKeys, 2*keyWireSize)

	var keys dataKeyBlock
	copy(keys.ClientCipher[:], raw[0:64])
	copy(keys.ClientHMAC[:], raw[64:128])
	copy(keys.ServerCipher[:], raw[128:192])
	copy(keys.ServerHMAC[:], raw[192:256])
	// Do not retain the temporary expansion buffer longer than needed.
	for i := range raw {
		raw[i] = 0
	}
	return master, keys
}

func shortKeyProof(k []byte) string {
	sum := sha256.Sum256(k)
	return fmt.Sprintf("%x", sum[:8])
}

func sanitizeOneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func cmdKeyProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("keyprobe", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 12*time.Second, "overall key-method timeout")
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
	request, err := marshalClientKeyMethod(clientSrc, ep)
	if err != nil {
		return err
	}
	if _, err := tc.Write(request); err != nil {
		return fmt.Errorf("send key-method 2: %w", err)
	}

	serverRec, err := readServerKeyMethod(tc)
	if err != nil {
		return fmt.Errorf("read key-method 2: %w", err)
	}
	master, keys := deriveOpenVPNKeys(clientSrc, serverRec.Source, cc.localSID, cc.remoteSID)

	fmt.Printf("Gateway:          %s (%s) %s UDP/%d\n", ep.Host, ep.Location, ep.IP, ep.Port)
	fmt.Printf("Reset RTT:        %s\n", resetLatency.Round(time.Millisecond))
	fmt.Println("TLS:              authenticated")
	fmt.Println("Key method:       2")
	fmt.Printf("Server options:   %s\n", sanitizeOneLine(serverRec.Options, 260))
	if serverRec.PeerInfo != "" {
		fmt.Printf("Server peer-info: %s\n", sanitizeOneLine(serverRec.PeerInfo, 260))
	}
	fmt.Printf("Master proof:     %s (SHA-256 prefix only)\n", shortKeyProof(master[:]))
	fmt.Printf("C->S AES key:     %s (SHA-256 prefix only)\n", shortKeyProof(keys.ClientCipher[:32]))
	fmt.Printf("S->C AES key:     %s (SHA-256 prefix only)\n", shortKeyProof(keys.ServerCipher[:32]))
	fmt.Println("Key Method 2 exchange and legacy OpenVPN PRF completed in pure Go.")
	fmt.Println("Raw key material was not logged.")
	fmt.Println("No TUN interface or host route was changed.")

	// Best-effort zeroization of the copies we own.
	for i := range clientSrc.PreMaster {
		clientSrc.PreMaster[i] = 0
	}
	for i := range master {
		master[i] = 0
	}
	keys = dataKeyBlock{}
	return nil
}
