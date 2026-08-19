package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

func readNULControlMessage(r *bufio.Reader, max int) (string, error) {
	var b strings.Builder
	for b.Len() <= max {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == 0 {
			return b.String(), nil
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("control message exceeded %d bytes", max)
}

func readPushReply(r *bufio.Reader) ([]string, error) {
	var parts []string
	for i := 0; i < 16; i++ {
		msg, err := readNULControlMessage(r, 256<<10)
		if err != nil {
			return nil, err
		}
		switch {
		case strings.HasPrefix(msg, "AUTH_FAILED"):
			return nil, fmt.Errorf("server authentication failed: %s", sanitizeOneLine(msg, 220))
		case strings.HasPrefix(msg, "RESTART"), strings.HasPrefix(msg, "HALT"):
			return nil, fmt.Errorf("server requested %s", sanitizeOneLine(msg, 220))
		case strings.HasPrefix(msg, "PUSH_REPLY"):
			parts = append(parts, msg)
			if strings.Contains(msg, ",push-continuation 2") {
				continue
			}
			return parts, nil
		case strings.HasPrefix(msg, "AUTH_PENDING"), strings.HasPrefix(msg, "INFO"):
			// Informational/auth-pending messages can legally precede PUSH_REPLY.
			continue
		default:
			// Unknown control strings are ignored during this read-only probe.
			continue
		}
	}
	return nil, errors.New("too many control messages before PUSH_REPLY")
}

func flattenPushOptions(messages []string) []string {
	var out []string
	for _, msg := range messages {
		body := strings.TrimPrefix(msg, "PUSH_REPLY")
		body = strings.TrimPrefix(body, ",")
		for _, item := range strings.Split(body, ",") {
			item = strings.TrimSpace(item)
			if item == "" || strings.HasPrefix(item, "push-continuation ") {
				continue
			}
			out = append(out, item)
		}
	}
	return out
}

func findPushOption(opts []string, name string) string {
	prefix := name + " "
	for _, o := range opts {
		if o == name {
			return ""
		}
		if strings.HasPrefix(o, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(o, prefix))
		}
	}
	return ""
}

func summarizePushOptions(opts []string) {
	virtual4 := findPushOption(opts, "ifconfig")
	virtual6 := findPushOption(opts, "ifconfig-ipv6")
	peerID := findPushOption(opts, "peer-id")
	cipher := findPushOption(opts, "cipher")
	tunMTU := findPushOption(opts, "tun-mtu")
	topology := findPushOption(opts, "topology")

	if virtual4 != "" {
		fmt.Printf("IPv4 assignment:  %s\n", virtual4)
	}
	if virtual6 != "" {
		fmt.Printf("IPv6 assignment:  %s\n", virtual6)
	}
	if peerID != "" {
		fmt.Printf("Peer ID:          %s\n", peerID)
	}
	if cipher != "" {
		fmt.Printf("Cipher selected:  %s\n", cipher)
	}
	if tunMTU != "" {
		fmt.Printf("TUN MTU:          %s\n", tunMTU)
	}
	if topology != "" {
		fmt.Printf("Topology:         %s\n", topology)
	}

	routes, dns := 0, 0
	var categories = map[string]int{}
	for _, o := range opts {
		fields := strings.Fields(o)
		if len(fields) == 0 {
			continue
		}
		categories[fields[0]]++
		if fields[0] == "route" || fields[0] == "route-ipv6" {
			routes++
		}
		if fields[0] == "dhcp-option" || fields[0] == "dns" {
			dns++
		}
	}
	fmt.Printf("Pushed options:   %d (%d route-related, %d DNS-related)\n", len(opts), routes, dns)

	keys := make([]string, 0, len(categories))
	for k := range categories {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var compact []string
	for _, k := range keys {
		compact = append(compact, k+"="+strconv.Itoa(categories[k]))
	}
	fmt.Printf("Option classes:   %s\n", strings.Join(compact, ", "))
}

func cmdPushProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pushprobe", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 18*time.Second, "overall configuration negotiation timeout")
	identityPath := fs.String("identity", defaultIdentityPath(), "client certificate/key path")
	showAll := fs.Bool("all", false, "show every pushed option")
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

	if _, err := tc.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return fmt.Errorf("send PUSH_REQUEST: %w", err)
	}
	reader := bufio.NewReaderSize(tc, 64<<10)
	messages, err := readPushReply(reader)
	if err != nil {
		return fmt.Errorf("PUSH_REPLY: %w", err)
	}
	opts := flattenPushOptions(messages)

	fmt.Printf("Gateway:          %s (%s) %s UDP/%d\n", ep.Host, ep.Location, ep.IP, ep.Port)
	fmt.Printf("Reset RTT:        %s\n", resetLatency.Round(time.Millisecond))
	fmt.Println("TLS + KeyMethod2: authenticated / complete")
	summarizePushOptions(opts)
	if *showAll {
		fmt.Println("Options received (not applied):")
		for _, o := range opts {
			fmt.Printf("  - %s\n", sanitizeOneLine(o, 500))
		}
	}
	fmt.Printf("Data-key proofs:  C->S=%s S->C=%s\n", shortKeyProof(keys.ClientCipher[:32]), shortKeyProof(keys.ServerCipher[:32]))
	fmt.Println("PUSH_REPLY parsed in pure Go; configuration was NOT applied to the host.")
	fmt.Println("No TUN interface or host route was changed.")

	for i := range clientSrc.PreMaster {
		clientSrc.PreMaster[i] = 0
	}
	for i := range master {
		master[i] = 0
	}
	keys = dataKeyBlock{}
	return nil
}

var _ io.Reader = (*bufio.Reader)(nil)
