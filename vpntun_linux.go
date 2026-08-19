package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

func sendFD(sock int, fd int) error {
	_, err := syscall.SendmsgN(sock, []byte{'T'}, syscall.UnixRights(fd), nil, 0)
	return err
}

func recvFD(sock int) (int, error) {
	data := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := syscall.Recvmsg(sock, data, oob, 0)
	if err != nil {
		return -1, err
	}
	if n != 1 || data[0] != 'T' {
		return -1, errors.New("invalid TUN fd transfer marker")
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	for _, msg := range msgs {
		fds, err := syscall.ParseUnixRights(&msg)
		if err != nil {
			return -1, err
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, errors.New("TUN fd not present in SCM_RIGHTS")
}

func recvFDWithChild(sock int, childDone <-chan error, childOut *bytes.Buffer, ctx context.Context) (int, error) {
	if err := syscall.SetNonblock(sock, true); err != nil {
		return -1, fmt.Errorf("fd-pass nonblock: %w", err)
	}
	for {
		fd, err := recvFD(sock)
		if err == nil {
			return fd, nil
		}
		if err != syscall.EAGAIN && err != syscall.EWOULDBLOCK {
			return -1, err
		}
		select {
		case childErr := <-childDone:
			if childErr == nil {
				return -1, fmt.Errorf("isolated child exited before sending TUN fd\n%s", childOut.String())
			}
			return -1, fmt.Errorf("isolated child exited before sending TUN fd: %w\n%s", childErr, childOut.String())
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func vpnTunChild(args []string) error {
	if len(args) != 3 {
		return errors.New("internal vpntun child requires ip prefix dns")
	}
	ip := net.ParseIP(args[0]).To4()
	if ip == nil {
		return errors.New("invalid child IPv4")
	}
	prefix64, err := strconv.ParseUint(args[1], 10, 8)
	if err != nil || prefix64 > 32 {
		return errors.New("invalid child prefix")
	}
	dns := net.ParseIP(args[2]).To4()
	if dns == nil {
		return errors.New("invalid child DNS")
	}

	tun, name, err := createTUN("disfree0")
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer tun.Close()
	if err := configureTUNIPv4(name, ip, uint8(prefix64)); err != nil {
		return err
	}

	pass := os.NewFile(uintptr(3), "disfree-fdpass")
	if pass == nil {
		return errors.New("missing fd-pass socket")
	}
	defer pass.Close()
	if err := sendFD(int(pass.Fd()), int(tun.Fd())); err != nil {
		return fmt.Errorf("send TUN fd: %w", err)
	}

	q, txid, err := buildDNSQuery("example.com")
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dns, Port: 53})
	if err != nil {
		return fmt.Errorf("isolated DNS socket: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	started := time.Now()
	if _, err := conn.Write(q); err != nil {
		return fmt.Errorf("isolated DNS write: %w", err)
	}
	reply := make([]byte, 4096)
	n, err := conn.Read(reply)
	if err != nil {
		return fmt.Errorf("isolated DNS read: %w", err)
	}
	if n < 12 {
		return errors.New("short DNS response inside namespace")
	}
	if got := binaryBigEndianU16(reply[0:2]); got != txid {
		return fmt.Errorf("DNS txid mismatch %d != %d", got, txid)
	}
	flags := binaryBigEndianU16(reply[2:4])
	answers := binaryBigEndianU16(reply[6:8])
	if flags&0x8000 == 0 {
		return errors.New("isolated DNS packet is not a response")
	}

	fmt.Printf("isolated app namespace: %s/%d via %s\n", ip, prefix64, name)
	fmt.Printf("normal UDP socket -> VPN DNS %s:53\n", dns)
	fmt.Printf("DNS reply returned to ordinary socket in %s (rcode=%d answers=%d)\n", time.Since(started).Round(time.Millisecond), flags&0x0f, answers)
	return nil
}

func binaryBigEndianU16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func launchVPNTunChild(ip net.IP, prefix int, dns net.IP) (*exec.Cmd, int, *bytes.Buffer, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, -1, nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
		return nil, -1, nil, err
	}

	childPass := os.NewFile(uintptr(pair[1]), "disfree-child-fdpass")
	cmd := exec.Command(exe, "__vpntun_child", ip.String(), strconv.Itoa(prefix), dns.String())
	cmd.ExtraFiles = []*os.File{childPass}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		childPass.Close()
		syscall.Close(pair[0])
		syscall.Close(pair[1])
		return nil, -1, nil, err
	}
	childPass.Close()
	return cmd, pair[0], out, nil
}

func bridgeTunAndVPN(ctx context.Context, tun *os.File, udp *net.UDPConn, ps pushedSession, keys dataKeyBlock) (uint64, uint64, <-chan error) {
	errCh := make(chan error, 2)
	var toVPN, fromVPN uint64

	_ = syscall.SetNonblock(int(tun.Fd()), true)
	go func() {
		var packetID uint32
		buf := make([]byte, 65535)
		lastSend := time.Now()
		pingPayload := []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
		sendPayload := func(payload []byte) error {
			packetID++
			enc, err := encryptDataV2(ps.PeerID, 0, packetID, keys.ClientCipher[:32], keys.ClientHMAC[:], payload)
			if err != nil {
				return err
			}
			if _, err := udp.Write(enc); err != nil {
				return fmt.Errorf("VPN UDP write: %w", err)
			}
			lastSend = time.Now()
			toVPN++
			return nil
		}
		for {
			select {
			case <-ctx.Done():
				errCh <- nil
				return
			default:
			}
			if time.Since(lastSend) >= 10*time.Second {
				if err := sendPayload(pingPayload); err != nil {
					errCh <- err
					return
				}
			}
			n, err := tun.Read(buf)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				errCh <- fmt.Errorf("TUN read: %w", err)
				return
			}
			if n == 0 {
				continue
			}
			if err := sendPayload(buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				errCh <- nil
				return
			default:
			}
			_ = udp.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, err := udp.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				errCh <- fmt.Errorf("VPN UDP read: %w", err)
				return
			}
			if n < 1 || int(buf[0]>>3) != openVPNDataV2Opcode {
				continue
			}
			dec, err := decryptDataV2(buf[:n], keys.ServerCipher[:32], keys.ServerHMAC[:])
			if err != nil {
				continue
			}
			if len(dec.Payload) == 0 {
				continue
			}
			version := dec.Payload[0] >> 4
			if version != 4 && version != 6 {
				continue
			} // OpenVPN ping/other control payload
			if _, err := tun.Write(dec.Payload); err != nil {
				errCh <- fmt.Errorf("TUN write: %w", err)
				return
			}
			fromVPN++
		}
	}()

	// Stats are returned by value only for API symmetry; the proof command uses
	// the child result as the end-to-end success signal.
	_ = toVPN
	_ = fromVPN
	return toVPN, fromVPN, errCh
}

func cmdVPNTunProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("vpntunprobe", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 30*time.Second, "overall end-to-end namespace VPN timeout")
	identityPath := fs.String("identity", defaultIdentityPath(), "client certificate/key path")
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

	sessionCtx, cancelSession := context.WithTimeout(ctx, *timeout)
	defer cancelSession()
	cc, resetLatency, err := dialControlUDP(sessionCtx, ep, *timeout)
	if err != nil {
		return fmt.Errorf("control reset: %w", err)
	}
	defer cc.Close()
	_ = cc.SetDeadline(time.Now().Add(*timeout))

	tc := tls.Client(cc, trust.tlsConfigForGateway(ep, id))
	if err := tc.HandshakeContext(sessionCtx); err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	clientSrc, err := randomClientKeySource()
	if err != nil {
		return err
	}
	km, err := marshalClientKeyMethod(clientSrc, ep)
	if err != nil {
		return err
	}
	if _, err := tc.Write(km); err != nil {
		return err
	}
	serverRec, err := readServerKeyMethod(tc)
	if err != nil {
		return err
	}
	master, keys := deriveOpenVPNKeys(clientSrc, serverRec.Source, cc.localSID, cc.remoteSID)
	if _, err := tc.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return err
	}
	br := bufio.NewReaderSize(tc, 64<<10)
	pushMsgs, err := readPushReply(br)
	if err != nil {
		return err
	}
	ps, err := parsePushedSession(flattenPushOptions(pushMsgs))
	if err != nil {
		return err
	}
	ones, bits := net.IPMask(ps.Netmask).Size()
	if bits != 32 || ones < 0 {
		return fmt.Errorf("invalid pushed IPv4 netmask %s", ps.Netmask)
	}

	child, passSock, childOut, err := launchVPNTunChild(ps.IPv4, ones, ps.DNS)
	if err != nil {
		return fmt.Errorf("launch isolated app: %w", err)
	}
	defer syscall.Close(passSock)
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	tunFD, err := recvFDWithChild(passSock, childDone, childOut, sessionCtx)
	if err != nil {
		_ = child.Process.Kill()
		return fmt.Errorf("receive TUN fd: %w", err)
	}
	tun := os.NewFile(uintptr(tunFD), "disfree0-from-netns")
	if tun == nil {
		return errors.New("failed to wrap received TUN fd")
	}
	defer tun.Close()

	bridgeCtx, cancelBridge := context.WithCancel(sessionCtx)
	_, _, bridgeErr := bridgeTunAndVPN(bridgeCtx, tun, cc.udp, ps, keys)

	var childErr error
	select {
	case childErr = <-childDone:
		cancelBridge()
	case err := <-bridgeErr:
		cancelBridge()
		_ = child.Process.Kill()
		childErr = <-childDone
		if err != nil {
			return err
		}
	case <-sessionCtx.Done():
		cancelBridge()
		_ = child.Process.Kill()
		childErr = <-childDone
		return sessionCtx.Err()
	}
	if childErr != nil {
		return fmt.Errorf("isolated app failed: %w\n%s", childErr, childOut.String())
	}

	fmt.Printf("Gateway:          %s (%s) %s UDP/%d\n", ep.Host, ep.Location, ep.IP, ep.Port)
	fmt.Printf("Control RTT:      %s\n", resetLatency.Round(time.Millisecond))
	fmt.Printf("Namespace IPv4:   %s/%d\n", ps.IPv4, ones)
	fmt.Printf("VPN DNS:          %s\n", ps.DNS)
	fmt.Printf("Peer/Cipher:      %d / %s\n", ps.PeerID, ps.Cipher)
	fmt.Print(childOut.String())
	fmt.Println("END-TO-END: ordinary socket in isolated namespace used the pure-Go VPN tunnel.")
	fmt.Println("The host default route and host DNS were never changed.")

	for i := range clientSrc.PreMaster {
		clientSrc.PreMaster[i] = 0
	}
	for i := range master {
		master[i] = 0
	}
	keys = dataKeyBlock{}
	return nil
}
