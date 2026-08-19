//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type windowsReverseFlowKey struct {
	Protocol   uint8
	RemoteIP   [4]byte
	LocalPort  uint16
	RemotePort uint16
}

type windowsDiscordFlow struct {
	id       string
	key      ipv4FlowKey
	ifIdx    uint32
	handle   *winDivertHandle
	ipv6Drop bool
	shared   bool // handle is owned by manager (broad UDP capture), not this flow
}

type windowsFlowManager struct {
	ctx              context.Context
	vpn              *liveVPN
	wd               *winDivertRuntime
	mu               sync.RWMutex
	flows            map[string]*windowsDiscordFlow
	reverse          map[windowsReverseFlowKey]*windowsDiscordFlow
	udpHandles       map[uint16]*winDivertHandle
	udpPortRefs      map[uint16]map[uint64]struct{} // local UDP port -> Discord socket endpoint IDs
	udpEndpointPorts map[uint64]uint16              // socket endpoint ID -> local UDP port
	vpnLocalUDPPort  uint16
	packetID         uint32
	errCh            chan error
	bootstrapActive  atomic.Bool
	tcpIntents       map[string]time.Time
}

func newWindowsFlowManager(ctx context.Context, vpn *liveVPN, wd *winDivertRuntime) *windowsFlowManager {
	m := &windowsFlowManager{
		ctx: ctx, vpn: vpn, wd: wd,
		flows:            make(map[string]*windowsDiscordFlow),
		reverse:          make(map[windowsReverseFlowKey]*windowsDiscordFlow),
		udpHandles:       make(map[uint16]*winDivertHandle),
		udpPortRefs:      make(map[uint16]map[uint64]struct{}),
		udpEndpointPorts: make(map[uint64]uint16),
		tcpIntents:       make(map[string]time.Time),
		errCh:            make(chan error, 8),
	}
	if vpn != nil && vpn.Control != nil && vpn.Control.udp != nil {
		if a, ok := vpn.Control.udp.LocalAddr().(*net.UDPAddr); ok && a.Port > 0 && a.Port <= 65535 {
			m.vpnLocalUDPPort = uint16(a.Port)
		}
	}
	return m
}

func windowsFlowIdentity(proto uint8, local net.IP, lp uint16, remote net.IP, rp uint16) string {
	return fmt.Sprintf("%d|%s|%d|%s|%d", proto, local.String(), lp, remote.String(), rp)
}

func windowsTCPIntentKey(lp uint16, remote net.IP, rp uint16) string {
	return fmt.Sprintf("%d|%s|%d", lp, remote.String(), rp)
}

func windowsTCPRemoteIntentKey(remote net.IP, rp uint16) string {
	return fmt.Sprintf("*|%s|%d", remote.String(), rp)
}

func (m *windowsFlowManager) markTCPIntent(a *wdAddress) {
	if a == nil || !m.bootstrapActive.Load() || a.flowProtocol() != 6 || !isDiscordPIDWindows(a.flowPID()) {
		return
	}
	_, remote, err := m.wd.flowIPs(a)
	if err != nil || remote.To4() == nil || remote.IsUnspecified() {
		return
	}
	lp, rp := a.flowLocalPort(), a.flowRemotePort()
	if rp == 0 {
		return
	}
	key := windowsTCPRemoteIntentKey(remote, rp)
	if lp != 0 {
		key = windowsTCPIntentKey(lp, remote, rp)
	}
	m.mu.Lock()
	m.tcpIntents[key] = time.Now().Add(3 * time.Second)
	m.mu.Unlock()
	fmt.Printf("DisFree Windows: armed Discord TCP SYN local=%d -> %s:%d\n", lp, remote, rp)
}

func (m *windowsFlowManager) consumeTCPIntent(k ipv4FlowKey) bool {
	remote := ipv4FromArray(k.RemoteIP)
	full := windowsTCPIntentKey(k.LocalPort, remote, k.RemotePort)
	fallback := windowsTCPRemoteIntentKey(remote, k.RemotePort)
	deadline := time.Now().Add(8 * time.Millisecond)
	for {
		now := time.Now()
		m.mu.Lock()
		for _, key := range []string{full, fallback} {
			if expires, ok := m.tcpIntents[key]; ok {
				if now.Before(expires) {
					delete(m.tcpIntents, key)
					m.mu.Unlock()
					return true
				}
				delete(m.tcpIntents, key)
			}
		}
		m.mu.Unlock()
		if !m.bootstrapActive.Load() || !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

func reverseKeyFromFlow(k ipv4FlowKey) windowsReverseFlowKey {
	return windowsReverseFlowKey{Protocol: k.Protocol, RemoteIP: k.RemoteIP, LocalPort: k.LocalPort, RemotePort: k.RemotePort}
}

func reverseKeyFromInboundPacket(packet []byte) (windowsReverseFlowKey, error) {
	k, err := parseIPv4Flow(packet, false)
	if err != nil {
		return windowsReverseFlowKey{}, err
	}
	return windowsReverseFlowKey{Protocol: k.Protocol, RemoteIP: k.RemoteIP, LocalPort: k.LocalPort, RemotePort: k.RemotePort}, nil
}

func windowsProtoName(proto uint8) (string, bool) {
	switch proto {
	case 6:
		return "tcp", true
	case 17:
		return "udp", true
	default:
		return "", false
	}
}

func windowsFlowFilter(proto uint8, local net.IP, lp uint16, remote net.IP, rp uint16) (string, error) {
	pn, ok := windowsProtoName(proto)
	if !ok {
		return "", fmt.Errorf("unsupported protocol %d", proto)
	}
	family := "ip"
	if local.To4() == nil || remote.To4() == nil {
		family = "ipv6"
	}
	return fmt.Sprintf("!impostor and !loopback and %s and %s and localAddr == %s and localPort == %d and remoteAddr == %s and remotePort == %d",
		family, pn, local.String(), lp, remote.String(), rp), nil
}

func (m *windowsFlowManager) addFromEvent(a *wdAddress) error {
	if !m.bootstrapActive.Load() {
		return nil
	}
	pid := a.flowPID()
	if !isDiscordPIDWindows(pid) {
		return nil
	}
	proto := a.flowProtocol()
	if proto != 6 {
		return nil
	}
	local, remote, err := m.wd.flowIPs(a)
	if err != nil {
		return err
	}
	// Socket CONNECT can still report an unspecified local address. The FLOW
	// event that follows has the routed local address, so wait for that one.
	if local.IsUnspecified() || remote.IsUnspecified() {
		return nil
	}
	lp, rp := a.flowLocalPort(), a.flowRemotePort()
	id := windowsFlowIdentity(proto, local, lp, remote, rp)

	m.mu.RLock()
	_, exists := m.flows[id]
	m.mu.RUnlock()
	if exists {
		return nil
	}

	filter, err := windowsFlowFilter(proto, local, lp, remote, rp)
	if err != nil {
		return err
	}

	if local.To4() == nil || remote.To4() == nil {
		// Current Riseup session is IPv4. Drop only Discord's IPv6 flow so the
		// app naturally retries/falls back to IPv4 instead of leaking it.
		h, err := m.wd.open(filter, wdLayerNetwork, 200, wdFlagDrop)
		if err != nil {
			return fmt.Errorf("open IPv6 kill-switch flow: %w", err)
		}
		f := &windowsDiscordFlow{id: id, handle: h, ipv6Drop: true}
		m.mu.Lock()
		if old := m.flows[id]; old != nil {
			m.mu.Unlock()
			_ = h.Close()
			return nil
		}
		m.flows[id] = f
		m.mu.Unlock()
		fmt.Printf("DisFree Windows: IPv6 blocked for Discord flow %s:%d -> %s:%d\n", local, lp, remote, rp)
		return nil
	}

	la, _ := ip4Array(local)
	ra, _ := ip4Array(remote)
	key := ipv4FlowKey{Protocol: proto, LocalIP: la, RemoteIP: ra, LocalPort: lp, RemotePort: rp}
	ifIdx, err := bestWindowsInterfaceIndex(remote)
	if err != nil {
		return fmt.Errorf("best interface for %s: %w", remote, err)
	}
	h, err := m.wd.open(filter, wdLayerNetwork, 200, 0)
	if err != nil {
		return fmt.Errorf("open Discord packet flow: %w", err)
	}
	f := &windowsDiscordFlow{id: id, key: key, ifIdx: ifIdx, handle: h}

	m.mu.Lock()
	if old := m.flows[id]; old != nil {
		m.mu.Unlock()
		_ = h.Close()
		return nil
	}
	m.flows[id] = f
	m.reverse[reverseKeyFromFlow(key)] = f
	m.mu.Unlock()

	go m.captureFlow(f)
	return nil
}

func (m *windowsFlowManager) installTCPFlowFromSYN(k ipv4FlowKey, addr *wdAddress) (*windowsDiscordFlow, error) {
	local := ipv4FromArray(k.LocalIP)
	remote := ipv4FromArray(k.RemoteIP)
	id := windowsFlowIdentity(6, local, k.LocalPort, remote, k.RemotePort)

	m.mu.RLock()
	existing := m.flows[id]
	m.mu.RUnlock()
	if existing != nil {
		return existing, nil
	}

	filter, err := windowsFlowFilter(6, local, k.LocalPort, remote, k.RemotePort)
	if err != nil {
		return nil, err
	}
	ifIdx := uint32(0)
	if addr != nil {
		ifIdx = addr.networkIfIdx()
	}
	if ifIdx == 0 {
		ifIdx, err = bestWindowsInterfaceIndex(remote)
		if err != nil {
			return nil, fmt.Errorf("best interface for %s: %w", remote, err)
		}
	}
	h, err := m.wd.open(filter, wdLayerNetwork, 200, 0)
	if err != nil {
		return nil, fmt.Errorf("open Discord TCP flow from SYN: %w", err)
	}
	f := &windowsDiscordFlow{id: id, key: k, ifIdx: ifIdx, handle: h}
	m.mu.Lock()
	if old := m.flows[id]; old != nil {
		m.mu.Unlock()
		_ = h.Close()
		return old, nil
	}
	m.flows[id] = f
	m.reverse[reverseKeyFromFlow(k)] = f
	m.mu.Unlock()
	fmt.Printf("DisFree Windows: first Discord TCP SYN captured %s:%d -> %s:%d\n", local, k.LocalPort, remote, k.RemotePort)
	go m.captureFlow(f)
	return f, nil
}

func (m *windowsFlowManager) captureInitialTCPSYN(h *winDivertHandle) {
	buf := make([]byte, 65535)
	for {
		var addr wdAddress
		n, err := h.recv(buf, &addr)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		if !m.bootstrapActive.Load() {
			if err := h.send(packet, &addr); err != nil {
				m.reportErr(fmt.Errorf("reinject pre-bootstrap SYN: %w", err))
				return
			}
			continue
		}
		k, err := parseIPv4Flow(packet, true)
		if err != nil || k.Protocol != 6 {
			_ = h.send(packet, &addr)
			continue
		}
		id := windowsFlowIdentity(6, ipv4FromArray(k.LocalIP), k.LocalPort, ipv4FromArray(k.RemoteIP), k.RemotePort)
		m.mu.RLock()
		existing := m.flows[id]
		m.mu.RUnlock()
		if existing == nil && !m.consumeTCPIntent(k) {
			if err := h.send(packet, &addr); err != nil {
				m.reportErr(fmt.Errorf("reinject non-Discord SYN: %w", err))
				return
			}
			continue
		}
		if existing == nil {
			if _, err := m.installTCPFlowFromSYN(k, &addr); err != nil {
				m.reportErr(err)
				return
			}
		}
		if _, err := clampTCPMSS(packet, 1180); err != nil {
			m.reportErr(fmt.Errorf("clamp first Discord SYN MSS: %w", err))
			return
		}
		if err := rewriteIPv4Source(packet, m.vpn.Session.IPv4); err != nil {
			m.reportErr(fmt.Errorf("rewrite first Discord SYN: %w", err))
			return
		}
		if err := m.sendPacketToVPN(packet); err != nil {
			m.reportErr(fmt.Errorf("VPN first SYN write: %w", err))
			return
		}
	}
}

func (m *windowsFlowManager) sendPacketToVPN(packet []byte) error {
	id := atomic.AddUint32(&m.packetID, 1)
	if id == 0 {
		id = atomic.AddUint32(&m.packetID, 1)
	}
	enc, err := encryptDataV2(m.vpn.Session.PeerID, 0, id, m.vpn.Keys.ClientCipher[:32], m.vpn.Keys.ClientHMAC[:], packet)
	if err != nil {
		return err
	}
	_, err = m.vpn.Control.udp.Write(enc)
	return err
}

func (m *windowsFlowManager) protectUDPPort(a *wdAddress) {
	if !m.bootstrapActive.Load() {
		return
	}
	if a == nil || a.flowProtocol() != 17 || !isDiscordPIDWindows(a.flowPID()) {
		return
	}
	port := a.flowLocalPort()
	endpointID := a.flowEndpointID()
	if port == 0 || endpointID == 0 {
		return
	}
	// Never capture the socket carrying DisFree's own encrypted transport.
	if m.vpnLocalUDPPort != 0 && port == m.vpnLocalUDPPort {
		return
	}

	m.mu.Lock()
	if oldPort, ok := m.udpEndpointPorts[endpointID]; ok {
		m.mu.Unlock()
		if oldPort == port {
			return
		}
		return
	}
	if refs := m.udpPortRefs[port]; refs != nil {
		refs[endpointID] = struct{}{}
		m.udpEndpointPorts[endpointID] = port
		m.mu.Unlock()
		return
	}

	filter := fmt.Sprintf("!impostor and !loopback and udp and localPort == %d", port)
	h, err := m.wd.open(filter, wdLayerNetwork, 240, 0)
	if err != nil {
		m.mu.Unlock()
		m.reportErr(fmt.Errorf("protect Discord UDP port %d: %w", port, err))
		return
	}
	m.udpHandles[port] = h
	m.udpPortRefs[port] = map[uint64]struct{}{endpointID: {}}
	m.udpEndpointPorts[endpointID] = port
	m.mu.Unlock()

	fmt.Printf("DisFree Windows: Discord UDP port %d protected before first voice packet\n", port)
	go m.captureUDPPort(port, h)
}

func (m *windowsFlowManager) unprotectUDPSocket(a *wdAddress) {
	if a == nil {
		return
	}
	endpointID := a.flowEndpointID()
	if endpointID == 0 {
		return
	}

	var closeHandle *winDivertHandle
	m.mu.Lock()
	port, ok := m.udpEndpointPorts[endpointID]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.udpEndpointPorts, endpointID)
	if refs := m.udpPortRefs[port]; refs != nil {
		delete(refs, endpointID)
		if len(refs) == 0 {
			delete(m.udpPortRefs, port)
			closeHandle = m.udpHandles[port]
			delete(m.udpHandles, port)
			for id, f := range m.flows {
				if f.key.Protocol == 17 && f.key.LocalPort == port {
					delete(m.flows, id)
					delete(m.reverse, reverseKeyFromFlow(f.key))
				}
			}
		}
	}
	m.mu.Unlock()
	if closeHandle != nil {
		_ = closeHandle.Close()
	}
}

func (m *windowsFlowManager) captureUDPPort(port uint16, h *winDivertHandle) {
	buf := make([]byte, 65535)
	for {
		var addr wdAddress
		n, err := h.recv(buf, &addr)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		// Direct inbound packets on a protected Discord UDP socket are dropped.
		// The only accepted response is the packet returned by the encrypted VPN.
		if !addr.outbound() {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		// Riseup currently gives this client an IPv4 session. Any Discord IPv6
		// datagram captured on the protected socket is deliberately dropped rather
		// than leaked outside the VPN.
		if len(packet) < 20 || packet[0]>>4 != 4 {
			continue
		}
		key, err := parseIPv4Flow(packet, true)
		if err != nil || key.Protocol != 17 || key.LocalPort != port {
			continue
		}
		id := windowsFlowIdentity(17, ipv4FromArray(key.LocalIP), key.LocalPort, ipv4FromArray(key.RemoteIP), key.RemotePort)

		m.mu.RLock()
		f := m.flows[id]
		m.mu.RUnlock()
		if f == nil {
			ifIdx := addr.networkIfIdx()
			if ifIdx == 0 {
				ifIdx, err = bestWindowsInterfaceIndex(ipv4FromArray(key.RemoteIP))
				if err != nil {
					continue
				}
			}
			candidate := &windowsDiscordFlow{id: id, key: key, ifIdx: ifIdx, handle: h, shared: true}
			m.mu.Lock()
			if existing := m.flows[id]; existing != nil {
				f = existing
			} else {
				m.flows[id] = candidate
				m.reverse[reverseKeyFromFlow(key)] = candidate
				f = candidate
			}
			m.mu.Unlock()
		}

		if err := rewriteIPv4Source(packet, m.vpn.Session.IPv4); err != nil {
			continue
		}
		if err := m.sendPacketToVPN(packet); err != nil {
			m.reportErr(fmt.Errorf("VPN UDP write: %w", err))
			return
		}
	}
}

func (m *windowsFlowManager) removeFromEvent(a *wdAddress) {
	local, remote, err := m.wd.flowIPs(a)
	if err != nil {
		return
	}
	id := windowsFlowIdentity(a.flowProtocol(), local, a.flowLocalPort(), remote, a.flowRemotePort())
	m.mu.Lock()
	f := m.flows[id]
	if f != nil {
		delete(m.flows, id)
		if !f.ipv6Drop {
			delete(m.reverse, reverseKeyFromFlow(f.key))
		}
	}
	m.mu.Unlock()
	if f != nil && !f.shared {
		_ = f.handle.Close()
	}
}

func (m *windowsFlowManager) captureFlow(f *windowsDiscordFlow) {
	buf := make([]byte, 65535)
	for {
		var addr wdAddress
		n, err := f.handle.recv(buf, &addr)
		if err != nil {
			return
		}
		if n <= 0 || !addr.outbound() {
			// Direct inbound traffic for a protected Discord flow is dropped.
			// Only the packet returned by the encrypted tunnel is reinjected.
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		if _, err := clampTCPMSS(packet, 1180); err != nil {
			continue
		}
		if err := rewriteIPv4Source(packet, m.vpn.Session.IPv4); err != nil {
			continue
		}
		if err := m.sendPacketToVPN(packet); err != nil {
			m.reportErr(fmt.Errorf("VPN data write: %w", err))
			return
		}
	}
}

func (m *windowsFlowManager) receiveVPN() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}
		_ = m.vpn.Control.udp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := m.vpn.Control.udp.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			m.reportErr(fmt.Errorf("VPN UDP read: %w", err))
			return
		}
		if n < 1 || int(buf[0]>>3) != openVPNDataV2Opcode {
			continue
		}
		dec, err := decryptDataV2(buf[:n], m.vpn.Keys.ServerCipher[:32], m.vpn.Keys.ServerHMAC[:])
		if err != nil || len(dec.Payload) < 20 || dec.Payload[0]>>4 != 4 {
			continue
		}
		rk, err := reverseKeyFromInboundPacket(dec.Payload)
		if err != nil {
			continue
		}
		m.mu.RLock()
		f := m.reverse[rk]
		m.mu.RUnlock()
		if f == nil {
			continue
		}
		packet := append([]byte(nil), dec.Payload...)
		if err := rewriteIPv4Destination(packet, ipv4FromArray(f.key.LocalIP)); err != nil {
			continue
		}
		_, _ = clampTCPMSS(packet, 1180)
		addr := makeInboundWDAddress(f.ifIdx)
		if err := f.handle.send(packet, &addr); err != nil {
			m.reportErr(fmt.Errorf("inject Discord response: %w", err))
			return
		}
	}
}

func (m *windowsFlowManager) keepalive() {
	ping := []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			id := atomic.AddUint32(&m.packetID, 1)
			if id == 0 {
				id = atomic.AddUint32(&m.packetID, 1)
			}
			enc, err := encryptDataV2(m.vpn.Session.PeerID, 0, id, m.vpn.Keys.ClientCipher[:32], m.vpn.Keys.ClientHMAC[:], ping)
			if err == nil {
				_, _ = m.vpn.Control.udp.Write(enc)
			}
		}
	}
}

func (m *windowsFlowManager) reportErr(err error) {
	select {
	case m.errCh <- err:
	default:
	}
}

func (m *windowsFlowManager) close() {
	m.mu.Lock()
	list := make([]*windowsDiscordFlow, 0, len(m.flows))
	for _, f := range m.flows {
		list = append(list, f)
	}
	m.flows = make(map[string]*windowsDiscordFlow)
	m.reverse = make(map[windowsReverseFlowKey]*windowsDiscordFlow)
	udpHandles := make([]*winDivertHandle, 0, len(m.udpHandles))
	for _, h := range m.udpHandles {
		udpHandles = append(udpHandles, h)
	}
	m.udpHandles = make(map[uint16]*winDivertHandle)
	m.udpPortRefs = make(map[uint16]map[uint64]struct{})
	m.udpEndpointPorts = make(map[uint64]uint16)
	m.mu.Unlock()
	for _, f := range list {
		if !f.shared {
			_ = f.handle.Close()
		}
	}
	for _, h := range udpHandles {
		_ = h.Close()
	}
}

func monitorWindowsFlowEvents(ctx context.Context, h *winDivertHandle, m *windowsFlowManager) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var a wdAddress
		_, err := h.recv(nil, &a)
		if err != nil {
			return
		}
		switch a.event() {
		case wdEventFlowEstablished:
			// TCP is armed from the already-intercepted first SYN. Attaching here
			// would be mid-stream and recreates the old first-packet race.
			continue
		case wdEventFlowDeleted:
			m.removeFromEvent(&a)
		}
	}
}

func monitorWindowsSocketEvents(ctx context.Context, h *winDivertHandle, m *windowsFlowManager) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var a wdAddress
		_, err := h.recv(nil, &a)
		if err != nil {
			return
		}
		if a.event() == wdEventSocketConnect && a.flowProtocol() == 6 {
			m.markTCPIntent(&a)
		}
	}
}

func windowsProcessName(pid uint32) string {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := syscall.Process32First(snap, &pe); err != nil {
		return ""
	}
	for {
		if pe.ProcessID == pid {
			return syscall.UTF16ToString(pe.ExeFile[:])
		}
		if err := syscall.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return ""
}

func isDiscordPIDWindows(pid uint32) bool {
	return strings.EqualFold(windowsProcessName(pid), "Discord.exe")
}

func terminateDiscordWindows() {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(snap)
	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := syscall.Process32First(snap, &pe); err != nil {
		return
	}
	for {
		if strings.EqualFold(syscall.UTF16ToString(pe.ExeFile[:]), "Discord.exe") {
			if h, err := syscall.OpenProcess(0x0001, false, pe.ProcessID); err == nil {
				_ = syscall.TerminateProcess(h, 0)
				_ = syscall.CloseHandle(h)
			}
		}
		if err := syscall.Process32Next(snap, &pe); err != nil {
			break
		}
	}
}

func stopExistingDiscordWindows() {
	terminateDiscordWindows()
	time.Sleep(600 * time.Millisecond)
}

func discordPathWindows() (string, error) {
	var candidates []string
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		matches, _ := filepath.Glob(filepath.Join(local, "Discord", "app-*", "Discord.exe"))
		candidates = append(candidates, matches...)
		candidates = append(candidates, filepath.Join(local, "Discord", "Discord.exe"))
	}
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if root != "" {
			candidates = append(candidates, filepath.Join(root, "Discord", "Discord.exe"))
		}
	}
	sort.Strings(candidates)
	for i := len(candidates) - 1; i >= 0; i-- {
		if st, err := os.Stat(candidates[i]); err == nil && !st.IsDir() {
			return candidates[i], nil
		}
	}
	if p, err := exec.LookPath("Discord.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("Discord.exe not found")
}

var procShellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")

func isWindowsElevated() bool {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	var elevated uint32
	var ret uint32
	if err := syscall.GetTokenInformation(tok, syscall.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &ret); err != nil {
		return false
	}
	return elevated != 0
}

func elevateWindowsSelf() (bool, error) {
	if isWindowsElevated() {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	parts := make([]string, 0, len(os.Args)-1)
	for _, a := range os.Args[1:] {
		parts = append(parts, syscall.EscapeArg(a))
	}
	params, _ := syscall.UTF16PtrFromString(strings.Join(parts, " "))
	cwd, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))
	rv, _, callErr := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(cwd)), 1)
	if rv <= 32 {
		if callErr != syscall.Errno(0) {
			return false, callErr
		}
		return false, fmt.Errorf("UAC elevation failed: code %d", rv)
	}
	return true, nil
}

var procGetBestInterfaceEx = syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetBestInterfaceEx")

type windowsSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

func bestWindowsInterfaceIndex(remote net.IP) (uint32, error) {
	ip := remote.To4()
	if ip == nil {
		return 0, errors.New("best interface currently requires IPv4")
	}
	sa := windowsSockaddrInet4{Family: syscall.AF_INET}
	copy(sa.Addr[:], ip)
	var idx uint32
	rv, _, _ := procGetBestInterfaceEx.Call(uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&idx)))
	if rv != 0 {
		return 0, syscall.Errno(rv)
	}
	if idx == 0 {
		return 0, errors.New("GetBestInterfaceEx returned interface 0")
	}
	return idx, nil
}

func streamDiscordOutput(r io.Reader, dst io.Writer, activate func(), ready chan<- struct{}) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintln(dst, line)
		if strings.Contains(line, "splashScreen.launchMainWindow:") || strings.Contains(line, "splashScreen.updateSplashState launching launching") {
			if activate != nil {
				activate()
			}
		}
		if strings.Contains(line, "Setting connection state to SESSION_ESTABLISHED") {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}
}

func cmdDiscordVPN(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("discord", flag.ContinueOnError)
	identityPath := fs.String("identity", defaultIdentityPath(), "client certificate/key path")
	setupTimeout := fs.Duration("setup-timeout", 35*time.Second, "VPN setup timeout")
	keepExisting := fs.Bool("keep-existing", false, "do not stop an already-running Discord")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !isWindowsElevated() {
		relaunched, err := elevateWindowsSelf()
		if err != nil {
			return fmt.Errorf("Administrator elevation: %w", err)
		}
		if relaunched {
			return nil
		}
	}

	path, err := discordPathWindows()
	if err != nil {
		return err
	}
	if !*keepExisting {
		stopExistingDiscordWindows()
	}

	setupCtx, cancelSetup := context.WithTimeout(ctx, *setupTimeout)
	vpn, err := establishLiveVPN(setupCtx, *identityPath)
	cancelSetup()
	if err != nil {
		return err
	}

	wd, err := loadWinDivertRuntime()
	if err != nil {
		vpn.Close()
		return err
	}
	flowH, err := wd.open("true", wdLayerFlow, 300, wdFlagSniff|wdFlagRecvOnly)
	if err != nil {
		_ = wd.Close()
		vpn.Close()
		return fmt.Errorf("WinDivert FLOW open (run DisFree as Administrator): %w", err)
	}
	socketH, err := wd.open("event == CONNECT or event == CLOSE", wdLayerSocket, 300, wdFlagSniff|wdFlagRecvOnly)
	if err != nil {
		_ = flowH.Close()
		_ = wd.Close()
		vpn.Close()
		return fmt.Errorf("WinDivert SOCKET open: %w", err)
	}
	synH, err := wd.open("!impostor and !loopback and outbound and ip and tcp and tcp.Syn and !tcp.Ack", wdLayerNetwork, 260, 0)
	if err != nil {
		_ = socketH.Close()
		_ = flowH.Close()
		_ = wd.Close()
		vpn.Close()
		return fmt.Errorf("WinDivert first-SYN gate open: %w", err)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	mgr := newWindowsFlowManager(runCtx, vpn, wd)
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			cancelRun()
			mgr.close()
			_ = flowH.Close()
			_ = socketH.Close()
			_ = synH.Close()
			_ = wd.Close()
			vpn.Close()
		})
	}
	defer cleanup()

	go monitorWindowsFlowEvents(runCtx, flowH, mgr)
	go monitorWindowsSocketEvents(runCtx, socketH, mgr)
	go mgr.captureInitialTCPSYN(synH)
	go mgr.receiveVPN()
	go mgr.keepalive()

	discordArgs := append([]string{}, fs.Args()...)
	discordArgs = append(discordArgs, "--disable-quic")
	cmd := exec.Command(path, discordArgs...)
	cmd.Env = append(os.Environ(), "DISFREE_VPN=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Discord stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("Discord stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start Discord: %w", err)
	}
	removeCloseHandler, err := installWindowsDiscordCloseHandler()
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("install Discord close handler: %w", err)
	}
	defer removeCloseHandler()

	ready := make(chan struct{}, 1)
	activate := func() {
		if mgr.bootstrapActive.CompareAndSwap(false, true) {
			fmt.Println("DisFree: updater finished; first-SYN gated TCP VPN enabled for Discord startup.")
		}
	}
	go streamDiscordOutput(stdout, os.Stdout, activate, ready)
	go streamDiscordOutput(stderr, os.Stderr, activate, ready)

	fmt.Printf("DisFree Windows stable bootstrap: %s (%s), RTT %s, %s, VPN IPv4 %s\n",
		vpn.Endpoint.Host, vpn.Endpoint.Location, vpn.ResetLatency.Round(time.Millisecond), vpn.Session.Cipher, vpn.Session.IPv4)
	fmt.Println("Updater/UDP stay normal; Discord TCP is tunneled from its first SYN until Gateway SESSION_ESTABLISHED.")

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		cleanup()
		return err
	case <-ready:
		cleanup()
		fmt.Println("DisFree: Discord Gateway SESSION_ESTABLISHED. VPN disconnected; normal internet restored.")
		return <-done
	case err := <-mgr.errCh:
		cleanup()
		_ = cmd.Process.Kill()
		return err
	case <-ctx.Done():
		cleanup()
		_ = cmd.Process.Kill()
		return ctx.Err()
	}
}
