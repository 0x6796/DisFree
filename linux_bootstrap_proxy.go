//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	linuxProxyDirect int32 = iota
	linuxProxyVPN
)

type linuxDialResult struct {
	conn net.Conn
	err  error
}

type linuxVPNDialer struct {
	sock      int
	writeMu   sync.Mutex
	pendingMu sync.Mutex
	pending   map[uint32]chan linuxDialResult
	nextID    uint32
	closeOnce sync.Once
	closed    chan struct{}
}

func newLinuxVPNDialer(sock int) *linuxVPNDialer {
	d := &linuxVPNDialer{
		sock:    sock,
		pending: make(map[uint32]chan linuxDialResult),
		closed:  make(chan struct{}),
	}
	go d.readLoop()
	return d
}

func (d *linuxVPNDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("VPN proxy only supports TCP, got %s", network)
	}
	id := atomic.AddUint32(&d.nextID, 1)
	if id == 0 {
		id = atomic.AddUint32(&d.nextID, 1)
	}
	ch := make(chan linuxDialResult, 1)
	d.pendingMu.Lock()
	d.pending[id] = ch
	d.pendingMu.Unlock()

	msg := make([]byte, 5+len(address))
	msg[0] = 'D'
	binary.BigEndian.PutUint32(msg[1:5], id)
	copy(msg[5:], address)

	d.writeMu.Lock()
	_, err := syscall.SendmsgN(d.sock, msg, nil, nil, 0)
	d.writeMu.Unlock()
	if err != nil {
		d.pendingMu.Lock()
		delete(d.pending, id)
		d.pendingMu.Unlock()
		return nil, err
	}

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		d.pendingMu.Lock()
		delete(d.pending, id)
		d.pendingMu.Unlock()
		return nil, ctx.Err()
	case <-d.closed:
		return nil, errors.New("VPN proxy dialer closed")
	}
}

func (d *linuxVPNDialer) deliver(id uint32, result linuxDialResult) {
	d.pendingMu.Lock()
	ch := d.pending[id]
	delete(d.pending, id)
	d.pendingMu.Unlock()
	if ch == nil {
		if result.conn != nil {
			_ = result.conn.Close()
		}
		return
	}
	ch <- result
}

func passedFDFromOOB(oob []byte) (int, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
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
	return -1, errors.New("connected socket fd missing")
}

func (d *linuxVPNDialer) readLoop() {
	data := make([]byte, 8192)
	oob := make([]byte, syscall.CmsgSpace(4))
	for {
		n, oobn, _, _, err := syscall.Recvmsg(d.sock, data, oob, 0)
		if err != nil {
			d.Close()
			return
		}
		if n < 5 {
			continue
		}
		status := data[0]
		id := binary.BigEndian.Uint32(data[1:5])
		switch status {
		case 'C':
			fd, err := passedFDFromOOB(oob[:oobn])
			if err != nil {
				d.deliver(id, linuxDialResult{err: err})
				continue
			}
			f := os.NewFile(uintptr(fd), "disfree-vpn-proxy-conn")
			if f == nil {
				_ = syscall.Close(fd)
				d.deliver(id, linuxDialResult{err: errors.New("wrap VPN proxy fd")})
				continue
			}
			conn, err := net.FileConn(f)
			_ = f.Close()
			d.deliver(id, linuxDialResult{conn: conn, err: err})
		case 'E':
			d.deliver(id, linuxDialResult{err: errors.New(string(data[5:n]))})
		}
	}
}

func (d *linuxVPNDialer) Close() {
	d.closeOnce.Do(func() {
		close(d.closed)
		_ = syscall.Shutdown(d.sock, syscall.SHUT_RDWR)
		_ = syscall.Close(d.sock)
		d.pendingMu.Lock()
		pending := d.pending
		d.pending = make(map[uint32]chan linuxDialResult)
		d.pendingMu.Unlock()
		for _, ch := range pending {
			ch <- linuxDialResult{err: errors.New("VPN proxy dialer closed")}
		}
	})
}

func sendLinuxProxyResult(sock int, status byte, id uint32, fd int, message string) error {
	data := make([]byte, 5+len(message))
	data[0] = status
	binary.BigEndian.PutUint32(data[1:5], id)
	copy(data[5:], message)
	var rights []byte
	if fd >= 0 {
		rights = syscall.UnixRights(fd)
	}
	_, err := syscall.SendmsgN(sock, data, rights, nil, 0)
	return err
}

func vpnProxyChild(args []string) error {
	if len(args) != 3 {
		return errors.New("internal VPN proxy child requires ip prefix dns")
	}
	ip := net.ParseIP(args[0]).To4()
	if ip == nil {
		return errors.New("invalid proxy child IPv4")
	}
	prefix64, err := strconv.ParseUint(args[1], 10, 8)
	if err != nil || prefix64 > 32 {
		return errors.New("invalid proxy child prefix")
	}
	dns := net.ParseIP(args[2]).To4()
	if dns == nil {
		return errors.New("invalid proxy child DNS")
	}

	tun, name, err := createTUN("disfree0")
	if err != nil {
		return fmt.Errorf("create proxy TUN: %w", err)
	}
	defer tun.Close()
	if err := configureTUNIPv4(name, ip, uint8(prefix64)); err != nil {
		return err
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startDNSProxy(childCtx, dns); err != nil {
		return err
	}

	control := os.NewFile(uintptr(3), "disfree-proxy-control")
	if control == nil {
		return errors.New("missing VPN proxy control socket")
	}
	defer control.Close()
	sock := int(control.Fd())
	if err := sendFD(sock, int(tun.Fd())); err != nil {
		return fmt.Errorf("send proxy TUN fd: %w", err)
	}
	if err := waitVPNReady(sock); err != nil {
		return fmt.Errorf("wait proxy VPN ready: %w", err)
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			proto := "udp4"
			if strings.HasPrefix(network, "tcp") {
				proto = "tcp4"
			}
			var nd net.Dialer
			return nd.DialContext(ctx, proto, "127.0.0.53:53")
		},
	}

	buf := make([]byte, 8192)
	for {
		n, err := syscall.Read(sock, buf)
		if err != nil {
			return err
		}
		if n < 6 || buf[0] != 'D' {
			continue
		}
		id := binary.BigEndian.Uint32(buf[1:5])
		target := string(buf[5:n])
		go func(id uint32, target string) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			nd := net.Dialer{Timeout: 12 * time.Second, Resolver: resolver}
			conn, err := nd.DialContext(ctx, "tcp4", target)
			if err != nil {
				_ = sendLinuxProxyResult(sock, 'E', id, -1, err.Error())
				return
			}
			tcp, ok := conn.(*net.TCPConn)
			if !ok {
				_ = conn.Close()
				_ = sendLinuxProxyResult(sock, 'E', id, -1, "VPN dial did not return TCP")
				return
			}
			file, err := tcp.File()
			if err != nil {
				_ = conn.Close()
				_ = sendLinuxProxyResult(sock, 'E', id, -1, err.Error())
				return
			}
			_ = sendLinuxProxyResult(sock, 'C', id, int(file.Fd()), "")
			_ = file.Close()
			_ = conn.Close()
		}(id, target)
	}
}

type linuxVPNProxyBackend struct {
	vpn          *liveVPN
	child        *exec.Cmd
	childDone    chan error
	tun          *os.File
	bridgeCancel context.CancelFunc
	dialer       *linuxVPNDialer
	errCh        chan error
	closeOnce    sync.Once
	closed       chan struct{}
}

func launchVPNProxyChild(ip net.IP, prefix int, dns net.IP) (*exec.Cmd, int, *bytes.Buffer, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, -1, nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		_ = syscall.Close(pair[0])
		_ = syscall.Close(pair[1])
		return nil, -1, nil, err
	}
	childControl := os.NewFile(uintptr(pair[1]), "disfree-proxy-child-control")
	cmd := exec.Command(exe, "__vpnproxy_child", ip.String(), strconv.Itoa(prefix), dns.String())
	cmd.ExtraFiles = []*os.File{childControl}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGTERM,
	}
	out := &bytes.Buffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		_ = childControl.Close()
		_ = syscall.Close(pair[0])
		return nil, -1, nil, err
	}
	_ = childControl.Close()
	return cmd, pair[0], out, nil
}

func startLinuxVPNProxyBackend(ctx context.Context, identityPath string, setupTimeout time.Duration) (*linuxVPNProxyBackend, error) {
	setupCtx, cancelSetup := context.WithTimeout(ctx, setupTimeout)
	vpn, err := establishLiveVPN(setupCtx, identityPath)
	cancelSetup()
	if err != nil {
		return nil, err
	}

	ones, bits := net.IPMask(vpn.Session.Netmask).Size()
	if bits != 32 || ones < 0 {
		vpn.Close()
		return nil, fmt.Errorf("invalid pushed IPv4 netmask %s", vpn.Session.Netmask)
	}
	child, controlSock, childOut, err := launchVPNProxyChild(vpn.Session.IPv4, ones, vpn.Session.DNS)
	if err != nil {
		vpn.Close()
		return nil, fmt.Errorf("launch VPN proxy namespace: %w", err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()

	fdCtx, cancelFD := context.WithTimeout(ctx, 8*time.Second)
	tunFD, err := recvFDWithChild(controlSock, childDone, childOut, fdCtx)
	cancelFD()
	if err != nil {
		_ = child.Process.Kill()
		_ = syscall.Close(controlSock)
		vpn.Close()
		return nil, fmt.Errorf("receive VPN proxy TUN fd: %w", err)
	}
	tun := os.NewFile(uintptr(tunFD), "disfree-proxy-tun")
	if tun == nil {
		_ = child.Process.Kill()
		_ = syscall.Close(controlSock)
		vpn.Close()
		return nil, errors.New("wrap VPN proxy TUN fd")
	}

	bridgeCtx, cancelBridge := context.WithCancel(ctx)
	_, _, bridgeErr := bridgeTunAndVPN(bridgeCtx, tun, vpn.Control.udp, vpn.Session, vpn.Keys)
	if err := signalVPNReady(controlSock); err != nil {
		cancelBridge()
		_ = tun.Close()
		_ = child.Process.Kill()
		_ = syscall.Close(controlSock)
		vpn.Close()
		return nil, fmt.Errorf("signal VPN proxy ready: %w", err)
	}
	if err := syscall.SetNonblock(controlSock, false); err != nil {
		cancelBridge()
		_ = tun.Close()
		_ = child.Process.Kill()
		_ = syscall.Close(controlSock)
		vpn.Close()
		return nil, fmt.Errorf("proxy control blocking mode: %w", err)
	}

	b := &linuxVPNProxyBackend{
		vpn:          vpn,
		child:        child,
		childDone:    childDone,
		tun:          tun,
		bridgeCancel: cancelBridge,
		dialer:       newLinuxVPNDialer(controlSock),
		errCh:        make(chan error, 2),
		closed:       make(chan struct{}),
	}
	go func() {
		select {
		case err := <-bridgeErr:
			if err == nil {
				err = errors.New("VPN proxy bridge stopped")
			}
			select {
			case b.errCh <- err:
			default:
			}
		case err := <-childDone:
			if err == nil {
				err = errors.New("VPN proxy namespace exited")
			}
			select {
			case b.errCh <- fmt.Errorf("VPN proxy namespace: %w", err):
			default:
			}
		case <-b.closed:
		}
	}()
	return b, nil
}

func (b *linuxVPNProxyBackend) Close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		close(b.closed)
		if b.dialer != nil {
			b.dialer.Close()
		}
		if b.bridgeCancel != nil {
			b.bridgeCancel()
		}
		if b.tun != nil {
			_ = b.tun.Close()
		}
		if b.child != nil && b.child.Process != nil {
			_ = b.child.Process.Kill()
		}
		if b.vpn != nil {
			b.vpn.Close()
		}
	})
}

type linuxHTTPProxy struct {
	ln        net.Listener
	vpn       *linuxVPNDialer
	mode      atomic.Int32
	mu        sync.Mutex
	active    map[net.Conn]struct{}
	closeOnce sync.Once
}

func newLinuxHTTPProxy(vpn *linuxVPNDialer) (*linuxHTTPProxy, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &linuxHTTPProxy{ln: ln, vpn: vpn, active: make(map[net.Conn]struct{})}
	p.mode.Store(linuxProxyDirect)
	go p.acceptLoop()
	return p, nil
}

func (p *linuxHTTPProxy) URL() string { return "http://" + p.ln.Addr().String() }

func (p *linuxHTTPProxy) setMode(mode int32) {
	old := p.mode.Swap(mode)
	if old == mode {
		return
	}
	p.mu.Lock()
	conns := make([]net.Conn, 0, len(p.active))
	for c := range p.active {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *linuxHTTPProxy) UseVPN()    { p.setMode(linuxProxyVPN) }
func (p *linuxHTTPProxy) UseDirect() { p.setMode(linuxProxyDirect) }

func (p *linuxHTTPProxy) track(c net.Conn, add bool) {
	p.mu.Lock()
	if add {
		p.active[c] = struct{}{}
	} else {
		delete(p.active, c)
	}
	p.mu.Unlock()
}

func (p *linuxHTTPProxy) acceptLoop() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.track(c, true)
		go func() {
			defer p.track(c, false)
			defer c.Close()
			p.handle(c)
		}()
	}
}

func addDefaultPort(hostport, port string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(strings.Trim(hostport, "[]"), port)
}

func (p *linuxHTTPProxy) dial(ctx context.Context, address string) (net.Conn, error) {
	if p.mode.Load() == linuxProxyVPN {
		return p.vpn.DialContext(ctx, "tcp4", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", address)
}

func copyDuplex(a net.Conn, aReader io.Reader, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, aReader)
		if tcp, ok := b.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		if tcp, ok := a.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

func (p *linuxHTTPProxy) handle(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if strings.EqualFold(req.Method, http.MethodConnect) {
		target := addDefaultPort(req.Host, "443")
		upstream, err := p.dial(ctx, target)
		if err != nil {
			_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
			return
		}
		defer upstream.Close()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		copyDuplex(client, br, upstream)
		return
	}

	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	port := "80"
	if strings.EqualFold(req.URL.Scheme, "https") {
		port = "443"
	}
	target = addDefaultPort(target, port)
	upstream, err := p.dial(ctx, target)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer upstream.Close()
	req.RequestURI = ""
	if req.URL != nil {
		req.URL.Scheme = ""
		req.URL.Host = ""
	}
	if err := req.Write(upstream); err != nil {
		return
	}
	copyDuplex(client, br, upstream)
}

func (p *linuxHTTPProxy) Close() {
	p.closeOnce.Do(func() {
		_ = p.ln.Close()
		p.mu.Lock()
		conns := make([]net.Conn, 0, len(p.active))
		for c := range p.active {
			conns = append(conns, c)
		}
		p.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
}

func streamLinuxDiscordOutput(r io.Reader, dst io.Writer, activate func(), ready chan<- struct{}) {
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

func waitForLinuxDiscordExit(ctx context.Context, firstErr error) error {
	grace := time.NewTimer(1200 * time.Millisecond)
	defer grace.Stop()
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	seen := len(discordPIDs()) > 0
	for {
		if len(discordPIDs()) > 0 {
			seen = true
		} else if seen {
			return firstErr
		}
		select {
		case <-ctx.Done():
			_ = stopExistingDiscord()
			return ctx.Err()
		case <-grace.C:
			if !seen {
				return firstErr
			}
		case <-ticker.C:
		}
	}
}

func runLinuxDiscordBootstrap(ctx context.Context, path string, discordArgs []string, identityPath string, setupTimeout time.Duration) error {
	backend, err := startLinuxVPNProxyBackend(ctx, identityPath, setupTimeout)
	if err != nil {
		return err
	}
	defer backend.Close()

	proxy, err := newLinuxHTTPProxy(backend.dialer)
	if err != nil {
		return fmt.Errorf("local bootstrap proxy: %w", err)
	}
	defer proxy.Close()

	args := append([]string{}, discordArgs...)
	args = append(args, "--proxy-server="+proxy.URL(), "--disable-quic")
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "DISFREE_VPN=1")
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
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

	ready := make(chan struct{}, 1)
	var activateOnce sync.Once
	activate := func() {
		activateOnce.Do(func() {
			proxy.UseVPN()
			fmt.Println("DisFree Linux: updater finished; Discord startup TCP switched to Riseup VPN.")
		})
	}
	go streamLinuxDiscordOutput(stdout, os.Stdout, activate, ready)
	go streamLinuxDiscordOutput(stderr, os.Stderr, activate, ready)

	fmt.Printf("DisFree Linux bootstrap ready: %s (%s), RTT %s, %s, VPN IPv4 %s\n",
		backend.vpn.Endpoint.Host, backend.vpn.Endpoint.Location, backend.vpn.ResetLatency.Round(time.Millisecond), backend.vpn.Session.Cipher, backend.vpn.Session.IPv4)
	fmt.Println("Updater is direct; launch traffic switches to VPN; after Gateway SESSION_ESTABLISHED traffic returns direct.")

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	handedOff := false
	for {
		select {
		case err := <-done:
			return waitForLinuxDiscordExit(ctx, err)
		case <-ready:
			if !handedOff {
				handedOff = true
				proxy.UseDirect()
				backend.Close()
				fmt.Println("DisFree: Discord Gateway SESSION_ESTABLISHED. Riseup VPN disconnected; proxy is direct and normal internet restored.")
			}
		case err := <-backend.errCh:
			if !handedOff {
				_ = stopExistingDiscord()
				return err
			}
		case <-ctx.Done():
			_ = stopExistingDiscord()
			return ctx.Err()
		}
	}
}
