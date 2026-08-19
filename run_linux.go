package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func setLoopbackUp() error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	return setLinkUp(lo.Index)
}

func startDNSProxy(ctx context.Context, upstream net.IP) error {
	if err := setLoopbackUp(); err != nil {
		return fmt.Errorf("loopback up: %w", err)
	}
	up := &net.UDPAddr{IP: upstream.To4(), Port: 53}
	if up.IP == nil {
		return errors.New("VPN DNS is not IPv4")
	}
	udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 53), Port: 53})
	if err != nil {
		return fmt.Errorf("local DNS UDP: %w", err)
	}
	tcpLn, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 53), Port: 53})
	if err != nil {
		udpLn.Close()
		return fmt.Errorf("local DNS TCP: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = udpLn.Close()
		_ = tcpLn.Close()
	}()

	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, client, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg := append([]byte(nil), buf[:n]...)
			go func(client *net.UDPAddr, msg []byte) {
				remote, err := net.DialUDP("udp4", nil, up)
				if err != nil {
					return
				}
				defer remote.Close()
				_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := remote.Write(msg); err != nil {
					return
				}
				reply := make([]byte, 64<<10)
				rn, err := remote.Read(reply)
				if err != nil {
					return
				}
				_, _ = udpLn.WriteToUDP(reply[:rn], client)
			}(client, msg)
		}
	}()

	go func() {
		for {
			client, err := tcpLn.AcceptTCP()
			if err != nil {
				return
			}
			go func(client *net.TCPConn) {
				defer client.Close()
				remote, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: up.IP, Port: 53})
				if err != nil {
					return
				}
				defer remote.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(remote, client); done <- struct{}{} }()
				go func() { _, _ = io.Copy(client, remote); done <- struct{}{} }()
				<-done
			}(client)
		}
	}()
	return nil
}

func waitVPNReady(sock int) error {
	var b [1]byte
	for {
		n, err := syscall.Read(sock, b[:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 1 && b[0] == 'R' {
			return nil
		}
		return errors.New("invalid VPN ready marker")
	}
}

func signalVPNReady(sock int) error {
	_, err := syscall.Write(sock, []byte{'R'})
	return err
}

func vpnAppChild(args []string) error {
	if len(args) < 5 {
		return errors.New("internal vpn app child arguments missing")
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
	if args[3] != "--" || len(args[4:]) == 0 {
		return errors.New("internal vpn app child command missing")
	}
	appArgs := args[4:]

	tun, name, err := createTUN("disfree0")
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
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

	pass := os.NewFile(uintptr(3), "disfree-fdpass")
	if pass == nil {
		return errors.New("missing fd-pass socket")
	}
	defer pass.Close()
	if err := sendFD(int(pass.Fd()), int(tun.Fd())); err != nil {
		return fmt.Errorf("send TUN fd: %w", err)
	}
	if err := waitVPNReady(int(pass.Fd())); err != nil {
		return fmt.Errorf("wait VPN ready: %w", err)
	}

	cmd := exec.Command(appArgs[0], appArgs[1:]...)
	cmd.Env = append(os.Environ(), "DISFREE_VPN=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 1000, HostID: 0, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 1000, HostID: 0, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Credential:                 &syscall.Credential{Uid: 1000, Gid: 1000},
		Pdeathsig:                  syscall.SIGTERM,
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("application: %w", err)
	}
	return nil
}

func launchVPNAppChild(ip net.IP, prefix int, dns net.IP, appArgs []string) (*exec.Cmd, int, error) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, -1, err
	}
	exe, err := os.Executable()
	if err != nil {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
		return nil, -1, err
	}
	childPass := os.NewFile(uintptr(pair[1]), "disfree-child-fdpass")
	argv := []string{"__vpnapp_child", ip.String(), strconv.Itoa(prefix), dns.String(), "--"}
	argv = append(argv, appArgs...)
	cmd := exec.Command(exe, argv...)
	cmd.ExtraFiles = []*os.File{childPass}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGTERM,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		childPass.Close()
		syscall.Close(pair[0])
		return nil, -1, err
	}
	childPass.Close()
	return cmd, pair[0], nil
}

func runVPNApplication(ctx context.Context, appArgs []string, identityPath string, setupTimeout time.Duration) error {
	if len(appArgs) == 0 {
		return errors.New("no application command supplied")
	}
	setupCtx, cancelSetup := context.WithTimeout(ctx, setupTimeout)
	vpn, err := establishLiveVPN(setupCtx, identityPath)
	cancelSetup()
	if err != nil {
		return err
	}
	defer vpn.Close()

	ones, bits := net.IPMask(vpn.Session.Netmask).Size()
	if bits != 32 || ones < 0 {
		return fmt.Errorf("invalid pushed IPv4 netmask %s", vpn.Session.Netmask)
	}
	child, passSock, err := launchVPNAppChild(vpn.Session.IPv4, ones, vpn.Session.DNS, appArgs)
	if err != nil {
		return fmt.Errorf("launch isolated application: %w", err)
	}
	defer syscall.Close(passSock)
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()

	emptyOut := &bytes.Buffer{}
	fdCtx, cancelFD := context.WithTimeout(ctx, 8*time.Second)
	tunFD, err := recvFDWithChild(passSock, childDone, emptyOut, fdCtx)
	cancelFD()
	if err != nil {
		_ = child.Process.Kill()
		return fmt.Errorf("receive TUN fd: %w", err)
	}
	tun := os.NewFile(uintptr(tunFD), "disfree0-from-netns")
	if tun == nil {
		_ = child.Process.Kill()
		return errors.New("failed to wrap TUN fd")
	}
	defer tun.Close()

	bridgeCtx, cancelBridge := context.WithCancel(ctx)
	bridgeErr := func() <-chan error {
		_, _, ch := bridgeTunAndVPN(bridgeCtx, tun, vpn.Control.udp, vpn.Session, vpn.Keys)
		return ch
	}()
	if err := signalVPNReady(passSock); err != nil {
		cancelBridge()
		_ = child.Process.Kill()
		return fmt.Errorf("signal application ready: %w", err)
	}

	fmt.Printf("DisFree connected: %s (%s), %s, %s/%d\n", vpn.Endpoint.Host, vpn.Endpoint.Location, vpn.Session.Cipher, vpn.Session.IPv4, ones)

	select {
	case childErr := <-childDone:
		cancelBridge()
		if childErr != nil {
			return childErr
		}
		return nil
	case err := <-bridgeErr:
		cancelBridge()
		_ = child.Process.Kill()
		if err != nil {
			return err
		}
		return errors.New("VPN bridge stopped unexpectedly")
	case <-ctx.Done():
		cancelBridge()
		_ = child.Process.Kill()
		return ctx.Err()
	}
}

func cmdRunVPN(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	identityPath := fs.String("identity", defaultIdentityPath(), "client certificate/key path")
	setupTimeout := fs.Duration("setup-timeout", 25*time.Second, "VPN setup timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	appArgs := fs.Args()
	if len(appArgs) == 0 {
		return errors.New("usage: disfree run [flags] -- <application> [args...]")
	}
	return runVPNApplication(ctx, appArgs, *identityPath, *setupTimeout)
}

func discordPath() (string, error) {
	cfg, err := os.UserConfigDir()
	if err == nil {
		p := filepath.Join(cfg, "discord", "Discord")
		if st, statErr := os.Stat(p); statErr == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return p, nil
		}
	}
	if p, err := exec.LookPath("discord"); err == nil {
		return p, nil
	}
	return "", errors.New("Discord executable not found")
}

func discordPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		proc := filepath.Join("/proc", e.Name())
		st, err := os.Stat(proc)
		if err != nil {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != uint32(os.Getuid()) {
			continue
		}
		exe, err := os.Readlink(filepath.Join(proc, "exe"))
		if err != nil {
			continue
		}
		base := filepath.Base(exe)
		if base != "Discord" {
			continue
		}
		cmdline, _ := os.ReadFile(filepath.Join(proc, "cmdline"))
		if bytes.Contains(cmdline, []byte("--type=")) {
			continue
		}
		out = append(out, pid)
	}
	return out
}

func stopExistingDiscord() error {
	pids := discordPIDs()
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if len(discordPIDs()) == 0 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, pid := range discordPIDs() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	return nil
}

func cmdDiscordVPN(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("discord", flag.ContinueOnError)
	identityPath := fs.String("identity", defaultIdentityPath(), "client certificate/key path")
	setupTimeout := fs.Duration("setup-timeout", 25*time.Second, "VPN setup timeout")
	keepExisting := fs.Bool("keep-existing", false, "do not stop an already-running normal Discord")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := discordPath()
	if err != nil {
		return err
	}
	if !*keepExisting {
		if err := stopExistingDiscord(); err != nil {
			return err
		}
	}
	signalCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()
	defer stopExistingDiscord()
	return runLinuxDiscordBootstrap(signalCtx, path, fs.Args(), *identityPath, *setupTimeout)
}

func isDisFreeChildCommand(s string) bool {
	return strings.HasPrefix(s, "__vpnapp_child") || strings.HasPrefix(s, "__vpnproxy_child")
}
