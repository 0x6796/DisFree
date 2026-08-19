//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

func platformDefaultCommand() string { return "discord" }

var procSetConsoleTitleW = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleTitleW")
var procSetConsoleCtrlHandler = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")

func platformSetWindowBranding() {
	title, err := syscall.UTF16PtrFromString("Discord Freedom Saiydero")
	if err != nil {
		return
	}
	_, _, _ = procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(title)))
}

// installWindowsDiscordCloseHandler makes the DisFree console own the Discord
// session. Windows calls this handler before the console process is closed.
func installWindowsDiscordCloseHandler() (func(), error) {
	callback := syscall.NewCallback(func(ctrlType uint32) uintptr {
		switch ctrlType {
		case 0, 1, 2, 5, 6: // CTRL_C, CTRL_BREAK, CTRL_CLOSE, LOGOFF, SHUTDOWN
			terminateDiscordWindows()
		}
		// Return FALSE so normal Windows console termination continues after
		// Discord has been stopped.
		return 0
	})
	rv, _, callErr := procSetConsoleCtrlHandler.Call(callback, 1)
	if rv == 0 {
		if callErr != syscall.Errno(0) {
			return nil, callErr
		}
		return nil, errors.New("SetConsoleCtrlHandler failed")
	}
	return func() {
		_, _, _ = procSetConsoleCtrlHandler.Call(callback, 0)
	}, nil
}

var errWindowsGenericTunPending = errors.New("generic Windows TUN/run mode is not enabled yet; use 'disfree discord'")

func cmdTunProbe() error                                      { return errWindowsGenericTunPending }
func cmdVPNTunProbe(ctx context.Context, args []string) error { return errWindowsGenericTunPending }
func cmdRunVPN(ctx context.Context, args []string) error      { return errWindowsGenericTunPending }
func tunProbeChild() error                                    { return errWindowsGenericTunPending }
func vpnTunChild(args []string) error                         { return errWindowsGenericTunPending }
func vpnAppChild(args []string) error                         { return errWindowsGenericTunPending }
func vpnProxyChild(args []string) error                       { return errWindowsGenericTunPending }

func cmdWindowsSelfTest() error {
	rt, err := loadWinDivertRuntime()
	if err != nil {
		return err
	}
	defer rt.Close()
	tests := []struct {
		layer  uint32
		filter string
	}{
		{wdLayerFlow, "true"},
		{wdLayerSocket, "event == BIND or event == CONNECT or event == CLOSE"},
		{wdLayerNetwork, "!impostor and !loopback and ip and tcp and localAddr == 192.168.1.10 and localPort == 50000 and remoteAddr == 162.159.128.233 and remotePort == 443"},
		{wdLayerNetwork, "!impostor and !loopback and tcp and localPort == 50000"},
		{wdLayerNetwork, "!impostor and !loopback and udp and localPort == 50001"},
		{wdLayerNetwork, "!impostor and !loopback and ip and udp and localAddr == 192.168.1.10 and localPort == 50001 and remoteAddr == 162.159.128.233 and remotePort == 443"},
		{wdLayerNetwork, "!impostor and !loopback and udp and localPort == 50001"},
		{wdLayerNetwork, "!impostor and !loopback and ipv6 and udp and localAddr == 2001:db8::1 and localPort == 50002 and remoteAddr == 2001:db8::2 and remotePort == 443"},
		{wdLayerNetwork, "!impostor and !loopback and outbound and ip and tcp and tcp.Syn and !tcp.Ack"},
		{wdLayerNetwork, "!impostor and !loopback and outbound and (ip or ipv6) and (tcp or udp)"},
	}
	for _, t := range tests {
		if err := rt.validateFilter(t.filter, t.layer); err != nil {
			return err
		}
	}
	fmt.Println("WinDivert embedded runtime OK")
	fmt.Println("FLOW/SOCKET/TCP/UDP/IPv6 filters compiled successfully")
	return nil
}
