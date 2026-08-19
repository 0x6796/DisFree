//go:build windows

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	wdLayerNetwork = 0
	wdLayerFlow    = 2
	wdLayerSocket  = 3

	wdEventPacket          = 0
	wdEventFlowEstablished = 1
	wdEventFlowDeleted     = 2
	wdEventSocketBind      = 3
	wdEventSocketConnect   = 4
	wdEventSocketClose     = 7

	wdFlagSniff     = 0x0001
	wdFlagDrop      = 0x0002
	wdFlagRecvOnly  = 0x0004
	wdFlagFragments = 0x0020
)

//go:embed windows/third_party/windivert/WinDivert.dll
var embeddedWinDivertDLL []byte

//go:embed windows/third_party/windivert/WinDivert64.sys
var embeddedWinDivertSYS []byte

//go:embed windows/third_party/windivert/LICENSE.txt
var embeddedWinDivertLicense []byte

type wdAddress struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Data      [64]byte
}

func (a *wdAddress) layer() uint8           { return uint8(a.Flags & 0xff) }
func (a *wdAddress) event() uint8           { return uint8((a.Flags >> 8) & 0xff) }
func (a *wdAddress) outbound() bool         { return a.Flags&(1<<17) != 0 }
func (a *wdAddress) loopback() bool         { return a.Flags&(1<<18) != 0 }
func (a *wdAddress) impostor() bool         { return a.Flags&(1<<19) != 0 }
func (a *wdAddress) ipv6() bool             { return a.Flags&(1<<20) != 0 }
func (a *wdAddress) flowEndpointID() uint64 { return binary.LittleEndian.Uint64(a.Data[0:8]) }
func (a *wdAddress) flowPID() uint32        { return binary.LittleEndian.Uint32(a.Data[16:20]) }
func (a *wdAddress) flowLocalPort() uint16 {
	return binary.LittleEndian.Uint16(a.Data[52:54])
}
func (a *wdAddress) flowRemotePort() uint16 {
	return binary.LittleEndian.Uint16(a.Data[54:56])
}
func (a *wdAddress) flowProtocol() uint8  { return a.Data[56] }
func (a *wdAddress) networkIfIdx() uint32 { return binary.LittleEndian.Uint32(a.Data[0:4]) }

func makeInboundWDAddress(ifIdx uint32) wdAddress {
	var a wdAddress
	a.Flags = uint32(wdLayerNetwork) | uint32(wdEventPacket)<<8
	binary.LittleEndian.PutUint32(a.Data[0:4], ifIdx)
	return a
}

type winDivertRuntime struct {
	dir               string
	dll               *syscall.DLL
	openProc          *syscall.Proc
	recvProc          *syscall.Proc
	sendProc          *syscall.Proc
	closeProc         *syscall.Proc
	shutdownProc      *syscall.Proc
	fmtIPv6Proc       *syscall.Proc
	compileFilterProc *syscall.Proc
}

type winDivertHandle struct {
	rt *winDivertRuntime
	h  syscall.Handle
}

func writeEmbeddedVerified(path string, data []byte, expected string) error {
	sum := fmt.Sprintf("%x", sha256.Sum256(data))
	if sum != expected {
		return fmt.Errorf("embedded WinDivert asset checksum mismatch for %s", filepath.Base(path))
	}
	if old, err := os.ReadFile(path); err == nil {
		if fmt.Sprintf("%x", sha256.Sum256(old)) == expected {
			return nil
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func loadWinDivertRuntime() (*winDivertRuntime, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		var err error
		base, err = os.UserCacheDir()
		if err != nil {
			return nil, err
		}
	}
	dir := filepath.Join(base, "DisFree", "runtime", "windivert-2.2.2")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	dllPath := filepath.Join(dir, "WinDivert.dll")
	sysPath := filepath.Join(dir, "WinDivert64.sys")
	licPath := filepath.Join(dir, "WinDivert-LICENSE.txt")
	if err := writeEmbeddedVerified(dllPath, embeddedWinDivertDLL, "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"); err != nil {
		return nil, err
	}
	if err := writeEmbeddedVerified(sysPath, embeddedWinDivertSYS, "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"); err != nil {
		return nil, err
	}
	_ = os.WriteFile(licPath, embeddedWinDivertLicense, 0600)

	dll, err := syscall.LoadDLL(dllPath)
	if err != nil {
		return nil, fmt.Errorf("load WinDivert.dll: %w", err)
	}
	find := func(name string) (*syscall.Proc, error) {
		p, e := dll.FindProc(name)
		if e != nil {
			return nil, fmt.Errorf("WinDivert export %s: %w", name, e)
		}
		return p, nil
	}
	rt := &winDivertRuntime{dir: dir, dll: dll}
	if rt.openProc, err = find("WinDivertOpen"); err != nil {
		dll.Release()
		return nil, err
	}
	if rt.recvProc, err = find("WinDivertRecv"); err != nil {
		dll.Release()
		return nil, err
	}
	if rt.sendProc, err = find("WinDivertSend"); err != nil {
		dll.Release()
		return nil, err
	}
	if rt.closeProc, err = find("WinDivertClose"); err != nil {
		dll.Release()
		return nil, err
	}
	if rt.shutdownProc, err = find("WinDivertShutdown"); err != nil {
		dll.Release()
		return nil, err
	}
	if rt.fmtIPv6Proc, err = find("WinDivertHelperFormatIPv6Address"); err != nil {
		dll.Release()
		return nil, err
	}
	if rt.compileFilterProc, err = find("WinDivertHelperCompileFilter"); err != nil {
		dll.Release()
		return nil, err
	}
	return rt, nil
}

func (r *winDivertRuntime) Close() error {
	if r == nil || r.dll == nil {
		return nil
	}
	return r.dll.Release()
}

func (r *winDivertRuntime) open(filter string, layer uint32, priority int16, flags uint64) (*winDivertHandle, error) {
	fp, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	rv, _, callErr := r.openProc.Call(
		uintptr(unsafe.Pointer(fp)),
		uintptr(layer),
		uintptr(uint16(priority)),
		uintptr(flags),
	)
	h := syscall.Handle(rv)
	if h == syscall.InvalidHandle {
		if callErr != syscall.Errno(0) {
			return nil, callErr
		}
		return nil, errors.New("WinDivertOpen failed")
	}
	return &winDivertHandle{rt: r, h: h}, nil
}

func (h *winDivertHandle) recv(packet []byte, addr *wdAddress) (int, error) {
	var ptr uintptr
	if len(packet) > 0 {
		ptr = uintptr(unsafe.Pointer(&packet[0]))
	}
	var n uint32
	rv, _, callErr := h.rt.recvProc.Call(
		uintptr(h.h), ptr, uintptr(len(packet)),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)),
	)
	if rv == 0 {
		if callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, errors.New("WinDivertRecv failed")
	}
	return int(n), nil
}

func (h *winDivertHandle) send(packet []byte, addr *wdAddress) error {
	if len(packet) == 0 {
		return errors.New("empty WinDivert packet")
	}
	var sent uint32
	rv, _, callErr := h.rt.sendProc.Call(
		uintptr(h.h), uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(addr)),
	)
	if rv == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("WinDivertSend failed")
	}
	if sent != uint32(len(packet)) {
		return fmt.Errorf("WinDivert short send %d/%d", sent, len(packet))
	}
	return nil
}

func (h *winDivertHandle) Close() error {
	if h == nil || h.h == syscall.InvalidHandle || h.h == 0 {
		return nil
	}
	_, _, _ = h.rt.shutdownProc.Call(uintptr(h.h), 3)
	rv, _, callErr := h.rt.closeProc.Call(uintptr(h.h))
	h.h = syscall.InvalidHandle
	if rv == 0 && callErr != syscall.Errno(0) {
		return callErr
	}
	return nil
}

func (r *winDivertRuntime) formatFlowIP(raw *[16]byte) (net.IP, error) {
	var out [64]byte
	rv, _, callErr := r.fmtIPv6Proc.Call(
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
	)
	if rv == 0 {
		if callErr != syscall.Errno(0) {
			return nil, callErr
		}
		return nil, errors.New("WinDivert IPv6 address formatter failed")
	}
	n := 0
	for n < len(out) && out[n] != 0 {
		n++
	}
	ip := net.ParseIP(string(out[:n]))
	if ip == nil {
		return nil, fmt.Errorf("invalid WinDivert address %q", string(out[:n]))
	}
	return ip, nil
}

func (r *winDivertRuntime) flowIPs(a *wdAddress) (local, remote net.IP, err error) {
	var l, rr [16]byte
	copy(l[:], a.Data[20:36])
	copy(rr[:], a.Data[36:52])
	local, err = r.formatFlowIP(&l)
	if err != nil {
		return nil, nil, err
	}
	remote, err = r.formatFlowIP(&rr)
	return
}

func cStringFromPointer(ptr uintptr, max int) string {
	if ptr == 0 || max <= 0 {
		return ""
	}
	b := make([]byte, 0, max)
	for i := 0; i < max; i++ {
		v := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if v == 0 {
			break
		}
		b = append(b, v)
	}
	return string(b)
}

func (r *winDivertRuntime) validateFilter(filter string, layer uint32) error {
	fp, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return err
	}
	obj := make([]byte, 4096)
	var errStr uintptr
	var errPos uint32
	rv, _, callErr := r.compileFilterProc.Call(
		uintptr(unsafe.Pointer(fp)), uintptr(layer),
		uintptr(unsafe.Pointer(&obj[0])), uintptr(len(obj)),
		uintptr(unsafe.Pointer(&errStr)), uintptr(unsafe.Pointer(&errPos)),
	)
	if rv == 0 {
		msg := cStringFromPointer(errStr, 256)
		if msg == "" && callErr != syscall.Errno(0) {
			msg = callErr.Error()
		}
		return fmt.Errorf("invalid WinDivert filter at %d: %s", errPos, msg)
	}
	return nil
}
