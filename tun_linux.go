package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000

	rtmNewLink  = 16
	rtmNewAddr  = 20
	rtmNewRoute = 24

	nlmFRequest = 0x0001
	nlmFAck     = 0x0004
	nlmFReplace = 0x0100
	nlmFExcl    = 0x0200
	nlmFCreate  = 0x0400

	ifaAddress = 1
	ifaLocal   = 2
	iflaMTU    = 4
	rtaOIF     = 4

	rtTableMain     = 254
	rtProtBoot      = 3
	rtScopeUniverse = 0
	rtScopeLink     = 253
	rtnUnicast      = 1
)

func createTUN(name string) (*os.File, string, error) {
	if len(name) == 0 || len(name) >= 16 {
		return nil, "", errors.New("TUN name must be 1..15 bytes")
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}
	var ifr [40]byte // Linux ifreq is 40 bytes on amd64; name occupies first IFNAMSIZ=16.
	copy(ifr[:16], []byte(name))
	binary.NativeEndian.PutUint16(ifr[16:18], uint16(iffTun|iffNoPI))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		f.Close()
		return nil, "", errno
	}
	actual := string(bytes.TrimRight(ifr[:16], "\x00"))
	return f, actual, nil
}

func nlAlign(n int) int { return (n + 3) &^ 3 }

func nlAttr(typ uint16, data []byte) []byte {
	n := 4 + len(data)
	out := make([]byte, nlAlign(n))
	binary.NativeEndian.PutUint16(out[0:2], uint16(n))
	binary.NativeEndian.PutUint16(out[2:4], typ)
	copy(out[4:], data)
	return out
}

func nlMarshal(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.NativeEndian, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func nlDo(msgType uint16, flags uint16, payload []byte, attrs ...[]byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	seq := uint32(time.Now().UnixNano())
	total := syscall.NLMSG_HDRLEN + len(payload)
	for _, a := range attrs {
		total += len(a)
	}
	hdr := syscall.NlMsghdr{Len: uint32(total), Type: msgType, Flags: flags, Seq: seq}
	hb, err := nlMarshal(hdr)
	if err != nil {
		return err
	}
	req := make([]byte, 0, total)
	req = append(req, hb...)
	req = append(req, payload...)
	for _, a := range attrs {
		req = append(req, a...)
	}
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	buf := make([]byte, 8192)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return errors.New("short netlink error")
				}
				code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
				if code == 0 {
					return nil
				}
				return syscall.Errno(-code)
			case syscall.NLMSG_DONE:
				return nil
			}
		}
	}
}

func setLinkUp(index int) error {
	msg := syscall.IfInfomsg{Family: syscall.AF_UNSPEC, Index: int32(index), Flags: syscall.IFF_UP, Change: syscall.IFF_UP}
	b, err := nlMarshal(msg)
	if err != nil {
		return err
	}
	return nlDo(rtmNewLink, nlmFRequest|nlmFAck, b)
}

func setLinkMTU(index int, mtu uint32) error {
	msg := syscall.IfInfomsg{Family: syscall.AF_UNSPEC, Index: int32(index)}
	b, err := nlMarshal(msg)
	if err != nil {
		return err
	}
	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], mtu)
	return nlDo(rtmNewLink, nlmFRequest|nlmFAck, b, nlAttr(iflaMTU, raw[:]))
}

func addIPv4Address(index int, ip net.IP, prefix uint8) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return errors.New("address is not IPv4")
	}
	msg := syscall.IfAddrmsg{Family: syscall.AF_INET, Prefixlen: prefix, Scope: rtScopeUniverse, Index: uint32(index)}
	b, err := nlMarshal(msg)
	if err != nil {
		return err
	}
	return nlDo(rtmNewAddr, nlmFRequest|nlmFAck|nlmFCreate|nlmFReplace, b,
		nlAttr(ifaLocal, ip4), nlAttr(ifaAddress, ip4))
}

func addDefaultRouteToInterface(index int) error {
	msg := syscall.RtMsg{Family: syscall.AF_INET, Dst_len: 0, Src_len: 0, Tos: 0, Table: rtTableMain, Protocol: rtProtBoot, Scope: rtScopeLink, Type: rtnUnicast, Flags: 0}
	b, err := nlMarshal(msg)
	if err != nil {
		return err
	}
	var idx [4]byte
	binary.NativeEndian.PutUint32(idx[:], uint32(index))
	return nlDo(rtmNewRoute, nlmFRequest|nlmFAck|nlmFCreate|nlmFReplace, b, nlAttr(rtaOIF, idx[:]))
}

func configureTUNIPv4(name string, ip net.IP, prefix uint8) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	if err := setLinkUp(iface.Index); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	if err := setLinkMTU(iface.Index, 1280); err != nil {
		return fmt.Errorf("mtu: %w", err)
	}
	if err := addIPv4Address(iface.Index, ip, prefix); err != nil {
		return fmt.Errorf("address: %w", err)
	}
	if err := addDefaultRouteToInterface(iface.Index); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	return nil
}

func tunProbeChild() error {
	tun, name, err := createTUN("disfree0")
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	defer tun.Close()
	if err := configureTUNIPv4(name, net.IPv4(10, 77, 0, 2), 24); err != nil {
		return err
	}
	if err := syscall.SetNonblock(int(tun.Fd()), true); err != nil {
		return err
	}

	dst := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 443}
	c, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return fmt.Errorf("namespace UDP socket: %w", err)
	}
	defer c.Close()
	payload := []byte("disfree-rootless-netns")
	if _, err := c.Write(payload); err != nil {
		return fmt.Errorf("namespace UDP write: %w", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		n, err := tun.Read(buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return err
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if ihl < 20 || n < ihl+8 || buf[9] != 17 {
			continue
		}
		gotDst := net.IPv4(buf[16], buf[17], buf[18], buf[19])
		if !gotDst.Equal(dst.IP) {
			continue
		}
		udp := buf[ihl:n]
		if binary.BigEndian.Uint16(udp[2:4]) != uint16(dst.Port) {
			continue
		}
		fmt.Printf("namespace uid=%d euid=%d\n", os.Getuid(), os.Geteuid())
		fmt.Printf("TUN=%s index=%d address=10.77.0.2/24\n", name, mustInterfaceIndex(name))
		fmt.Printf("captured app packet: UDP -> %s:%d bytes=%d\n", gotDst, dst.Port, n)
		fmt.Println("rootless user+network namespace and pure-Go TUN routing work")
		return nil
	}
	return errors.New("timed out waiting for application packet on TUN")
}

func mustInterfaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return -1
	}
	return iface.Index
}

func cmdTunProbe() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "__tunprobe_child")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rootless namespace child: %w\n%s", err, out.String())
	}
	fmt.Print(out.String())
	fmt.Println("namespace exited; host networking was not changed")
	return nil
}
