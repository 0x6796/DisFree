package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type ipv4FlowKey struct {
	Protocol   uint8
	LocalIP    [4]byte
	RemoteIP   [4]byte
	LocalPort  uint16
	RemotePort uint16
}

func ip4Array(ip net.IP) ([4]byte, error) {
	var out [4]byte
	v := ip.To4()
	if v == nil {
		return out, errors.New("not IPv4")
	}
	copy(out[:], v)
	return out, nil
}

func parseIPv4Flow(packet []byte, outbound bool) (ipv4FlowKey, error) {
	var k ipv4FlowKey
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return k, errors.New("not IPv4")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return k, errors.New("short IPv4 packet")
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return k, fmt.Errorf("unsupported protocol %d", proto)
	}
	var src, dst [4]byte
	copy(src[:], packet[12:16])
	copy(dst[:], packet[16:20])
	sp := binary.BigEndian.Uint16(packet[ihl : ihl+2])
	dp := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	k.Protocol = proto
	if outbound {
		k.LocalIP, k.RemoteIP = src, dst
		k.LocalPort, k.RemotePort = sp, dp
	} else {
		k.LocalIP, k.RemoteIP = dst, src
		k.LocalPort, k.RemotePort = dp, sp
	}
	return k, nil
}

func rewriteIPv4Source(packet []byte, ip net.IP) error {
	v := ip.To4()
	if v == nil || len(packet) < 20 || packet[0]>>4 != 4 {
		return errors.New("invalid IPv4 source rewrite")
	}
	copy(packet[12:16], v)
	return recalcIPv4TransportChecksums(packet)
}

func rewriteIPv4Destination(packet []byte, ip net.IP) error {
	v := ip.To4()
	if v == nil || len(packet) < 20 || packet[0]>>4 != 4 {
		return errors.New("invalid IPv4 destination rewrite")
	}
	copy(packet[16:20], v)
	return recalcIPv4TransportChecksums(packet)
}

func checksumWords(data []byte, sum uint32) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func recalcIPv4TransportChecksums(packet []byte) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return errors.New("invalid IPv4 packet")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return errors.New("invalid IPv4 header length")
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total == 0 || total > len(packet) {
		total = len(packet)
	}
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], finishChecksum(checksumWords(packet[:ihl], 0)))

	proto := packet[9]
	if proto != 6 && proto != 17 {
		return nil
	}
	l4 := packet[ihl:total]
	if proto == 6 {
		if len(l4) < 20 {
			return errors.New("short TCP packet")
		}
		l4[16], l4[17] = 0, 0
	} else {
		if len(l4) < 8 {
			return errors.New("short UDP packet")
		}
		l4[6], l4[7] = 0, 0
	}
	sum := uint32(0)
	sum = checksumWords(packet[12:20], sum)
	sum += uint32(proto)
	sum += uint32(len(l4))
	sum = checksumWords(l4, sum)
	csum := finishChecksum(sum)
	if proto == 6 {
		binary.BigEndian.PutUint16(l4[16:18], csum)
	} else {
		if csum == 0 {
			csum = 0xffff
		}
		binary.BigEndian.PutUint16(l4[6:8], csum)
	}
	return nil
}

func clampTCPMSS(packet []byte, maxMSS uint16) (bool, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 6 {
		return false, nil
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+20 {
		return false, errors.New("short TCP packet")
	}
	tcp := packet[ihl:]
	hdrLen := int(tcp[12]>>4) * 4
	if hdrLen < 20 || len(tcp) < hdrLen {
		return false, errors.New("invalid TCP header length")
	}
	if tcp[13]&0x02 == 0 { // SYN
		return false, nil
	}
	changed := false
	for i := 20; i < hdrLen; {
		kind := tcp[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= hdrLen {
			break
		}
		n := int(tcp[i+1])
		if n < 2 || i+n > hdrLen {
			break
		}
		if kind == 2 && n == 4 {
			cur := binary.BigEndian.Uint16(tcp[i+2 : i+4])
			if cur > maxMSS {
				binary.BigEndian.PutUint16(tcp[i+2:i+4], maxMSS)
				changed = true
			}
		}
		i += n
	}
	if changed {
		return true, recalcIPv4TransportChecksums(packet)
	}
	return false, nil
}

func ipv4FromArray(a [4]byte) net.IP { return net.IPv4(a[0], a[1], a[2], a[3]) }
