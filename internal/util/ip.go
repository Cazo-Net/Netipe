package util

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ParseIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	return nil
}

func ParseCIDR(s string) (net.IP, net.IPMask, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		s = s + "/32"
	}
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, nil, err
	}
	return ip, ipNet.Mask, nil
}

func MaskToCIDR(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

func CIDRString(ip net.IP, mask net.IPMask) string {
	ones, _ := mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), ones)
}

func WildcardFromMask(mask net.IPMask) string {
	wildcard := make(net.IPMask, len(mask))
	for i, b := range mask {
		wildcard[i] = ^b
	}
	return wildcard.String()
}

func IsValidIP(s string) bool {
	return net.ParseIP(s) != nil
}

func IsPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
	}

	for _, r := range privateRanges {
		if bytesCompare(ip.To4(), r.start.To4()) >= 0 &&
			bytesCompare(ip.To4(), r.end.To4()) <= 0 {
			return true
		}
	}
	return false
}

func bytesCompare(a, b []byte) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func ZeroIP() net.IP {
	return net.IPv4(0, 0, 0, 0)
}

func BroadcastIP(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = ip4[i] | ^mask[i]
	}
	return bcast
}

func HostnameFromIP(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ""
}

func ParsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		port, err := strconv.Atoi(parts[0])
		return port, err
	}
	port, err := strconv.Atoi(s)
	return port, err
}

func ParseProtocol(s string) int {
	switch strings.ToLower(s) {
	case "ip":
		return 0
	case "icmp":
		return 1
	case "igmp":
		return 2
	case "tcp":
		return 6
	case "udp":
		return 17
	case "ospf":
		return 89
	default:
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
		return -1
	}
}

func ProtocolName(proto int) string {
	protos := map[int]string{
		0:   "ip",
		1:   "icmp",
		2:   "igmp",
		6:   "tcp",
		8:   "egp",
		9:   "igp",
		17:  "udp",
		47:  "gre",
		50:  "esp",
		51:  "ah",
		58:  "icmpv6",
		89:  "ospf",
		103: "pim",
		112: "vrrp",
	}
	if name, ok := protos[proto]; ok {
		return name
	}
	return strconv.Itoa(proto)
}

func IsAnyAddress(ip string) bool {
	ip = strings.TrimSpace(ip)
	return ip == "any" || ip == "0.0.0.0" || ip == "0.0.0.0/0" || ip == "::" || ip == "::/0"
}
