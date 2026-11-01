package main

import (
	"net"
	"strings"
)

// Iface is one network interface as the inventory reports it, so a machine can be matched to what is seen on
// the network: its MAC address and its IP addresses.
type Iface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac,omitempty"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

// networkInterfaces lists the interfaces that are up and reachable from a network: an IPv4 address or a
// routable IPv6 one (an interface with only fe80:: says nothing about where the machine is). The kernel is
// asked over netlink, read-only; the systemd unit allows AF_NETLINK for this alone.
func networkInterfaces(_ string) (any, bool) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, false
	}
	var out []Iface
	for _, i := range list {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		if row, ok := ifaceRow(i.Name, i.HardwareAddr.String(), addrs); ok {
			out = append(out, row)
		}
	}
	if out == nil {
		return nil, false
	}
	return out, true
}

// ifaceRow sorts an interface's addresses into IPv4 and IPv6 and says whether it is worth reporting.
func ifaceRow(name, mac string, addrs []net.Addr) (Iface, bool) {
	row := Iface{Name: name, MAC: mac}
	routable := false
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			row.IPv4 = append(row.IPv4, v4.String())
			routable = true
		} else {
			row.IPv6 = append(row.IPv6, ip.String())
			if !strings.HasPrefix(strings.ToLower(ip.String()), "fe80") {
				routable = true
			}
		}
	}
	return row, routable
}
