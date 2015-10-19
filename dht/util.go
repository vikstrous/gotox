package dht

import (
	"bytes"
	"net"
)

func addrEq(addr1, addr2 net.UDPAddr) bool {
	if !bytes.Equal(addr1.IP, addr2.IP) {
		return false
	}
	if addr1.Port != addr2.Port {
		return false
	}
	return true
}
