package util

import "net"

// CIDRIncrementIP
//
//	@Description: Increment the IP address by one
//	@param ip
func CIDRIncrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
