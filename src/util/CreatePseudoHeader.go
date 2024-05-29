package util

import "net"

// CreatePseudoHeader
//
//	@Description: Create a pseudo header
//	@param srcIP
//	@param dstIP
//	@return []byte
func CreatePseudoHeader(srcIP, dstIP string, length int) []byte {
	// 00
	// 06 	- Protocol (TCP)
	// 00 14 	- TCP Length
	// 将ip从string转换为[]byte，以.切割
	srcIPBytes := net.ParseIP(srcIP).To4()
	dstIPBytes := net.ParseIP(dstIP).To4()
	return append(append(srcIPBytes, dstIPBytes...), []byte{0x00, 0x06, 0x00, byte(length)}...)
}
