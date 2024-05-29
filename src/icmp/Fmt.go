package icmp

import (
	"fmt"
	"time"
)

// String
//
//	@Description: Convert the packet to a string
//	@receiver pkt
//	@return string
func (pkt *EchoResponse) String() string {
	t := time.Now().Format("2006-01-02 15:04:05")
	return fmt.Sprintf("%s | %s | %s | %s (0x%x), %s 0x%x, | %s %d",
		t, pkt.OtherInfo, "ICMP Echo Response",
		pkt.getStatus(), pkt.Header.Type,
		"code:", pkt.Header.Type,
		"TTL (ms):", pkt.TTL,
	)
}

// getStatus
//
//	@Description: Get the status of the response
//	@receiver pkt
//	@return string
func (pkt *EchoResponse) getStatus() string {
	switch pkt.Header.Code {
	case 0: // Echo Reply
		return "Echo Reply"
	case 3: // Destination Unreachable
		return "Destination Unreachable"
	case 4: // Source Quench
		return "Source Quench"
	case 5: // Redirect
		return "Redirect"
	case 8: // Echo Request
		return "Echo Request"
	case 11: // Time Exceeded
		return "Time Exceeded"
	case 12: // Parameter Problem
		return "Parameter Problem"
	case 13: // Timestamp Request
		return "Timestamp Request"
	case 14: // Timestamp Reply
		return "Timestamp Reply"
	case 15: // Information Request
		return "Information Request"
	case 16: // Information Reply
		return "Information Reply"
	case 17: // Address Mask Request
		return "Address Mask Request"
	case 18: // Address Mask Reply
		return "Address Mask Reply"
	}
	return "Unknown Type"
}
