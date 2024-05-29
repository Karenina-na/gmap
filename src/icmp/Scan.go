package icmp

import (
	"net"
	"time"
)

// SendPingRequest
//
//	@Description: Send an ICMP EchoRequest and receive the response
//	@param Address string, Timeout int (ms)
//	@return string response
//	@return log string, payload string, error
func SendPingRequest(Address string, Timeout time.Duration) (string, string, error) {
	start_time := time.Now()

	// Connect to the address
	conn, err := net.DialTimeout("ip4:icmp", Address, Timeout)
	if err != nil {
		return "", "", err
	}
	_ = conn.SetDeadline(time.Now().Add(Timeout))

	// Create an ICMP EchoRequest
	pkt, err := CreateICMPEchoRequest(2024, 2024^2)

	if err != nil {
		return "", "", err
	}

	// Send
	buf := pkt.Serialize()
	_, err = conn.Write(buf)

	if err != nil {
		return "", "", err
	}

	// Receive the response
	buf = make([]byte, 1024)
	_, err = conn.Read(buf)

	if err != nil {
		return "", "", err
	}

	// Decode the response
	var pkt_resp *EchoResponse
	pkt_resp, err = DecodeICMPEchoResponse(buf, len(buf))

	if err != nil {
		return "", "", err
	}

	// payload
	payload := string(pkt_resp.Payload)
	pkt_resp.TTL = int(time.Since(start_time) / time.Millisecond)

	return pkt_resp.String(), payload, nil
}
