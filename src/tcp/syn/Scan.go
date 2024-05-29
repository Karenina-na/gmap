package syn

import (
	"net"
	"time"
)

func SendSynRequest(
	srcIP string, srcP uint16,
	dstIP string, dstP uint16, Timeout time.Duration,
) (string, string, error) {
	// Connect to the address
	conn, err := net.DialTimeout("ip:tcp", dstIP, Timeout)

	if err != nil {
		return "", "", err
	}
	_ = conn.SetDeadline(time.Now().Add(Timeout))

	// Create a TCP SYN packet
	pkt, err := CreateTcpSyn(srcIP, dstIP, srcP, dstP, 2024, 2024^2)

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

	// Decode the response, dst -> src
	var pkt_resp *TcpSynAck
	pkt_resp, err = DecodeTcpSynAck(dstIP, srcIP, buf)

	if err != nil {
		return "", "", err
	}

	// payload
	payload := string(pkt_resp.payload)

	return pkt_resp.String(), payload, nil
}
