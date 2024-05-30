package tcp

import (
	"fmt"
	"net"
	"time"
)

// SendTCPRequest
//
//	@Description:  Send a TCP request to the target IP and port
//	@param IP
//	@param Port
//	@param Timeout
//	@return string
//	@return string
//	@return error
func SendTCPRequest(IP string, Port string, Timeout time.Duration) (string, string, error) {
	startTime := time.Now()

	// Connect to the address
	conn, err := net.DialTimeout("tcp", IP+":"+Port, Timeout)

	if err != nil {
		return "", "", err
	}

	_ = conn.SetDeadline(time.Now().Add(Timeout))

	// close
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			return // ignore
		}
	}(conn)

	tcpLog := fmt.Sprintf("%s | %s | %s | %s | %s %d",
		time.Now().Format("2006-01-02 15:04:05"),
		"TCP", "Connection Established", IP+":"+Port,
		"TTL (ms):", int(time.Since(startTime)/time.Millisecond),
	)

	return tcpLog, "", nil
}
