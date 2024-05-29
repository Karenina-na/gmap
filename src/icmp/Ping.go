package icmp

import (
	"fmt"
	"net"
	"time"
)

// Header
// @Description: ICMP Header
type Header struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16
}

// EchoRequest
// @Description: ICMP EchoRequest
type EchoRequest struct {
	Header  Header
	Payload []byte
}

// EchoResponse
// @Description: ICMP EchoResponse
type EchoResponse struct {
	Header    Header
	Payload   []byte
	OtherInfo string
}

// calculateChecksum
//
//	@Description: Calculate the checksum of the data
//	@param data	[]byte
//	@return uint16
func calculateChecksum(data []byte) uint16 {
	sum := 0
	length := len(data)
	for i := 0; i < length; i += 2 {
		if i+1 == length {
			sum += int(data[i]) << 8
			break
		}
		sum += int(data[i])<<8 | int(data[i+1])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16

	return uint16(^sum)
}

// Serialize
//
//	@Description: Serialize the packet
//	@receiver pkt	*EchoRequest
//	@return []byte	Serialized packet
func (pkt *EchoRequest) Serialize() []byte {
	buf := make([]byte, 8+len(pkt.Payload))
	buf[0] = pkt.Header.Type
	buf[1] = pkt.Header.Code
	buf[2] = 0
	buf[3] = 0
	buf[4] = byte(pkt.Header.Identifier >> 8)
	buf[5] = byte(pkt.Header.Identifier)
	buf[6] = byte(pkt.Header.SequenceNum >> 8)
	buf[7] = byte(pkt.Header.SequenceNum)
	copy(buf[8:], pkt.Payload)

	// checksum
	buf[2] = byte(pkt.Header.Checksum >> 8)
	buf[3] = byte(pkt.Header.Checksum)

	return buf
}

// Serialize
//
//	@Description: Serialize the packet
//	@receiver pkt	*EchoResponse
//	@return []byte	Serialized packet
func (pkt *EchoResponse) Serialize() []byte {
	buf := make([]byte, 8+len(pkt.Payload))
	buf[0] = pkt.Header.Type
	buf[1] = pkt.Header.Code
	buf[2] = 0
	buf[3] = 0
	buf[4] = byte(pkt.Header.Identifier >> 8)
	buf[5] = byte(pkt.Header.Identifier)
	buf[6] = byte(pkt.Header.SequenceNum >> 8)
	buf[7] = byte(pkt.Header.SequenceNum)
	copy(buf[8:], pkt.Payload)

	// checksum
	buf[2] = byte(pkt.Header.Checksum >> 8)
	buf[3] = byte(pkt.Header.Checksum)

	return buf
}

// String
//
//	@Description: Convert the packet to a string
//	@receiver pkt
//	@return string
func (pkt *EchoResponse) String() string {
	//return fmt.Sprintf("Type: %d, Code: %d, Checksum: %d, Identifier: %d, SequenceNum: %d, Payload: %s",
	//	pkt.Header.Type, pkt.Header.Code, pkt.Header.Checksum, pkt.Header.Identifier, pkt.Header.SequenceNum, pkt.Payload)
	t := time.Now().Format("2006-01-02 15:04:05")
	return fmt.Sprintf("%s | %s | %s | %s 0x%x, %s 0x%x",
		t, pkt.OtherInfo, "ICMP Echo Response",
		"Identifier:", pkt.Header.Identifier,
		"SequenceNum:", pkt.Header.SequenceNum)
}

// CreateICMPEchoRequest
//
//	@Description: Create an ICMP EchoRequest
//	@param identifier
//	@param sequenceNum
//	@return *EchoRequest
func CreateICMPEchoRequest(identifier, sequenceNum uint16) (*EchoRequest, error) {
	header := Header{
		Type:        8,
		Code:        0,
		Checksum:    0,
		Identifier:  identifier,
		SequenceNum: sequenceNum,
	}

	pkt := EchoRequest{
		Header:  header,
		Payload: []byte("Send Echo Request by gmap (Karenina-na, https://www.weizixiang.top)"),
	}

	// checksum
	pkt.Header.Checksum = calculateChecksum(pkt.Serialize())

	return &pkt, nil
}

// DecodeICMPEchoResponse
//
//	@Description: Decode an ICMP EchoResponse
//	@param data
//	@param length
//	@return *EchoResponse
//	@return error
func DecodeICMPEchoResponse(data []byte, length int) (*EchoResponse, error) {
	pkt := EchoResponse{
		Header: Header{
			Type:        data[20],
			Code:        data[21],
			Checksum:    0,
			Identifier:  uint16(data[24])<<8 | uint16(data[25]),
			SequenceNum: uint16(data[26])<<8 | uint16(data[27]),
		},
		Payload: data[28:length],
	}

	checksum := uint16(data[22])<<8 | uint16(data[23])

	// checksum
	if checksum != calculateChecksum(pkt.Serialize()) {
		return nil, fmt.Errorf("checksum error")
	}

	// OtherInfo (IP)
	pkt.OtherInfo = fmt.Sprintf("IP: %d.%d.%d.%d", data[12], data[13], data[14], data[15])

	return &pkt, nil
}

func SendPingRequest(Address string) (string, error) {
	conn, err := net.Dial("ip4:icmp", Address)
	if err != nil {
		return "", err
	}

	// Create an ICMP EchoRequest
	pkt, err := CreateICMPEchoRequest(2024, 2024^2)

	if err != nil {
		return "", err
	}

	// Serialize the packet
	buf := pkt.Serialize()

	// Send the packet
	_, err = conn.Write(buf)

	if err != nil {
		return "", err
	}

	// Receive the response
	buf = make([]byte, 1024)
	_, err = conn.Read(buf)

	if err != nil {
		return "", err
	}

	// Decode the response
	var pkt_resp *EchoResponse
	pkt_resp, err = DecodeICMPEchoResponse(buf, len(buf))

	if err != nil {
		return "", err
	}

	return pkt_resp.String(), nil
}
