package icmp

import (
	"fmt"
	"gmap/src"
	"gmap/src/util"
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
	TTL       int // (ms)
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
		Payload: []byte(src.PAYLOAD),
	}

	// checksum
	pkt.Header.Checksum = util.CalculateChecksum(pkt.Serialize())

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
	if checksum != util.CalculateChecksum(pkt.Serialize()) {
		return nil, fmt.Errorf("checksum error")
	}

	// OtherInfo (IP)
	pkt.OtherInfo = fmt.Sprintf("IP: %d.%d.%d.%d", data[12], data[13], data[14], data[15])

	return &pkt, nil
}
