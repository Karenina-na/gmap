package syn

import (
	"fmt"
	"gmap/src/tcp"
	"gmap/src/util"
)

// TcpSyn
// @Description: A TCP SYN packet
type TcpSyn struct {
	Header  tcp.Header
	payload []byte
}

// TcpSynAck
// @Description: A TCP SYN-ACK packet
type TcpSynAck struct {
	Header  tcp.Header
	payload []byte
}

// CreateTcpSyn
//
//	@Description: Create a TCP SYN packet
//	@param srcIP
//	@param dstIP
//	@param srcPort
//	@param dstPort
//	@param seqNum
//	@param ackNum
//	@return *TcpSyn
//	@return error
func CreateTcpSyn(srcIP, dstIP string, srcPort, dstPort uint16, seqNum, ackNum uint32) (*TcpSyn, error) {
	header := tcp.Header{
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		SequenceNumber:  seqNum,
		AckNumber:       ackNum,
		DataOffset:      6,
		Reserved:        0,
		Flags:           0x02, // SYN
		WindowSize:      1024,
		Checksum:        0,
		UrgentPointer:   0,
	}

	pkt := TcpSyn{
		Header: header,
		// Option: Maximum Segment Size 1460 bytes
		payload: []byte{0x02, 0x04, 0x05, 0xb4},
	}

	pkt.Header.OtherInfo = fmt.Sprintf("TCP SYN: %s:%d -> %s:%d",
		srcIP, srcPort, dstIP, dstPort,
	)

	// checksum
	pseudoHeader := util.CreatePseudoHeader(srcIP, dstIP, len(pkt.payload)+20)
	pkt.Header.Checksum = util.CalculateChecksum(append(pseudoHeader, pkt.Serialize()...))

	return &pkt, nil
}

// DecodeTcpSynAck
//
//	@Description: Decode a TCP SYN-ACK packet
//	@param srcIP
//	@param dstIP
//	@param data
//	@return *TcpSynAck
//	@return error
func DecodeTcpSynAck(srcIP, dstIP string, data []byte) (*TcpSynAck, error) {
	// Header
	header, err := tcp.DecodeTCPHeader(data[0:20])
	if err != nil {
		return nil, err
	}

	pkt := TcpSynAck{
		Header:  *header,
		payload: data[20:],
	}

	checksum := pkt.Header.Checksum
	pkt.Header.Checksum = 0

	// checksum
	pseudoHeader := util.CreatePseudoHeader(srcIP, dstIP, len(pkt.payload)+20)
	if checksum != util.CalculateChecksum(append(pseudoHeader, pkt.Serialize()...)) {
		return nil, fmt.Errorf("checksum error")
	}

	pkt.Header.Checksum = checksum

	// OtherInfo
	pkt.Header.OtherInfo = fmt.Sprintf("TCP SYN-ACK: %s:%d -> %s:%d",
		srcIP, header.SourcePort, dstIP, header.DestinationPort,
	)

	return &pkt, nil
}
