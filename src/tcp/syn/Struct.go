package syn

import (
	"fmt"
	"gmap/src/tcp"
	"gmap/src/util"
)

// TcpSyn
// @Description: A TCP SYN packet
type TcpSyn struct {
	header  tcp.Header
	payload []byte
}

// TcpSynAck
// @Description: A TCP SYN-ACK packet
type TcpSynAck struct {
	header  tcp.Header
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
		DataOffset:      5,
		Reserved:        0,
		Flags:           0x02, // SYN
		WindowSize:      1024,
		Checksum:        0,
		UrgentPointer:   0,
	}

	pkt := TcpSyn{
		header:  header,
		payload: []byte(""),
	}

	pkt.header.OtherInfo = fmt.Sprintf("TCP SYN: %s:%d -> %s:%d",
		srcIP, srcPort, dstIP, dstPort,
	)

	// checksum
	pseudoHeader := util.CreatePseudoHeader(srcIP, dstIP, len(pkt.payload)+20)
	pkt.header.Checksum = util.CalculateChecksum(append(pseudoHeader, pkt.Serialize()...))

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
		header:  *header,
		payload: data[20:],
	}

	checksum := header.Checksum
	header.Checksum = 0

	// checksum
	pseudoHeader := util.CreatePseudoHeader(srcIP, dstIP, len(pkt.payload)+20)
	if checksum != util.CalculateChecksum(append(pseudoHeader, pkt.Serialize()...)) {
		return nil, fmt.Errorf("checksum error")
	}

	pkt.header.Checksum = checksum

	// OtherInfo
	pkt.header.OtherInfo = fmt.Sprintf("TCP SYN-ACK: %s:%d -> %s:%d",
		srcIP, header.SourcePort, dstIP, header.DestinationPort,
	)

	return &pkt, nil
}
