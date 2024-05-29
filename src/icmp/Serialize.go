package icmp

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
