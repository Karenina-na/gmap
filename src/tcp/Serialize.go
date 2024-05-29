package tcp

// Serialize	- Serialize the TCP packet
// @Description: Serialize the TCP packet
// @Return: []byte - The serialized packet
func (h *Header) Serialize() []byte {
	// 20 bytes
	data := make([]byte, 20)

	// Source Port
	data[0] = byte(h.SourcePort >> 8)
	data[1] = byte(h.SourcePort)

	// Destination Port
	data[2] = byte(h.DestinationPort >> 8)
	data[3] = byte(h.DestinationPort)

	// Sequence Number
	data[4] = byte(h.SequenceNumber >> 24)
	data[5] = byte(h.SequenceNumber >> 16)
	data[6] = byte(h.SequenceNumber >> 8)
	data[7] = byte(h.SequenceNumber)

	// Acknowledgement Number
	data[8] = byte(h.AckNumber >> 24)
	data[9] = byte(h.AckNumber >> 16)
	data[10] = byte(h.AckNumber >> 8)
	data[11] = byte(h.AckNumber)

	// Data Offset
	data[12] = (h.DataOffset << 4) | 0

	// Flags
	data[13] = byte(h.Flags)

	// Window Size
	data[14] = byte(h.WindowSize >> 8)
	data[15] = byte(h.WindowSize)

	// Checksum
	data[16] = byte(h.Checksum >> 8)
	data[17] = byte(h.Checksum)

	// Urgent Pointer
	data[18] = byte(h.UrgentPointer >> 8)
	data[19] = byte(h.UrgentPointer)

	return data
}
