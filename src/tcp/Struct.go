package tcp

// Header	- The header of a TCP packet
// @Description: The header of a TCP packet
type Header struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	DataOffset      uint8
	Reserved        uint8
	Flags           uint16
	WindowSize      uint16
	Checksum        uint16
	UrgentPointer   uint16
	OtherInfo       string
}

func DecodeTCPHeader(data []byte) (*Header, error) {
	return &Header{
		SourcePort:      uint16(data[0])<<8 | uint16(data[1]),
		DestinationPort: uint16(data[2])<<8 | uint16(data[3]),
		SequenceNumber:  uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		AckNumber:       uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
		DataOffset:      data[12] >> 4,
		Reserved:        data[12] & 0x0f,
		Flags:           uint16(data[13] & 0x3f),
		WindowSize:      uint16(data[14])<<8 | uint16(data[15]),
		Checksum:        uint16(data[16])<<8 | uint16(data[17]),
		UrgentPointer:   uint16(data[18])<<8 | uint16(data[19]),
	}, nil
}
