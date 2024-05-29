package syn

// Serialize
//
//	@Description: Serialize the packet
//	@receiver pkt
//	@return []byte
func (pkt *TcpSyn) Serialize() []byte {
	return append(pkt.header.Serialize(), pkt.payload...)
}

// Serialize
//
//	@Description: Serialize the packet
//	@receiver pkt
//	@return []byte
func (pkt *TcpSynAck) Serialize() []byte {
	return append(pkt.header.Serialize(), pkt.payload...)
}
