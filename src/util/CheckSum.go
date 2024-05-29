package util

// CalculateChecksum
//
//	@Description: Calculate the checksum of the data
//	@param data	[]byte
//	@return uint16
func CalculateChecksum(data []byte) uint16 {
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
