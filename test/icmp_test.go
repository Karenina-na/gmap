package test

import (
	"gmap/src"
	"gmap/src/icmp"
	"gmap/src/util"
	"testing"
)

func TestCreateICMPeEchoRequest(t *testing.T) {
	packet_bytes := []byte{
		0x08, 0x00, 0x4c, 0x5f, 0x00, 0x01, 0x00, 0xfc,
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
		0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	}
	PAYLOAD := "abcdefghijklmnopqrstuvwabcdefghi"

	// Create an ICMP EchoRequest
	pkt, err := icmp.CreateICMPEchoRequest(1, 252)
	if err != nil {
		panic(err)
	}

	// Set the payload
	pkt.Payload = []byte(PAYLOAD)
	pkt.Header.Checksum = 0
	buf := pkt.Serialize()
	pkt.Header.Checksum = util.CalculateChecksum(buf)
	buf = pkt.Serialize()

	bufH := buf[:8]
	for i := 0; i < len(bufH); i++ {
		if bufH[i] != packet_bytes[i] {
			t.Errorf("TestCreateICMPeEchoRequest failed | %d | 0x%x | 0x%x",
				i, bufH[i], packet_bytes[i])
		}
	}

	payload := string(buf[8:])
	if payload != PAYLOAD {
		t.Errorf("TestCreateICMPeEchoRequest failed | %s | %s", payload, src.PAYLOAD)
	}

	t.Log("TestCreateICMPeEchoRequest passed")
}

func TestDecodeICMPEchoReply(t *testing.T) {
	packet_bytes := []byte{
		0x45, 0x00, 0x00, 0x3c, 0xe5, 0xa6, 0x00, 0x00,
		0x40, 0x01, 0x73, 0x00, 0xc0, 0xa8, 0x50, 0xc8,
		0xc0, 0xa8, 0x50, 0x01,
		0x00, 0x00, 0x54, 0x5f, 0x00, 0x01, 0x00, 0xfc,
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
		0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
		0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	}
	PAYLOAD := "abcdefghijklmnopqrstuvwabcdefghi"

	// Decode an ICMP EchoReply
	pkt, err := icmp.DecodeICMPEchoResponse(packet_bytes, len(packet_bytes))
	if err != nil {
		t.Error(err)
	}

	payload := string(pkt.Payload)
	if payload != PAYLOAD {
		t.Errorf("TestDecodeICMPEchoReply failed | %s | %s", payload, src.PAYLOAD)
	}

	t.Log("TestDecodeICMPEchoReply passed")
}
