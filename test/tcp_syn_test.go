package test

import (
	"gmap/src/tcp/syn"
	"testing"
)

func TestCreateTcpSyn(t *testing.T) {
	packet_bytes := []byte{
		0xc7, 0x51, 0x06, 0xbb, 0xdb, 0x4f, 0xf9, 0xd6,
		0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0x04, 0x00,
		0xce, 0xd8, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
	}
	packet, err := syn.CreateTcpSyn(
		"192.168.80.1",
		"192.168.80.200",
		51025, 1723,
		3679451606, 0,
	)

	if err != nil {
		t.Errorf("TestCreateTcpSyn failed | %s", err)
	}

	buf := packet.Serialize()
	for i := 0; i < len(buf); i++ {
		if buf[i] != packet_bytes[i] {
			t.Errorf("TestCreateTcpSyn failed | %d | 0x%x | 0x%x",
				i, buf[i], packet_bytes[i])
		}
	}

	t.Log("TestCreateTcpSyn passed")
}

func TestDecodeTcpSyn(t *testing.T) {
	packet_bytes := []byte{
		0x02, 0x01, 0xc7, 0x51, 0x69, 0x6c, 0xd5, 0xbe,
		0xdb, 0x4f, 0xf9, 0xd7, 0x60, 0x12, 0x16, 0xd0,
		0x81, 0x86, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
	}

	packet, err := syn.DecodeTcpSynAck(
		"192.168.80.200",
		"192.168.80.1",
		packet_bytes,
	)
	if err != nil {
		t.Errorf("TestDecodeTcpSyn failed | %s", err)
	}

	if packet.Header.SourcePort != 513 {
		t.Errorf("TestDecodeTcpSyn failed | %d", packet.Header.SourcePort)
	}

	if packet.Header.DestinationPort != 51025 {
		t.Errorf("TestDecodeTcpSyn failed | %d", packet.Header.DestinationPort)
	}

	if packet.Header.SequenceNumber != 1768740286 {
		t.Errorf("TestDecodeTcpSyn failed | %d", packet.Header.SequenceNumber)
	}

	if packet.Header.AckNumber != 3679451607 {
		t.Errorf("TestDecodeTcpSyn failed | %d", packet.Header.AckNumber)
	}

	t.Log("TestDecodeTcpSyn passed")
}
