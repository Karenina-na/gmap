package syn

import (
	"fmt"
	"time"
)

func (pkt *TcpSyn) String() string {
	t := time.Now().Format("2006-01-02 15:04:05")
	return fmt.Sprintf("%s | %s | %s ",
		t, pkt.Header.OtherInfo, "TCP SYN",
	)
}

func (pkt *TcpSynAck) String() string {
	t := time.Now().Format("2006-01-02 15:04:05")
	return fmt.Sprintf("%s | %s | %s ",
		t, pkt.Header.OtherInfo, "TCP SYN-ACK",
	)
}
