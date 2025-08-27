package pktstat

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func CaptureAndHandle(interfaceName, filter string, snaplen int32, handler PacketHandler) error {
	handle, err := pcap.OpenLive(interfaceName, snaplen, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %v", interfaceName, err)
	} else if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	return handler(handle)
}
