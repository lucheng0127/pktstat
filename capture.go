// Package pktstat provides functionality for capturing and processing network packets.
// Example usage:
//
//	ctx := context.Background()
//	statCh := make(chan pktstat.StatKeyCh, 1000)
//	defer close(statCh)
//	statHandler := pktstat.NewStatHandler(ctx, statCh)
//	go func() {
//	    err := pktstat.CaptureAndHandle("eth0", "tcp", 65535, statHandler)
//	    if err != nil {
//	        log.Fatalf("Capture error: %v", err)
//	    }
//	}()
//
// This will start capturing TCP packets on the "eth0" interface and process them using the statHandler.
//
// PacketHandler is a function type that processes packets from a pcap handle.
// NewStatHandler creates a PacketHandler that statistics packets and sends them to the provided channel.
// CaptureAndHandle opens a live packet capture on the specified network interface,
// applies the given BPF filter, and processes packets using the provided handler function.
package pktstat

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

// CaptureAndHandle opens a live packet capture on the specified network interface,
// applies the given BPF filter, and processes packets using the provided handler function.
// It returns an error if any step fails.
// Parameters:
// - interfaceName: the name of the network interface to capture packets from.
// - filter: the BPF filter string to apply.
// - snaplen: the maximum size to capture for each packet.
// - handler: a function that processes packets from the pcap handle.
func CaptureAndHandle(interfaceName, filter string, snaplen int32, handler PacketHandler) error {
	handle, err := pcap.OpenLive(interfaceName, snaplen, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %v", interfaceName, err)
	} else if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	return handler(handle)
}
