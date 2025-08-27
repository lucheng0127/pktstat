package pktstat

import (
	"context"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

type StatKey struct {
	SrcIP   string
	DstIP   string
	Proto   gopacket.LayerType
	SrcPort uint16
	DstPort uint16
}

type StatChKey struct {
	Key  StatKey
	Size int
}

type StatEntry struct {
	Bytes   int64
	Packets int64
}

type StatMap map[StatKey]StatEntry

type PacketHandler func(handle *pcap.Handle) error

func NewStatHandler(ctx context.Context, statCh chan<- StatChKey) PacketHandler {
	return func(handle *pcap.Handle) error {
		packetSource := gopacket.ZeroCopyPacketDataSource(handle)
		defer handle.Close()

		var (
			eth   layers.Ethernet
			ip4   layers.IPv4
			ip6   layers.IPv6
			tcp   layers.TCP
			udp   layers.UDP
			icmp4 layers.ICMPv4
			icmp6 layers.ICMPv6
		)

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &icmp4, &icmp6)
		parser.IgnoreUnsupported = true

		decodedLayers := make([]gopacket.LayerType, 0, 10)

		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			// Read packet data
			data, _, err := packetSource.ZeroCopyReadPacketData()
			if err != nil {
				log.Errorf("error reading packet data: %v", err)
				continue
			}

			if err := parser.DecodeLayers(data, &decodedLayers); err != nil {
				log.Warnf("error decoding packet: %v", err)
				continue
			}

			var k StatKey

			for _, t := range decodedLayers {
				k.Proto = t

				switch t {
				case layers.LayerTypeIPv4:
					k.SrcIP = ip4.SrcIP.String()
					k.DstIP = ip4.DstIP.String()
				case layers.LayerTypeIPv6:
					k.SrcIP = ip6.SrcIP.String()
					k.DstIP = ip6.DstIP.String()
				case layers.LayerTypeTCP:
					k.SrcPort = uint16(tcp.SrcPort)
					k.DstPort = uint16(tcp.DstPort)
				case layers.LayerTypeUDP:
					k.SrcPort = uint16(udp.SrcPort)
					k.DstPort = uint16(udp.DstPort)
				}
			}

			if k.Proto == 0 || k.SrcIP == "" || k.DstIP == "" {
				continue
			}

			pktLen := len(data)
			statCh <- StatChKey{Key: k, Size: pktLen}
		}
	}
}
