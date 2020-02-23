package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Server describes the packet capture on the server side
type Server struct {
	ListenPort    uint16
	ListenDevs    []*Device
	UpDev         *Device
	GatewayDev    *Device
	listenHandles []*pcap.Handle
	upHandle      *pcap.Handle
	seq           uint32
	// TODO: attempt to initialize IPv4 id to reduce the possibility of collision
	id            uint16
}

// Open implements a method opens the pcap
func (p *Server) Open() error {
	p.id = 0

	// Verify
	if len(p.ListenDevs) <= 0 {
		return fmt.Errorf("open: %w", errors.New("missing listen device"))
	}
	if p.UpDev == nil {
		return fmt.Errorf("open: %w", errors.New("missing upstream device"))
	}
	if p.GatewayDev == nil {
		return fmt.Errorf("open: %w", errors.New("missing gateway"))
	}
	if len(p.ListenDevs) == 1 {
		dev := p.ListenDevs[0]
		strIPs := ""
		for i, addr := range dev.IPAddrs {
			if i != 0 {
				strIPs = strIPs + fmt.Sprintf(", %s", addr.IP)
			} else {
				strIPs = strIPs + addr.IP.String()
			}
		}
		if dev.IsLoop {
			fmt.Printf("Listen on %s: %s\n", dev.FriendlyName, strIPs)
		} else {
			fmt.Printf("Listen on %s [%s]: %s\n", dev.FriendlyName, dev.HardwareAddr, strIPs)
		}
	} else {
		fmt.Println("Listen on:")
		for _, dev := range p.ListenDevs {
			strIPs := ""
			for j, addr := range dev.IPAddrs {
				if j != 0 {
					strIPs = strIPs + fmt.Sprintf(", %s", addr.IP)
				} else {
					strIPs = strIPs + addr.IP.String()
				}
			}
			if dev.IsLoop {
				fmt.Printf("  %s: %s\n", dev.FriendlyName, strIPs)
			} else {
				fmt.Printf("  %s [%s]: %s\n", dev.FriendlyName, dev.HardwareAddr, strIPs)
			}
		}
	}
	strUpIPs := ""
	for i, addr := range p.UpDev.IPAddrs {
		if i != 0 {
			strUpIPs = strUpIPs + fmt.Sprintf(", %s", addr.IP)
		} else {
			strUpIPs = strUpIPs + addr.IP.String()
		}
	}
	if !p.GatewayDev.IsLoop {
		fmt.Printf("Route upstream from %s [%s]: %s to gateway [%s]: %s\n", p.UpDev.FriendlyName,
			p.UpDev.HardwareAddr, strUpIPs, p.GatewayDev.HardwareAddr, p.GatewayDev.IPAddr().IP)
	} else {
		fmt.Printf("Route upstream to loopback %s\n", p.UpDev.FriendlyName)
	}

	// Handles for listening
	p.listenHandles = make([]*pcap.Handle, 0)
	for _, dev := range p.ListenDevs {
		handle, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		err = handle.SetBPFFilter(fmt.Sprintf("(tcp || udp) && dst port %d", p.ListenPort))
		p.listenHandles = append(p.listenHandles, handle)
	}
	for _, handle := range p.listenHandles {
		packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
		go func() {
			for packet := range packetSrc.Packets() {
				p.handleListen(packet, handle)
			}
		}()
	}

	// Handles for routing upstream
	var err error
	p.upHandle, err = pcap.OpenLive(p.UpDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	packetSrc := gopacket.NewPacketSource(p.upHandle, p.upHandle.LinkType())
	go func() {
		for packet := range packetSrc.Packets() {
			p.handleUpstream(packet)
		}
	}()

	select {}
}

// Close implements a method closes the pcap
func (p *Server) Close() {
	for _, handle := range p.listenHandles {
		handle.Close()
	}
	p.upHandle.Close()
}

func (p *Server) handleListen(packet gopacket.Packet, handle *pcap.Handle) {

}

func (p *Server) handleUpstream(packet gopacket.Packet) {

}