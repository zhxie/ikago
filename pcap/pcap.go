package pcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Pcap is a struct for packet capture
type Pcap struct {
	Device       string
	LocalPort    uint16
	RemotePort   uint16
	gateway      Device
	localHandle  *pcap.Handle
	remoteHandle *pcap.Handle
}

// Open implements a method opens the pcap
func (p *Pcap) Open() error {
	gateway, err := FindGateway(p.Device)
	if err != nil {
		return err
	}
	p.gateway = *gateway
	fmt.Printf("Route upstream to %s: %s\n", p.gateway.Addrs[0], p.gateway.HardwareAddr)

	p.localHandle, err = pcap.OpenLive(LoopDev().Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	err = p.localHandle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d", p.LocalPort))
	if err != nil {
		return err
	}
	localPacketSrc := gopacket.NewPacketSource(p.localHandle, p.localHandle.LinkType())
	go func() {
		for packet := range localPacketSrc.Packets() {
			handle(packet)
		}
	}()

	p.remoteHandle, err = pcap.OpenLive(p.Device, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	err = p.remoteHandle.SetBPFFilter(fmt.Sprintf("tcp and src port %d", p.RemotePort))
	if err != nil {
		return err
	}
	remotePacketSrc := gopacket.NewPacketSource(p.remoteHandle, p.remoteHandle.LinkType())
	go func() {
		for packet := range remotePacketSrc.Packets() {
			handle(packet)
		}
	}()

	select {}
}

// Close implements a method closes the pcap
func (p *Pcap) Close() {
	p.localHandle.Close()
	p.remoteHandle.Close()
}

func handle(packet gopacket.Packet) {
	packet.LinkLayer()
	switch t := packet.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		fmt.Println(packet)
	default:
		fmt.Printf("Received packet with invalid transport protocol: %s\n", t)
	}
}
