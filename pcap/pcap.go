package pcap

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Pcap is a struct for packet capture
type Pcap struct {
	Device       string
	LocalPort    uint16
	RemotePort   uint16
	localHandle  *pcap.Handle
	remoteHandle *pcap.Handle
}

// Open implements a method opens the pcap
func (p *Pcap) Open() error {
	var err error

	p.localHandle, err = pcap.OpenLive(LoopDev().Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	err = p.localHandle.SetBPFFilter(fmt.Sprintf("tcp and port %d", p.LocalPort))
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
	err = p.remoteHandle.SetBPFFilter(fmt.Sprintf("tcp and port %d", p.RemotePort))
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
	fmt.Println(packet)
}
