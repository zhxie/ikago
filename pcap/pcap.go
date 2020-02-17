package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

// Pcap describes a packet capture
type Pcap struct {
	LocalPort    uint16
	RemotePort   uint16
	Dev          *Device
	gatewayDev   *Device
	localHandle  *pcap.Handle
	remoteHandle *pcap.Handle
}

// Open implements a method opens the pcap
func (p *Pcap) Open() error {
	if p.Dev == nil {
		gatewayAddr, err := FindGatewayAddr()
		if err != nil {
			return err
		}
		devs, err := FindAllDevs()
		if err != nil {
			return err
		}
		for _, dev := range devs {
			if dev.IsLoop {
				continue
			}
			for _, addr := range dev.Addrs {
				ipnet := net.IPNet{IP:addr.IP, Mask:addr.Mask}
				if ipnet.Contains(gatewayAddr.IP) {
					p.gatewayDev, err = FindGatewayDev(dev.Name)
					if err != nil {
						continue
					}
					p.Dev = &dev
					break
				}
			}
			if p.Dev != nil {
				break
			}
		}
		if p.gatewayDev == nil {
			return errors.New("can not determine device")
		}
	} else {
		var err error
		p.gatewayDev, err = FindGatewayDev(p.Dev.Name)
		if err != nil {
			return err
		}
	}
	fmt.Printf("Route upstream from %s [%s] to gateway %s [%s]\n", p.Dev.FriendlyName, p.Dev.HardwareAddr,
		p.gatewayDev.Addrs[0].IP, p.gatewayDev.HardwareAddr)

	loopDev, err := FindLoopDev()
	if err != nil {
		return err
	}
	p.localHandle, err = pcap.OpenLive(loopDev.Name, 1600, true, pcap.BlockForever)
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

	p.remoteHandle, err = pcap.OpenLive(p.Dev.Name, 1600, true, pcap.BlockForever)
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
