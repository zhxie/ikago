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
	RemoteAddr   net.IP
	RemotePort   uint16
	LocalDev     *Device
	RemoteDev    *Device
	gatewayDev   *Device
	localHandle  *pcap.Handle
	remoteHandle *pcap.Handle
}

// Open implements a method opens the pcap
func (p *Pcap) Open() error {
	if p.LocalDev == nil {
		gatewayAddr, err := FindGatewayAddr()
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		devs, err := FindAllDevs()
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		for _, dev := range devs {
			if dev.IsLoop {
				continue
			}
			for _, addr := range dev.Addrs {
				ipnet := net.IPNet{IP:addr.IP, Mask:addr.Mask}
				if ipnet.Contains(gatewayAddr.IP) {
					p.LocalDev = &Device{
						Name:         dev.Name,
						FriendlyName: dev.FriendlyName,
						Addrs:        append(make([]Addr, 0), addr),
						HardwareAddr: dev.HardwareAddr,
						IsLoop:       dev.IsLoop,
					}
					break
				}
			}
			if p.LocalDev != nil {
				break
			}
		}
	}
	if p.RemoteDev == nil {
		gatewayAddr, err := FindGatewayAddr()
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		devs, err := FindAllDevs()
		if err != nil {
			return fmt.Errorf("open: %w", err)
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
					p.RemoteDev = &Device{
						Name:         dev.Name,
						FriendlyName: dev.FriendlyName,
						Addrs:        append(make([]Addr, 0), addr),
						HardwareAddr: dev.HardwareAddr,
						IsLoop:       dev.IsLoop,
					}
					break
				}
			}
			if p.RemoteDev != nil {
				break
			}
		}
	} else {
		if p.RemoteDev.IsLoop {
			p.gatewayDev = p.RemoteDev
		} else {
			var err error
			p.gatewayDev, err = FindGatewayDev(p.RemoteDev.Name)
			if err != nil {
				return fmt.Errorf("open: %w", err)
			}
		}
	}
	if p.LocalDev == nil || p.RemoteDev == nil || p.gatewayDev == nil {
		return fmt.Errorf("open: %w", errors.New("can not determine device"))
	}
	if !p.LocalDev.IsLoop {
		fmt.Printf("Listen on %s %s [%s]\n", p.LocalDev.FriendlyName, p.LocalDev.Addrs[0].IP,
			p.LocalDev.HardwareAddr)
	} else {
		fmt.Printf("Listen on loopback %s\n", p.LocalDev.FriendlyName)
	}
	if !p.gatewayDev.IsLoop {
		fmt.Printf("Route upstream from %s %s [%s] to gateway %s [%s]\n", p.RemoteDev.FriendlyName,
			p.RemoteDev.Addrs[0].IP, p.RemoteDev.HardwareAddr, p.gatewayDev.Addrs[0].IP, p.gatewayDev.HardwareAddr)
	} else {
		fmt.Printf("Route upstream to loopback %s\n", p.RemoteDev.FriendlyName)
	}

	var err error
	p.localHandle, err = pcap.OpenLive(p.LocalDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = p.localHandle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d", p.LocalPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	localPacketSrc := gopacket.NewPacketSource(p.localHandle, p.localHandle.LinkType())
	go func() {
		for packet := range localPacketSrc.Packets() {
			p.handle(packet)
		}
	}()

	p.remoteHandle, err = pcap.OpenLive(p.RemoteDev.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	err = p.remoteHandle.SetBPFFilter(fmt.Sprintf("tcp and src host %s and dst port %d", p.RemoteAddr, p.LocalPort))
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	remotePacketSrc := gopacket.NewPacketSource(p.remoteHandle, p.remoteHandle.LinkType())
	go func() {
		for packet := range remotePacketSrc.Packets() {
			p.handle(packet)
		}
	}()

	select {}
}

// Close implements a method closes the pcap
func (p *Pcap) Close() {
	p.localHandle.Close()
	p.remoteHandle.Close()
}

func (p *Pcap) handle(packet gopacket.Packet) {
	packet.LinkLayer()
	switch t := packet.TransportLayer().LayerType(); t {
	case layers.LayerTypeTCP:
		fmt.Println(packet)
	default:
		fmt.Printf("Received packet with invalid transport protocol: %s\n", t)
	}
}
