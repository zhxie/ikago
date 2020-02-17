package pcap

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"

	"../proxy"
)

// Addr describes an address of an device
type Addr struct {
	IP   net.IP
	Mask net.IPMask
}

// Device describes an network device
type Device struct {
	Name         string
	FriendlyName string
	Addrs        []Addr
	HardwareAddr net.HardwareAddr
	IsLoop       bool
}

const flagPcapLoopback = 1

// FindAllDevs returns all valid network devices in current computer
func FindAllDevs() ([]Device, error) {
	t := make([]Device, 0)
	result := make([]Device, 0)

	inters, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("find all devs: %w", err)
	}
	for _, inter := range inters {
		if inter.Flags&net.FlagUp == 0 && inter.Flags&net.FlagLoopback == 0 {
			continue
		}
		var isLoop bool
		if inter.Flags&net.FlagLoopback != 0 {
			isLoop = true
		}
		addrs, err := inter.Addrs()
		if err != nil {
			fmt.Println(fmt.Errorf("find all devs: %w", err))
			continue
		}
		as := make([]Addr, 0)
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				fmt.Println(fmt.Errorf("find all devs: %w", errors.New("invalid address")))
				continue
			}
			as = append(as, Addr{IP:ipnet.IP, Mask:ipnet.Mask})
		}
		t = append(t, Device{FriendlyName:inter.Name, Addrs:as, HardwareAddr:inter.HardwareAddr, IsLoop:isLoop})
	}

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find all devs: %w", err)
	}
	for _, dev := range devs {
		if dev.Flags&flagPcapLoopback != 0 {
			d := findLoopDev(&t)
			if d == nil {
				continue
			}
			if d.Name != "" {
				return nil, fmt.Errorf("find all devs: %w", errors.New("multiple loopback devices"))
			}
			d.Name = dev.Name
			result = append(result, *d)
			continue
		}
		if len(dev.Addresses) <= 0 {
			continue
		}
		for _, addr := range dev.Addresses {
			d := findDev(&t, addr.IP)
			if d == nil {
				continue
			}
			if d.Name != "" {
				return nil,fmt.Errorf("find all devs: %w", errors.New("multiple devices with same address"))
			}
			d.Name = dev.Name
			result = append(result, *d)
			break
		}
	}

	return result, nil
}

func findLoopDev(devs *[]Device) *Device {
	for i := 0; i < len(*devs); i++ {
		if (*devs)[i].IsLoop {
			return &(*devs)[i]
		}
	}
	return nil
}

func findDev(devs *[]Device, ip net.IP) *Device {
	for i := 0; i < len(*devs); i++ {
		for j := 0; j < len((*devs)[i].Addrs); j++ {
			if (*devs)[i].Addrs[j].IP.Equal(ip) {
				return &(*devs)[i]
			}
		}
	}
	return nil
}

// FindLoopDev returns the loop device in current computer
func FindLoopDev() (*Device, error) {
	devs, err := FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find loop dev: %w", err)
	}
	return findLoopDev(&devs), nil
}

// FindGatewayAddr returns the gatewayDev address
func FindGatewayAddr() (*Addr, error) {
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("find gateway addr: %w", err)
	}
	return &Addr{IP:ip}, nil
}

// FindGatewayDev returns the gatewayDev device
func FindGatewayDev(dev string) (*Device, error) {
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("find gateway dev: %w", err)
	}

	handle, err := pcap.OpenLive(dev, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("find gateway dev: %w", err)
	}
	err = handle.SetBPFFilter(fmt.Sprintf("udp and dst %s and dst port 65535", ip.String()))
	if err != nil {
		return nil, fmt.Errorf("find gateway dev: %w", err)
	}
	localPacketSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	c := make(chan gopacket.Packet, 1)
	go func() {
		for packet := range localPacketSrc.Packets() {
			c <- packet
			break
		}
	}()
	go func() {
		time.Sleep(3 * time.Second)
		c <- nil
	}()

	err = proxy.SendUDPPacket(ip.String()+":65535", []byte("0"))
	if err != nil {
		return nil, fmt.Errorf("find gateway dev: %w", err)
	}

	packet := <-c
	if packet == nil {
		return nil, fmt.Errorf("find gateway dev: %w", errors.New("timeout"))
	}
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil, fmt.Errorf("find gateway dev: %w", errors.New("layer type out of range"))
	}
	ethernetPacket, ok := ethernetLayer.(*layers.Ethernet)
	if !ok {
		return nil, fmt.Errorf("find gateway dev: %w", errors.New("invalid packet"))
	}
	addrs := append(make([]Addr, 0), Addr{IP:ip})
	return &Device{Addrs: addrs, HardwareAddr: ethernetPacket.DstMAC}, nil
}

func (dev Device) String() string {
	var result string
	if dev.HardwareAddr != nil {
		result = dev.Name + " [" + dev.HardwareAddr.String() + "]: "
	} else {
		result = dev.Name + ": "
	}
	for i, addr := range dev.Addrs {
		result = result + addr.IP.String()
		if i < len(dev.Addrs)-1 {
			result = result + ", "
		}
	}
	if dev.IsLoop {
		result = result + " (Loopback)"
	}
	return result
}
