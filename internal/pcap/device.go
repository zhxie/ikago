package pcap

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"ikago/internal/log"
	"net"
	"strings"
	"time"
)

// Device describes an network device
type Device struct {
	Name         string
	Alias        string
	IPAddrs      []*net.IPNet
	HardwareAddr net.HardwareAddr
	IsLoop       bool
}

// IPAddr returns the first IP address of the device
func (dev *Device) IPAddr() *net.IPNet {
	if len(dev.IPAddrs) > 0 {
		return dev.IPAddrs[0]
	}
	return nil
}

// IPv4Addr returns the first IPv4 address of the device
func (dev *Device) IPv4Addr() *net.IPNet {
	for _, addr := range dev.IPAddrs {
		if addr.IP.To4() != nil {
			return addr
		}
	}
	return nil
}

// IPv6Addr returns the first IPv6Addr address of the device
func (dev *Device) IPv6Addr() *net.IPNet {
	for _, addr := range dev.IPAddrs {
		if addr.IP.To4() == nil && addr.IP.To16() != nil {
			return addr
		}
	}
	return nil
}

// To4 returns the device with IPv4 addresses only
func (dev *Device) To4() *Device {
	addrs := make([]*net.IPNet, 0)
	for _, addr := range dev.IPAddrs {
		if addr.IP.To4() != nil {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) <= 0 {
		return nil
	}
	return &Device{
		Name:         dev.Name,
		Alias:        dev.Alias,
		IPAddrs:      addrs,
		HardwareAddr: dev.HardwareAddr,
		IsLoop:       dev.IsLoop,
	}
}

// To16Only returns the device with IPv6 addresses only
func (dev *Device) To16Only() *Device {
	addrs := make([]*net.IPNet, 0)
	for _, addr := range dev.IPAddrs {
		if addr.IP.To4() == nil {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) <= 0 {
		return nil
	}
	return &Device{
		Name:         dev.Name,
		Alias:        dev.Alias,
		IPAddrs:      addrs,
		HardwareAddr: dev.HardwareAddr,
		IsLoop:       dev.IsLoop,
	}
}

func (dev Device) String() string {
	var result string
	if dev.HardwareAddr != nil {
		result = dev.Alias + " [" + dev.HardwareAddr.String() + "]: "
	} else {
		result = dev.Alias + ": "
	}
	addrs := make([]string, 0)
	for _, addr := range dev.IPAddrs {
		addrs = append(addrs, addr.IP.String())
	}
	result = result + strings.Join(addrs, ", ")
	if dev.IsLoop {
		result = result + " (Loopback)"
	}
	return result
}

const flagPcapLoopback = 1

var blacklist map[string]bool

// FindAllDevs returns all valid network devices in current computer
func FindAllDevs() ([]*Device, error) {
	t := make([]*Device, 0)
	result := make([]*Device, 0)
	if blacklist == nil {
		blacklist = make(map[string]bool)
	}

	// Enumerate system's network interfaces
	inters, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("find interfaces: %w", err)
	}
	for _, inter := range inters {
		// Loopback interface
		var isLoop bool
		if inter.Flags&net.FlagLoopback != 0 {
			isLoop = true
		}

		// Ignore not up and not loopback interfaces
		if inter.Flags&net.FlagUp == 0 && !isLoop {
			continue
		}

		addrs, err := inter.Addrs()
		if err != nil {
			log.Errorln(fmt.Errorf("parse interface %s: %w", inter.Name, err))
			continue
		}

		as := make([]*net.IPNet, 0)
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				log.Errorln(fmt.Errorf("parse interface %s: %w", inter.Name, errors.New("invalid address")))
				continue
			}
			as = append(as, ipnet)
		}

		t = append(t, &Device{Alias: inter.Name, IPAddrs: as, HardwareAddr: inter.HardwareAddr, IsLoop: isLoop})
	}

	// Enumerate pcap devices
	mid := make([]*Device, 0)
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find pcap devices: %w", err)
	}
	for _, dev := range devs {
		// Check blacklist
		_, ok := blacklist[dev.Name]
		if ok {
			continue
		}

		// Match pcap device with interface
		if dev.Flags&flagPcapLoopback != 0 {
			d := FindLoopDev(t)
			if d == nil {
				continue
			}
			if d.Name != "" {
				// return nil, errors.New("too many loopback devices")
				blacklist[dev.Name] = true
				blacklist[d.Name] = true
				log.Infof("Device %s is a loopback device but so is %s, these devices will not be used\n", dev.Name, d.Name)
			}
			d.Name = dev.Name
			mid = append(mid, d)
		} else {
			if len(dev.Addresses) <= 0 {
				continue
			}
			for _, addr := range dev.Addresses {
				d := FindDev(t, addr.IP)
				if d == nil {
					continue
				}
				if d.Name != "" {
					// return nil, fmt.Errorf("parse pcap device %s: %w", dev.Name, fmt.Errorf("same address with %s", d.Name))
					blacklist[dev.Name] = true
					blacklist[d.Name] = true
					log.Infof("Device %s has the same address with %s, these devices will not be used\n", dev.Name, d.Name)
					break
				}
				d.Name = dev.Name
				mid = append(mid, d)
				break
			}
		}
	}

	// Check blacklist
	for _, dev := range mid {
		_, ok := blacklist[dev.Name]
		if !ok {
			result = append(result, dev)
		}
	}

	return result, nil
}

// FindLoopDev returns the loop device in designated devices
func FindLoopDev(devs []*Device) *Device {
	for _, dev := range devs {
		if dev.IsLoop {
			return dev
		}
	}
	return nil
}

// FindDev returns the device with designated IP in designated devices
func FindDev(devs []*Device, ip net.IP) *Device {
	for _, dev := range devs {
		for _, addr := range dev.IPAddrs {
			if addr.IP.Equal(ip) {
				return dev
			}
		}
	}
	return nil
}

// FindGatewayAddr returns the gateway's address
func FindGatewayAddr() (net.IP, error) {
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("discover gateway: %w", err)
	}

	return ip, nil
}

// FindGatewayDev returns the gateway device
func FindGatewayDev(dev string, ip net.IP) (*Device, error) {
	// Create a packet capture for testing
	handle, err := pcap.OpenLive(dev, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open device %s: %w", dev, err)
	}
	err = handle.SetBPFFilter(fmt.Sprintf("udp and dst %s and dst port 65535", ip.String()))
	if err != nil {
		return nil, fmt.Errorf("set bpf filter: %w", err)
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

	// Attempt to send and capture a UDP packet
	err = sendUDPPacket(ip.String()+":65535", []byte("0"))
	if err != nil {
		return nil, fmt.Errorf("send udp packet: %w", err)
	}

	// Analyze the packet and get gateway's hardware address
	packet := <-c
	if packet == nil {
		return nil, errors.New("timeout")
	}
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil, errors.New("missing ethernet layer")
	}
	ethernetPacket, ok := ethernetLayer.(*layers.Ethernet)
	if !ok {
		return nil, errors.New("invalid packet")
	}
	addrs := append(make([]*net.IPNet, 0), &net.IPNet{IP: ip})
	return &Device{Alias: "Gateway", IPAddrs: addrs, HardwareAddr: ethernetPacket.DstMAC}, nil
}

// FindListenDevs returns all valid pcap devices for listening
func FindListenDevs(names []string) ([]*Device, error) {
	result := make([]*Device, 0)

	devs, err := FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find all devices: %w", err)
	}

	if len(names) <= 0 {
		result = devs
	} else {
		m := make(map[string]*Device)
		for _, dev := range devs {
			m[dev.Alias] = dev
		}

		for _, name := range names {
			dev, ok := m[name]
			if !ok {
				return nil, fmt.Errorf("unknown listen device %s", name)
			}
			result = append(result, dev)
		}
	}

	return result, nil
}

// FindUpstreamDevAndGatewayDev returns the pcap device for routing upstream and the gateway
func FindUpstreamDevAndGatewayDev(name string, gateway net.IP) (upDev, gatewayDev *Device, err error) {
	devs, err := FindAllDevs()
	if err != nil {
		return nil, nil, fmt.Errorf("find all devices: %w", err)
	}

	if name != "" {
		// Find upstream device
		for _, dev := range devs {
			if dev.Alias == name {
				upDev = dev
				break
			}
		}
		if upDev == nil {
			return nil, nil, fmt.Errorf("unknown upstream device %s", name)
		}

		// Find gateway device
		if upDev.IsLoop {
			gatewayDev = upDev
		} else {
			// Find gateway's address
			if gateway == nil {
				gateway, err = FindGatewayAddr()
				if err != nil {
					return nil, nil, fmt.Errorf("find gateway address: %w", err)
				}
			}

			gatewayDev, err = FindGatewayDev(upDev.Name, gateway)
			if err != nil {
				return nil, nil, fmt.Errorf("find gateway device: %w", err)
			}

			// Test if device's IP is in the same domain of the gateway's
			var newUpDev *Device
			for _, addr := range upDev.IPAddrs {
				if addr.Contains(gatewayDev.IPAddrs[0].IP) {
					newUpDev = &Device{
						Name:         upDev.Name,
						Alias:        upDev.Alias,
						IPAddrs:      append(make([]*net.IPNet, 0), addr),
						HardwareAddr: upDev.HardwareAddr,
						IsLoop:       upDev.IsLoop,
					}
					break
				}
			}
			if newUpDev == nil {
				return nil, nil, fmt.Errorf("different domain in upstream device %s and gateway", upDev.Alias)
			}

			upDev = newUpDev
		}
	} else {
		// Find gateway's address
		if gateway == nil {
			gateway, err = FindGatewayAddr()
			if err != nil {
				return nil, nil, fmt.Errorf("find gateway address: %w", err)
			}
		}

		// Find upstream device and gateway device
		for _, dev := range devs {
			if dev.IsLoop {
				continue
			}

			// Test if device's IP is in the same domain of the gateway's
			for _, addr := range dev.IPAddrs {
				if addr.Contains(gateway) {
					gatewayDev, err = FindGatewayDev(dev.Name, gateway)
					if err != nil {
						continue
					}
					upDev = &Device{
						Name:         dev.Name,
						Alias:        dev.Alias,
						IPAddrs:      append(make([]*net.IPNet, 0), addr),
						HardwareAddr: dev.HardwareAddr,
						IsLoop:       dev.IsLoop,
					}
					break
				}
			}
			if upDev != nil {
				break
			}
		}
	}

	return upDev, gatewayDev, nil
}
