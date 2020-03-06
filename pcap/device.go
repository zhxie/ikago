package pcap

import (
	"errors"
	"fmt"
	"ikago/log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
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
		result = dev.Name + " [" + dev.HardwareAddr.String() + "]: "
	} else {
		result = dev.Name + ": "
	}
	for i, addr := range dev.IPAddrs {
		result = result + addr.IP.String()
		if i < len(dev.IPAddrs)-1 {
			result = result + ", "
		}
	}
	if dev.IsLoop {
		result = result + " (Loopback)"
	}
	return result
}

// AliasString returns the string of device with its alias
func (dev Device) AliasString() string {
	var result string
	if dev.HardwareAddr != nil {
		result = dev.Alias + " [" + dev.HardwareAddr.String() + "]: "
	} else {
		result = dev.Alias + ": "
	}
	for i, addr := range dev.IPAddrs {
		result = result + addr.IP.String()
		if i < len(dev.IPAddrs)-1 {
			result = result + ", "
		}
	}
	if dev.IsLoop {
		result = result + " (Loopback)"
	}
	return result
}

const flagPcapLoopback = 1

// FindAllDevs returns all valid network devices in current computer
func FindAllDevs() ([]*Device, error) {
	t := make([]*Device, 0)
	result := make([]*Device, 0)

	// Enumerate system's network interfaces
	inters, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("find all devs: %w", err)
	}
	for _, inter := range inters {
		// Ignore not up and not loopback interfaces
		if inter.Flags&net.FlagUp == 0 && inter.Flags&net.FlagLoopback == 0 {
			continue
		}
		var isLoop bool
		if inter.Flags&net.FlagLoopback != 0 {
			isLoop = true
		}
		addrs, err := inter.Addrs()
		if err != nil {
			log.Errorln(fmt.Errorf("find all devs: %w", err))
			continue
		}
		as := make([]*net.IPNet, 0)
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				log.Errorln(fmt.Errorf("find all devs: %w", fmt.Errorf("invalid address in %s", inter.Name)))
				continue
			}
			as = append(as, ipnet)
		}
		t = append(t, &Device{Alias: inter.Name, IPAddrs: as, HardwareAddr: inter.HardwareAddr, IsLoop: isLoop})
	}

	// Enumerate pcap devices
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find all devs: %w", err)
	}
	for _, dev := range devs {
		// Match pcap device with interface
		if dev.Flags&flagPcapLoopback != 0 {
			d := FindLoopDev(t)
			if d == nil {
				continue
			}
			if d.Name != "" {
				return nil, fmt.Errorf("find all devs: %w", errors.New("too many loopback devices"))
			}
			d.Name = dev.Name
			result = append(result, d)
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
					return nil, fmt.Errorf("find all devs: %w", errors.New("multiple devices with same address"))
				}
				d.Name = dev.Name
				result = append(result, d)
				break
			}
		}
	}

	return result, nil
}

// FindAllIPv4Devs returns all valid IPv4 network devices in current computer
func FindAllIPv4Devs() ([]*Device, error) {
	devs, err := FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find all ipv4 devs: %w", err)
	}

	result := make([]*Device, 0)
	for _, dev := range devs {
		ipv4Dev := dev.To4()
		if ipv4Dev == nil {
			continue
		}
		result = append(result, ipv4Dev)
	}

	return result, nil
}

// FindAllIPv6Devs returns all valid IPv6 network devices in current computer
func FindAllIPv6Devs() ([]*Device, error) {
	devs, err := FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find all ipv6 devs: %w", err)
	}

	result := make([]*Device, 0)
	for _, dev := range devs {
		ipv6Dev := dev.To16Only()
		if ipv6Dev == nil {
			continue
		}
		result = append(result, ipv6Dev)
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
func FindGatewayAddr() (*net.IPNet, error) {
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("find gateway addr: %w", err)
	}
	return &net.IPNet{IP: ip}, nil
}

// FindGatewayDev returns the gateway device
func FindGatewayDev(dev string) (*Device, error) {
	// Find gateway's IP
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("find gateway dev: %w", err)
	}

	// Create a packet capture for testing
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

	// Attempt to send and capture a UDP packet
	err = sendUDPPacket(ip.String()+":65535", []byte("0"))
	if err != nil {
		return nil, fmt.Errorf("find gateway dev: %w", err)
	}

	// Analyze the packet and get gateway's hardware address
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
	addrs := append(make([]*net.IPNet, 0), &net.IPNet{IP: ip})
	return &Device{Alias: "Gateway", IPAddrs: addrs, HardwareAddr: ethernetPacket.DstMAC}, nil
}

// FindListenDevs returns all valid pcap devices for listening
func FindListenDevs(strDevs []string, isLocal bool, option IPVersionOption) ([]*Device, error) {
	result := make([]*Device, 0)

	var devs []*Device
	var err error
	switch option {
	case IPv4AndIPv6:
		devs, err = FindAllDevs()
	case IPv4Only:
		devs, err = FindAllIPv4Devs()
	case IPv6Only:
		devs, err = FindAllIPv6Devs()
	}
	if err != nil {
		return nil, fmt.Errorf("find listen devs: %w", err)
	}

	if len(strDevs) <= 0 {
		if isLocal {
			for _, dev := range devs {
				if dev.IsLoop {
					result = append(result, dev)
				}
			}
		} else {
			result = devs
		}
	} else {
		m := make(map[string]*Device)
		for _, dev := range devs {
			m[dev.Name] = dev
		}

		for _, strDev := range strDevs {
			dev, ok := m[strDev]
			if !ok {
				return nil, fmt.Errorf("find listen devs: %w", fmt.Errorf("unknown device %s", strDev))
			}
			if isLocal {
				if dev.IsLoop {
					result = append(result, dev)
				}
			} else {
				result = append(result, dev)
			}
		}
	}

	return result, nil
}

// FindUpstreamDevAndGateway returns the pcap device for routing upstream and the gateway
func FindUpstreamDevAndGateway(strDev string, isLocal bool, option IPVersionOption) (upDev, gatewayDev *Device, err error) {
	var devs []*Device
	switch option {
	case IPv4AndIPv6:
		devs, err = FindAllDevs()
	case IPv4Only:
		devs, err = FindAllIPv4Devs()
	case IPv6Only:
		devs, err = FindAllIPv6Devs()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("find upstream devs and gateway: %w", err)
	}

	if strDev != "" {
		// Find upstream device
		for _, dev := range devs {
			if dev.Name == strDev {
				if isLocal {
					upDev = FindLoopDev(devs)
				} else {
					upDev = dev
				}
				break
			}
		}
		if upDev == nil {
			return nil, nil, fmt.Errorf("find upstream dev: %w", fmt.Errorf("unknown device %s", strDev))
		}
		// Find gateway
		if upDev.IsLoop {
			gatewayDev = upDev
		} else {
			gatewayDev, err = FindGatewayDev(upDev.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("find gateway: %w", err)
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
				return nil, nil, fmt.Errorf("find gateway: %w", errors.New("different domain in upstream device and gateway"))
			}
			upDev = newUpDev
		}
	} else {
		if isLocal {
			// Find upstream device and gateway
			loopDev := FindLoopDev(devs)
			upDev = loopDev
			gatewayDev = upDev
		} else {
			// Find upstream device and gateway
			gatewayAddr, err := FindGatewayAddr()
			if err != nil {
				return nil, nil, fmt.Errorf("find upstream dev: %w", fmt.Errorf("find gateway's address: %w", err))
			}
			for _, dev := range devs {
				if dev.IsLoop {
					continue
				}
				// Test if device's IP is in the same domain of the gateway's
				for _, addr := range dev.IPAddrs {
					if addr.Contains(gatewayAddr.IP) {
						gatewayDev, err = FindGatewayDev(dev.Name)
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
	}
	return upDev, gatewayDev, nil
}
