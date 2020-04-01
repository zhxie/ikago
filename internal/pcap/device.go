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

// Device describes an network device.
type Device struct {
	name         string
	alias        string
	ipAddrs      []*net.IPNet
	hardwareAddr net.HardwareAddr
	isLoop       bool
}

// Name returns the pcap name of the device.
func (dev *Device) Name() string {
	return dev.name
}

// Alias returns the alias of the device.
func (dev *Device) Alias() string {
	return dev.alias
}

// IPAddrs returns all IP address of the device.
func (dev *Device) IPAddrs() []*net.IPNet {
	return dev.ipAddrs
}

// HardwareAddr returns the hardware address of the device.
func (dev *Device) HardwareAddr() net.HardwareAddr {
	return dev.hardwareAddr
}

// IsLoop returns if the device is a loopback device.
func (dev *Device) IsLoop() bool {
	return dev.isLoop
}

// IPAddr returns the first IP address of the device.
func (dev *Device) IPAddr() *net.IPNet {
	if len(dev.ipAddrs) > 0 {
		return dev.ipAddrs[0]
	}

	return nil
}

// IPv4Addr returns the first IPv4 address of the device.
func (dev *Device) IPv4Addr() *net.IPNet {
	for _, addr := range dev.ipAddrs {
		if addr.IP.To4() != nil {
			return addr
		}
	}

	return nil
}

// IPv6Addr returns the first IPv6Addr address of the device.
func (dev *Device) IPv6Addr() *net.IPNet {
	for _, addr := range dev.ipAddrs {
		if addr.IP.To4() == nil && addr.IP.To16() != nil {
			return addr
		}
	}

	return nil
}

// To4 returns the device with IPv4 addresses only.
func (dev *Device) To4() *Device {
	addrs := make([]*net.IPNet, 0)

	for _, addr := range dev.ipAddrs {
		if addr.IP.To4() != nil {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) <= 0 {
		return nil
	}

	return &Device{
		name:         dev.name,
		alias:        dev.alias,
		ipAddrs:      addrs,
		hardwareAddr: dev.hardwareAddr,
		isLoop:       dev.isLoop,
	}
}

// To16Only returns the device with IPv6 addresses only.
func (dev *Device) To16Only() *Device {
	addrs := make([]*net.IPNet, 0)

	for _, addr := range dev.ipAddrs {
		if addr.IP.To4() == nil {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) <= 0 {
		return nil
	}

	return &Device{
		name:         dev.name,
		alias:        dev.alias,
		ipAddrs:      addrs,
		hardwareAddr: dev.hardwareAddr,
		isLoop:       dev.isLoop,
	}
}

func (dev Device) String() string {
	var result string

	if dev.hardwareAddr != nil {
		result = dev.alias + " [" + dev.hardwareAddr.String() + "]: "
	} else {
		result = dev.alias + ": "
	}

	addrs := make([]string, 0)
	for _, addr := range dev.ipAddrs {
		addrs = append(addrs, addr.IP.String())
	}
	result = result + strings.Join(addrs, ", ")

	if dev.isLoop {
		result = result + " (Loopback)"
	}

	return result
}

// IPv4String returns a string with IPv4 addresses only.
func (dev Device) IPv4String() string {
	var result string

	if dev.hardwareAddr != nil {
		result = dev.alias + " [" + dev.hardwareAddr.String() + "]: "
	} else {
		result = dev.alias + ": "
	}

	addrs := make([]string, 0)
	for _, addr := range dev.ipAddrs {
		if addr.IP.To4() != nil {
			addrs = append(addrs, addr.IP.String())
		}
	}
	if len(addrs) > 0 {
		result = result + strings.Join(addrs, ", ")
	} else {
		result = result + "(No IPv4 address)"
	}

	if dev.isLoop {
		result = result + " (Loopback)"
	}

	return result
}

const flagPcapLoopback = 1

var blacklist map[string]bool

// FindAllDevs returns all valid network devices in current computer.
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

		t = append(t, &Device{alias: inter.Name, ipAddrs: as, hardwareAddr: inter.HardwareAddr, isLoop: isLoop})
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
			if d.name != "" {
				// return nil, errors.New("too many loopback devices")
				blacklist[dev.Name] = true
				blacklist[d.name] = true
				log.Infof("Device %s is a loopback device but so is %s, these devices will not be used\n", dev.Name, d.name)
			}
			d.name = dev.Name
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
				if d.name != "" {
					// return nil, fmt.Errorf("parse pcap device %s: %w", dev.Name, fmt.Errorf("same address with %s", d.Name))
					blacklist[dev.Name] = true
					blacklist[d.name] = true
					log.Infof("Device %s has the same address with %s, these devices will not be used\n", dev.Name, d.name)
					break
				}
				d.name = dev.Name
				mid = append(mid, d)
				break
			}
		}
	}

	// Check blacklist
	for _, dev := range mid {
		_, ok := blacklist[dev.name]
		if !ok {
			result = append(result, dev)
		}
	}

	return result, nil
}

// FindLoopDev returns the loop device in designated devices.
func FindLoopDev(devs []*Device) *Device {
	for _, dev := range devs {
		if dev.isLoop {
			return dev
		}
	}

	return nil
}

// FindDev returns the device with designated IP in designated devices.
func FindDev(devs []*Device, ip net.IP) *Device {
	for _, dev := range devs {
		for _, addr := range dev.ipAddrs {
			if addr.IP.Equal(ip) {
				return dev
			}
		}
	}

	return nil
}

// FindGatewayAddr returns the gateway's address.
func FindGatewayAddr() (net.IP, error) {
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("discover gateway: %w", err)
	}

	return ip, nil
}

// FindGatewayDev returns the gateway device.
func FindGatewayDev(dev string, ip net.IP) (*Device, error) {
	conn, err := createPureRawConn(dev, fmt.Sprintf("ip && udp && dst %s && dst port 65535", ip))

	c := make(chan gopacket.Packet, 1)
	go func() {
		packet, err := conn.ReadPacket()
		if err != nil {
			c <- nil
		}
		c <- packet
	}()
	go func() {
		time.Sleep(3 * time.Second)
		c <- nil
	}()

	// Attempt to send and capture a UDP packet
	err = SendUDPPacket(ip.String()+":65535", []byte("0"))
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

	return &Device{alias: "Gateway", ipAddrs: addrs, hardwareAddr: ethernetPacket.DstMAC}, nil
}

// FindListenDevs returns all valid pcap devices for listening.
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
			m[dev.alias] = dev
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

// FindUpstreamDevAndGatewayDev returns the pcap device for routing upstream and the gateway.
func FindUpstreamDevAndGatewayDev(name string, gateway net.IP) (upDev, gatewayDev *Device, err error) {
	devs, err := FindAllDevs()
	if err != nil {
		return nil, nil, fmt.Errorf("find all devices: %w", err)
	}

	if name != "" {
		// Find upstream device
		for _, dev := range devs {
			if dev.alias == name {
				upDev = dev
				break
			}
		}
		if upDev == nil {
			return nil, nil, fmt.Errorf("unknown upstream device %s", name)
		}

		// Find gateway device
		if upDev.isLoop {
			gatewayDev = upDev
		} else {
			// Find gateway's address
			if gateway == nil {
				gateway, err = FindGatewayAddr()
				if err != nil {
					return nil, nil, fmt.Errorf("find gateway address: %w", err)
				}
			}

			gatewayDev, err = FindGatewayDev(upDev.name, gateway)
			if err != nil {
				return nil, nil, fmt.Errorf("find gateway device: %w", err)
			}

			// Test if device's IP is in the same domain of the gateway's
			var newUpDev *Device
			for _, addr := range upDev.ipAddrs {
				if addr.Contains(gatewayDev.ipAddrs[0].IP) {
					newUpDev = &Device{
						name:         upDev.name,
						alias:        upDev.alias,
						ipAddrs:      append(make([]*net.IPNet, 0), addr),
						hardwareAddr: upDev.hardwareAddr,
						isLoop:       upDev.isLoop,
					}
					break
				}
			}
			if newUpDev == nil {
				return nil, nil, fmt.Errorf("different domain in upstream device %s and gateway", upDev.alias)
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
			if dev.isLoop {
				continue
			}

			// Test if device's IP is in the same domain of the gateway's
			for _, addr := range dev.ipAddrs {
				if addr.Contains(gateway) {
					gatewayDev, err = FindGatewayDev(dev.name, gateway)
					if err != nil {
						continue
					}
					upDev = &Device{
						name:         dev.name,
						alias:        dev.alias,
						ipAddrs:      append(make([]*net.IPNet, 0), addr),
						hardwareAddr: dev.hardwareAddr,
						isLoop:       dev.isLoop,
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
