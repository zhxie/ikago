package pcap

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"

	"../proxy"
)

type Device struct {
	Name         string
	Addrs        []string
	HardwareAddr string
}

// FindAllDevs implements a method enumerates all valid network devices in current computer
func FindAllDevs() ([]Device, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	m := make(map[string]string)
	inters, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, inter := range inters {
		addrs, err := inter.Addrs()
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, addr := range addrs {
			addrSplit := strings.Split(addr.String(), "/")
			_, exist := m[addrSplit[0]]
			if exist {
				return nil, errors.New("same address in multiple net interfaces")
			}
			m[addrSplit[0]] = inter.HardwareAddr.String()
		}
	}

	result := make([]Device, 0)
	if runtime.GOOS == "windows" {
		result = append(result, LoopDev())
	}
	for _, dev := range devs {
		if len(dev.Addresses) <= 0 {
			continue
		}
		var hardwareAddr string
		addrs := make([]string, 0)
		for _, addr := range dev.Addresses {
			if hardwareAddr == "" {
				elem, exist := m[addr.IP.String()]
				if exist {
					hardwareAddr = elem
				}
			}
			addrs = append(addrs, addr.IP.String())
		}
		if hardwareAddr == "" {
			continue
		}
		result = append(result, Device{Name: dev.Name, Addrs: addrs, HardwareAddr: hardwareAddr})
	}

	return result, err
}

// LoopDev returns loopback network device in current computer
func LoopDev() Device {
	if runtime.GOOS == "windows" {
		addresses := append(make([]string, 0), "::1", "127.0.0.1")
		return Device{Name: "\\Device\\NPF_Loopback", Addrs: addresses}
	}
	return Device{Name: "lo"}
}

// FindGateway implements a method finds the gateway
func FindGateway(dev string) (*Device, error) {
	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(dev, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	err = handle.SetBPFFilter(fmt.Sprintf("udp and dst %s and dst port 65535", ip.String()))
	if err != nil {
		return nil, err
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
		return nil, err
	}

	packet := <-c
	if packet == nil {
		return nil, errors.New("timeout")
	}
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil, errors.New("layer type is out of range")
	}
	ethernetPacket, ok := ethernetLayer.(*layers.Ethernet)
	if !ok {
		return nil, errors.New("ethernet packet is invalid")
	}
	addrs := append(make([]string, 0), ip.String())
	return &Device{Addrs: addrs, HardwareAddr: ethernetPacket.SrcMAC.String()}, nil
}

func (dev Device) String() string {
	result := dev.Name + ": "
	if dev.HardwareAddr != "" {
		result = result + dev.HardwareAddr + ", "
	}
	for i, address := range dev.Addrs {
		result = result + address
		if i < len(dev.Addrs)-1 {
			result = result + ", "
		}
	}
	return result
}
