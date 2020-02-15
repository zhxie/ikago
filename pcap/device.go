package pcap

import (
	"github.com/google/gopacket/pcap"
	"runtime"
)

type Device struct {
	Name      string
	Addresses []string
}

// FindAllDevs implements a method enumerate all valid network devices in current computer
func FindAllDevs() ([]Device, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	result := make([]Device, 0)
	if runtime.GOOS == "windows" {
		result = append(result, LoopDev())
	}
	for _, dev := range devs {
		if len(dev.Addresses) <= 0 {
			continue
		}
		addresses := make([]string, 0)
		for _, address := range dev.Addresses {
			addresses = append(addresses, address.IP.String())
		}
		result = append(result, Device{Name:dev.Name, Addresses:addresses})
	}
	return result, err
}

// LoopDev returns loopback network device in current computer
func LoopDev() Device {
	if runtime.GOOS == "windows" {
		addresses := append(make([]string, 0), "::1", "127.0.0.1")
		return Device{Name:"\\Device\\NPF_Loopback", Addresses:addresses}
	}
	return Device{Name:"lo"}
}

func (dev Device) String() string {
	result := dev.Name + ": "
	for i, address := range dev.Addresses {
		result = result + address
		if i < len(dev.Addresses)-1 {
			result = result + ", "
		}
	}
	return result
}
