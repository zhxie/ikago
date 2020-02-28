package pcap

import (
	"errors"
	"fmt"
	"net"
)

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
			return nil, nil,
				fmt.Errorf("find upstream dev: %w", fmt.Errorf("unknown device %s", strDev))
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
						FriendlyName: upDev.FriendlyName,
						IPAddrs:      append(make([]*net.IPNet, 0), addr),
						HardwareAddr: upDev.HardwareAddr,
						IsLoop:       upDev.IsLoop,
					}
					break
				}
			}
			if newUpDev == nil {
				return nil, nil, fmt.Errorf("find gateway: %w",
					errors.New("different domain in upstream device and gateway"))
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
				return nil, nil,
					fmt.Errorf("find upstream dev: %w", fmt.Errorf("find gateway's address: %w", err))
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
							FriendlyName: dev.FriendlyName,
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
