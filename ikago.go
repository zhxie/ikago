package main

import (
	"./pcap"
	"./proxy"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
var argListenLocal = flag.Bool("listen-local", false, "Listen loopback device only.")
var argListenDevs = flag.String("listen-devices", "", "Designated pcap devices for listening.")
var argUpLocal = flag.Bool("upstream-local", false, "Route upstream to loopback device only.")
var argUpDev = flag.String("upstream-device", "", "Designated pcap device for routing upstream to.")
var argListenPort = flag.Int("p", 0, "Port for listening.")
var argUpPort = flag.Int("upstream-port", 0, "Port for routing upstream.")
var argServer = flag.String("s", "", "Server.")

func main() {
	var (
		serverIP   net.IP
		serverPort uint64
		err        error
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
		gatewayDev *pcap.Device
	)

	// Parse arguments
	flag.Parse()
	if *argListDevs {
		fmt.Println("Available devices are listed below, use -listen-device [device] or " +
			"-upstream-device [device] to designate device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("list devices: %w", err))
			os.Exit(1)
		}
		for _, dev := range devs {
			fmt.Printf("  %s\n", dev)
		}
		os.Exit(0)
	}
	if *argListenPort == 0 {
		fmt.Fprintln(os.Stderr, "Please provide listen port by -p [port].")
		os.Exit(1)
	}
	if *argServer == "" {
		fmt.Fprintln(os.Stderr, "Please provide server by -s [address:port].")
		os.Exit(1)
	}

	// Verify parameters
	if *argListenPort <= 0 || *argListenPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("listen port out of range")))
		os.Exit(1)
	}
	if *argUpPort < 0 || *argUpPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("upstream port out of range")))
		os.Exit(1)
	}
	// Randomize upstream port
	if *argUpPort == 0 {
		s := rand.NewSource(time.Now().UnixNano())
		r := rand.New(s)
		for {
			randUpPort := 49152 + r.Intn(16384)
			argUpPort = &randUpPort
			if *argListenPort != *argUpPort {
				break
			}
		}
	}
	if *argListenPort == *argUpPort {
		fmt.Fprintln(os.Stderr,
			fmt.Errorf("parse: %w", errors.New("same port for listening and routing upstream")))
		os.Exit(1)
	}
	serverSplit := strings.Split(*argServer, ":")
	if len(serverSplit) < 2 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("invalid server")))
		os.Exit(1)
	}
	serverIP = net.ParseIP(serverSplit[0])
	if serverIP == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("invalid server ip")))
		os.Exit(1)
	}
	serverPort, err = strconv.ParseUint(serverSplit[len(serverSplit) - 1], 10, 16)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("invalid server port")))
		os.Exit(1)
	}
	if serverPort <= 0 || serverPort >= 65535 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("server port out of range")))
		os.Exit(1)
	}
	fmt.Printf("Starting proxying from :%d through :%d to %s...\n",
		*argListenPort, *argUpPort, *argServer)

	// Find devices
	if *argListenDevs == "" {
		listenDevs, err = findListenDevs(nil, *argListenLocal)
	} else {
		listenDevs, err = findListenDevs(strings.Split(*argListenDevs, ","), *argListenLocal)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
		os.Exit(1)
	}
	if len(listenDevs) <= 0 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine listen device")))
		os.Exit(1)
	}
	upDev, gatewayDev, err = findUpstreamDevAndGateway(*argUpDev, *argUpLocal)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
		os.Exit(1)
	}
	if upDev == nil && gatewayDev == nil {
		fmt.Fprintln(os.Stderr,
			fmt.Errorf("parse: %w", errors.New("cannot determine upstream device and gateway")))
		os.Exit(1)
	}
	if upDev == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine upstream device")))
		os.Exit(1)
	}
	if gatewayDev == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("cannot determine gateway")))
		os.Exit(1)
	}

	// Packet capture
	pc := pcap.Pcap{
		ListenPort:    uint16(*argListenPort),
		UpPort:        uint16(*argUpPort),
		ServerIP:      serverIP,
		ServerPort:    uint16(serverPort),
		ListenDevs:    listenDevs,
		UpDev:         upDev,
		GatewayDev:    gatewayDev,
	}
	// Proxy, for debug use
	p := proxy.Proxy{
		LocalPort:  uint16(*argListenPort),
		RemoteAddr: *argServer,
	}

	// Wait signals
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		pc.Close()
		p.Close()
		os.Exit(0)
	}()

	go func() {
		err := pc.Open()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("pcap: %w", err))
			os.Exit(1)
		}
	}()
	go func() {
		err := p.Open()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("proxy: %w", err))
			os.Exit(1)
		}
	}()

	select {}
}

func findListenDevs(strDevs []string, isLocal bool) ([]*pcap.Device, error) {
	result := make([]*pcap.Device, 0)

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("find listen devices: %w", err)
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
		m := make(map[string]*pcap.Device)
		for _, dev := range devs {
			m[dev.Name] = dev
		}

		for _, strDev := range strDevs {
			dev, ok := m[strDev]
			if !ok {
				return nil, fmt.Errorf("find listen devices: %w",
					fmt.Errorf("unknown device %s", strDev))
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

func findUpstreamDevAndGateway(strDev string, isLocal bool) (upDev, gatewayDev *pcap.Device, err error) {
	devs, err := pcap.FindAllDevs()
	if strDev != "" {
		// Find upstream device
		for _, dev := range devs {
			if dev.Name == strDev {
				if isLocal {
					if dev.IsLoop {
						upDev = dev
					}
				} else {
					upDev = dev
				}
				break
			}
		}
		if upDev == nil {
			return nil, nil,
			fmt.Errorf("find upstream device: %w",fmt.Errorf("unknown device %s", strDev))
		}
		// Find gateway
		if upDev.IsLoop {
			gatewayDev = upDev
		} else {
			gatewayDev, err = pcap.FindGatewayDev(upDev.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("find gateway: %w", err)
			}
			// Test if device's IP is in the same domain of the gateway's
			var newUpDev *pcap.Device
			for _, addr := range upDev.IPAddrs {
				if addr.Contains(gatewayDev.IPAddrs[0].IP) {
					newUpDev = &pcap.Device{
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
			loopDev, err := pcap.FindLoopDev()
			if err != nil {
				return nil, nil, fmt.Errorf("find upstream device: %w", err)
			}
			upDev = loopDev
			gatewayDev = upDev
		} else {
			// Find upstream device and gateway
			gatewayAddr, err := pcap.FindGatewayAddr()
			if err != nil {
				return nil, nil,
				fmt.Errorf("find upstream device: %w", fmt.Errorf("find gateway's address: %w", err))
			}
			for _, dev := range devs {
				if dev.IsLoop {
					continue
				}
				// Test if device's IP is in the same domain of the gateway's
				for _, addr := range dev.IPAddrs {
					if addr.Contains(gatewayAddr.IP) {
						gatewayDev, err = pcap.FindGatewayDev(dev.Name)
						if err != nil {
							continue
						}
						upDev = &pcap.Device{
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
