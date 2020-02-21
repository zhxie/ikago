package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"./pcap"
	"./proxy"
)

var listDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
var listenLocal = flag.Bool("listen-local", false, "Listen loopback device only.")
var listenDev = flag.String("listen-device", "", "Designated pcap device for listening.")
var local = flag.Bool("upstream-local", false, "Route upstream to loopback device only.")
var upDev = flag.String("upstream-device", "", "Designated pcap device for routing upstream to.")
var listenPort = flag.Int("p", 0, "Port for listening.")
var server = flag.String("s", "", "Server.")

func main() {
	var (
		serverIP   net.IP
		serverPort uint64
		err        error
	)

	// Parse arguments
	flag.Parse()
	if *listDevs {
		fmt.Println("Available devices are listed below, use -listen-device [device] or " +
			"-upstream-device [device] to designate device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("list devices: %w", err))
			os.Exit(1)
		}
		for _, d := range devs {
			fmt.Printf("  %s\n", d)
		}
		os.Exit(0)
	}
	if *listenPort == 0 {
		fmt.Fprintln(os.Stderr, "Please provide listen port by -p [port].")
		os.Exit(1)
	}
	if *server == "" {
		fmt.Fprintln(os.Stderr, "Please provide server by -s [address:port].")
		os.Exit(1)
	}

	// Verify parameters
	if *listenPort <= 0 || *listenPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("listen port out of range")))
		os.Exit(1)
	}
	serverSplit := strings.Split(*server, ":")
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
	fmt.Printf("Starting proxying from :%d to %s...\n", *listenPort, *server)

	// Packet capture
	var listenDevs []*pcap.Device
	if *listenDev != "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", fmt.Errorf("listen device: %w", err)))
			os.Exit(1)
		}
		for _, dev := range devs {
			if dev.Name == *listenDev {
				listenDevs = append(listenDevs, dev)
				break
			}
		}
	}
	var upD *pcap.Device
	if *upDev != "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", fmt.Errorf("upstream device: %w", err)))
			os.Exit(1)
		}
		for _, dev := range devs {
			if dev.Name == *upDev {
				upD = dev
				break
			}
		}
	}
	pc := pcap.Pcap{
		ListenPort:    uint16(*listenPort),
		ServerIP:      serverIP,
		ServerPort:    uint16(serverPort),
		IsListenLocal: *listenLocal,
		ListenDevs:    listenDevs,
		IsLocal:       *local,
		UpDev:         upD,
	}
	// Proxy, for debug use
	p := proxy.Proxy{
		LocalPort:  uint16(*listenPort),
		RemoteAddr: *server,
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
