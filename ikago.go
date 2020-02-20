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

var listDevs = flag.Bool("list-devices", false, "List Devices")
var localOnly = flag.Bool("local-only", false, "Local Only")
var remoteDev = flag.String("d", "", "Remote Device")
var localPort = flag.Int("p", 0, "Port")
var server = flag.String("s", "", "Server")

func main() {
	flag.Parse()
	if *listDevs {
		fmt.Println("Available devices are listed below, use -d [device] to designate remote device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("list devices: %w", err))
			os.Exit(1)
		}
		for _, d := range devs {
			fmt.Println(d)
		}
		os.Exit(0)
	}
	if *localPort == 0 {
		fmt.Fprintln(os.Stderr, "Please provide local port by -l [port].")
		os.Exit(1)
	}
	if *server == "" {
		fmt.Fprintln(os.Stderr, "Please provide server by -r [address:port].")
		os.Exit(1)
	}

	if *localPort <= 0 || *localPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", errors.New("local port out of range")))
		os.Exit(1)
	}
	serverSplit := strings.Split(*server, ":")
	if len(serverSplit) < 2 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("invalid"))))
		os.Exit(1)
	}
	remoteIP := net.ParseIP(serverSplit[0])
	if remoteIP == nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("invalid ip"))))
		os.Exit(1)
	}
	remotePort, err := strconv.ParseUint(serverSplit[len(serverSplit) - 1], 10, 16)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("invalid port"))))
		os.Exit(1)
	}
	if remotePort <= 0 || remotePort >= 65535 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w",
			fmt.Errorf("server: %w", errors.New("port out of range"))))
		os.Exit(1)
	}
	fmt.Printf("Starting proxying from :%d to %s...\n", *localPort, *server)

	var remoteD *pcap.Device
	if *remoteDev != "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse: %w", err))
			os.Exit(1)
		}
		for _, dev := range devs {
			if dev.Name == *remoteDev {
				remoteD = dev
				break
			}
		}
	}
	pc := pcap.Pcap{
		LocalPort:   uint16(*localPort),
		RemoteIP:    remoteIP,
		RemotePort:  uint16(remotePort),
		RemoteDev:   remoteD,
		IsLocalOnly: *localOnly,
	}
	// This is a tcp proxy for debug
	p := proxy.Proxy{
		LocalPort:  uint16(*localPort),
		RemoteAddr: *server,
	}

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
