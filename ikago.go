package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"./pcap"
	"./proxy"
)

var dev = flag.String("d", "", "Device")
var listDevs = flag.Bool("ds", false, "List Devices")
var localPort = flag.Int("l", 0, "Local Port")
var remoteAddr = flag.String("r", "", "Remote Address")

func main() {
	flag.Parse()
	if *listDevs {
		fmt.Println("Available devices are listed below, use -d [device] to designate:")
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
		fmt.Fprintln(os.Stderr, "Please provide local port port by -l [port].")
		os.Exit(1)
	}
	if *remoteAddr == "" {
		fmt.Fprintln(os.Stderr, "Please provide remote address by -r [address:port].")
		os.Exit(1)
	}

	if *localPort <= 0 || *localPort >= 65536 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse local port: %w", errors.New("out of range")))
		os.Exit(1)
	}
	remoteAddrSplit := strings.Split(*remoteAddr, ":")
	if len(remoteAddrSplit) < 2 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse remote address: %w", errors.New("invalid")))
		os.Exit(1)
	}
	remotePort, err := strconv.ParseUint(remoteAddrSplit[len(remoteAddrSplit) - 1], 10, 16)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse remote port: %w", errors.New("invalid")))
		os.Exit(1)
	}
	if remotePort <= 0 || remotePort >= 65535 {
		fmt.Fprintln(os.Stderr, fmt.Errorf("parse remote port: %w", errors.New("out of range")))
		os.Exit(1)
	}
	fmt.Printf("Starting proxying from :%d to %s...\n", *localPort, *remoteAddr)

	var d *pcap.Device
	if *dev != "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, fmt.Errorf("parse device: %w", err))
			os.Exit(1)
		}
		for _, d2 := range devs {
			if d2.Name == *dev {
				d = &d2
				break
			}
		}
	}
	pc := pcap.Pcap{
		LocalPort:  uint16(*localPort),
		RemotePort: uint16(remotePort),
		Dev: d,
	}
	// This is a tcp proxy for debug
	p := proxy.Proxy{
		LocalPort:  uint16(*localPort),
		RemoteAddr: *remoteAddr,
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
