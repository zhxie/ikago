package main

import (
	"errors"
	"flag"
	"fmt"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"ikago/internal/pcap"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var argListDevs = flag.Bool("list-devices", false, "List all valid devices in current computer.")
var argConfig = flag.String("c", "", "Configuration file.")
var argListenDevs = flag.String("listen-devices", "", "Devices for listening.")
var argUpDev = flag.String("upstream-device", "", "Device for routing upstream to.")
var argGateway = flag.String("gateway", "", "Gateway address.")
var argMethod = flag.String("method", "plain", "Method of encryption.")
var argPassword = flag.String("password", "", "Password of encryption.")
var argVerbose = flag.Bool("v", false, "Print verbose messages.")
var argListenPort = flag.Int("p", 0, "Port for listening.")

func init() {
	// Parse arguments
	flag.Parse()
}

func main() {
	var (
		err        error
		cfg        *config.Config
		gateway    net.IP
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
		gatewayDev *pcap.Device
		crypt      crypto.Crypt
	)

	// Configuration file
	if *argConfig != "" {
		cfg, err = config.ParseFile(*argConfig)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse config file %s: %w", *argConfig, err))
		}
	} else {
		cfg = &config.Config{
			ListenDevs: splitArg(*argListenDevs),
			UpDev:      *argUpDev,
			Gateway:    *argGateway,
			Method:     *argMethod,
			Password:   *argPassword,
			Verbose:    *argVerbose,
			ListenPort: *argListenPort,
		}
	}

	// Log
	log.SetVerbose(cfg.Verbose)

	// Exclusive commands
	if *argListDevs {
		log.Infoln("Available devices are listed below, use -listen-devices [devices] or -upstream-device [device] to designate device:")
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalln(fmt.Errorf("list devices: %w", err))
		}
		for _, dev := range devs {
			log.Infof("  %s\n", dev)
		}
		os.Exit(0)
	}

	// Verify parameters
	if cfg.ListenPort == 0 {
		log.Fatalln("Please provide listen port by -p [port].")
	}
	if cfg.Gateway != "" {
		gateway = net.ParseIP(cfg.Gateway)
		if gateway == nil {
			log.Fatalln(fmt.Errorf("invalid gateway %s", cfg.Gateway))
		}
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		log.Fatalln(fmt.Errorf("listen port %d out of range", cfg.ListenPort))
	}
	crypt, err = crypto.ParseCrypt(cfg.Method, cfg.Password)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse crypt: %w", err))
	}
	log.Infof("Proxy from :%d\n", cfg.ListenPort)

	// Find devices
	listenDevs, err = pcap.FindListenDevs(cfg.ListenDevs)
	if err != nil {
		log.Fatalln(fmt.Errorf("find listen devices: %w", err))
	}
	if len(cfg.ListenDevs) <= 0 {
		// Remove loopback devices by default
		result := make([]*pcap.Device, 0)

		for _, dev := range listenDevs {
			if dev.IsLoop {
				continue
			}
			result = append(result, dev)
		}

		listenDevs = result
	}
	if len(listenDevs) <= 0 {
		log.Fatalln(errors.New("cannot determine listen device"))
	}

	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGatewayDev(cfg.UpDev, gateway)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	if upDev == nil && gatewayDev == nil {
		log.Fatalln(errors.New("cannot determine upstream device and gateway device"))
	}
	if upDev == nil {
		log.Fatalln(errors.New("cannot determine upstream device"))
	}
	if gatewayDev == nil {
		log.Fatalln(errors.New("cannot determine gateway device"))
	}

	// Packet capture
	p := pcap.NewServer()
	p.Port = uint16(cfg.ListenPort)
	p.ListenDevs = listenDevs
	p.UpDev = upDev
	p.GatewayDev = gatewayDev
	p.Crypt = crypt

	// Wait signals
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		p.Close()
		os.Exit(0)
	}()

	err = p.Open()
	if err != nil {
		log.Fatalln(fmt.Errorf("open pcap: %w", err))
	}
}

func splitArg(s string) []string {
	if s == "" {
		return nil
	} else {
		result := make([]string, 0)

		strs := strings.Split(s, ",")

		for _, str := range strs {
			result = append(result, strings.Trim(str, " "))
		}

		return result
	}
}
