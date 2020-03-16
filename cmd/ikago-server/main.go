package main

import (
	"errors"
	"flag"
	"fmt"
	"ikago/internal/config"
	"ikago/internal/crypto"
	"ikago/internal/log"
	"ikago/internal/pcap"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var argListDevs = flag.Bool("list-devices", false, "List all valid pcap devices in current computer.")
var argConfig = flag.String("c", "", "Configuration file.")
var argListenDevs = flag.String("listen-devices", "", "pcap devices for listening.")
var argUpDev = flag.String("upstream-device", "", "pcap device for routing upstream to.")
var argMethod = flag.String("method", "plain", "Method of encryption.")
var argPassword = flag.String("password", "", "Password of the encryption.")
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
		listenDevs = make([]*pcap.Device, 0)
		upDev      *pcap.Device
		gatewayDev *pcap.Device
		c          crypto.Crypto
	)

	// Configuration file
	if *argConfig != "" {
		cfg, err = config.Parse(*argConfig)
		if err != nil {
			log.Fatalln(fmt.Errorf("parse: %w", err))
		}
	} else {
		cfg = &config.Config{
			ListenDevs: splitArg(*argListenDevs),
			UpDev:      *argUpDev,
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
	if cfg.ListenPort <= 0 || cfg.ListenPort >= 65536 {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("listen port out of range")))
	}
	c, err = crypto.Parse(cfg.Method, cfg.Password)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	log.Infof("Proxy from :%d\n", cfg.ListenPort)

	// Find devices
	listenDevs, err = pcap.FindListenDevs(cfg.ListenDevs)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	if len(listenDevs) <= 0 {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine listen device")))
	}
	upDev, gatewayDev, err = pcap.FindUpstreamDevAndGateway(cfg.UpDev)
	if err != nil {
		log.Fatalln(fmt.Errorf("parse: %w", err))
	}
	if upDev == nil && gatewayDev == nil {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine upstream device and gateway")))
	}
	if upDev == nil {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine upstream device")))
	}
	if gatewayDev == nil {
		log.Fatalln(fmt.Errorf("parse: %w", errors.New("cannot determine gateway")))
	}

	// Packet capture
	p := pcap.Server{
		ListenPort: uint16(cfg.ListenPort),
		ListenDevs: listenDevs,
		UpDev:      upDev,
		GatewayDev: gatewayDev,
		Crypto:     c,
	}

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
		log.Fatalln(fmt.Errorf("pcap: %w", err))
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
