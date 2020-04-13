package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
)

// Config describes the configuration of IkaGo.
type Config struct {
	ListenDevs []string  `json:"listen-devices"`
	UpDev      string    `json:"upstream-device"`
	Gateway    string    `json:"gateway"`
	Method     string    `json:"method"`
	Password   string    `json:"password"`
	KCP        bool      `json:"kcp"`
	KCPConfig  KCPConfig `json:"kcp-tuning"`
	MTU        int       `json:"mtu"`
	Rule       bool      `json:"rule"`
	Verbose    bool      `json:"verbose"`
	Log        string    `json:"log"`
	Publish    []string  `json:"publish"`
	Fragment   int       `json:"fragment"`
	UpPort     int       `json:"upstream-port"`
	Filters    []string  `json:"filters"`
	Server     string    `json:"server"`
	Port       int       `json:"port"`
}

// NewConfig returns a new config.
func NewConfig() *Config {
	return &Config{
		Method:    "plain",
		KCPConfig: *NewKCPConfig(),
		Publish:   make([]string, 0),
		Filters:   make([]string, 0),
	}
}

// ParseFile returns the config parsed from file.
func ParseFile(path string) (*Config, error) {
	config := NewConfig()

	// Open file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	fi, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	// Empty file
	size := fi.Size()
	if size == 0 {
		return nil, errors.New("empty file")
	}

	// Read file
	buffer := make([]byte, size)
	_, err = file.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// Trim comments
	buffer, err = trimComments(buffer)
	if err != nil {
		return nil, fmt.Errorf("trim comments: %w", err)
	}

	// Expand environment variables
	buffer = []byte(os.ExpandEnv(string(buffer)))

	// Unmarshal
	err = json.Unmarshal(buffer, config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return config, nil
}

func trimComments(data []byte) ([]byte, error) {
	// Windows CRLF to Unix LF
	data = bytes.Replace(data, []byte("\r"), []byte(""), 0)

	lines := bytes.Split(data, []byte("\n"))

	filtered := make([][]byte, 0)
	for _, line := range lines {
		match, err := regexp.Match(`^\s*#`, line)
		if err != nil {
			return nil, fmt.Errorf("match: %w", err)
		}

		if !match {
			filtered = append(filtered, line)
		}
	}

	return bytes.Join(filtered, []byte("\n")), nil
}
