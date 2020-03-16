package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Config describes the configuration of IkaGo
type Config struct {
	ListenDevs []string `json:"listen-devices"`
	UpDev      string   `json:"upstream-device"`
	Method     string   `json:"method"`
	Password   string   `json:"password"`
	Verbose    bool     `json:"verbose"`
	UpPort     int      `json:"upstream-port"`
	Filters    []string `json:"filters"`
	Server     string   `json:"server"`
	ListenPort int      `json:"listen-port"`
}

// ListenDevsString returns pcap devices for listening in config in string
func (config *Config) ListenDevsString() string {
	if len(config.ListenDevs) <= 0 {
		return ""
	}
	return strings.Join(config.ListenDevs, ",")
}

// FiltersString returns filters in config in string
func (config *Config) FiltersString() string {
	if len(config.Filters) <= 0 {
		return ""
	}
	return strings.Join(config.Filters, ",")
}

// New returns a new config
func New() *Config {
	return &Config{
		Method: "plain",
	}
}

// Parse returns the config parsed from file
func Parse(path string) (*Config, error) {
	config := New()

	// Open file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	fi, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	// Empty file
	size := fi.Size()
	if size == 0 {
		return nil, fmt.Errorf("parse: %w", errors.New("empty file"))
	}

	// Read file
	buffer := make([]byte, size)
	_, err = file.Read(buffer)

	// Trim comments
	buffer, err = trimComments(buffer)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	// Expand environment variables
	buffer = []byte(os.ExpandEnv(string(buffer)))

	// Unmarshal
	err = json.Unmarshal(buffer, config)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
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
			return nil, fmt.Errorf("trim comments: %w", err)
		}

		if !match {
			filtered = append(filtered, line)
		}
	}

	return bytes.Join(filtered, []byte("\n")), nil
}
