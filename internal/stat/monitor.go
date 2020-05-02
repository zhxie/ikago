package stat

import (
	"fmt"
	"strings"
)

// Direction describes the direction of the traffic.
type Direction int

const (
	// DirectionIn describes the traffic is inbound.
	DirectionIn Direction = iota
	// DirectionOut describes the traffic is outbound.
	DirectionOut
)

// TrafficMonitor describes inbound and outbound traffic statistics in different nodes.
type TrafficMonitor struct {
	inManager  *TrafficManager
	outManager *TrafficManager
}

// NewTrafficMonitor returns a new traffic monitor.
func NewTrafficMonitor() *TrafficMonitor {
	return &TrafficMonitor{
		inManager:  NewTrafficManager(),
		outManager: NewTrafficManager(),
	}
}

// Add adds a data of traffic to a node.
func (manager *TrafficMonitor) Add(node string, direction Direction, size uint) {
	switch direction {
	case DirectionIn:
		manager.inManager.Add(node, size)
	case DirectionOut:
		manager.outManager.Add(node, size)
	default:
		panic(fmt.Errorf("direction %d out of range", direction))
	}
}

func (manager TrafficMonitor) String() string {
	sb := strings.Builder{}

	sb.WriteString("Outbound statistics:\n")
	for _, node := range manager.outManager.Nodes() {
		indicator, err := manager.outManager.Indicator(node)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s", fmt.Errorf("statistics: %s: %w", node, err)))
		}

		sb.WriteString(fmt.Sprintf("%s: %s", node, indicator))

		sb.WriteString("\n")
	}

	sb.WriteString("Inbound statistics:\n")
	for _, node := range manager.inManager.Nodes() {
		indicator, err := manager.inManager.Indicator(node)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s", fmt.Errorf("statistics: %s: %w", node, err)))
		}

		sb.WriteString(fmt.Sprintf("%s: %s", node, indicator))

		sb.WriteString("\n")
	}

	return sb.String()
}

// VerboseString prints string with verbose contents.
func (manager TrafficMonitor) VerboseString() string {
	sb := strings.Builder{}

	sb.WriteString("Outbound statistics:\n")
	for _, node := range manager.outManager.Nodes() {
		indicator, err := manager.outManager.Indicator(node)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s", fmt.Errorf("statistics: %s: %w", node, err)))
		}

		sb.WriteString(fmt.Sprintf("%s: %s", node, indicator.VerboseString()))

		sb.WriteString("\n")
	}

	sb.WriteString("\nInbound statistics:\n")
	for _, node := range manager.inManager.Nodes() {
		indicator, err := manager.inManager.Indicator(node)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%s", fmt.Errorf("statistics: %s: %w", node, err)))
		}

		sb.WriteString(fmt.Sprintf("%s: %s", node, indicator.VerboseString()))

		sb.WriteString("\n")
	}

	return sb.String()
}
