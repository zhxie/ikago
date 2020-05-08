package stat

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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
	lock             sync.RWMutex
	localInManager   *TrafficManager
	localOutManager  *TrafficManager
	remoteInManager  *TrafficManager
	remoteOutManager *TrafficManager
}

// NewTrafficMonitor returns a new traffic monitor.
func NewTrafficMonitor() *TrafficMonitor {
	return &TrafficMonitor{
		localInManager:  NewTrafficManager(),
		localOutManager: NewTrafficManager(),
	}
}

// Add adds a data of traffic to a node.
func (monitor *TrafficMonitor) Add(node string, direction Direction, size uint) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	switch direction {
	case DirectionIn:
		monitor.localInManager.Add(node, size)
	case DirectionOut:
		monitor.localOutManager.Add(node, size)
	default:
		panic(fmt.Errorf("direction %d out of range", direction))
	}
}

// AddBidirectional adds a data of traffic to both local and remote nodes.
func (monitor *TrafficMonitor) AddBidirectional(local string, remote string, direction Direction, size uint) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	switch direction {
	case DirectionIn:
		monitor.localInManager.Add(local, size)

		if monitor.remoteInManager == nil {
			monitor.remoteInManager = NewTrafficManager()
		}
		monitor.remoteInManager.Add(remote, size)
	case DirectionOut:
		monitor.localOutManager.Add(local, size)

		if monitor.remoteOutManager == nil {
			monitor.remoteOutManager = NewTrafficManager()
		}
		monitor.remoteOutManager.Add(remote, size)
	default:
		panic(fmt.Errorf("direction %d out of range", direction))
	}
}

func (monitor *TrafficMonitor) MarshalJSON() ([]byte, error) {
	monitor.lock.RLock()
	monitor.lock.RUnlock()

	type UnidirectionalTrafficMonitor struct {
		InManager  *TrafficManager `json:"in"`
		OutManager *TrafficManager `json:"out"`
	}

	return json.Marshal(&struct {
		Local  *UnidirectionalTrafficMonitor `json:"local"`
		Remote *UnidirectionalTrafficMonitor `json:"remote"`
	}{
		Local: &UnidirectionalTrafficMonitor{
			InManager:  monitor.localInManager,
			OutManager: monitor.localOutManager,
		},
		Remote: &UnidirectionalTrafficMonitor{
			InManager:  monitor.remoteInManager,
			OutManager: monitor.remoteOutManager,
		},
	})
}

func (monitor *TrafficMonitor) String() string {
	monitor.lock.RLock()
	defer monitor.lock.RUnlock()

	sb := strings.Builder{}

	sb.WriteString("Local:\n")

	sb.WriteString("Outbound statistics:\n")
	sb.WriteString(monitor.localOutManager.String())

	sb.WriteString("\n")

	sb.WriteString("Inbound statistics:\n")
	sb.WriteString(monitor.localInManager.String())

	sb.WriteString("\n")

	if monitor.remoteOutManager != nil || monitor.remoteInManager != nil {
		sb.WriteString("Remote:\n")

		sb.WriteString("Outbound statistics:\n")
		sb.WriteString(monitor.remoteOutManager.String())

		sb.WriteString("\n")

		sb.WriteString("Inbound statistics:\n")
		sb.WriteString(monitor.remoteInManager.String())
	}

	return sb.String()
}
