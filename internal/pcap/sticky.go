package pcap

import (
	"ikago/internal/log"
	"time"
)

// Desticker is a machine concatenate and separate TCP sticky data.
type Desticker struct {
	data     []byte
	deadline time.Duration
	appear   time.Time
}

// NewDesticker returns a new desticker.
func NewDesticker() *Desticker {
	return &Desticker{data: make([]byte, 0)}
}

// Append adds a sticky data to the Desticker.
func (d *Desticker) Append(data []byte) ([]*PacketIndicator, error) {
	indicators := make([]*PacketIndicator, 0)

	// Discard old data
	if d.deadline > 0 && time.Now().Sub(d.appear) > d.deadline {
		log.Verboseln("Discard previous data")

		d.data = make([]byte, 0)
	}

	// Append data
	d.data = append(d.data, data...)

	for length := len(d.data); length > 0; {
		// Parse embedded packet
		indicator, err := ParseEmbPacket(d.data)
		if err != nil {
			break
		}
		if indicator != nil {
			if uint16(len(d.data)) > indicator.IPv4Layer().Length {
				d.data = d.data[indicator.IPv4Layer().Length:]
			} else if uint16(len(d.data)) == indicator.IPv4Layer().Length {
				d.data = make([]byte, 0)
			} else {
				// TODO: Optimize by recording indicator lacking data
				break
			}

			indicators = append(indicators, indicator)
		}
	}

	if len(indicators) > 0 {
		d.appear = time.Now()
	}

	return indicators, nil
}

// SetDeadline sets the deadline associated with the sticky data.
func (d *Desticker) SetDeadline(t time.Duration) {
	d.deadline = t
}
