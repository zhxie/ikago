package pcap

import (
	"ikago/internal/log"
	"time"
)

// Desticker is a machine concatenate and separate TCP sticky data.
type Desticker struct {
	data      []byte
	deadline  time.Duration
	appear    time.Time
	indicator *PacketIndicator
}

// NewDesticker returns a new desticker.
func NewDesticker() *Desticker {
	return &Desticker{data: make([]byte, 0), appear: time.Now()}
}

// Append adds a sticky data to the Desticker. This is a copy method.
func (d *Desticker) Append(data []byte) ([][]byte, error) {
	packets := make([][]byte, 0)

	// Discard old data
	if d.deadline > 0 && time.Now().Sub(d.appear) > d.deadline {
		log.Verboseln("Discard previous data")

		d.data = make([]byte, 0)
		d.indicator = nil
	}

	// Append data
	d.data = append(d.data, data...)

	for length := len(d.data); length > 0; {
		if d.indicator != nil {
			if len(d.data) >= int(d.indicator.IPv4Layer().Length) {
				packets = append(packets, d.data[:d.indicator.IPv4Layer().Length])

				if len(d.data) > int(d.indicator.IPv4Layer().Length) {
					d.data = d.data[d.indicator.IPv4Layer().Length:]
				} else {
					d.data = make([]byte, 0)
				}
				d.indicator = nil
			} else {
				break
			}
		} else {
			// Parse embedded packet
			indicator, err := ParseEmbPacket(d.data)
			if err != nil {
				break
			}

			if indicator != nil {
				d.indicator = indicator
			}
		}
	}

	if len(packets) > 0 {
		d.appear = time.Now()
	}

	return packets, nil
}

// SetDeadline sets the deadline associated with the sticky data.
func (d *Desticker) SetDeadline(t time.Duration) {
	d.deadline = t
}
