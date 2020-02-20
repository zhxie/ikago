package pcap

import (
	"github.com/google/gopacket/layers"
	"net"
)

type TCPPseudoHeaderIPv4 struct {
	SrcIP     net.IP
	DstIP     net.IP
	reserved  uint8
	protocol  uint8
	TCPLength uint16
}

func (header *TCPPseudoHeaderIPv4) Bytes() []byte {
	header.protocol = uint8(layers.IPProtocolTCP)

	b := make([]byte, 0)
	b = append(b, []byte(header.SrcIP.To4())...)
	b = append(b, []byte(header.DstIP.To4())...)
	b = append(b, header.reserved, header.protocol)
	b = append(b, uint16ToBytes(header.TCPLength)...)

	return b
}

type TCPSegment struct {
	Header  *layers.TCP
	Payload []byte
}

func (segment *TCPSegment) Length() uint16 {
	return uint16(len(segment.Header.LayerContents()) + len(segment.Payload))
}

func (segment *TCPSegment) Bytes() []byte {
	b := make([]byte, 0)

	b = append(b, segment.Header.LayerContents()...)
	b = append(b, segment.Payload...)

	return b
}

type TCPSegmentWithPseudoHeaderIPv4 struct {
	Header  *TCPPseudoHeaderIPv4
	Segment *TCPSegment
}

func (s *TCPSegmentWithPseudoHeaderIPv4) Bytes() []byte {
	b := make([]byte, 0)

	b = append(b, s.Header.Bytes()...)
	b = append(b, s.Segment.Bytes()...)

	return b
}

func (s *TCPSegmentWithPseudoHeaderIPv4) CheckSum() uint16 {
	return checkSum(s.Bytes())
}

func CheckTCPIPv4Sum(tcp *layers.TCP, payload []byte, ipv4 *layers.IPv4) uint16 {
	segment := TCPSegment{
		Header:  tcp,
		Payload: payload,
	}

	header := TCPPseudoHeaderIPv4{
		SrcIP:     ipv4.SrcIP,
		DstIP:     ipv4.DstIP,
		TCPLength: segment.Length(),
	}

	s := TCPSegmentWithPseudoHeaderIPv4{
		Header:  &header,
		Segment: &segment,
	}
	return s.CheckSum()
}

func checkSum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	var index int

	for length > 1 {
		sum += uint32((data)[index])<<8 + uint32((data)[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32((data)[index])
	}
	sum += sum >> 16
	return uint16(^sum)
}

func uint16ToBytes(n uint16) []byte {
	return []byte{
		byte(n),
		byte(n >> 8),
	}
}
