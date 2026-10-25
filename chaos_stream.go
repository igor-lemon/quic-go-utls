package quic

import (
	"math/rand/v2"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
)

// firstFlightPlan is where a client's first flight laid out by chaos is: a
// first packet of the ClientHello's first and last bytes, then its middle.
type firstFlightPlan struct {
	step        flightStep
	next        flightStep // after a packet ends
	length      protocol.ByteCount
	first, last protocol.ByteCount
}

type flightStep int

const (
	flightUndecided flightStep = iota // the ClientHello not planned yet: its first bytes next, once planned
	flightLast                        // its last bytes next
	flightPacketEnd                   // the packet ends: no frame next
	flightMiddle                      // its middle next
	flightPlain                       // the stream's own frames, the flight laid out or not to be
)

// setChaos has the stream lay out a client's first flight by chaos, drawing
// with rng, in place of the scramble.
func (s *initialCryptoStream) setChaos(c *chaosLayout, rng *rand.Rand) {
	s.chaos, s.rng = c, rng
	s.scramble = false
}

// clientHelloLength is the length of the ClientHello at the start of b, 0
// while it is not all written, -1 when b does not begin with one.
func clientHelloLength(b []byte) protocol.ByteCount {
	if len(b) == 0 {
		return 0
	}
	if b[0] != 1 { // typeClientHello
		return -1
	}
	if len(b) < 4 {
		return 0
	}
	n := 4 + protocol.ByteCount(b[1])<<16 + protocol.ByteCount(b[2])<<8 + protocol.ByteCount(b[3])
	if protocol.ByteCount(len(b)) < n {
		return 0
	}
	return n
}

func (s *initialCryptoStream) chaosHasData() bool {
	switch s.flight.step {
	case flightUndecided:
		if s.writeOffset == 0 && clientHelloLength(s.writeBuf) == 0 {
			// the whole ClientHello first, or it cannot be laid out
			return false
		}
		return s.baseCryptoStream.HasData()
	case flightPlain:
		return s.baseCryptoStream.HasData()
	}
	return true
}

func (s *initialCryptoStream) chaosPop(maxLen protocol.ByteCount) *wire.CryptoFrame {
	f := &s.flight
	switch f.step {
	case flightUndecided:
		n := clientHelloLength(s.writeBuf)
		if s.writeOffset == 0 && n == 0 {
			return nil // the whole ClientHello first
		}
		if s.writeOffset != 0 || n < 0 {
			f.step = flightPlain
			return s.baseCryptoStream.PopCryptoFrame(maxLen)
		}
		first, last, ok := s.chaos.firstFlight(n, maxLen, s.rng)
		if !ok {
			f.step = flightPlain
			return s.baseCryptoStream.PopCryptoFrame(maxLen)
		}
		f.length, f.first, f.last, f.step = n, first, last, flightLast
		return &wire.CryptoFrame{Offset: 0, Data: s.writeBuf[:first]}
	case flightLast:
		f.step, f.next = flightPacketEnd, flightMiddle
		s.writeOffset = f.first
		return &wire.CryptoFrame{Offset: f.length - f.last, Data: s.writeBuf[f.length-f.last : f.length]}
	case flightPacketEnd:
		f.step = f.next
		return nil
	case flightMiddle:
		end := f.length - f.last
		cf := &wire.CryptoFrame{Offset: s.writeOffset}
		k := min(cf.MaxDataLen(maxLen), end-s.writeOffset)
		if k <= 0 {
			return nil
		}
		cf.Data = s.writeBuf[s.writeOffset : s.writeOffset+k]
		s.writeOffset += k
		// quiche ends a packet after each frame of the middle
		f.step, f.next = flightPacketEnd, flightMiddle
		if s.writeOffset == end {
			// all of the ClientHello is out: what is written after it goes plainly
			s.writeBuf, s.writeOffset = s.writeBuf[f.length:], f.length
			f.next = flightPlain
		}
		return cf
	}
	return s.baseCryptoStream.PopCryptoFrame(maxLen)
}
