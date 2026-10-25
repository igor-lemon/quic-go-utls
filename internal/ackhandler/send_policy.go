package ackhandler

import (
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
)

// SendPolicy is how a profile has the handler number its packets and probe a
// silent peer. The zero value is quic-go's: a counter of each space's own,
// the application's skipping a number now and then, a number of two bytes at
// least, two probes at each probe timeout and a number skipped there in the
// application's space alone, the alarm on time.
type SendPolicy struct {
	// SharedPacketNumbers numbers the packets of the three spaces with one
	// counter from FirstPacketNumber, as quiche does, with no random skips.
	SharedPacketNumbers bool
	FirstPacketNumber   protocol.PacketNumber
	// WindowPacketNumberLength writes a number in as few bytes as four times
	// the larger of the packets the peer has yet to acknowledge and the
	// congestion window in packets of the room left take (quiche's
	// UpdatePacketNumberLength): the room is what is left of the datagram
	// while packets are coalesced, before the handshake is confirmed, else a
	// whole one; a number begins one byte long.
	WindowPacketNumberLength bool
	// SkipInEverySpace skips a number at every probe timeout, whatever space
	// it probes (quiche's OnRetransmissionAlarm).
	SkipInEverySpace bool
	// Probes are the probe packets a probe timeout sends; 0 is two.
	Probes int
	// AlarmSlack is how late the loss detection alarm fires: Chrome's
	// network thread runs an alarm when its timer's leeway has passed.
	AlarmSlack time.Duration
}

// SetSendPolicy has the handler number and probe as p says. It is called
// before the first packet is sent.
func (h *sentPacketHandler) SetSendPolicy(p SendPolicy) {
	h.policy = p
	if !p.SharedPacketNumbers {
		return
	}
	first := max(p.FirstPacketNumber, h.initialPackets.pns.Peek())
	h.shared = &sequentialPacketNumberGenerator{next: first}
	for _, s := range []*packetNumberSpace{h.initialPackets, h.handshakePackets, h.appDataPackets} {
		s.pns = h.shared
		s.history.sharedCounter = true
	}
	h.pnLen = protocol.PacketNumberLen1
}

// PlanPacket says a packet of size bytes (an Initial's before its padding)
// goes in the datagram being packed, so that the number and length the
// next PeekPacketNumber gives are those of the packet after it.
func (h *sentPacketHandler) PlanPacket(encLevel protocol.EncryptionLevel, size protocol.ByteCount) {
	if h.shared == nil {
		return
	}
	h.planned++
	h.plannedBytes += size
	if !h.policy.WindowPacketNumberLength {
		return
	}
	room := h.maxDatagramSize
	if !h.handshakeConfirmed && h.plannedBytes < h.maxDatagramSize {
		room = h.maxDatagramSize - h.plannedBytes
	}
	h.pnLen = h.windowLength(h.shared.next+protocol.PacketNumber(h.planned), encLevel, room)
}

// KeysInstalled says keys of encLevel came: quiche sets its default level
// then, and works out the length of the next number again, in a whole room.
func (h *sentPacketHandler) KeysInstalled(encLevel protocol.EncryptionLevel) {
	if h.shared == nil || !h.policy.WindowPacketNumberLength || h.planned > 0 {
		return
	}
	h.pnLen = h.windowLength(h.shared.next, encLevel, h.maxDatagramSize)
}

// windowLength is quiche's length of a number for next, the peer awaiting
// packets of encLevel's space, room bytes in the datagram.
func (h *sentPacketHandler) windowLength(next protocol.PacketNumber, encLevel protocol.EncryptionLevel, room protocol.ByteCount) protocol.PacketNumberLen {
	var delta uint64
	if least := h.leastAwaited(encLevel); next > least {
		delta = uint64(next - least)
	}
	if room > 0 {
		delta = max(delta, uint64(h.congestion.GetCongestionWindow()/room))
	}
	// quiche's GetMinPacketNumberLength knows no three-byte number.
	switch n := delta * 4; {
	case n < 1<<8:
		return protocol.PacketNumberLen1
	case n < 1<<16:
		return protocol.PacketNumberLen2
	default:
		return protocol.PacketNumberLen4
	}
}

// leastAwaited is the least number the peer awaits of encLevel's space
// (quiche's GetLeastPacketAwaitedByPeer): the first number while it has
// acknowledged none there, else the one after the largest it did, or the
// least one unacknowledged of any space when that is lower.
func (h *sentPacketHandler) leastAwaited(encLevel protocol.EncryptionLevel) protocol.PacketNumber {
	space := h.getPacketNumberSpace(encLevel)
	if space == nil || space.largestAcked == protocol.InvalidPacketNumber {
		return h.policy.FirstPacketNumber
	}
	least := space.largestAcked + 1
	for _, s := range []*packetNumberSpace{h.initialPackets, h.handshakePackets, h.appDataPackets} {
		if s == nil {
			continue
		}
		if pn := s.history.LowestPacketNumber(); pn != protocol.InvalidPacketNumber && pn < least {
			least = pn
		}
	}
	return least
}

// skipForProbe skips a number before the probe of encLevel's space, the
// application's always and any space's with SkipInEverySpace, and in a
// whole room works out the next number's length again.
func (h *sentPacketHandler) skipForProbe(encLevel protocol.EncryptionLevel) {
	if encLevel != protocol.Encryption1RTT && !h.policy.SkipInEverySpace {
		return
	}
	pn := h.PopPacketNumber(encLevel)
	h.getPacketNumberSpace(encLevel).history.SkippedPacket(pn)
	if h.shared != nil && h.policy.WindowPacketNumberLength {
		h.pnLen = h.windowLength(h.shared.next, encLevel, h.maxDatagramSize)
	}
}

// probes is the number of probe packets a probe timeout sends.
func (h *sentPacketHandler) probes() int {
	if h.policy.Probes > 0 {
		return h.policy.Probes
	}
	return 2
}
