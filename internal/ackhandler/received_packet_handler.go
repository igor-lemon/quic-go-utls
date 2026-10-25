package ackhandler

import (
	"fmt"
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
)

type ReceivedPacketHandler struct {
	initialPackets   *receivedPacketTracker
	handshakePackets *receivedPacketTracker
	appDataPackets   appDataReceivedPacketTracker

	// With a handshake ACK delay (SetHandshakeAckDelay), the Initial and
	// Handshake packets are acknowledged as the application's are, after
	// two ack-eliciting packets, a missing one, or the delay, and these
	// track them in place of initialPackets and handshakePackets.
	initialDelayed   *appDataReceivedPacketTracker
	handshakeDelayed *appDataReceivedPacketTracker

	lowest1RTTPacket protocol.PacketNumber
	logger           utils.Logger
}

func NewReceivedPacketHandler(logger utils.Logger) *ReceivedPacketHandler {
	return &ReceivedPacketHandler{
		initialPackets:   newReceivedPacketTracker(),
		handshakePackets: newReceivedPacketTracker(),
		appDataPackets:   *newAppDataReceivedPacketTracker(logger),
		lowest1RTTPacket: protocol.InvalidPacketNumber,
		logger:           logger,
	}
}

// SetMaxAckDelay sets the application-data ACK timer before receiving packets.
func (h *ReceivedPacketHandler) SetMaxAckDelay(delay time.Duration) {
	h.appDataPackets.maxAckDelay = delay
}

// SetHandshakeAckDelay has the Initial and Handshake packets acknowledged
// within delay, as quiche does with its alarm's granularity (its
// UberReceivedPacketManager), not at once: a client whose handshake ends
// within it never acknowledges the server's Initial. It is called before
// any packet is received; 0 acknowledges them at once.
func (h *ReceivedPacketHandler) SetHandshakeAckDelay(delay time.Duration) {
	if delay <= 0 {
		return
	}
	h.initialDelayed = newAppDataReceivedPacketTracker(h.logger)
	h.initialDelayed.maxAckDelay = delay
	h.handshakeDelayed = newAppDataReceivedPacketTracker(h.logger)
	h.handshakeDelayed.maxAckDelay = delay
}

func (h *ReceivedPacketHandler) ReceivedPacket(
	pn protocol.PacketNumber,
	ecn protocol.ECN,
	encLevel protocol.EncryptionLevel,
	rcvTime monotime.Time,
	ackEliciting bool,
) error {
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialDelayed != nil {
			return h.initialDelayed.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
		}
		return h.initialPackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.EncryptionHandshake:
		// The Handshake packet number space might already have been dropped as a result
		// of processing the CRYPTO frame that was contained in this packet.
		if h.handshakePackets == nil {
			return nil
		}
		if h.handshakeDelayed != nil {
			return h.handshakeDelayed.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
		}
		return h.handshakePackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.Encryption0RTT:
		if h.lowest1RTTPacket != protocol.InvalidPacketNumber && pn > h.lowest1RTTPacket {
			return fmt.Errorf("received packet number %d on a 0-RTT packet after receiving %d on a 1-RTT packet", pn, h.lowest1RTTPacket)
		}
		return h.appDataPackets.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	case protocol.Encryption1RTT:
		if h.lowest1RTTPacket == protocol.InvalidPacketNumber || pn < h.lowest1RTTPacket {
			h.lowest1RTTPacket = pn
		}
		return h.appDataPackets.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	default:
		panic(fmt.Sprintf("received packet with unknown encryption level: %s", encLevel))
	}
}

func (h *ReceivedPacketHandler) IgnorePacketsBelow(pn protocol.PacketNumber) {
	h.appDataPackets.IgnoreBelow(pn)
}

func (h *ReceivedPacketHandler) DropPackets(encLevel protocol.EncryptionLevel) {
	//nolint:exhaustive // 1-RTT packet number space is never dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
		h.initialDelayed = nil
	case protocol.EncryptionHandshake:
		h.handshakePackets = nil
		h.handshakeDelayed = nil
	case protocol.Encryption0RTT:
		// Nothing to do here.
		// If we are rejecting 0-RTT, no 0-RTT packets will have been decrypted.
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
}

// GetAlarmTimeout is when the first ACK that waits for its delay is due.
func (h *ReceivedPacketHandler) GetAlarmTimeout() monotime.Time {
	alarm := h.appDataPackets.GetAlarmTimeout()
	for _, d := range []*appDataReceivedPacketTracker{h.initialDelayed, h.handshakeDelayed} {
		if d == nil {
			continue
		}
		if t := d.GetAlarmTimeout(); !t.IsZero() && (alarm.IsZero() || t.Before(alarm)) {
			alarm = t
		}
	}
	return alarm
}

func (h *ReceivedPacketHandler) GetAckFrame(encLevel protocol.EncryptionLevel, now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	//nolint:exhaustive // 0-RTT packets can't contain ACK frames.
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialDelayed != nil {
			return h.initialDelayed.GetAckFrame(now, onlyIfQueued)
		}
		if h.initialPackets != nil {
			return h.initialPackets.GetAckFrame()
		}
		return nil
	case protocol.EncryptionHandshake:
		if h.handshakeDelayed != nil {
			return h.handshakeDelayed.GetAckFrame(now, onlyIfQueued)
		}
		if h.handshakePackets != nil {
			return h.handshakePackets.GetAckFrame()
		}
		return nil
	case protocol.Encryption1RTT:
		return h.appDataPackets.GetAckFrame(now, onlyIfQueued)
	default:
		// 0-RTT packets can't contain ACK frames
		return nil
	}
}

func (h *ReceivedPacketHandler) IsPotentiallyDuplicate(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) bool {
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialDelayed != nil {
			return h.initialDelayed.IsPotentiallyDuplicate(pn)
		}
		if h.initialPackets != nil {
			return h.initialPackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.EncryptionHandshake:
		if h.handshakeDelayed != nil {
			return h.handshakeDelayed.IsPotentiallyDuplicate(pn)
		}
		if h.handshakePackets != nil {
			return h.handshakePackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.appDataPackets.IsPotentiallyDuplicate(pn)
	}
	panic("unexpected encryption level")
}
