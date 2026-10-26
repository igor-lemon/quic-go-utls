package ackhandler

import (
	"fmt"
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
)

const reorderingThreshold = 1

// The receivedPacketTracker tracks packets for the Initial and Handshake packet number space.
// Every received packet is acknowledged immediately.
type receivedPacketTracker struct {
	ect0, ect1, ecnce uint64

	packetHistory receivedPacketHistory

	lastAck   *wire.AckFrame
	hasNewAck bool // true as soon as we received an ack-eliciting new packet
}

func newReceivedPacketTracker() *receivedPacketTracker {
	return &receivedPacketTracker{packetHistory: *newReceivedPacketHistory()}
}

func (h *receivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, ackEliciting bool) error {
	if isNew := h.packetHistory.ReceivedPacket(pn); !isNew {
		return fmt.Errorf("receivedPacketTracker BUG: ReceivedPacket called for old / duplicate packet %d", pn)
	}

	//nolint:exhaustive // Only need to count ECT(0), ECT(1) and ECN-CE.
	switch ecn {
	case protocol.ECT0:
		h.ect0++
	case protocol.ECT1:
		h.ect1++
	case protocol.ECNCE:
		h.ecnce++
	}
	if !ackEliciting {
		return nil
	}
	h.hasNewAck = true
	return nil
}

func (h *receivedPacketTracker) GetAckFrame() *wire.AckFrame {
	if !h.hasNewAck {
		return nil
	}

	// This function always returns the same ACK frame struct, filled with the most recent values.
	ack := h.lastAck
	if ack == nil {
		ack = &wire.AckFrame{}
	}
	ack.Reset()
	ack.ECT0 = h.ect0
	ack.ECT1 = h.ect1
	ack.ECNCE = h.ecnce
	for r := range h.packetHistory.Backward() {
		ack.AckRanges = append(ack.AckRanges, wire.AckRange{Smallest: r.Start, Largest: r.End})
	}

	h.lastAck = ack
	h.hasNewAck = false
	return ack
}

func (h *receivedPacketTracker) IsPotentiallyDuplicate(pn protocol.PacketNumber) bool {
	return h.packetHistory.IsPotentiallyDuplicate(pn)
}

// number of ack-eliciting packets received before sending an ACK
const packetsBeforeAck = 2

// AckDecimation is how the application data's packets are acknowledged once
// the peer has sent many, as quiche's QuicReceivedPacketManager does
// (MaybeEnableAckDecimation, GetMaxAckDelay): from the first ack-eliciting
// packet numbered the peer's first plus After on, every Packets
// ack-eliciting packets; a packet numbered so waits RTTPercent of the least
// round trip MinRTT says, no less than Min and no more than the ACK delay
// (Min wins over the delay, as quiche's max of its granularity). A packet
// after the first one not acknowledged never puts the ACK off, only brings
// it nearer.
type AckDecimation struct {
	After      protocol.PacketNumber
	Packets    int
	RTTPercent int
	Min        time.Duration
	MinRTT     func() time.Duration
}

// The appDataReceivedPacketTracker tracks packets received in the Application Data packet number space.
// It waits until at least 2 packets were received before queueing an ACK, or until the max_ack_delay was reached.
type appDataReceivedPacketTracker struct {
	receivedPacketTracker

	largestObservedRcvdTime monotime.Time

	largestObserved protocol.PacketNumber
	ignoreBelow     protocol.PacketNumber
	// leastReceived is the least packet number received, the peer's first
	// to the tracker's knowledge (quiche's PeerFirstSendingPacketNumber)
	leastReceived protocol.PacketNumber

	maxAckDelay time.Duration
	// alarmSlack is how late the ACK alarm fires after maxAckDelay
	// (SetAlarmSlack), and with slackPercent no later than that percent of
	// the delay (SetAlarmSlackPercent)
	alarmSlack   time.Duration
	slackPercent int
	ackQueued    bool // true if we need send a new ACK

	// packetsBeforeAck is the ack-eliciting packets an ACK waits for,
	// decimation's once it began (SetAckDecimation)
	packetsBeforeAck int
	decimation       *AckDecimation
	// gapPackets, when set (SetGapPackets), is how many packets after a gap
	// are each acknowledged at once, as quiche's HasNewMissingPackets says
	gapPackets int

	ackElicitingPacketsReceivedSinceLastAck int
	ackAlarm                                monotime.Time

	logger utils.Logger
}

func newAppDataReceivedPacketTracker(logger utils.Logger) *appDataReceivedPacketTracker {
	h := &appDataReceivedPacketTracker{
		receivedPacketTracker: *newReceivedPacketTracker(),
		leastReceived:         protocol.InvalidPacketNumber,
		maxAckDelay:           protocol.MaxAckDelay,
		packetsBeforeAck:      packetsBeforeAck,
		logger:                logger,
	}
	return h
}

func (h *appDataReceivedPacketTracker) ReceivedPacket(pn protocol.PacketNumber, ecn protocol.ECN, rcvTime monotime.Time, ackEliciting bool) error {
	if err := h.receivedPacketTracker.ReceivedPacket(pn, ecn, ackEliciting); err != nil {
		return err
	}
	if h.leastReceived == protocol.InvalidPacketNumber || pn < h.leastReceived {
		h.leastReceived = pn
	}
	if pn >= h.largestObserved {
		h.largestObserved = pn
		h.largestObservedRcvdTime = rcvTime
	}
	if !ackEliciting {
		return nil
	}
	h.ackElicitingPacketsReceivedSinceLastAck++
	decimated := h.decimation != nil && pn >= h.leastReceived+h.decimation.After
	if decimated {
		h.packetsBeforeAck = h.decimation.Packets
	}
	isMissing := h.isMissing(pn)
	if !h.ackQueued && h.shouldQueueACK(pn, ecn, isMissing) {
		h.ackQueued = true
		h.ackAlarm = 0 // cancel the ack alarm
	}
	if !h.ackQueued {
		// No ACK queued, but we'll need to acknowledge the packet after max_ack_delay.
		delay := h.maxAckDelay
		if decimated {
			d := h.decimation
			delay = max(min(h.maxAckDelay, d.MinRTT()*time.Duration(d.RTTPercent)/100), d.Min)
		}
		// the alarm of the first packet not acknowledged is never put off,
		// as quiche's MaybeUpdateAckTimeout keeps the earliest timeout:
		// without decimation the next packet makes an ACK due anyway
		slack := h.slack(delay)
		if alarm := rcvTime.Add(delay + slack); h.ackAlarm.IsZero() || alarm.Before(h.ackAlarm) {
			h.ackAlarm = alarm
		}
		if h.logger.Debug() {
			h.logger.Debugf("\tSetting ACK timer to max ack delay: %s (%s late)", delay, slack)
		}
	}
	return nil
}

// slack is how late the alarm of an ACK that waits delay fires: the alarm's
// slack, and with slackPercent no more than that part of the delay, as a
// kernel that coalesces timers makes one late by a part of how long it waits
// (macOS, Chrome's network thread: a quarter, 5 ms at most).
func (h *appDataReceivedPacketTracker) slack(delay time.Duration) time.Duration {
	if h.slackPercent == 0 {
		return h.alarmSlack
	}
	return min(h.alarmSlack, delay*time.Duration(h.slackPercent)/100)
}

// IgnoreBelow sets a lower limit for acknowledging packets.
// Packets with packet numbers smaller than p will not be acked.
func (h *appDataReceivedPacketTracker) IgnoreBelow(pn protocol.PacketNumber) {
	if pn <= h.ignoreBelow {
		return
	}
	h.ignoreBelow = pn
	h.packetHistory.DeleteBelow(pn)
	if h.logger.Debug() {
		h.logger.Debugf("\tIgnoring all packets below %d.", pn)
	}
}

// isMissing says if a packet was reported missing in the last ACK.
func (h *appDataReceivedPacketTracker) isMissing(p protocol.PacketNumber) bool {
	if h.lastAck == nil || p < h.ignoreBelow {
		return false
	}
	return p < h.lastAck.LargestAcked() && !h.lastAck.AcksPacket(p)
}

func (h *appDataReceivedPacketTracker) hasNewMissingPackets() bool {
	if h.gapPackets > 0 {
		return h.afterGap()
	}
	if h.lastAck == nil {
		return false
	}
	if h.largestObserved < reorderingThreshold {
		return false
	}
	highestMissing := h.packetHistory.HighestMissingUpTo(h.largestObserved - reorderingThreshold)
	if highestMissing == protocol.InvalidPacketNumber {
		return false
	}
	if highestMissing < h.lastAck.LargestAcked() {
		// the packet was already reported missing in the last ACK
		return false
	}
	return highestMissing > h.lastAck.LargestAcked()-reorderingThreshold
}

// afterGap says, as quiche's HasNewMissingPackets does, whether the packets
// received have a gap (between two ranges, or below the least the peer knows
// was acknowledged, IgnoreBelow) and their highest range holds no more than
// gapPackets packets: each of the first packets after a gap is acknowledged
// at once, every time, and not only the first as quic-go's rule has it.
func (h *appDataReceivedPacketTracker) afterGap() bool {
	// the packet just received is in a range
	ranges := h.packetHistory.ranges
	missing := len(ranges) > 1 || h.ignoreBelow > 0 && ranges[0].Start > h.ignoreBelow
	last := ranges[len(ranges)-1]
	return missing && last.End-last.Start < protocol.PacketNumber(h.gapPackets)
}

func (h *appDataReceivedPacketTracker) shouldQueueACK(pn protocol.PacketNumber, ecn protocol.ECN, wasMissing bool) bool {
	// Send an ACK if this packet was reported missing in an ACK sent before.
	// Ack decimation with reordering relies on the timer to send an ACK, but if
	// missing packets we reported in the previous ACK, send an ACK immediately.
	if wasMissing {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d was missing before.", pn)
		}
		return true
	}

	// send an ACK every 2 ack-eliciting packets, or decimation's
	if h.ackElicitingPacketsReceivedSinceLastAck >= h.packetsBeforeAck {
		if h.logger.Debug() {
			h.logger.Debugf("\tQueueing ACK because packet %d packets were received after the last ACK (using threshold: %d).", h.ackElicitingPacketsReceivedSinceLastAck, h.packetsBeforeAck)
		}
		return true
	}

	// queue an ACK if there are new missing packets to report
	if h.hasNewMissingPackets() {
		h.logger.Debugf("\tQueuing ACK because there's a new missing packet to report.")
		return true
	}

	// queue an ACK if the packet was ECN-CE marked
	if ecn == protocol.ECNCE {
		h.logger.Debugf("\tQueuing ACK because the packet was ECN-CE marked.")
		return true
	}
	return false
}

func (h *appDataReceivedPacketTracker) GetAckFrame(now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	if onlyIfQueued && !h.ackQueued {
		if h.ackAlarm.IsZero() || h.ackAlarm.After(now) {
			return nil
		}
		if h.logger.Debug() && !h.ackAlarm.IsZero() {
			h.logger.Debugf("Sending ACK because the ACK timer expired.")
		}
	}
	ack := h.receivedPacketTracker.GetAckFrame()
	if ack == nil {
		return nil
	}
	ack.DelayTime = max(0, now.Sub(h.largestObservedRcvdTime))
	h.ackQueued = false
	h.ackAlarm = 0
	h.ackElicitingPacketsReceivedSinceLastAck = 0
	return ack
}

func (h *appDataReceivedPacketTracker) GetAlarmTimeout() monotime.Time { return h.ackAlarm }
