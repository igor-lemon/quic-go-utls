package quic

import (
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/ackhandler"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/utls/behavior"
)

// setAckPolicy has a client acknowledge its peer's packets as its profile
// says, as quiche's QuicReceivedPacketManager and QuicConnection do:
// decimated once the peer has sent many (quic.ack_decimation_*), each of the
// first packets after a gap at once (quic.ack_gap_packets), an ACK sent as
// soon as the packet that makes it due is taken, before the next
// (quic.ack_sent_after packet, quiche's ScopedPacketFlusher of
// ProcessUdpPacket), and an ACK alarm late by a part of its delay at most
// (quic.ack_alarm_slack_percent).
func (c *Conn) setAckPolicy(pol behavior.Policy) {
	if pol.Has("quic.ack_decimation_after") {
		c.receivedPacketHandler.SetAckDecimation(ackhandler.AckDecimation{
			After:      protocol.PacketNumber(pol.Uint("quic.ack_decimation_after")),
			Packets:    pol.Int("quic.ack_decimation_packets"),
			RTTPercent: pol.Int("quic.ack_decimation_rtt_percent"),
			Min:        time.Duration(pol.Uint("quic.ack_decimation_min_ms")) * time.Millisecond,
			MinRTT:     c.minRTT,
		})
	}
	c.receivedPacketHandler.SetGapPackets(pol.Int("quic.ack_gap_packets"))
	c.receivedPacketHandler.SetAlarmSlackPercent(pol.Int("quic.ack_alarm_slack_percent"))
	c.acksAfterPacket = pol.Text("quic.ack_sent_after") == "packet"
}

// minRTT is the least round trip the connection measured, 0 before its
// first sample, as quiche's RttStats has it (quic-go's starts at its
// initial round trip).
func (c *Conn) minRTT() time.Duration {
	if !c.rttStats.HasMeasurement() {
		return 0
	}
	return c.rttStats.MinRTT()
}
