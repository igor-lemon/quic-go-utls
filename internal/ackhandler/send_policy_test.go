package ackhandler

import (
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/stretchr/testify/require"
)

// chromeSendPolicy is Chrome 155's (quiche's): one counter from 1, the window
// rule of a number's length, a number skipped at every probe timeout, one
// probe, the alarm 8 ms late.
var chromeSendPolicy = SendPolicy{SharedPacketNumbers: true, FirstPacketNumber: 1, WindowPacketNumberLength: true,
	SkipInEverySpace: true, Probes: 1, AlarmSlack: 8 * time.Millisecond}

func newPolicySender(t *testing.T, p SendPolicy) *sentPacketHandler {
	t.Helper()
	rtt := utils.NewRTTStats()
	rtt.SetPTOPolicy(utils.PTOPolicy{InitialRTT: 100 * time.Millisecond, NoSampleMultiplier: 3,
		NoSampleMin: 10 * time.Millisecond, RTTVarMultiplier: 2})
	h := NewSentPacketHandler(0, 1250, rtt, &utils.ConnectionStats{}, false, false, nil,
		protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.SetSendPolicy(p)
	return h
}

// sendPlanned sends an ack-eliciting packet of encLevel, planned in its
// datagram with size bytes before its padding, as the packer sends one, and
// says its number and the length the packer wrote it with.
func sendPlanned(t *testing.T, h *sentPacketHandler, now monotime.Time, encLevel protocol.EncryptionLevel, size protocol.ByteCount) (protocol.PacketNumber, protocol.PacketNumberLen) {
	t.Helper()
	pn, l := h.PeekPacketNumber(encLevel)
	h.PlanPacket(encLevel, size)
	require.Equal(t, pn, h.PopPacketNumber(encLevel))
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, size, false, false)
	return pn, l
}

func TestOneCounterNumbersEverySpaceAsChromeDoes(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	now := monotime.Now()
	// Chrome 155's first flight on the bench: 983 and 985 bytes before
	// their padding, the second number two bytes long
	pn, l := sendPlanned(t, h, now, protocol.EncryptionInitial, 983)
	require.Equal(t, protocol.PacketNumber(1), pn)
	require.Equal(t, protocol.PacketNumberLen1, l)
	pn, l = sendPlanned(t, h, now, protocol.EncryptionInitial, 985)
	require.Equal(t, protocol.PacketNumber(2), pn)
	require.Equal(t, protocol.PacketNumberLen2, l)
	// the server's flight: Handshake keys, then 1-RTT keys, each a whole room
	h.KeysInstalled(protocol.EncryptionHandshake)
	h.KeysInstalled(protocol.Encryption1RTT)
	// the Handshake Finished and the first 1-RTT packet in one datagram
	hsPN, hsLen := h.PeekPacketNumber(protocol.EncryptionHandshake)
	h.PlanPacket(protocol.EncryptionHandshake, 74)
	appPN, appLen := h.PeekPacketNumber(protocol.Encryption1RTT)
	h.PlanPacket(protocol.Encryption1RTT, 74)
	require.Equal(t, []protocol.PacketNumber{3, 4}, []protocol.PacketNumber{hsPN, appPN})
	require.Equal(t, []protocol.PacketNumberLen{protocol.PacketNumberLen1, protocol.PacketNumberLen1}, []protocol.PacketNumberLen{hsLen, appLen})
	require.Equal(t, hsPN, h.PopPacketNumber(protocol.EncryptionHandshake))
	require.Equal(t, appPN, h.PopPacketNumber(protocol.Encryption1RTT))
	// the next datagram begins after the two
	pn, _ = h.PeekPacketNumber(protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(5), pn)
	require.Zero(t, h.planned)
	require.Zero(t, h.plannedBytes)
}

func TestKeysThatComeWhilePacketsArePlannedLeaveTheLengthAlone(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	h.PlanPacket(protocol.EncryptionInitial, 983)
	require.Equal(t, protocol.PacketNumberLen2, h.pnLen)
	h.KeysInstalled(protocol.EncryptionHandshake)
	require.Equal(t, protocol.PacketNumberLen2, h.pnLen)
}

func TestSharedNumbersMayKeepQuicGosLength(t *testing.T) {
	p := chromeSendPolicy
	p.WindowPacketNumberLength = false
	h := newPolicySender(t, p)
	now := monotime.Now()
	for range 3 {
		_, l := sendPlanned(t, h, now, protocol.EncryptionInitial, 983)
		require.Equal(t, protocol.PacketNumberLen2, l)
	}
	h.KeysInstalled(protocol.EncryptionHandshake)
	_, l := h.PeekPacketNumber(protocol.EncryptionHandshake)
	require.Equal(t, protocol.PacketNumberLen2, l)
}

func TestAnUnplannedPacketTakesTheNextNumber(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	require.Equal(t, protocol.PacketNumber(1), h.PopPacketNumber(protocol.EncryptionInitial))
	require.Equal(t, protocol.PacketNumber(2), h.PopPacketNumber(protocol.Encryption1RTT))
	pn, _ := h.PeekPacketNumber(protocol.EncryptionHandshake)
	require.Equal(t, protocol.PacketNumber(3), pn)
}

func TestTheWindowRuleIsQuiches(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	cwnd := h.congestion.GetCongestionWindow()
	for _, tc := range []struct {
		next protocol.PacketNumber
		room protocol.ByteCount
		want protocol.PacketNumberLen
	}{
		{1, 1250, protocol.PacketNumberLen1},
		// the congestion window in packets of the room left decides
		{2, cwnd / 63, protocol.PacketNumberLen1},
		{2, cwnd / 64, protocol.PacketNumberLen2},
		{2, 1, protocol.PacketNumberLen4},
		// no room said: the packets the peer awaits alone
		{64, 0, protocol.PacketNumberLen1},
		{65, 0, protocol.PacketNumberLen2},
		{16384, 0, protocol.PacketNumberLen2},
		{16385, 0, protocol.PacketNumberLen4},
		// a number below the first awaited is none awaited
		{0, 0, protocol.PacketNumberLen1},
	} {
		require.Equal(t, tc.want, h.windowLength(tc.next, protocol.EncryptionInitial, tc.room), "next %d, room %d", tc.next, tc.room)
	}
}

func TestTheLeastAwaitedIsQuiches(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	now := monotime.Now()
	// none acknowledged in the space: the first number
	require.Equal(t, protocol.PacketNumber(1), h.leastAwaited(protocol.EncryptionInitial))
	for range 4 {
		sendPlanned(t, h, now, protocol.EncryptionInitial, 100)
	}
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(3)}, protocol.EncryptionInitial, now)
	require.NoError(t, err)
	// packets 1 and 2 still unacknowledged: the least of them
	require.Equal(t, protocol.PacketNumber(1), h.leastAwaited(protocol.EncryptionInitial))
	_, err = h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(1, 2, 3)}, protocol.EncryptionInitial, now)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(4), h.leastAwaited(protocol.EncryptionInitial))
	// another space with none acknowledged
	require.Equal(t, protocol.PacketNumber(1), h.leastAwaited(protocol.EncryptionHandshake))
	// a space dropped awaits the first number
	h.DropPackets(protocol.EncryptionInitial, now)
	require.Equal(t, protocol.PacketNumber(1), h.leastAwaited(protocol.EncryptionInitial))
}

func TestAProbeTimeoutSkipsANumberAndProbesOnceAsChromeDoes(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	start := monotime.Now()
	sendPlanned(t, h, start, protocol.EncryptionInitial, 983)
	sendPlanned(t, h, start, protocol.EncryptionInitial, 985)
	for i, want := range []time.Duration{300, 600, 1200} {
		alarm := h.GetLossDetectionTimeout()
		require.Equal(t, start.Add(want*time.Millisecond+8*time.Millisecond), alarm, "PTO %d", i+1)
		require.NoError(t, h.OnLossDetectionTimeout(alarm))
		require.Equal(t, SendPTOInitial, h.SendMode(alarm))
		require.Equal(t, 1, h.numProbesToSend)
		// the probe after a skipped number, one byte long in a whole room
		pn, l := h.PeekPacketNumber(protocol.EncryptionInitial)
		require.Equal(t, protocol.PacketNumber(4+2*i), pn)
		require.Equal(t, protocol.PacketNumberLen1, l)
		require.True(t, h.QueueProbePacket(protocol.EncryptionInitial))
		sendPlanned(t, h, alarm, protocol.EncryptionInitial, 960)
		require.NotEqual(t, SendPTOInitial, h.SendMode(alarm))
		start = alarm
	}
	require.EqualValues(t, 3, h.PTOCount())
}

func TestAProbeOfAnEmptySpaceSkipsANumberToo(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	now := monotime.Now()
	// a client whose Initials were all acknowledged, the server not yet
	// sure of its address: quic-go's anti-deadlock probe
	sendPlanned(t, h, now, protocol.EncryptionInitial, 983)
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(1)}, protocol.EncryptionInitial, now)
	require.NoError(t, err)
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	pn, _ := h.PeekPacketNumber(protocol.EncryptionInitial)
	require.Equal(t, protocol.PacketNumber(3), pn)
	h.DropPackets(protocol.EncryptionInitial, now)
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	require.Equal(t, SendPTOHandshake, h.SendMode(now))
	pn, _ = h.PeekPacketNumber(protocol.EncryptionHandshake)
	require.Equal(t, protocol.PacketNumber(4), pn)
}

func TestQuicGoSkipsANumberInTheApplicationsSpaceAloneAndProbesTwice(t *testing.T) {
	h := newPolicySender(t, SendPolicy{})
	now := monotime.Now()
	pn := h.PopPacketNumber(protocol.EncryptionInitial)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 1250, false, false)
	alarm := h.GetLossDetectionTimeout()
	require.Equal(t, now.Add(300*time.Millisecond), alarm)
	require.NoError(t, h.OnLossDetectionTimeout(alarm))
	require.Equal(t, 2, h.numProbesToSend)
	next, l := h.PeekPacketNumber(protocol.EncryptionInitial)
	require.Equal(t, pn+1, next)
	require.Equal(t, protocol.PacketNumberLen2, l)
	// a plan says nothing to separate counters
	h.PlanPacket(protocol.EncryptionInitial, 100)
	require.Zero(t, h.planned)
}

func TestTheAlarmOfATimeLossIsLateToo(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	h.rttStats.UpdateRTT(10*time.Millisecond, 0)
	now := monotime.Now()
	for range 3 {
		sendPlanned(t, h, now, protocol.EncryptionInitial, 100)
	}
	// the last acknowledged, the first two not yet lost by time
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(3)}, protocol.EncryptionInitial, now.Add(time.Millisecond))
	require.NoError(t, err)
	lossTime := h.initialPackets.lossTime
	require.False(t, lossTime.IsZero())
	require.Equal(t, lossTime.Add(8*time.Millisecond), h.GetLossDetectionTimeout())
}

func TestARetryKeepsTheOneCounter(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	now := monotime.Now()
	sendPlanned(t, h, now, protocol.EncryptionInitial, 983)
	sendPlanned(t, h, now, protocol.EncryptionInitial, 985)
	h.ResetForRetry(now)
	pn, _ := h.PeekPacketNumber(protocol.EncryptionInitial)
	require.Equal(t, protocol.PacketNumber(3), pn)
	sendPlanned(t, h, now, protocol.EncryptionInitial, 983)
	pn, _ = h.PeekPacketNumber(protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(4), pn)
	require.Same(t, h.shared, h.initialPackets.pns)
	require.Same(t, h.shared, h.appDataPackets.pns)
	require.True(t, h.appDataPackets.history.sharedCounter)
}

func TestAFirstNumberBelowTheConnectionsOwnKeepsItsOwn(t *testing.T) {
	// a connection made again after a version negotiation goes on from its
	// next number
	rtt := utils.NewRTTStats()
	h := NewSentPacketHandler(7, 1250, rtt, &utils.ConnectionStats{}, false, false, nil,
		protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.SetSendPolicy(chromeSendPolicy)
	pn, _ := h.PeekPacketNumber(protocol.EncryptionInitial)
	require.Equal(t, protocol.PacketNumber(7), pn)
}

func TestAMaxDatagramSizeIsTheWholeRoom(t *testing.T) {
	h := newPolicySender(t, chromeSendPolicy)
	h.SetMaxDatagramSize(1452)
	require.Equal(t, protocol.ByteCount(1452), h.maxDatagramSize)
}

func TestTheHistoryOfASpaceKeepsTheNumbersOfTheOthers(t *testing.T) {
	h := newSentPacketHistory(false)
	h.sharedCounter = true
	h.SentAckElicitingPacket(1, &packet{})
	// 2 and 3 went to other spaces
	h.SentAckElicitingPacket(4, &packet{})
	var pns []protocol.PacketNumber
	for pn := range h.Packets() {
		pns = append(pns, pn)
	}
	require.Equal(t, []protocol.PacketNumber{1, 4}, pns)
	require.Equal(t, protocol.PacketNumber(3), h.Difference(4, 1))
	require.NoError(t, h.Remove(1))
	pn, _ := h.FirstOutstanding()
	require.Equal(t, protocol.PacketNumber(4), pn)
	require.Panics(t, func() { h.SentAckElicitingPacket(4, &packet{}) })
	// the first packet of an empty history begins it, whatever the gap
	empty := newSentPacketHistory(false)
	empty.sharedCounter = true
	empty.SentAckElicitingPacket(9, &packet{})
	require.Equal(t, protocol.PacketNumber(9), empty.LowestPacketNumber())
	require.Equal(t, 1, empty.Len())
	// a history of a counter of its own takes no gap
	own := newSentPacketHistory(false)
	own.SentAckElicitingPacket(1, &packet{})
	require.Panics(t, func() { own.SentAckElicitingPacket(3, &packet{}) })
}

func TestTheSpacesOfOneCounterTakeItsNumbersInTurn(t *testing.T) {
	// each space's history has the numbers the others took between its own
	h := newPolicySender(t, chromeSendPolicy)
	now := monotime.Now()
	var got []protocol.PacketNumber
	for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake,
		protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		pn, _ := sendPlanned(t, h, now, encLevel, 100)
		got = append(got, pn)
	}
	require.Equal(t, []protocol.PacketNumber{1, 2, 3, 4}, got)
}

func TestOnceTheHandshakeIsConfirmedAPacketHasAWholeDatagram(t *testing.T) {
	// 40000 bytes of window: 32 packets of a whole datagram, a number of one
	// byte; 160 of the 250 bytes left, two
	for _, confirmed := range []bool{false, true} {
		h := newPolicySender(t, chromeSendPolicy)
		if confirmed {
			// dropping the Handshake space confirms the handshake (RFC 9001, 4.9.2)
			h.DropPackets(protocol.EncryptionInitial, monotime.Now())
			h.DropPackets(protocol.EncryptionHandshake, monotime.Now())
		}
		h.PlanPacket(protocol.Encryption1RTT, 1000)
		_, l := h.PeekPacketNumber(protocol.Encryption1RTT)
		want := protocol.PacketNumberLen2
		if confirmed {
			want = protocol.PacketNumberLen1
		}
		require.Equal(t, want, l, "confirmed %v", confirmed)
	}
}

func TestQuicGoSkipsANumberWhenItProbesItsApplicationsSpace(t *testing.T) {
	h := newPolicySender(t, SendPolicy{})
	now := monotime.Now()
	h.DropPackets(protocol.EncryptionInitial, now)
	h.DropPackets(protocol.EncryptionHandshake, now)
	pn := h.PopPacketNumber(protocol.Encryption1RTT)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1250, false, false)
	require.NoError(t, h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()))
	next, _ := h.PeekPacketNumber(protocol.Encryption1RTT)
	require.Equal(t, pn+2, next, "a number skipped to elicit an ACK at once")
}
