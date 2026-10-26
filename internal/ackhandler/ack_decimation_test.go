package ackhandler

import (
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"

	"github.com/stretchr/testify/require"
)

// chromeTracker is an application data tracker that acknowledges as Chrome
// 155's QUIC client does (quiche at its DEPS revision): decimated from the
// peer's first packet number plus 100, every tenth ack-eliciting packet or a
// quarter of the least round trip *rtt says, 1 ms at least, the 24 ms timer
// at most; each of four packets after a gap at once; its alarm 4 ms late,
// and no more than a fifth of its delay.
func chromeTracker(rtt *time.Duration) *appDataReceivedPacketTracker {
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.maxAckDelay = 24 * time.Millisecond
	tr.alarmSlack = 4 * time.Millisecond
	tr.slackPercent = 20
	tr.gapPackets = 4
	tr.decimation = &AckDecimation{
		After: 100, Packets: 10, RTTPercent: 25, Min: time.Millisecond,
		MinRTT: func() time.Duration { return *rtt },
	}
	return tr
}

func TestDecimationBeginsAtThePeersFirstPacketNumberPlusItsAfter(t *testing.T) {
	rtt := 40 * time.Millisecond
	tr := chromeTracker(&rtt)
	now := monotime.Now()
	// the peer's first is 2: 2 to 101 are acknowledged two by two
	for pn := protocol.PacketNumber(2); pn <= 101; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		ack := tr.GetAckFrame(now, true)
		if pn%2 == 1 {
			require.NotNil(t, ack, pn)
			require.Equal(t, pn, ack.LargestAcked())
		} else {
			require.Nil(t, ack, pn)
		}
	}
	// from 102, the first plus 100, every tenth
	for pn := protocol.PacketNumber(102); pn <= 141; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		ack := tr.GetAckFrame(now, true)
		if (pn-101)%10 == 0 {
			require.NotNil(t, ack, pn)
			require.Equal(t, pn, ack.LargestAcked())
		} else {
			require.Nil(t, ack, pn)
		}
	}
	// a packet that is not ack-eliciting counts for nothing
	for pn := protocol.PacketNumber(142); pn <= 151; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, pn != 145))
		require.Nil(t, tr.GetAckFrame(now, true), pn)
	}
	require.NoError(t, tr.ReceivedPacket(152, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
}

func TestDecimationCountsFromTheLeastPacketNumberReceived(t *testing.T) {
	rtt := 40 * time.Millisecond
	tr := chromeTracker(&rtt)
	now := monotime.Now()
	// 11 first, then 10: the peer's first is 10, as far as the tracker
	// knows, and decimation begins at 110, not 111
	for _, pn := range []protocol.PacketNumber{11, 10} {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
	}
	require.NotNil(t, tr.GetAckFrame(now, true))
	for pn := protocol.PacketNumber(12); pn <= 107; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		tr.GetAckFrame(now, true)
	}
	require.NoError(t, tr.ReceivedPacket(108, protocol.ECNNon, now, true))
	require.Equal(t, now.Add(28*time.Millisecond), tr.GetAlarmTimeout(), "108 is not decimated: 24 ms, 4 late")
	require.NoError(t, tr.ReceivedPacket(109, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true), "nor 109")
	require.NoError(t, tr.ReceivedPacket(110, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true), "110 waits for nine more")
	require.Equal(t, now.Add(12*time.Millisecond), tr.GetAlarmTimeout(), "110 is: 10 ms, 2 late")
}

func TestADecimatedACKWaitsAQuarterOfTheLeastRoundTripFromTheFirstPacket(t *testing.T) {
	rtt := 40 * time.Millisecond
	tr := chromeTracker(&rtt)
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn < 100; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
	}
	tr.GetAckFrame(now, false)
	// 10 ms, a quarter of 40, and 2 ms late, a fifth of it
	require.NoError(t, tr.ReceivedPacket(100, protocol.ECNNon, now, true))
	require.Equal(t, now.Add(12*time.Millisecond), tr.GetAlarmTimeout())
	// a packet after it brings it no later, whatever the round trip says now
	rtt = 80 * time.Millisecond
	later := now.Add(5 * time.Millisecond)
	require.NoError(t, tr.ReceivedPacket(101, protocol.ECNNon, later, true))
	require.Equal(t, now.Add(12*time.Millisecond), tr.GetAlarmTimeout())
	require.Nil(t, tr.GetAckFrame(now.Add(12*time.Millisecond-1), true))
	ack := tr.GetAckFrame(now.Add(12*time.Millisecond), true)
	require.NotNil(t, ack)
	require.Equal(t, protocol.PacketNumber(101), ack.LargestAcked())
	require.Equal(t, 7*time.Millisecond, ack.DelayTime, "said from the largest")
	// one that would come sooner brings it nearer
	rtt = 40 * time.Millisecond
	require.NoError(t, tr.ReceivedPacket(102, protocol.ECNNon, later, true))
	require.Equal(t, later.Add(12*time.Millisecond), tr.GetAlarmTimeout())
	rtt = 8 * time.Millisecond
	require.NoError(t, tr.ReceivedPacket(103, protocol.ECNNon, later.Add(time.Millisecond), true))
	require.Equal(t, later.Add(time.Millisecond+2400*time.Microsecond), tr.GetAlarmTimeout(),
		"2 ms, and 0.4 late")
}

func TestADecimatedACKWaitsNoLessThanItsFloorAndNoMoreThanTheTimer(t *testing.T) {
	for _, tc := range []struct {
		rtt, alarm time.Duration
	}{
		{0, 1200 * time.Microsecond},                    // no sample yet: the floor, 0.2 late
		{2 * time.Millisecond, 1200 * time.Microsecond}, // half a millisecond: the floor
		{4 * time.Millisecond, 1200 * time.Microsecond}, // the floor itself
		{6 * time.Millisecond, 1800 * time.Microsecond}, // 1.5 ms, 0.3 late
		{96 * time.Millisecond, 28 * time.Millisecond},  // the timer, and 4 late, less than a fifth
		{400 * time.Millisecond, 28 * time.Millisecond}, // no more than the timer
	} {
		rtt := tc.rtt
		tr := chromeTracker(&rtt)
		now := monotime.Now()
		for pn := protocol.PacketNumber(0); pn < 100; pn++ {
			require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
		}
		tr.GetAckFrame(now, false)
		require.NoError(t, tr.ReceivedPacket(100, protocol.ECNNon, now, true))
		require.Equal(t, now.Add(tc.alarm), tr.GetAlarmTimeout(), tc.rtt.String())
	}
	// a floor above the timer is the floor, as quiche's granularity is over
	// a delay an ACK_FREQUENCY frame makes shorter: 10 ms, and 2 late
	rtt := 400 * time.Millisecond
	tr := chromeTracker(&rtt)
	tr.maxAckDelay = 5 * time.Millisecond
	tr.decimation.Min = 10 * time.Millisecond
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn < 100; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
	}
	tr.GetAckFrame(now, false)
	require.NoError(t, tr.ReceivedPacket(100, protocol.ECNNon, now, true))
	require.Equal(t, now.Add(12*time.Millisecond), tr.GetAlarmTimeout())
}

func TestEachOfTheFirstPacketsAfterAGapIsAcknowledgedAtOnceAsQuicheDoes(t *testing.T) {
	now := monotime.Now()
	acked := func(tr *appDataReceivedPacketTracker, pns ...protocol.PacketNumber) []bool {
		var out []bool
		for _, pn := range pns {
			require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
			out = append(out, tr.GetAckFrame(now, true) != nil)
		}
		return out
	}
	// 2 never comes: 3, 4, 5 and 6 each at once, then two by two again
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.gapPackets = 4
	require.Equal(t, []bool{false, true, true, true, true, true, false, true, false, true},
		acked(tr, 0, 1, 3, 4, 5, 6, 7, 8, 9, 10))
	// a second gap: the highest range is new and short again
	require.Equal(t, []bool{true, true, true, true, false, true}, acked(tr, 12, 13, 14, 15, 16, 17))
	// quic-go's rule: a gap at once when it is new, and no more
	tr = newAppDataReceivedPacketTracker(utils.DefaultLogger)
	require.Equal(t, []bool{false, true, true, false, true, false, true},
		acked(tr, 0, 1, 3, 4, 5, 6, 7))
	// one packet after a gap, as quiche's 1ACK
	tr = newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.gapPackets = 1
	require.Equal(t, []bool{false, true, true, false, true}, acked(tr, 0, 1, 3, 4, 5))
}

func TestAPacketMissingBelowWhatThePeerKnowsWasAcknowledgedIsAGap(t *testing.T) {
	now := monotime.Now()
	tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.gapPackets = 4
	for pn := protocol.PacketNumber(0); pn < 10; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
	}
	tr.GetAckFrame(now, false)
	// the peer knows 0 to 11 were acknowledged: 12, the least the tracker
	// waits for, never came, and 13 is the first after a gap
	tr.IgnoreBelow(12)
	require.NoError(t, tr.ReceivedPacket(13, protocol.ECNNon, now, true))
	require.NotNil(t, tr.GetAckFrame(now, true))
	// had it come, no gap
	tr = newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.gapPackets = 4
	for pn := protocol.PacketNumber(0); pn < 10; pn++ {
		require.NoError(t, tr.ReceivedPacket(pn, protocol.ECNNon, now, true))
	}
	tr.GetAckFrame(now, false)
	tr.IgnoreBelow(12)
	require.NoError(t, tr.ReceivedPacket(12, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
	// nor before the peer knew of anything
	tr = newAppDataReceivedPacketTracker(utils.DefaultLogger)
	tr.gapPackets = 4
	require.NoError(t, tr.ReceivedPacket(5, protocol.ECNNon, now, true))
	require.Nil(t, tr.GetAckFrame(now, true))
}

func TestAnACKAlarmIsLateByAPartOfItsDelayAtMost(t *testing.T) {
	now := monotime.Now()
	for _, tc := range []struct {
		delay   time.Duration
		percent int
		alarm   time.Duration
	}{
		{24 * time.Millisecond, 20, 28 * time.Millisecond},              // the slack whole: 4 ms of 4.8
		{10 * time.Millisecond, 20, 12 * time.Millisecond},              // a fifth of the delay
		{10 * time.Millisecond, 0, 14 * time.Millisecond},               // none said: the slack whole
		{time.Millisecond, 25, time.Millisecond + 250*time.Microsecond}, // a quarter
		{time.Millisecond, 100, 2 * time.Millisecond},                   // the whole delay
	} {
		tr := newAppDataReceivedPacketTracker(utils.DefaultLogger)
		tr.maxAckDelay = tc.delay
		tr.alarmSlack = 4 * time.Millisecond
		tr.slackPercent = tc.percent
		require.NoError(t, tr.ReceivedPacket(0, protocol.ECNNon, now, true))
		require.Equal(t, now.Add(tc.alarm), tr.GetAlarmTimeout(), "%s, %d%%", tc.delay, tc.percent)
	}
}

func TestAHandlerTellsItsApplicationDataTrackerHowToAcknowledge(t *testing.T) {
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	h.SetMaxAckDelay(24 * time.Millisecond)
	h.SetAlarmSlack(4 * time.Millisecond)
	h.SetAlarmSlackPercent(20)
	h.SetGapPackets(4)
	rtt := 40 * time.Millisecond
	h.SetAckDecimation(AckDecimation{
		After: 100, Packets: 10, RTTPercent: 25, Min: time.Millisecond,
		MinRTT: func() time.Duration { return rtt },
	})
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn < 100; pn++ {
		require.NoError(t, h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true))
		require.Equal(t, pn%2 == 1, h.AckQueued(), pn)
		if h.AckQueued() {
			require.NotNil(t, h.GetAckFrame(protocol.Encryption1RTT, now, true))
		}
	}
	require.False(t, h.AckQueued())
	// decimated: 10 ms, 2 late
	require.NoError(t, h.ReceivedPacket(100, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.Equal(t, now.Add(12*time.Millisecond), h.GetAlarmTimeout())
	// 102 after a gap, at once
	require.NoError(t, h.ReceivedPacket(102, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.True(t, h.AckQueued())
	require.NotNil(t, h.GetAckFrame(protocol.Encryption1RTT, now, true))
	require.False(t, h.AckQueued())
}
