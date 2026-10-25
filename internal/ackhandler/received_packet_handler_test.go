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

func TestGenerateACKsForPacketNumberSpaces(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	now := monotime.Now()
	sendTime := now.Add(-time.Second)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECT0, protocol.EncryptionInitial, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(5, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECT0, protocol.EncryptionInitial, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECT1, protocol.EncryptionHandshake, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNCE, protocol.Encryption1RTT, sendTime, true))

	// Initial
	initialAck := handler.GetAckFrame(protocol.EncryptionInitial, now, true)
	require.NotNil(t, initialAck)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 3}}, initialAck.AckRanges)
	require.Zero(t, initialAck.DelayTime)
	require.EqualValues(t, 2, initialAck.ECT0)
	require.Zero(t, initialAck.ECT1)
	require.Zero(t, initialAck.ECNCE)

	// Handshake
	handshakeAck := handler.GetAckFrame(protocol.EncryptionHandshake, now, true)
	require.NotNil(t, handshakeAck)
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, handshakeAck.AckRanges)
	require.Zero(t, handshakeAck.DelayTime)
	require.Zero(t, handshakeAck.ECT0)
	require.EqualValues(t, 2, handshakeAck.ECT1)
	require.Zero(t, handshakeAck.ECNCE)

	// 1-RTT
	oneRTTAck := handler.GetAckFrame(protocol.Encryption1RTT, now, true)
	require.NotNil(t, oneRTTAck)
	require.Equal(t, []wire.AckRange{{Smallest: 4, Largest: 5}}, oneRTTAck.AckRanges)
	require.Equal(t, time.Second, oneRTTAck.DelayTime)
	require.Zero(t, oneRTTAck.ECT0)
	require.Zero(t, oneRTTAck.ECT1)
	require.EqualValues(t, 2, oneRTTAck.ECNCE)
}

func TestReceive0RTTAnd1RTT(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	sendTime := monotime.Now().Add(-time.Second)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	ack := handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 3}}, ack.AckRanges)

	// 0-RTT packets with higher packet numbers than 1-RTT packets are rejected...
	require.Error(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true))
	// ... but reordered 0-RTT packets are allowed
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption0RTT, sendTime, true))
}

func TestDropPackets(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	sendTime := monotime.Now().Add(-time.Second)

	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.EncryptionInitial, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.EncryptionHandshake, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	// Initial
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionInitial, monotime.Now(), true))
	handler.DropPackets(protocol.EncryptionInitial)
	require.Nil(t, handler.GetAckFrame(protocol.EncryptionInitial, monotime.Now(), true))

	// Handshake
	require.NotNil(t, handler.GetAckFrame(protocol.EncryptionHandshake, monotime.Now(), true))
	handler.DropPackets(protocol.EncryptionHandshake)
	require.Nil(t, handler.GetAckFrame(protocol.EncryptionHandshake, monotime.Now(), true))

	// 1-RTT
	require.NotNil(t, handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true))

	// 0-RTT is a no-op
	handler.DropPackets(protocol.Encryption0RTT)
}

func TestAckRangePruning(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)

	sendTime := monotime.Now()
	require.NoError(t, handler.ReceivedPacket(1, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))
	require.NoError(t, handler.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	ack := handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 1, Largest: 2}}, ack.AckRanges)

	require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))
	handler.IgnorePacketsBelow(2)
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))

	ack = handler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true)
	require.NotNil(t, ack)
	require.Equal(t, []wire.AckRange{{Smallest: 2, Largest: 4}}, ack.AckRanges)
}

func TestPacketDuplicateDetection(t *testing.T) {
	handler := NewReceivedPacketHandler(utils.DefaultLogger)
	sendTime := monotime.Now()

	// 1-RTT is tested separately at the end
	encLevels := []protocol.EncryptionLevel{
		protocol.EncryptionInitial,
		protocol.EncryptionHandshake,
		protocol.Encryption0RTT,
	}

	for _, encLevel := range encLevels {
		// first, packet 3 is not a duplicate
		require.False(t, handler.IsPotentiallyDuplicate(3, encLevel))
		require.NoError(t, handler.ReceivedPacket(3, protocol.ECNNon, encLevel, sendTime, true))
		// now packet 3 is considered a duplicate
		require.True(t, handler.IsPotentiallyDuplicate(3, encLevel))
	}

	// 1-RTT
	require.True(t, handler.IsPotentiallyDuplicate(3, protocol.Encryption1RTT))
	require.False(t, handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT))
	require.NoError(t, handler.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption1RTT, sendTime, true))
	require.True(t, handler.IsPotentiallyDuplicate(4, protocol.Encryption1RTT))
}

func TestHandshakePacketsAreAcknowledgedWithinTheirDelayAsChromeDoes(t *testing.T) {
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		h := NewReceivedPacketHandler(utils.DefaultLogger)
		h.SetMaxAckDelay(24 * time.Millisecond)
		h.SetHandshakeAckDelay(time.Millisecond)
		now := monotime.Now()
		require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, level, now, true), level.String())
		// not before the delay, unless sent with data of the level
		require.Equal(t, now.Add(time.Millisecond), h.GetAlarmTimeout(), level.String())
		require.Nil(t, h.GetAckFrame(level, now.Add(time.Millisecond-1), true), level.String())
		require.True(t, h.IsPotentiallyDuplicate(0, level), level.String())
		ack := h.GetAckFrame(level, now.Add(time.Millisecond), true)
		require.NotNil(t, ack, level.String())
		require.Equal(t, time.Millisecond, ack.DelayTime, level.String())
		require.True(t, h.GetAlarmTimeout().IsZero(), level.String())
		// with data of the level, at once
		require.NoError(t, h.ReceivedPacket(1, protocol.ECNNon, level, now, true), level.String())
		require.NotNil(t, h.GetAckFrame(level, now, false), level.String())
		// two ack-eliciting packets are acknowledged at once
		require.NoError(t, h.ReceivedPacket(2, protocol.ECNNon, level, now, true), level.String())
		require.NoError(t, h.ReceivedPacket(3, protocol.ECNNon, level, now, true), level.String())
		require.NotNil(t, h.GetAckFrame(level, now, true), level.String())
		// the earliest of the spaces' alarms is the handler's
		require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true))
		require.NoError(t, h.ReceivedPacket(4, protocol.ECNNon, level, now.Add(time.Millisecond), true))
		require.Equal(t, now.Add(2*time.Millisecond), h.GetAlarmTimeout(), level.String())
		require.Equal(t, now.Add(24*time.Millisecond), h.appDataPackets.GetAlarmTimeout())
		h.DropPackets(level)
		require.Nil(t, h.GetAckFrame(level, now.Add(time.Second), false), level.String())
		require.Equal(t, now.Add(24*time.Millisecond), h.GetAlarmTimeout(), level.String())
	}
	// none said: acknowledged at once, as quic-go does
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	h.SetHandshakeAckDelay(0)
	now := monotime.Now()
	require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, protocol.EncryptionInitial, now, true))
	require.NotNil(t, h.GetAckFrame(protocol.EncryptionInitial, now, true))
	require.True(t, h.GetAlarmTimeout().IsZero())
}

func TestADelayedHandshakeSpaceDroppedTakesNoPacket(t *testing.T) {
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	h.SetHandshakeAckDelay(time.Millisecond)
	h.DropPackets(protocol.EncryptionHandshake)
	require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, protocol.EncryptionHandshake, monotime.Now(), true))
	require.Nil(t, h.GetAckFrame(protocol.EncryptionHandshake, monotime.Now(), false))
	h.DropPackets(protocol.EncryptionInitial)
	require.Nil(t, h.GetAckFrame(protocol.EncryptionInitial, monotime.Now(), false))
}
