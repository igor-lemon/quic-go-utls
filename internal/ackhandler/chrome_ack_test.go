package ackhandler

import (
	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestChromeAckDeadlineIncludesTimerMargin(t *testing.T) {
	h := NewReceivedPacketHandler(utils.DefaultLogger)
	h.SetMaxAckDelay(protocol.DefaultMaxAckDelay - protocol.TimerGranularity)
	now := monotime.Now()
	later := now
	require.NoError(t, h.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, later, true))
	deadline := h.GetAlarmTimeout()
	require.Equal(t, later.Add(24*time.Millisecond), deadline)
	require.Nil(t, h.GetAckFrame(protocol.Encryption1RTT, deadline.Add(-time.Nanosecond), true))
	require.NotNil(t, h.GetAckFrame(protocol.Encryption1RTT, deadline, true))
}
