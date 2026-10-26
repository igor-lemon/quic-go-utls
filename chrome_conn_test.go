package quic

import (
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/ackhandler"
	"github.com/igor-lemon/quic-go-utls/internal/handshake"
	"github.com/igor-lemon/quic-go-utls/internal/mocks"
	mockackhandler "github.com/igor-lemon/quic-go-utls/internal/mocks/ackhandler"
	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// chromeConnPolicy is chromeHandshakePolicy with Chrome's probe timeout,
// alarms, handshake timers and idle close.
func chromeConnPolicy(t *testing.T) behavior.Policy {
	t.Helper()
	p := chromeHandshakePolicy(t)
	for k, v := range map[string]string{
		"quic.pto_initial_rtt_ms": "100", "quic.pto_no_sample_multiplier": "3", "quic.pto_no_sample_min_ms": "10",
		"quic.pto_rttvar_multiplier": "2", "quic.alarm_slack_ms": "8", "quic.handshake_idle_timeout_ms": "4000",
		"quic.handshake_timeout_ms": "10000", "quic.handshake_ack_timer_ms": "1", "quic.idle_close": `"after-pto"`,
		"quic.idle_close_code": "0", "quic.idle_close_reason": `"25:No recent network activity after {elapsed}. Timeout:{timeout}"`,
		"quic.handshake_idle_close_reason": `"25:idle {elapsed}/{timeout}"`,
	} {
		p[k] = []byte(v)
	}
	require.NoError(t, p.Validate())
	return p
}

func TestAProfilesFieldsSayItsSendAndProbeTimeoutPolicies(t *testing.T) {
	pol := chromeConnPolicy(t)
	require.Equal(t, ackhandler.SendPolicy{SharedPacketNumbers: true, FirstPacketNumber: 1, WindowPacketNumberLength: true,
		SkipInEverySpace: true, Probes: 1, AlarmSlack: 8 * time.Millisecond}, sendPolicyOf(pol))
	require.Equal(t, utils.PTOPolicy{InitialRTT: 100 * time.Millisecond, NoSampleMultiplier: 3, NoSampleMin: 10 * time.Millisecond,
		RTTVarMultiplier: 2}, ptoPolicyOf(pol))
	// nothing said is quic-go's way
	require.Equal(t, ackhandler.SendPolicy{}, sendPolicyOf(behavior.Legacy()))
	require.Equal(t, utils.PTOPolicy{}, ptoPolicyOf(behavior.Legacy()))
}

func TestAClientConnectionTakesItsProfilesPolicies(t *testing.T) {
	tc := newClientTestConnection(t, nil, &Config{Behavior: chromeConnPolicy(t), DisablePathMTUDiscovery: true}, false)
	c := tc.conn
	pn, l := c.sentPacketHandler.PeekPacketNumber(protocol.EncryptionInitial)
	require.Equal(t, protocol.PacketNumber(1), pn, "one counter from 1")
	require.Equal(t, protocol.PacketNumberLen1, l)
	require.Equal(t, 300*time.Millisecond, c.rttStats.PTO(false), "3 x 100 ms")
	require.Equal(t, 8*time.Millisecond, c.alarmSlack())
	require.Equal(t, 4008*time.Millisecond, c.handshakeIdleTimeout())
	require.NotNil(t, c.initialStream.chaos, "the first flight laid out by chaos")
	// the server's Initial acknowledged within a millisecond, not at once
	now := monotime.Now()
	require.NoError(t, c.receivedPacketHandler.ReceivedPacket(0, protocol.ECNNon, protocol.EncryptionInitial, now, true))
	require.Nil(t, c.receivedPacketHandler.GetAckFrame(protocol.EncryptionInitial, now, true))
	require.NotNil(t, c.receivedPacketHandler.GetAckFrame(protocol.EncryptionInitial, now.Add(time.Millisecond), true))
	// a lone 1-RTT packet's ACK the alarm's slack after its delay, the
	// profile's 24 ms
	require.NoError(t, c.receivedPacketHandler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.Equal(t, now.Add(32*time.Millisecond), c.receivedPacketHandler.GetAlarmTimeout())
	// quic-go's, without the profile
	tc = newClientTestConnection(t, nil, &Config{DisablePathMTUDiscovery: true}, false)
	pn, _ = tc.conn.sentPacketHandler.PeekPacketNumber(protocol.EncryptionInitial)
	require.Zero(t, pn)
	require.Nil(t, tc.conn.initialStream.chaos)
	require.Zero(t, tc.conn.alarmSlack())
	require.NoError(t, tc.conn.receivedPacketHandler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.Equal(t, now.Add(protocol.MaxAckDelay), tc.conn.receivedPacketHandler.GetAlarmTimeout())
}

func TestAServersAlarmsAreOnTime(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	sph.EXPECT().PTOCount().Return(uint32(2)).AnyTimes()
	tc := newServerTestConnection(t, mockCtrl, &Config{Behavior: chromeConnPolicy(t), DisablePathMTUDiscovery: true}, false,
		connectionOptSentPacketHandler(sph))
	require.Zero(t, tc.conn.alarmSlack(), "the slack is a client's, Chrome's network thread's")
	now := monotime.Now()
	require.NoError(t, tc.conn.receivedPacketHandler.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.Equal(t, now.Add(protocol.MaxAckDelay), tc.conn.receivedPacketHandler.GetAlarmTimeout(), "its ACK alarm on time")
	// and its idle connection ends silently, whatever the profile says and
	// however many probes went unanswered
	tc.conn.closeIdle(time.Second)
	e := tc.conn.closeErr.Load()
	require.NotNil(t, e)
	require.True(t, e.immediate)
	require.ErrorIs(t, e.err, qerr.ErrIdleTimeout)
}

func TestAnIdleClientIsToldOfOnlyWhenItsProbesWentUnanswered(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	for _, tc := range []struct {
		probes uint32
		told   bool
	}{{0, false}, {1, true}} {
		sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
		sph.EXPECT().PTOCount().Return(tc.probes).AnyTimes()
		c := newClientTestConnection(t, mockCtrl, &Config{Behavior: chromeConnPolicy(t), DisablePathMTUDiscovery: true}, false,
			connectionOptSentPacketHandler(sph)).conn
		c.closeIdle(4008 * time.Millisecond)
		e := c.closeErr.Load()
		require.NotNil(t, e)
		require.Equal(t, !tc.told, e.immediate, "%d probes", tc.probes)
		var idle *idleClose
		if tc.told {
			require.ErrorAs(t, e.err, &idle)
			require.Equal(t, "25:idle 4008ms/4s", idle.close.ErrorMessage)
		} else {
			require.ErrorIs(t, e.err, qerr.ErrIdleTimeout)
		}
	}
}

func TestAClientTellsItsHandlerOfEachSetOfReadKeys(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	c := newClientTestConnection(t, mockCtrl, &Config{Behavior: chromeConnPolicy(t), DisablePathMTUDiscovery: true}, false,
		connectionOptSentPacketHandler(sph), connectionOptCryptoSetup(cs)).conn
	gomock.InOrder(
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedReadKeys}),
		sph.EXPECT().KeysInstalled(protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedReadKeys}),
		sph.EXPECT().KeysInstalled(protocol.Encryption1RTT),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
	)
	require.NoError(t, c.handleHandshakeEvents(monotime.Now()))
}

func TestAHandshakeTakesAsLongAsItsProfileSays(t *testing.T) {
	require.Equal(t, 10*time.Second, populateConfig(&Config{Behavior: chromeConnPolicy(t)}).handshakeTimeout())
	require.Equal(t, 4*time.Second, populateConfig(&Config{Behavior: chromeConnPolicy(t)}).HandshakeIdleTimeout)
	// quic-go's: twice the idle time
	c := populateConfig(&Config{HandshakeIdleTimeout: 3 * time.Second})
	require.Equal(t, 6*time.Second, c.handshakeTimeout())
}
