package quic

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/synctest"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// chromeAckPolicy is chromeConnPolicy with how Chrome 155's client
// acknowledges (quiche at its DEPS revision, measured on the bench): decimated
// from the server's first packet number plus 100, each of four packets after
// a gap at once, an ACK sent before the next packet is taken, the twentieth
// ACK-only packet carrying MAX_DATA, its alarm late by a fifth of its delay
// at most.
func chromeAckPolicy(t *testing.T) behavior.Policy {
	t.Helper()
	p := chromeConnPolicy(t)
	for k, v := range map[string]string{
		"quic.ack_timer_ms": "24", "quic.max_ack_delay_ms": "25", "quic.ack_decimation_after": "100",
		"quic.ack_decimation_packets": "10", "quic.ack_decimation_rtt_percent": "25", "quic.ack_decimation_min_ms": "1",
		"quic.ack_gap_packets": "4", "quic.ack_sent_after": `"packet"`, "quic.ack_only_max": "19",
		"quic.ack_only_frame": `"max-data"`, "quic.ack_alarm_slack_percent": "20",
	} {
		p[k] = []byte(v)
	}
	require.NoError(t, p.Validate())
	return p
}

// aClientConnection is a client connection made as newClientConnection
// makes it, its packer its own.
func aClientConnection(t *testing.T, config *Config) *Conn {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	sendConn := NewMockSendConn(mockCtrl)
	sendConn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
	sendConn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}).AnyTimes()
	sendConn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}).AnyTimes()
	conn := newClientConnection(context.Background(), sendConn, NewMockConnRunner(mockCtrl),
		protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6}), protocol.ParseConnectionID([]byte{7, 8, 9, 10, 11, 12}),
		&protocol.DefaultConnectionIDGenerator{}, newStatelessResetter(nil), populateConfig(config),
		&tls.Config{ServerName: "quic-go.net"}, 0, false, false, nil, utils.DefaultLogger, protocol.Version1)
	return conn.Conn
}

func TestAClientConnectionAcknowledgesAsItsProfileSays(t *testing.T) {
	c := aClientConnection(t, &Config{
		Behavior: chromeAckPolicy(t), DisablePathMTUDiscovery: true,
		InitialConnectionReceiveWindow: 15728640, MaxConnectionReceiveWindow: 15728640,
	})
	require.True(t, c.acksAfterPacket)
	packer := c.packer.(*packetPacker)
	require.Equal(t, 19, packer.ackOnlyMax)
	require.NotNil(t, packer.maxData)
	require.Equal(t, protocol.ByteCount(15728640), packer.maxData(), "the connection's receive window")
	// no round trip measured: quiche's least is 0, so a decimated ACK waits
	// its floor, 1 ms, and a fifth of it late
	require.Zero(t, c.minRTT())
	h := &c.receivedPacketHandler
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn < 100; pn++ {
		require.NoError(t, h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true))
		h.GetAckFrame(protocol.Encryption1RTT, now, true)
	}
	require.NoError(t, h.ReceivedPacket(100, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.Equal(t, now.Add(1200*time.Microsecond), h.GetAlarmTimeout())
	// measured: a quarter of the least, 10 ms, and 2 ms late
	h.GetAckFrame(protocol.Encryption1RTT, now, false)
	c.rttStats.UpdateRTT(40*time.Millisecond, 0)
	c.rttStats.UpdateRTT(60*time.Millisecond, 0)
	require.Equal(t, 40*time.Millisecond, c.minRTT())
	require.NoError(t, h.ReceivedPacket(101, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.Equal(t, now.Add(12*time.Millisecond), h.GetAlarmTimeout())
	// each of the first packets after a gap at once
	require.NoError(t, h.ReceivedPacket(103, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.True(t, h.AckQueued())

	// quic-go's, without the profile
	c = aClientConnection(t, &Config{DisablePathMTUDiscovery: true})
	require.False(t, c.acksAfterPacket)
	packer = c.packer.(*packetPacker)
	require.Equal(t, protocol.MaxNonAckElicitingAcks, packer.ackOnlyMax)
	require.Nil(t, packer.maxData)
	h = &c.receivedPacketHandler
	for pn := protocol.PacketNumber(0); pn < 100; pn++ {
		require.NoError(t, h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true))
		h.GetAckFrame(protocol.Encryption1RTT, now, true)
	}
	require.NoError(t, h.ReceivedPacket(100, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.Equal(t, now.Add(protocol.MaxAckDelay), h.GetAlarmTimeout())
	require.NoError(t, h.ReceivedPacket(101, protocol.ECNNon, protocol.Encryption1RTT, now, true))
	require.True(t, h.AckQueued(), "every second packet")

	// a profile that says a PING, and another count
	pol := chromeAckPolicy(t)
	pol["quic.ack_only_frame"] = []byte(`"ping"`)
	pol["quic.ack_only_max"] = []byte("5")
	c = aClientConnection(t, &Config{Behavior: pol, DisablePathMTUDiscovery: true})
	packer = c.packer.(*packetPacker)
	require.Equal(t, 5, packer.ackOnlyMax)
	require.Nil(t, packer.maxData)
}

// ackOnlyPackets packs n packets of an ACK and nothing else.
func ackOnlyPackets(t *testing.T, tp *testPacketPacker, mockCtrl *gomock.Controller, n int) []shortHeaderPacket {
	t.Helper()
	var out []shortHeaderPacket
	for range n {
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
		tp.framer.EXPECT().HasData().Return(true)
		tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), false).Return(
			&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}},
		)
		expectAppendFrames(tp.framer, nil, nil)
		p, err := tp.packer.AppendPacket(getPacketBuffer(), 1000, monotime.Now(), protocol.Version1)
		require.NoError(t, err)
		require.NotNil(t, p.Ack)
		out = append(out, p)
	}
	return out
}

func TestTheTwentiethACKOnlyPacketCarriesMaxDataAsChromes(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.packer.setPolicy(behavior.Policy{"quic.ack_only_max": []byte("19"), "quic.ack_only_frame": []byte(`"max-data"`)})
	window := protocol.ByteCount(15728640)
	tp.packer.maxData = func() protocol.ByteCount { return window }
	// the window as it stands each time
	for _, offset := range []protocol.ByteCount{15728640, 15729640} {
		window = offset
		packets := ackOnlyPackets(t, tp, mockCtrl, 20)
		for i, p := range packets[:19] {
			require.Empty(t, p.Frames, i)
		}
		require.Len(t, packets[19].Frames, 1)
		require.Equal(t, &wire.MaxDataFrame{MaximumData: offset}, packets[19].Frames[0].Frame)
		require.NotNil(t, packets[19].Frames[0].Handler, "a lost MAX_DATA is sent again, as quiche's control frames are")
	}
	require.Empty(t, ackOnlyPackets(t, tp, mockCtrl, 1)[0].Frames)
	// a count of the profile's, and none: an ack-eliciting frame every time
	for _, n := range []int{0, 3} {
		tp = newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
		tp.packer.setPolicy(behavior.Policy{"quic.ack_only_max": []byte{byte('0' + n)}, "quic.ack_only_frame": []byte(`"max-data"`)})
		tp.packer.maxData = func() protocol.ByteCount { return 1 }
		for i, p := range ackOnlyPackets(t, tp, mockCtrl, 8) {
			require.Equal(t, i%(n+1) == n, len(p.Frames) == 1, "%d after %d", i, n)
		}
	}
}

func TestAnACKDueGoesBeforeTheNextPacketIsTaken(t *testing.T) {
	for _, afterPacket := range []bool{true, false} {
		mockCtrl := gomock.NewController(t)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptUnpacker(unpacker), connectionOptHandshakeConfirmed())
		tc.conn.acksAfterPacket = afterPacket
		var unpacked protocol.PacketNumber
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
			func(monotime.Time, []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				unpacked++
				return unpacked, protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0, 1} /* PADDING, PING */, nil
			},
		).AnyTimes()
		for i := range 7 {
			tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, protocol.PacketNumber(i), []byte("foobar")))
		}
		processed, err := tc.conn.handlePackets()
		require.NoError(t, err)
		require.True(t, processed)
		h := &tc.conn.receivedPacketHandler
		if !afterPacket {
			// quic-go's: every packet read at once, then the ACK
			require.Equal(t, protocol.PacketNumber(7), unpacked)
			continue
		}
		// the second makes an ACK due: it goes before the third is taken
		require.Equal(t, protocol.PacketNumber(2), unpacked)
		require.True(t, h.AckQueued())
		h.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true) // sent
		processed, err = tc.conn.handlePackets()
		require.NoError(t, err)
		require.True(t, processed)
		require.Equal(t, protocol.PacketNumber(4), unpacked)
		// while the send queue is full, the packets wait for the ACK
		tc.conn.sendQueueFull = true
		processed, err = tc.conn.handlePackets()
		require.NoError(t, err)
		require.False(t, processed)
		require.Equal(t, protocol.PacketNumber(4), unpacked)
		// once it is sent, they are taken, the queue full or not
		h.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true)
		processed, err = tc.conn.handlePackets()
		require.NoError(t, err)
		require.True(t, processed)
		require.Equal(t, protocol.PacketNumber(6), unpacked)
		// an ACK the loop could not send with room in the queue (a sent
		// packet handler that says SendNone) holds no packet up: the
		// packets may be the ACKs that let it send
		tc.conn.sendQueueFull = false
		processed, err = tc.conn.handlePackets()
		require.NoError(t, err)
		require.True(t, processed)
		require.Equal(t, protocol.PacketNumber(7), unpacked)
		h.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true)
		require.False(t, h.AckQueued())
	}
}

func TestPacketsWaitForAnACKAFullSendQueueHoldsUp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sender := NewMockSender(mockCtrl)
		unpacker := NewMockUnpacker(mockCtrl)
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptSender(sender),
			connectionOptUnpacker(unpacker), connectionOptHandshakeConfirmed())
		tc.conn.acksAfterPacket = true
		// the send queue is full once the first ACK is in it
		var full atomic.Bool
		available := make(chan struct{}, 1)
		sender.EXPECT().Run().MaxTimes(1)
		sender.EXPECT().WouldBlock().DoAndReturn(full.Load).AnyTimes()
		sender.EXPECT().Available().Return(available).AnyTimes()
		var unpacked atomic.Int64
		unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
			func(monotime.Time, []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
				return protocol.PacketNumber(unpacked.Add(1)), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{1} /* PING */, nil
			},
		).AnyTimes()
		var acks atomic.Int64
		var taken atomic.Bool
		taken.Store(true)
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(*packetBuffer, protocol.ByteCount, monotime.Time, protocol.Version) (shortHeaderPacket, error) {
				// the ACK taken as a packet would take it
				if taken.Load() && tc.conn.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, monotime.Now(), true) != nil {
					if acks.Add(1) == 1 {
						full.Store(true)
					}
				}
				return shortHeaderPacket{}, errNothingToPack
			},
		).AnyTimes()
		for i := range 7 {
			tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, protocol.PacketNumber(i), []byte("foobar")))
		}
		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		synctest.Wait()
		// the first ACK went and filled the queue; the second is due after
		// two more packets, and the rest wait for room to send it
		require.Equal(t, int64(1), acks.Load())
		require.Equal(t, int64(4), unpacked.Load())
		full.Store(false)
		available <- struct{}{}
		synctest.Wait()
		require.Equal(t, int64(3), acks.Load())
		require.Equal(t, int64(7), unpacked.Load())
		// an ACK the loop cannot send with room in the queue (a sent packet
		// handler that says SendNone) holds no packet up: they may be what
		// lets it send
		taken.Store(false)
		for i := 7; i < 9; i++ {
			tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, protocol.PacketNumber(i), []byte("foobar")))
		}
		synctest.Wait()
		require.Equal(t, int64(9), unpacked.Load())
		require.True(t, tc.conn.receivedPacketHandler.AckQueued())

		// test teardown
		sender.EXPECT().Close()
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)
		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("timeout")
		}
	})
}
