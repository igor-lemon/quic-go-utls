package quic

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/igor-lemon/quic-go-utls/internal/ackhandler"
	"github.com/igor-lemon/quic-go-utls/internal/handshake"
	"github.com/igor-lemon/quic-go-utls/internal/mocks"
	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// chromeHandshakePolicy is the QUIC handshake of Chrome 155's profiles.
func chromeHandshakePolicy(t *testing.T) behavior.Policy {
	t.Helper()
	p := behavior.Legacy()
	for k, v := range map[string]string{
		"quic.packet_numbers": `"shared"`, "quic.first_packet_number": "1", "quic.packet_number_length": `"window"`,
		"quic.pto_skip": `"every-space"`, "quic.pto_probes": "1", "quic.initial_layout": `"chaos"`,
		"quic.chaos_first_frame_min": "55", "quic.chaos_first_frame_spread": "32", "quic.chaos_crypto_splits_min": "2",
		"quic.chaos_crypto_splits_max": "10", "quic.chaos_pings_min": "2", "quic.chaos_pings_max": "10",
		"quic.padding_position": `"end"`,
	} {
		p[k] = []byte(v)
	}
	require.NoError(t, p.Validate())
	return p
}

type chromeTestPacker struct {
	packer  *packetPacker
	sent    ackhandler.SentPacketHandler
	sealing *MockSealingManager
	acks    *MockAckFrameSource
	initial *initialCryptoStream
}

// newChromeTestPacker is a client's packer with the profile's policy, its
// packets numbered by a real handler, sealed by a sealer that writes them
// in the clear.
func newChromeTestPacker(t *testing.T, mockCtrl *gomock.Controller) *chromeTestPacker {
	pol := chromeHandshakePolicy(t)
	sent := ackhandler.NewSentPacketHandler(0, 1250, utils.NewRTTStats(), &utils.ConnectionStats{}, false, false, nil,
		protocol.PerspectiveClient, nil, utils.DefaultLogger)
	sent.SetSendPolicy(sendPolicyOf(pol))
	initial := newInitialCryptoStream(true)
	tp := &chromeTestPacker{sent: sent, sealing: NewMockSealingManager(mockCtrl), acks: NewMockAckFrameSource(mockCtrl), initial: initial}
	tp.packer = newPacketPacker(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		func() protocol.ConnectionID { return protocol.ParseConnectionID([]byte{1, 2, 3, 4}) },
		initial, newCryptoStream(), sent, newRetransmissionQueue(), tp.sealing, NewMockFrameSource(mockCtrl), tp.acks,
		newDatagramQueue(func() {}, utils.DefaultLogger), protocol.PerspectiveClient)
	tp.packer.setPolicy(pol)
	initial.setChaos(tp.packer.chaos, &tp.packer.rand)
	return tp
}

func syntheticClientHello(n int) []byte {
	b := make([]byte, n)
	b[0], b[1], b[2], b[3] = 1, byte((n-4)>>16), byte((n-4)>>8), byte(n-4)
	for i := 4; i < n; i++ {
		b[i] = byte(i * 7)
	}
	return b
}

// payloadOf is the plaintext payload of a long header packet sealed by the
// mock sealer, its header, and the bytes after the packet.
func payloadOf(t *testing.T, data []byte) (*wire.ExtendedHeader, []byte, []byte) {
	t.Helper()
	hdr, _, rest, err := wire.ParsePacket(data)
	require.NoError(t, err)
	ext, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	start := int(ext.ParsedLen())
	end := start + int(ext.Length) - int(ext.PacketNumberLen) - 7 // the mock sealer's tag
	return ext, data[start:end], rest
}

func TestAClientsFirstFlightIsLaidOutAsChromes(t *testing.T) {
	for range 20 {
		mockCtrl := gomock.NewController(t)
		tp := newChromeTestPacker(t, mockCtrl)
		hello := syntheticClientHello(1883)
		_, err := tp.initial.Write(hello)
		require.NoError(t, err)
		sealer := newMockShortHeaderSealer(mockCtrl)
		tp.sealing.EXPECT().GetInitialSealer().Return(sealer, nil).Times(2)
		tp.sealing.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)
		tp.sealing.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)
		tp.sealing.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).Times(2)
		tp.acks.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Times(2)
		now := monotime.Now()

		var got []byte
		var layouts []laidOut
		for i, want := range []struct {
			pn  protocol.PacketNumber
			len protocol.PacketNumberLen
		}{{1, protocol.PacketNumberLen1}, {2, protocol.PacketNumberLen2}} {
			p, err := tp.packer.PackCoalescedPacket(false, 1250, now, protocol.Version1)
			require.NoError(t, err)
			require.Len(t, p.longHdrPackets, 1)
			require.Equal(t, protocol.ByteCount(1250), p.buffer.Len(), "packet %d is padded to the datagram", i+1)
			hdr, pl, rest := payloadOf(t, p.buffer.Data)
			require.Empty(t, rest)
			require.Equal(t, want.pn, hdr.PacketNumber)
			require.Equal(t, want.len, hdr.PacketNumberLen)
			// read from a copy: the buffer goes back to its pool
			l := readLayout(t, append([]byte{}, pl...))
			pings := bytes.Count(l.kinds, []byte("P"))
			require.GreaterOrEqual(t, pings, 2)
			require.LessOrEqual(t, pings, 10)
			require.GreaterOrEqual(t, bytes.Count(l.kinds, []byte("C")), 3, "split at least twice: %s", l.kinds)
			layouts = append(layouts, l)
			p.buffer.Release()
		}
		// the first: the hello's first bytes and its end; the second: its middle
		first := layouts[0].joined(0)
		require.GreaterOrEqual(t, len(first), 55)
		require.Less(t, len(first), 87)
		var end protocol.ByteCount
		for off := range layouts[0].crypto {
			if off > 0 && (end == 0 || off < end) && layouts[0].joined(off) != nil && off >= protocol.ByteCount(len(first)) {
				end = off
			}
		}
		last := layouts[0].joined(end)
		require.Equal(t, 1883, int(end)+len(last))
		middle := layouts[1].joined(protocol.ByteCount(len(first)))
		require.Equal(t, int(end), len(first)+len(middle))
		got = append(append(append(got, first...), middle...), last...)
		require.Equal(t, hello, got)
		require.False(t, tp.initial.HasData())
	}
}

func TestACloseIsPaddedAfterItsFrameAsChromePadsIt(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newChromeTestPacker(t, mockCtrl)
	tp.sealing.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
	tp.sealing.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealing.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	tp.sealing.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
	reason := "25:No recent network activity after 4008694us. Timeout:4s num_undecryptable_packets: 0 {}"
	p, err := tp.packer.PackConnectionClose(&qerr.TransportError{ErrorCode: 0, ErrorMessage: reason}, 1250, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(1250), p.buffer.Len())
	hdr, pl, _ := payloadOf(t, p.buffer.Data)
	require.Equal(t, protocol.PacketNumber(1), hdr.PacketNumber)
	parser := wire.NewFrameParser(false, false, false)
	ft, n, err := parser.ParseType(pl, protocol.EncryptionInitial)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the CONNECTION_CLOSE first")
	f, m, err := parser.ParseLessCommonFrame(ft, pl[n:], protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, reason, f.(*wire.ConnectionCloseFrame).ReasonPhrase)
	require.Equal(t, bytes.Repeat([]byte{0}, len(pl)-n-m), pl[n+m:], "then the padding")
}

func TestPacketsCoalescedAreNumberedInOrderOfOneCounter(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newChromeTestPacker(t, mockCtrl)
	now := monotime.Now()
	// two Initials sent: the next three numbers go in one datagram
	tp.sent.PopPacketNumber(protocol.EncryptionInitial)
	tp.sent.PopPacketNumber(protocol.EncryptionInitial)
	sealer := newMockShortHeaderSealer(mockCtrl)
	tp.sealing.EXPECT().GetInitialSealer().Return(sealer, nil)
	tp.sealing.EXPECT().GetHandshakeSealer().Return(sealer, nil)
	tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil)
	tp.acks.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, true).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}})
	tp.acks.EXPECT().GetAckFrame(protocol.EncryptionHandshake, now, gomock.Any()).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}})
	tp.acks.EXPECT().GetAckFrame(protocol.Encryption1RTT, now, gomock.Any()).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 3}}})
	framer := tp.packer.framer.(*MockFrameSource)
	framer.EXPECT().HasData().Return(false).AnyTimes()
	// the Handshake Finished
	tp.packer.handshakeStream.Write([]byte("finished"))
	p, err := tp.packer.PackCoalescedPacket(false, 1250, now, protocol.Version1)
	require.NoError(t, err)
	require.Len(t, p.longHdrPackets, 2)
	require.NotNil(t, p.shortHdrPacket)
	require.Equal(t, protocol.PacketNumber(3), p.longHdrPackets[0].header.PacketNumber)
	require.Equal(t, protocol.PacketNumber(4), p.longHdrPackets[1].header.PacketNumber)
	require.Equal(t, protocol.PacketNumber(5), p.shortHdrPacket.PacketNumber)
	// ACKs alone: the Initial's padding at its end
	_, pl, _ := payloadOf(t, p.buffer.Data)
	require.Equal(t, byte(0x02), pl[0])
	require.Zero(t, pl[len(pl)-1])
	next, _ := tp.sent.PeekPacketNumber(protocol.Encryption1RTT)
	require.Equal(t, protocol.PacketNumber(6), next)
}

func TestProbesAndOneShotPacketsArePlanned(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newChromeTestPacker(t, mockCtrl)
	now := monotime.Now()
	sealer := newMockShortHeaderSealer(mockCtrl)
	// an Initial probe of a retransmitted CRYPTO frame, laid out by chaos
	tp.sealing.EXPECT().GetInitialSealer().Return(sealer, nil)
	tp.acks.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, false)
	tp.packer.retransmissionQueue.addInitial(&wire.CryptoFrame{Offset: 0, Data: syntheticClientHello(600)})
	p, err := tp.packer.PackPTOProbePacket(protocol.EncryptionInitial, 1250, false, now, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(1250), p.buffer.Len())
	hdr, pl, _ := payloadOf(t, p.buffer.Data)
	require.Equal(t, protocol.PacketNumber(1), hdr.PacketNumber)
	require.Equal(t, syntheticClientHello(600), readLayout(t, pl).joined(0))
	// a 1-RTT probe, a packet of the application's, an MTU and a path probe:
	// each the next number
	tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil).Times(4)
	framer := tp.packer.framer.(*MockFrameSource)
	framer.EXPECT().HasData().Return(false).AnyTimes()
	tp.acks.EXPECT().GetAckFrame(protocol.Encryption1RTT, now, gomock.Any())
	p, err = tp.packer.PackPTOProbePacket(protocol.Encryption1RTT, 1250, true, now, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(2), p.shortHdrPacket.PacketNumber)
	tp.acks.EXPECT().GetAckFrame(protocol.Encryption1RTT, now, gomock.Any()).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}})
	sp, err := tp.packer.AppendPacket(getPacketBuffer(), 1250, now, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(3), sp.PacketNumber)
	sp, _, err = tp.packer.PackMTUProbePacket(ackhandler.Frame{Frame: &wire.PingFrame{}}, 1300, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(4), sp.PacketNumber)
	sp, _, err = tp.packer.PackPathProbePacket(protocol.ParseConnectionID([]byte{9, 9, 9, 9}),
		[]ackhandler.Frame{{Frame: &wire.PathChallengeFrame{}}}, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(5), sp.PacketNumber)
}

// confirmed drops the Initial and Handshake spaces, which confirms the
// handshake: a datagram is then a whole room, whatever is planned in it.
func (tp *chromeTestPacker) confirmed(now monotime.Time) {
	tp.sent.DropPackets(protocol.EncryptionInitial, now)
	tp.sent.DropPackets(protocol.EncryptionHandshake, now)
}

func TestTheNumberAfterEveryKindOfPacketIsAsLongAsTheWindowSays(t *testing.T) {
	ccf := &qerr.TransportError{ErrorCode: 0x1, ErrorMessage: "gone"}
	for _, kind := range []struct {
		name string
		// the packets of the datagram, and whether streams have data to send
		packets int
		data    bool
		pack    func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time)
	}{
		{"a Handshake probe", 1, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.sealing.EXPECT().GetHandshakeSealer().Return(sealer, nil)
			tp.acks.EXPECT().GetAckFrame(protocol.EncryptionHandshake, now, false)
			tp.packer.handshakeStream.Write([]byte("finished"))
			_, err := tp.packer.PackPTOProbePacket(protocol.EncryptionHandshake, 1250, false, now, protocol.Version1)
			require.NoError(t, err)
		}},
		{"a 1-RTT probe", 1, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.confirmed(now)
			tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil)
			tp.acks.EXPECT().GetAckFrame(protocol.Encryption1RTT, now, gomock.Any())
			_, err := tp.packer.PackPTOProbePacket(protocol.Encryption1RTT, 1250, true, now, protocol.Version1)
			require.NoError(t, err)
		}},
		{"a packet of the application's", 1, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.confirmed(now)
			tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil)
			tp.acks.EXPECT().GetAckFrame(protocol.Encryption1RTT, now, gomock.Any()).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}})
			_, err := tp.packer.AppendPacket(getPacketBuffer(), 1250, now, protocol.Version1)
			require.NoError(t, err)
		}},
		{"an MTU probe", 1, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.confirmed(now)
			tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil)
			_, _, err := tp.packer.PackMTUProbePacket(ackhandler.Frame{Frame: &wire.PingFrame{}}, 1300, protocol.Version1)
			require.NoError(t, err)
		}},
		{"a path probe", 1, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.confirmed(now)
			tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil)
			_, _, err := tp.packer.PackPathProbePacket(protocol.ParseConnectionID([]byte{9, 9, 9, 9}),
				[]ackhandler.Frame{{Frame: &wire.PathChallengeFrame{}}}, protocol.Version1)
			require.NoError(t, err)
		}},
		{"an Initial, a Handshake and a 1-RTT packet", 3, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.sealing.EXPECT().GetInitialSealer().Return(sealer, nil)
			tp.sealing.EXPECT().GetHandshakeSealer().Return(sealer, nil)
			tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil)
			tp.acks.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, true).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}})
			tp.acks.EXPECT().GetAckFrame(protocol.EncryptionHandshake, now, gomock.Any())
			tp.acks.EXPECT().GetAckFrame(protocol.Encryption1RTT, now, gomock.Any()).Return(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}})
			tp.packer.handshakeStream.Write([]byte("finished"))
			p, err := tp.packer.PackCoalescedPacket(false, 1250, now, protocol.Version1)
			require.NoError(t, err)
			require.Len(t, p.longHdrPackets, 2)
			require.NotNil(t, p.shortHdrPacket)
		}},
		{"a 0-RTT packet", 1, true, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.sealing.EXPECT().GetInitialSealer().Return(sealer, nil)
			tp.sealing.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			tp.sealing.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			tp.sealing.EXPECT().Get0RTTSealer().Return(sealer, nil)
			tp.acks.EXPECT().GetAckFrame(protocol.EncryptionInitial, now, true)
			expectAppendFrames(tp.packer.framer.(*MockFrameSource), []ackhandler.Frame{{Frame: &wire.MaxDataFrame{MaximumData: 0x1337}}}, nil)
			p, err := tp.packer.PackCoalescedPacket(false, 1250, now, protocol.Version1)
			require.NoError(t, err)
			require.Len(t, p.longHdrPackets, 1)
			require.Equal(t, protocol.Encryption0RTT, p.longHdrPackets[0].EncryptionLevel())
		}},
		{"a close in an Initial and a Handshake packet", 2, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.sealing.EXPECT().GetInitialSealer().Return(sealer, nil)
			tp.sealing.EXPECT().GetHandshakeSealer().Return(sealer, nil)
			tp.sealing.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			tp.sealing.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
			p, err := tp.packer.PackConnectionClose(ccf, 1250, protocol.Version1)
			require.NoError(t, err)
			require.Len(t, p.longHdrPackets, 2)
		}},
		{"a close in a 1-RTT packet", 1, false, func(t *testing.T, tp *chromeTestPacker, sealer *mocks.MockShortHeaderSealer, now monotime.Time) {
			tp.confirmed(now)
			tp.sealing.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
			tp.sealing.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysDropped)
			tp.sealing.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysDropped)
			tp.sealing.EXPECT().Get1RTTSealer().Return(sealer, nil)
			p, err := tp.packer.PackConnectionClose(ccf, 1250, protocol.Version1)
			require.NoError(t, err)
			require.NotNil(t, p.shortHdrPacket)
		}},
	} {
		// nothing acknowledged: the peer awaits the first number, so after
		// 63 a number is one byte long (4 x 63 < 256), after 64 two
		for _, last := range []protocol.PacketNumber{63, 64} {
			t.Run(fmt.Sprintf("%s, %d the last", kind.name, last), func(t *testing.T) {
				mockCtrl := gomock.NewController(t)
				tp := newChromeTestPacker(t, mockCtrl)
				tp.packer.framer.(*MockFrameSource).EXPECT().HasData().Return(kind.data).AnyTimes()
				for range int(last) - kind.packets {
					tp.sent.PopPacketNumber(protocol.Encryption1RTT)
				}
				now := monotime.Now()
				kind.pack(t, tp, newMockShortHeaderSealer(mockCtrl), now)
				pn, l := tp.sent.PeekPacketNumber(protocol.Encryption1RTT)
				require.Equal(t, last+1, pn)
				want := protocol.PacketNumberLen1
				if last == 64 {
					want = protocol.PacketNumberLen2
				}
				require.Equal(t, want, l)
			})
		}
	}
}
