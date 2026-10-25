package quic

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/igor-lemon/quic-go-utls/internal/ackhandler"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/stretchr/testify/require"
)

// chromeChaos is Chrome 155's (quiche's) chaos protection.
var chromeChaos = &chaosLayout{firstMin: 55, firstSpread: 32, splitsMin: 2, splitsMax: 10, pingsMin: 2, pingsMax: 10}

func TestTheFirstFlightIsPlannedAsChromePlannedIt(t *testing.T) {
	// Chrome 155's first flights on the bench (h3a-*, h3b-*): the
	// ClientHello's length and its first frame's give the last frame's,
	// in a first packet with 1215 bytes for its frames
	for _, tc := range []struct{ length, first, last protocol.ByteCount }{
		{1883, 81, 858}, {1886, 71, 870}, {1907, 72, 879}, {1879, 74, 863}, {1873, 60, 874}, {1914, 72, 883},
	} {
		got := false
		for seed := range uint64(200) {
			first, last, ok := chromeChaos.firstFlight(tc.length, 1215, rand.New(rand.NewPCG(seed, 1)))
			require.True(t, ok)
			require.GreaterOrEqual(t, first, protocol.ByteCount(55))
			require.Less(t, first, protocol.ByteCount(87))
			require.Equal(t, tc.first+tc.last, first+last, "length %d", tc.length)
			got = got || first == tc.first
		}
		require.True(t, got, "length %d never began with %d bytes", tc.length, tc.first)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for _, tc := range []struct {
		name         string
		length, room protocol.ByteCount
	}{
		{"one that fits a packet", 1205, 1215},
		{"a first packet with no room for two frames", 1883, 9},
		{"a first packet too small for its first frame", 56, 60},
	} {
		_, _, ok := chromeChaos.firstFlight(tc.length, tc.room, rng)
		require.False(t, ok, tc.name)
	}
	first, last, ok := chromeChaos.firstFlight(1206, 1215, rng)
	require.True(t, ok)
	require.Equal(t, protocol.ByteCount(601), first+last)
	// three packets: the middle split evenly between the second and third
	first, last, ok = chromeChaos.firstFlight(3000, 1215, rng)
	require.True(t, ok)
	require.Equal(t, protocol.ByteCount(1002-5), first+last)
}

// laidOut is a payload read back: its frames in order, a padding run as
// one, and its CRYPTO data by offset.
type laidOut struct {
	kinds   []byte // A ack, C crypto, P ping, _ padding
	crypto  map[protocol.ByteCount][]byte
	padding int
}

func readLayout(t *testing.T, b []byte) laidOut {
	t.Helper()
	out := laidOut{crypto: map[protocol.ByteCount][]byte{}}
	parser := wire.NewFrameParser(false, false, false)
	for len(b) > 0 {
		switch b[0] {
		case 0x00:
			if len(out.kinds) == 0 || out.kinds[len(out.kinds)-1] != '_' {
				out.kinds = append(out.kinds, '_')
			}
			out.padding++
			b = b[1:]
		case 0x01:
			out.kinds = append(out.kinds, 'P')
			b = b[1:]
		case 0x02:
			_, n, err := parser.ParseAckFrame(wire.FrameTypeAck, b[1:], protocol.EncryptionInitial, protocol.Version1)
			require.NoError(t, err)
			out.kinds = append(out.kinds, 'A')
			b = b[1+n:]
		case 0x06:
			offset, n, err := quicvarint.Parse(b[1:])
			require.NoError(t, err)
			length, m, err := quicvarint.Parse(b[1+n:])
			require.NoError(t, err)
			start := 1 + n + m
			require.NotContains(t, out.crypto, protocol.ByteCount(offset))
			out.crypto[protocol.ByteCount(offset)] = b[start : start+int(length)]
			out.kinds = append(out.kinds, 'C')
			b = b[start+int(length):]
		default:
			t.Fatalf("frame type %#x in a laid out Initial", b[0])
		}
	}
	return out
}

// joined is the CRYPTO data of a layout from offset on, as long as it runs.
func (l laidOut) joined(offset protocol.ByteCount) []byte {
	var data []byte
	for {
		d, ok := l.crypto[offset]
		if !ok {
			return data
		}
		data = append(data, d...)
		offset += protocol.ByteCount(len(d))
	}
}

func cryptoPayload(frames ...*wire.CryptoFrame) payload {
	var pl payload
	for _, f := range frames {
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
		pl.length += f.Length(protocol.Version1)
	}
	return pl
}

func TestAnInitialIsLaidOutAsQuicheLaysItOut(t *testing.T) {
	hello := make([]byte, 1883)
	for i := range hello {
		hello[i] = byte(i)
	}
	first := &wire.CryptoFrame{Offset: 0, Data: hello[:81]}
	last := &wire.CryptoFrame{Offset: 1025, Data: hello[1025:]}
	pl := cryptoPayload(first, last)
	seen := map[string]bool{}
	for seed := range uint64(500) {
		raw, ok, err := chromeChaos.appendPayload([]byte("hdr"), pl, 267, rand.New(rand.NewPCG(seed, 7)), protocol.Version1)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, []byte("hdr"), raw[:3])
		require.Equal(t, int(pl.length)+267, len(raw)-3, "seed %d: the payload keeps its length", seed)
		l := readLayout(t, raw[3:])
		// the same bytes at the same offsets, in more frames
		require.Equal(t, hello[:81], l.joined(0))
		require.Equal(t, hello[1025:], l.joined(1025))
		crypto, pings := bytes.Count(l.kinds, []byte("C")), bytes.Count(l.kinds, []byte("P"))
		require.GreaterOrEqual(t, crypto, 2)
		require.LessOrEqual(t, crypto, 2+10)
		require.GreaterOrEqual(t, pings, 2)
		require.LessOrEqual(t, pings, 10)
		seen[string(l.kinds)] = true
		// the packet's own frames are left as they were, to be retransmitted
		require.Equal(t, hello[:81], first.Data)
		require.Equal(t, protocol.ByteCount(1025), last.Offset)
	}
	require.Greater(t, len(seen), 400, "layouts drawn")
}

func TestAnAckStaysFirstWithNoPaddingBeforeIt(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 300)
	pl := cryptoPayload(&wire.CryptoFrame{Offset: 0, Data: data})
	pl.ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 3}}}
	pl.length += pl.ack.Length(protocol.Version1)
	for seed := range uint64(200) {
		raw, ok, err := chromeChaos.appendPayload(nil, pl, 500, rand.New(rand.NewPCG(seed, 3)), protocol.Version1)
		require.NoError(t, err)
		require.True(t, ok)
		l := readLayout(t, raw)
		require.Equal(t, byte('A'), l.kinds[0], "seed %d: %s", seed, l.kinds)
		require.Equal(t, data, l.joined(0))
	}
}

func TestAnInitialQuicheDoesNotLayOutIsLeftPlain(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 1))
	crypto := cryptoPayload(&wire.CryptoFrame{Offset: 0, Data: []byte("hello")})
	raw, ok, err := chromeChaos.appendPayload([]byte("x"), crypto, 0, rng, protocol.Version1)
	require.NoError(t, err)
	require.False(t, ok, "no padding")
	require.Equal(t, []byte("x"), raw)
	ackOnly := payload{ack: &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}}
	ackOnly.frames = []ackhandler.Frame{{Frame: &wire.PingFrame{}}}
	raw, ok, err = chromeChaos.appendPayload([]byte("x"), ackOnly, 100, rng, protocol.Version1)
	require.NoError(t, err)
	require.False(t, ok, "no CRYPTO")
	require.Equal(t, []byte("x"), raw)
}

func TestLittlePaddingLimitsTheSplitsAndPings(t *testing.T) {
	data := bytes.Repeat([]byte{1}, 400)
	pl := cryptoPayload(&wire.CryptoFrame{Offset: 1000, Data: data})
	for seed := range uint64(100) {
		// too little for a split's frame, room for two PINGs at most
		raw, ok, err := chromeChaos.appendPayload(nil, pl, 2, rand.New(rand.NewPCG(seed, 5)), protocol.Version1)
		require.NoError(t, err)
		require.True(t, ok)
		l := readLayout(t, raw)
		require.Equal(t, 1, bytes.Count(l.kinds, []byte("C")))
		require.Equal(t, 2, bytes.Count(l.kinds, []byte("P"))+l.padding)
		require.Equal(t, data, l.joined(1000))
	}
	// one byte of CRYPTO cannot be split
	one := cryptoPayload(&wire.CryptoFrame{Offset: 0, Data: []byte{9}})
	raw, ok, err := chromeChaos.appendPayload(nil, one, 300, rand.New(rand.NewPCG(9, 9)), protocol.Version1)
	require.NoError(t, err)
	require.True(t, ok)
	l := readLayout(t, raw)
	require.Equal(t, 1, bytes.Count(l.kinds, []byte("C")))
	// no splits and no pings said
	none := &chaosLayout{firstMin: 55, firstSpread: 32}
	raw, ok, err = none.appendPayload(nil, pl, 300, rand.New(rand.NewPCG(9, 9)), protocol.Version1)
	require.NoError(t, err)
	require.True(t, ok)
	l = readLayout(t, raw)
	require.Equal(t, 1, bytes.Count(l.kinds, []byte("C")))
	require.Zero(t, bytes.Count(l.kinds, []byte("P")))
	require.Equal(t, 300, l.padding)
}

func TestTheFirstFlightIsPoppedAsQuicheSendsIt(t *testing.T) {
	hello := make([]byte, 1883)
	hello[0] = 1 // ClientHello
	hello[1], hello[2], hello[3] = 0, byte((1883-4)>>8), byte((1883-4)&0xff)
	for i := 4; i < len(hello); i++ {
		hello[i] = byte(i)
	}
	s := newInitialCryptoStream(true)
	s.setChaos(chromeChaos, rand.New(rand.NewPCG(3, 3)))
	require.False(t, s.scramble)
	require.False(t, s.HasData())
	_, err := s.Write(hello[:100])
	require.NoError(t, err)
	require.False(t, s.HasData(), "the whole ClientHello first")
	require.Nil(t, s.PopCryptoFrame(1215))
	_, err = s.Write(hello[100:])
	require.NoError(t, err)
	require.True(t, s.HasData())
	// the first packet: its first bytes and its end
	f1 := s.PopCryptoFrame(1215)
	require.Zero(t, f1.Offset)
	f2 := s.PopCryptoFrame(1215 - f1.Length(protocol.Version1))
	require.Equal(t, protocol.ByteCount(1883), f2.Offset+protocol.ByteCount(len(f2.Data)))
	require.Equal(t, protocol.ByteCount(939), protocol.ByteCount(len(f1.Data)+len(f2.Data)))
	require.True(t, s.HasData())
	require.Nil(t, s.PopCryptoFrame(1000), "the first packet ends")
	// the next: the middle, and the packet ends
	require.True(t, s.HasData())
	m := s.PopCryptoFrame(1214)
	require.Equal(t, protocol.ByteCount(len(f1.Data)), m.Offset)
	require.Equal(t, f2.Offset, m.Offset+protocol.ByteCount(len(m.Data)))
	require.Nil(t, s.PopCryptoFrame(1000))
	require.False(t, s.HasData())
	got := append(append(append([]byte{}, f1.Data...), m.Data...), f2.Data...)
	require.Equal(t, hello, got)
	// what comes after it (a second ClientHello) goes plainly
	_, err = s.Write([]byte{1, 0, 0, 1, 42})
	require.NoError(t, err)
	require.True(t, s.HasData())
	after := s.PopCryptoFrame(1215)
	require.Equal(t, protocol.ByteCount(1883), after.Offset)
	require.Equal(t, []byte{1, 0, 0, 1, 42}, after.Data)
}

func TestAMiddleOfMorePacketsGoesOnePacketAtATime(t *testing.T) {
	n := 3000
	hello := make([]byte, n)
	hello[0], hello[2], hello[3] = 1, byte((n-4)>>8), byte((n-4)&0xff)
	s := newInitialCryptoStream(true)
	s.setChaos(chromeChaos, rand.New(rand.NewPCG(4, 4)))
	_, _ = s.Write(hello)
	f1 := s.PopCryptoFrame(1215)
	f2 := s.PopCryptoFrame(1215 - f1.Length(protocol.Version1))
	require.Nil(t, s.PopCryptoFrame(1215))
	var middle []*wire.CryptoFrame
	for s.HasData() {
		if f := s.PopCryptoFrame(1214); f != nil {
			middle = append(middle, f)
		}
	}
	require.Len(t, middle, 2)
	require.Equal(t, protocol.ByteCount(len(f1.Data)), middle[0].Offset)
	require.Equal(t, f2.Offset, middle[1].Offset+protocol.ByteCount(len(middle[1].Data)))
	// a packet with no room for any of the middle ends at once
	s = newInitialCryptoStream(true)
	s.setChaos(chromeChaos, rand.New(rand.NewPCG(4, 4)))
	_, _ = s.Write(hello)
	s.PopCryptoFrame(1215)
	s.PopCryptoFrame(1000)
	s.PopCryptoFrame(1000)
	require.Nil(t, s.PopCryptoFrame(3))
	require.True(t, s.HasData())
}

func TestAFlightTheChaosCannotLayOutGoesPlainly(t *testing.T) {
	// a ClientHello that fits one packet
	short := make([]byte, 600)
	short[0], short[2], short[3] = 1, byte((600-4)>>8), byte((600-4)&0xff)
	s := newInitialCryptoStream(true)
	s.setChaos(chromeChaos, rand.New(rand.NewPCG(5, 5)))
	_, _ = s.Write(short)
	f := s.PopCryptoFrame(1215)
	require.Equal(t, short, f.Data)
	require.False(t, s.HasData())
	// data that is no ClientHello
	s = newInitialCryptoStream(true)
	s.setChaos(chromeChaos, rand.New(rand.NewPCG(5, 5)))
	_, _ = s.Write([]byte{2, 0, 0, 0})
	require.True(t, s.HasData())
	f = s.PopCryptoFrame(1215)
	require.Equal(t, []byte{2, 0, 0, 0}, f.Data)
	// a stream written past its first data: a hello of two packets not laid out
	long := make([]byte, 1900)
	long[0], long[2], long[3] = 1, byte((1900-4)>>8), byte((1900-4)&0xff)
	s = newInitialCryptoStream(true)
	s.setChaos(chromeChaos, rand.New(rand.NewPCG(5, 5)))
	s.writeOffset = 10
	_, _ = s.Write(long)
	f = s.PopCryptoFrame(1215)
	require.Equal(t, protocol.ByteCount(10), f.Offset)
	require.Greater(t, len(f.Data), 1000, "a frame as long as the packet, not the chaos's head")
}

func TestASplitTakesTheRoomOfItsFramesWhateverTheirOrder(t *testing.T) {
	// the CRYPTO frames out of order: their span is from the lowest offset,
	// a split's frame as long as quiche reckons it (5 bytes), more than the 4
	// of padding there are
	pl := cryptoPayload(&wire.CryptoFrame{Offset: 1000, Data: bytes.Repeat([]byte{1}, 10)},
		&wire.CryptoFrame{Offset: 0, Data: bytes.Repeat([]byte{2}, 10)})
	for seed := range uint64(50) {
		raw, ok, err := chromeChaos.appendPayload(nil, pl, 4, rand.New(rand.NewPCG(seed, 1)), protocol.Version1)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, 2, bytes.Count(readLayout(t, raw).kinds, []byte("C")), "seed %d", seed)
	}
}

func TestTheSplitsAndPingsAreDrawnInTheirRange(t *testing.T) {
	c := &chaosLayout{firstMin: 55, firstSpread: 32, splitsMin: 0, splitsMax: 3, pingsMin: 0, pingsMax: 3}
	pl := cryptoPayload(&wire.CryptoFrame{Offset: 0, Data: bytes.Repeat([]byte{1}, 800)})
	splits, pings := map[int]bool{}, map[int]bool{}
	for seed := range uint64(200) {
		raw, _, err := c.appendPayload(nil, pl, 300, rand.New(rand.NewPCG(seed, 2)), protocol.Version1)
		require.NoError(t, err)
		l := readLayout(t, raw)
		splits[bytes.Count(l.kinds, []byte("C"))-1] = true
		pings[bytes.Count(l.kinds, []byte("P"))] = true
	}
	require.Equal(t, map[int]bool{0: true, 1: true, 2: true, 3: true}, splits)
	require.Equal(t, map[int]bool{0: true, 1: true, 2: true, 3: true}, pings)
	// a byte of padding left takes a PING
	raw, _, err := chromeChaos.appendPayload(nil, pl, 1, rand.New(rand.NewPCG(3, 3)), protocol.Version1)
	require.NoError(t, err)
	l := readLayout(t, raw)
	require.Equal(t, 1, bytes.Count(l.kinds, []byte("P")))
	require.Zero(t, l.padding)
}

func TestTheFramesAreShuffledAsFisherAndYatesShuffle(t *testing.T) {
	// three frames take every order, the last one staying last too
	seen := map[string]bool{}
	for seed := range uint64(600) {
		spread := []chaosFrame{{padding: 1}, {padding: 2}, {padding: 3}}
		reorderFrames(spread, rand.New(rand.NewPCG(seed, 4)))
		seen[string([]byte{byte(spread[0].padding), byte(spread[1].padding), byte(spread[2].padding)})] = true
	}
	require.Len(t, seen, 6)
	// an ACK stays where it is
	spread := []chaosFrame{{isAck: true}, {padding: 1}, {padding: 2}}
	for seed := range uint64(50) {
		reorderFrames(spread, rand.New(rand.NewPCG(seed, 4)))
		require.True(t, spread[0].isAck)
	}
}

func TestAFirstFlightIsPlannedOnlyWhereItsPacketsHaveRoom(t *testing.T) {
	// a first packet of room for one frame's overhead, or less, plans nothing
	minFrame := protocol.ByteCount(minCryptoFrameSize(1999, 2000))
	for _, room := range []protocol.ByteCount{minFrame, minFrame + 1, 2*minFrame - 1} {
		_, _, ok := chromeChaos.firstFlight(2000, room, rand.New(rand.NewPCG(1, 1)))
		require.False(t, ok, "room %d", room)
	}
	// wherever a flight is planned, its first packet has the hello's head and
	// end, both of something, and its middle is left for the others
	for room := protocol.ByteCount(100); room <= 1300; room += 7 {
		for length := room - 50; length <= 3*room; length += 13 {
			first, last, ok := chromeChaos.firstFlight(length, room, rand.New(rand.NewPCG(uint64(room), uint64(length))))
			if ok {
				require.Positive(t, last, "room %d, length %d", room, length)
				require.Less(t, first+last, length, "room %d, length %d", room, length)
			}
		}
	}
}

func TestTheLengthOfAClientHello(t *testing.T) {
	require.Zero(t, clientHelloLength(nil))
	require.Zero(t, clientHelloLength([]byte{1, 0}))
	require.Zero(t, clientHelloLength([]byte{1, 0, 0, 2, 9}))
	require.Equal(t, protocol.ByteCount(6), clientHelloLength([]byte{1, 0, 0, 2, 9, 9, 8}))
	require.Zero(t, clientHelloLength([]byte{1, 0, 0}), "a header cut short")
	require.Equal(t, protocol.ByteCount(-1), clientHelloLength([]byte{2}))
	require.Equal(t, protocol.ByteCount(4+0x010203), clientHelloLength(append([]byte{1, 1, 2, 3}, make([]byte, 0x010203)...)))
}
