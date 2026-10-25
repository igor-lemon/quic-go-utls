package quic

import (
	"math/rand/v2"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
)

// chaosLayout is how a client lays out its Initial packets when its profile
// says quic.initial_layout chaos, as quiche's QuicChaosProtector and
// MultiPacketChaosProtect do: a ClientHello that takes more than one packet
// has its first firstMin to firstMin+firstSpread-1 bytes and its end in the
// first packet and its middle in the next, and every Initial that carries
// CRYPTO and PADDING has its CRYPTO split splitsMin to splitsMax more times
// (while its padding allows), pingsMin to pingsMax PING frames added, its
// padding spread between the frames and the frames shuffled, its ACK kept
// where it is.
type chaosLayout struct {
	firstMin, firstSpread uint64
	splitsMin, splitsMax  uint64
	pingsMin, pingsMax    uint64
}

func chaosOf(p behavior.Policy) *chaosLayout {
	if p.Text("quic.initial_layout") != "chaos" {
		return nil
	}
	return &chaosLayout{
		firstMin: p.Uint("quic.chaos_first_frame_min"), firstSpread: p.Uint("quic.chaos_first_frame_spread"),
		splitsMin: p.Uint("quic.chaos_crypto_splits_min"), splitsMax: p.Uint("quic.chaos_crypto_splits_max"),
		pingsMin: p.Uint("quic.chaos_pings_min"), pingsMax: p.Uint("quic.chaos_pings_max"),
	}
}

// chaosFrame is a frame of a chaos layout: a frame of the packet's own, a
// CRYPTO frame cut from one of them, a PING, or that many bytes of padding.
type chaosFrame struct {
	frame   wire.Frame
	crypto  *wire.CryptoFrame
	isAck   bool
	padding protocol.ByteCount
}

// minCryptoFrameSize is quiche's GetMinCryptoFrameSize: a CRYPTO frame's
// type, offset and length, without its data.
func minCryptoFrameSize(offset, length protocol.ByteCount) int {
	return 1 + quicvarint.Len(uint64(offset)) + quicvarint.Len(uint64(length))
}

// appendPayload writes a client Initial's payload laid out by chaos, the
// same number of bytes as plainly: the ACK and the frames of pl and padding
// bytes of padding. It returns false, writing nothing, for a payload
// quiche's IngestFrames passes over: without CRYPTO, or without padding.
func (c *chaosLayout) appendPayload(raw []byte, pl payload, padding protocol.ByteCount, rng *rand.Rand, v protocol.Version) ([]byte, bool, error) {
	if padding <= 0 {
		return raw, false, nil
	}
	var frames []chaosFrame
	if pl.ack != nil {
		frames = append(frames, chaosFrame{frame: pl.ack, isAck: true})
	}
	var start, end protocol.ByteCount
	hasCrypto := false
	for _, f := range pl.frames {
		cf, ok := f.Frame.(*wire.CryptoFrame)
		if !ok {
			frames = append(frames, chaosFrame{frame: f.Frame})
			continue
		}
		// a copy: the packet's own frames are what it retransmits
		piece := &wire.CryptoFrame{Offset: cf.Offset, Data: cf.Data}
		frames = append(frames, chaosFrame{crypto: piece})
		fEnd := cf.Offset + protocol.ByteCount(len(cf.Data))
		if !hasCrypto || cf.Offset < start {
			start = cf.Offset
		}
		end = max(end, fEnd)
		hasCrypto = true
	}
	if !hasCrypto {
		return raw, false, nil
	}
	remaining := int(padding)

	// SplitCryptoFrame
	maxOverhead := minCryptoFrameSize(end, end-start)
	splits := c.splitsMin + rng.Uint64()%(c.splitsMax+1-c.splitsMin)
	for range splits {
		if remaining < maxOverhead {
			break
		}
		i := rng.Uint64() % uint64(len(frames))
		cf := frames[i].crypto
		if cf == nil || len(cf.Data) <= 1 {
			continue
		}
		oldOverhead := minCryptoFrameSize(cf.Offset, protocol.ByteCount(len(cf.Data)))
		keep := 1 + rng.Uint64()%uint64(len(cf.Data)-1)
		moved := &wire.CryptoFrame{Offset: cf.Offset + protocol.ByteCount(keep), Data: cf.Data[keep:]}
		cf.Data = cf.Data[:keep]
		frames = append(frames, chaosFrame{crypto: moved})
		remaining -= minCryptoFrameSize(moved.Offset, protocol.ByteCount(len(moved.Data)))
		remaining -= minCryptoFrameSize(cf.Offset, protocol.ByteCount(len(cf.Data)))
		remaining += oldOverhead
	}

	// AddPingFrames
	if remaining > 0 {
		pings := min(c.pingsMin+rng.Uint64()%(c.pingsMax+1-c.pingsMin), uint64(remaining))
		for range pings {
			frames = append(frames, chaosFrame{frame: &wire.PingFrame{}})
		}
		remaining -= int(pings)
	}

	// SpreadPadding: padding before a frame but an ACK, the rest at the end
	spread := make([]chaosFrame, 0, 2*len(frames)+1)
	for _, f := range frames {
		n := int(rng.Uint64() % uint64(remaining+1))
		if n > 0 && !f.isAck {
			spread = append(spread, chaosFrame{padding: protocol.ByteCount(n)})
			remaining -= n
		}
		spread = append(spread, f)
	}
	if remaining > 0 {
		spread = append(spread, chaosFrame{padding: protocol.ByteCount(remaining)})
	}

	reorderFrames(spread, rng)

	for _, f := range spread {
		var err error
		switch {
		case f.padding > 0:
			raw = append(raw, make([]byte, f.padding)...)
		case f.crypto != nil:
			raw, err = f.crypto.Append(raw, v)
		default:
			raw, err = f.frame.Append(raw, v)
		}
		if err != nil {
			return nil, false, err
		}
	}
	return raw, true, nil
}

// reorderFrames is quiche's ReorderFrames: from the end, each frame swapped
// with a random one at or before it (Fisher-Yates), an ACK left in its place.
func reorderFrames(spread []chaosFrame, rng *rand.Rand) {
	for i := len(spread) - 1; i > 0; i-- {
		j := rng.Uint64() % uint64(i+1)
		if !spread[i].isAck && !spread[j].isAck {
			spread[i], spread[j] = spread[j], spread[i]
		}
	}
}

// firstFlight is the plan of a ClientHello of length bytes over the packets
// of its first flight (quiche's MultiPacketChaosProtect), the first packet
// having room bytes for frames: its first first bytes and its last last ones
// in the first packet, the middle in the next ones. ok is false for a
// ClientHello that fits one packet, or a first packet too full to split.
func (c *chaosLayout) firstFlight(length, room protocol.ByteCount, rng *rand.Rand) (first, last protocol.ByteCount, ok bool) {
	minFrame := protocol.ByteCount(minCryptoFrameSize(length-1, length))
	if room < 2*minFrame {
		return 0, 0, false
	}
	maxFirst := room - 2*minFrame
	maxOther := room - minFrame
	if length <= maxFirst {
		return 0, 0, false
	}
	occupied := maxOther - maxFirst
	packets := (length + occupied + maxOther - 1) / maxOther
	other := (length + occupied + packets - 1) / packets
	inFirst := other - occupied // below zero when the first packet has room for no more than its frames
	first = protocol.ByteCount(c.firstMin + rng.Uint64()%c.firstSpread)
	if length <= first || inFirst <= first {
		return 0, 0, false
	}
	return first, inFirst - first, true
}
