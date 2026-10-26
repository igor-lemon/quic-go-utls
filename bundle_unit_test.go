package quic

import (
	"context"
	"testing"

	"github.com/igor-lemon/quic-go-utls/internal/ackhandler"
	"github.com/igor-lemon/quic-go-utls/internal/flowcontrol"
	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/quic-go-utls/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// fakeSource is a stream that sends opportunistically: has is what it says
// when asked, frames what it gives once active.
type fakeSource struct {
	has    bool
	asked  int
	frames []*wire.StreamFrame
}

func (f *fakeSource) takeOpportunistic() bool { f.asked++; return f.has }

func (f *fakeSource) popStreamFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
	if len(f.frames) == 0 {
		return ackhandler.StreamFrame{}, nil, false
	}
	frame := f.frames[0]
	f.frames = f.frames[1:]
	return ackhandler.StreamFrame{Frame: frame}, nil, len(f.frames) > 0
}

func sourceOf(id protocol.StreamID, has bool) *fakeSource {
	return &fakeSource{has: has, frames: []*wire.StreamFrame{{StreamID: id, Data: []byte{byte(id)}, DataLenPresent: true}}}
}

func appendedStreams(t *testing.T, f *framer) []protocol.StreamID {
	t.Helper()
	_, fs, _ := f.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	var ids []protocol.StreamID
	for _, s := range fs {
		ids = append(ids, s.Frame.StreamID)
	}
	return ids
}

func TestTheFramerBundlesItsSourcesAheadOfTheOtherStreams(t *testing.T) {
	f := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	// no source: nothing asked
	require.False(t, f.BundleOpportunistically())
	// two sources with something, one with nothing, and a stream already
	// waiting: the sources first, in the order of their IDs
	six, ten, fourteen := sourceOf(6, true), sourceOf(10, true), sourceOf(14, false)
	f.AddOpportunisticSource(10, ten)
	f.AddOpportunisticSource(6, six)
	f.AddOpportunisticSource(14, fourteen)
	f.AddActiveStream(0, sourceOf(0, false))
	require.True(t, f.BundleOpportunistically())
	require.Equal(t, []protocol.StreamID{6, 10, 0}, appendedStreams(t, f))
	require.Equal(t, 1, fourteen.asked)
	// a source still active is not asked again
	ten.frames = append(ten.frames, &wire.StreamFrame{StreamID: 10, Data: []byte{1}, DataLenPresent: true},
		&wire.StreamFrame{StreamID: 10, Data: []byte{2}, DataLenPresent: true})
	six.has, fourteen.has = false, false
	require.True(t, f.BundleOpportunistically())
	asked := ten.asked
	require.False(t, f.BundleOpportunistically())
	require.Equal(t, asked, ten.asked)
	require.Equal(t, []protocol.StreamID{10}, appendedStreams(t, f))
	// none with something
	f = newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	f.AddOpportunisticSource(6, sourceOf(6, false))
	require.False(t, f.BundleOpportunistically())
	require.False(t, f.HasData(), "a source makes no packet of its own")
}

func TestASourceGoesWithItsStream(t *testing.T) {
	f := newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
	src := sourceOf(6, true)
	f.AddOpportunisticSource(6, src)
	f.RemoveActiveStream(2) // another stream's completion leaves it
	require.True(t, f.BundleOpportunistically())
	_ = appendedStreams(t, f)
	f.RemoveActiveStream(6)
	require.False(t, f.BundleOpportunistically())
	require.Zero(t, f.sourceCount.Load())
	// and with a rejected 0-RTT
	f.AddOpportunisticSource(6, sourceOf(6, true))
	f.Handle0RTTRejection()
	require.False(t, f.BundleOpportunistically())
	require.Zero(t, f.sourceCount.Load())
}

// quietSender takes what a stream tells it, and does nothing.
type quietSender struct{ data int }

func (*quietSender) onHasConnectionData()                                                {}
func (s *quietSender) onHasStreamData(protocol.StreamID, *SendStream)                    { s.data++ }
func (*quietSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {}
func (*quietSender) onStreamCompleted(protocol.StreamID)                                 {}

func testFlowController(id protocol.StreamID) flowcontrol.StreamFlowController {
	rtt := utils.NewRTTStats()
	conn := flowcontrol.NewConnectionFlowController(1<<20, 1<<20, nil, rtt, utils.DefaultLogger)
	conn.UpdateSendWindow(1 << 20)
	return flowcontrol.NewStreamFlowController(id, conn, 1<<20, 1<<20, 1<<20, rtt, utils.DefaultLogger)
}

func TestAStreamTakesWhatItsSourceGivesWhenNothingIsLeftToGo(t *testing.T) {
	var asked int
	give := []byte("abc")
	source := func(b []byte) []byte { asked++; return append(b, give...) }
	str := newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
	// no source: nothing
	require.False(t, str.takeOpportunistic())
	str.source = source
	require.True(t, str.takeOpportunistic())
	require.Equal(t, 1, asked)
	require.Equal(t, []byte("abc"), str.dataForWriting)
	// what it gave still to go: not asked again
	require.True(t, str.takeOpportunistic())
	require.Equal(t, 1, asked)
	f, _, more := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.Equal(t, []byte("abc"), f.Frame.Data)
	require.False(t, more)
	// a source with nothing
	give = nil
	require.False(t, str.takeOpportunistic())
	require.Equal(t, 2, asked)
	// a stream with a frame of its own still to go
	str.nextFrame = &wire.StreamFrame{StreamID: 2, Data: []byte("x")}
	require.True(t, str.takeOpportunistic())
	require.Equal(t, 2, asked)
	str.nextFrame = nil
	// a stream that can send no more
	give = []byte("d")
	for _, end := range []func(s *SendStream){
		func(s *SendStream) { s.shutdownErr = errOpportunistic },
		func(s *SendStream) { s.resetErr = &StreamError{} },
		func(s *SendStream) { s.finishedWriting = true },
	} {
		s := newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
		s.source = source
		end(s)
		require.False(t, s.takeOpportunistic())
	}
	require.Equal(t, 2, asked)
}

func TestAStreamsWriterWaitsWhileItsDataIsToGo(t *testing.T) {
	str := newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
	require.False(t, str.writerWaits())
	str.dataForWriting = []byte("x")
	require.True(t, str.writerWaits())
}

// activated are the streams the framer was made to send, which it forgets.
func activated(f *framer) []protocol.StreamID {
	var ids []protocol.StreamID
	for !f.streamQueue.Empty() {
		id := f.streamQueue.PopFront()
		delete(f.activeStreams, id)
		ids = append(ids, id)
	}
	return ids
}

func TestABundleHoldsAStreamOnce(t *testing.T) {
	c := &Conn{framer: newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil)), sendingScheduled: make(chan struct{}, 1)}
	a := newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
	b := newSendStream(context.Background(), 6, &quietSender{}, testFlowController(6), false)
	// no bundle: nothing held
	require.False(t, c.bundling.hold(2, a, c.framer))
	bundle := c.BundleWrites()
	require.True(t, c.bundling.hold(6, b, c.framer))
	require.True(t, c.bundling.hold(2, a, c.framer))
	require.True(t, c.bundling.hold(6, b, c.framer))
	require.Len(t, c.bundling.held, 2)
	require.False(t, c.framer.HasData())
	bundle.Flush()
	require.Len(t, c.sendingScheduled, 1)
	require.Equal(t, []protocol.StreamID{6, 2}, activated(c.framer))
	// a flush of nothing schedules nothing
	<-c.sendingScheduled
	c.BundleWrites().Flush()
	require.Empty(t, c.sendingScheduled)
	// a spilled bundle holds nothing, a waiting writer's stream among them
	bundle = c.BundleWrites()
	require.True(t, c.bundling.hold(6, b, c.framer))
	a.dataForWriting = []byte("x")
	require.False(t, c.bundling.hold(2, a, c.framer))
	require.Equal(t, []protocol.StreamID{6}, activated(c.framer))
	a.dataForWriting = nil
	require.False(t, c.bundling.hold(2, a, c.framer))
	bundle.Flush()
	require.Empty(t, c.bundling.held)
	require.Empty(t, activated(c.framer))
	require.False(t, b.held)
	// a bundle after holds again, its stream held from where it was given
	// what it holds, and a second Flush of a bundle flushes no other
	bundle = c.BundleWrites()
	other := c.BundleWrites()
	select {
	case <-bundle.Spilled():
		t.Fatal("a bundle after a spilled one spilled")
	default:
	}
	b.wroteAt = 7
	require.True(t, c.bundling.hold(6, b, c.framer))
	require.True(t, b.held)
	require.Equal(t, protocol.ByteCount(7), b.heldAt)
	bundle.Flush()
	bundle.Flush()
	require.True(t, c.bundling.hold(2, a, c.framer))
	other.Flush()
	require.Equal(t, []protocol.StreamID{6, 2}, activated(c.framer))
	require.False(t, a.held)
}

func TestReceiveStreamTellsItsResetHandlerOfThePeersResetOnce(t *testing.T) {
	newStr := func() (*ReceiveStream, *[]bool) {
		str := newReceiveStream(0, &quietSender{}, testFlowController(0))
		var calls []bool
		str.resetHandler = func(fin bool) { calls = append(calls, fin) }
		return str, &calls
	}
	reset := &wire.ResetStreamFrame{StreamID: 0, ErrorCode: 0x200, FinalSize: 3}
	// before the FIN
	str, calls := newStr()
	require.NoError(t, str.handleResetStreamFrame(reset, monotime.Now()))
	require.NoError(t, str.handleResetStreamFrame(reset, monotime.Now()))
	require.Equal(t, []bool{false}, *calls)
	// after it
	str, calls = newStr()
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{StreamID: 0, Data: []byte("abc"), Fin: true}, monotime.Now()))
	require.NoError(t, str.handleResetStreamFrame(reset, monotime.Now()))
	require.Equal(t, []bool{true}, *calls)
	// a stream whose reading was cancelled before
	str, calls = newStr()
	str.CancelRead(0x10c)
	require.NoError(t, str.handleResetStreamFrame(reset, monotime.Now()))
	require.Empty(t, *calls)
	// no handler
	str, _ = newStr()
	str.resetHandler = nil
	require.NoError(t, str.handleResetStreamFrame(reset, monotime.Now()))
	// set through the stream it is a half of
	s := newStream(context.Background(), 0, &quietSender{}, testFlowController(0), false)
	var told []bool
	s.SetResetHandler(func(fin bool) { told = append(told, fin) })
	require.NoError(t, s.handleResetStreamFrame(reset, monotime.Now()))
	require.Equal(t, []bool{false}, told)
}

// fakeBundler is a framer's BundleOpportunistically: has is what it says.
type fakeBundler struct {
	has   bool
	asked int
}

func (f *fakeBundler) BundleOpportunistically() bool { f.asked++; return f.has }

func TestAPacketThatGoesAnywayCarriesWhatIsSentOpportunistically(t *testing.T) {
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
	stream := ackhandler.StreamFrame{Frame: &wire.StreamFrame{StreamID: 6, Data: []byte("c"), DataLenPresent: true}}
	for _, tc := range []struct {
		why                  string
		data, retransmission bool
		datagram             bool
		ack                  bool // the ACK the packet gets
		onlyAck              bool
		has                  bool // the bundler's answer
		asked                bool
		streams              int
	}{
		{why: "an ACK alone", ack: true, has: true, asked: true, streams: 1},
		{why: "an ACK alone, nothing to bundle", ack: true, asked: true},
		{why: "new frames", data: true, has: true, asked: true, streams: 1},
		{why: "a DATAGRAM", datagram: true, has: true, asked: true, streams: 1},
		{why: "a retransmission and an ACK", retransmission: true, ack: true, has: true},
		{why: "nothing", has: true},
		{why: "an ACK only packet", onlyAck: true, ack: true, has: true},
	} {
		mockCtrl := gomock.NewController(t)
		tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
		bundler := &fakeBundler{has: tc.has}
		tp.packer.opportunistic = bundler
		if !tc.onlyAck {
			tp.framer.EXPECT().HasData().Return(tc.data)
		}
		if tc.retransmission {
			tp.retransmissionQueue.addAppData(&wire.MaxDataFrame{MaximumData: 1})
		}
		if tc.datagram {
			go func() { _ = tp.datagramQueue.Add(&wire.DatagramFrame{Data: []byte("d")}) }()
			for tp.datagramQueue.Peek() == nil {
			}
		}
		var got *wire.AckFrame
		if tc.ack {
			got = ack
		}
		tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), gomock.Any()).Return(got).AnyTimes()
		if tc.streams > 0 || tc.data {
			expectAppendFrames(tp.framer, nil, []ackhandler.StreamFrame{stream})
		}
		pl := tp.packer.composeNextPacket(protocol.MaxByteCount, tc.onlyAck, true, monotime.Now(), protocol.Version1)
		require.Equal(t, tc.asked, bundler.asked > 0, tc.why)
		require.Len(t, pl.streamFrames, tc.streams, tc.why)
		mockCtrl.Finish()
	}
	// a framer of no bundler's
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	require.Nil(t, tp.packer.opportunistic)
	tp.framer.EXPECT().HasData().Return(false)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Return(ack)
	pl := tp.packer.composeNextPacket(protocol.MaxByteCount, false, true, monotime.Now(), protocol.Version1)
	require.Equal(t, ack, pl.ack)
	// the connection's framer is one
	require.NotNil(t, newPacketPacker(protocol.ConnectionID{}, nil, nil, nil, nil, nil, nil,
		newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil)), nil, nil, protocol.PerspectiveClient).opportunistic)
}

func TestAHeldStreamSendsWhatItWasGivenBeforeItsBundle(t *testing.T) {
	pop := func(s *SendStream) (*wire.StreamFrame, bool) {
		f, _, more := s.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
		return f.Frame, more
	}
	// given "abc", then "def" and its FIN while held: "abc" goes, the rest
	// once let go
	str := newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
	_, err := str.Write([]byte("abc"))
	require.NoError(t, err)
	_, err = str.Write([]byte("def"))
	require.NoError(t, err)
	str.holdBack()
	require.NoError(t, str.Close())
	f, more := pop(str)
	require.Equal(t, []byte("abc"), f.Data)
	require.False(t, f.Fin)
	require.True(t, more)
	lost := f
	f, more = pop(str)
	require.Nil(t, f)
	require.False(t, more, "a held stream stays in the framer's queue")
	// a lost frame goes again, held or not
	(*sendStreamAckHandler)(str).OnLost(lost)
	f, _ = pop(str)
	require.Equal(t, []byte("abc"), f.Data)
	str.letGo()
	f, more = pop(str)
	require.Equal(t, []byte("def"), f.Data)
	require.Equal(t, protocol.ByteCount(3), f.Offset)
	require.True(t, f.Fin)
	require.False(t, more)
	// its FIN alone, given while held
	str = newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
	_, err = str.Write([]byte("abc"))
	require.NoError(t, err)
	f, _ = pop(str)
	require.Equal(t, []byte("abc"), f.Data)
	require.NoError(t, str.Close())
	str.holdBack()
	f, more = pop(str)
	require.Nil(t, f)
	require.False(t, more)
	str.letGo()
	f, more = pop(str)
	require.True(t, f.Fin)
	require.Empty(t, f.Data)
	require.False(t, more)
	// nothing at all to send
	f, more = pop(str)
	require.Nil(t, f)
	require.False(t, more)
	// given "abc" before, and its FIN while held: "abc" goes, its FIN after
	str = newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
	_, err = str.Write([]byte("abc"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	str.holdBack()
	f, more = pop(str)
	require.Equal(t, []byte("abc"), f.Data)
	require.False(t, f.Fin)
	require.False(t, more)
	str.letGo()
	f, _ = pop(str)
	require.True(t, f.Fin)
	// what a packet took before the hold is not held
	str = newSendStream(context.Background(), 2, &quietSender{}, testFlowController(2), false)
	_, err = str.Write([]byte("abc"))
	require.NoError(t, err)
	f, _ = pop(str)
	require.Equal(t, []byte("abc"), f.Data)
	str.holdBack()
	require.Equal(t, protocol.ByteCount(3), str.heldAt)
}
