package quic

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils/ringbuffer"
)

// A WriteBundle holds back the packets that writes on a connection's streams
// would send, until it is flushed (Conn.BundleWrites).
type WriteBundle struct {
	conn  *Conn
	spill chan struct{}
	once  sync.Once
}

// bundling is what a connection's write bundles hold back: the streams given
// something to send while one is open, in the order they were first given it.
type bundling struct {
	mu      sync.Mutex
	open    atomic.Int32 // bundles taken and not flushed, changed under mu
	spilled bool
	spill   chan struct{}
	held    []heldStream
}

type heldStream struct {
	id  protocol.StreamID
	str *SendStream
}

// BundleWrites holds back, until the bundle it returns is flushed, the
// packets that what the connection's streams are given would send: what they
// are given goes out once the bundle is flushed, together, in as few packets
// as it fits in, the STREAM frames of each stream after those of the streams
// given something before it, as quiche's QuicConnection::ScopedPacketFlusher
// holds the writes of a task (Chromium's QuicHttpStream::DoLoop writes a
// request's PRIORITY_UPDATE, QPACK encoder instructions and HEADERS under
// one). Bundles nest: what they hold goes once every one is flushed. A write
// that has to wait for its data to be sent (a stream given more than it keeps
// for sending) spills them: what they held goes at once, in order, and they
// hold nothing more back. Only STREAM frames are held back, not ACKs nor any
// other frame.
func (c *Conn) BundleWrites() *WriteBundle {
	b := &c.bundling
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open.Load() == 0 {
		b.spill = make(chan struct{})
		b.spilled = false
	}
	b.open.Add(1)
	return &WriteBundle{conn: c, spill: b.spill}
}

// Flush lets what the bundle held back go, once every bundle taken with it is
// flushed. Calling it again does nothing.
func (w *WriteBundle) Flush() {
	w.once.Do(func() {
		c := w.conn
		b := &c.bundling
		b.mu.Lock()
		held := 0
		if b.open.Add(-1) == 0 {
			held = len(b.held)
			b.release(c.framer)
		}
		b.mu.Unlock()
		if held > 0 {
			c.scheduleSending()
		}
	})
}

// Spilled is closed once a write the bundle would have held back had to wait
// for its data to be sent: from then on the bundle holds nothing back.
func (w *WriteBundle) Spilled() <-chan struct{} { return w.spill }

// hold keeps str, given something to send, back while a write bundle is open,
// and says whether it did. A stream whose writer waits for its data to be
// sent is never held back: what was held goes first, in order, and the
// bundles spill.
func (b *bundling) hold(id protocol.StreamID, str *SendStream, f *framer) bool {
	if b.open.Load() == 0 {
		// a Write or Close that held itself while a bundle was open, which
		// closed before it got here
		str.letGo()
		return false
	}
	waits := str.writerWaits()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open.Load() == 0 || b.spilled {
		str.letGo()
		return false
	}
	if waits {
		b.spilled = true
		close(b.spill)
		b.release(f)
		return false
	}
	if !slices.ContainsFunc(b.held, func(h heldStream) bool { return h.id == id }) {
		str.holdBack()
		b.held = append(b.held, heldStream{id: id, str: str})
	}
	return true
}

// release lets what the bundles held go, in the order the streams were
// held. It is called with mu held.
func (b *bundling) release(f *framer) {
	for _, h := range b.held {
		h.str.letGo()
		f.AddActiveStream(h.id, h.str)
	}
	b.held = nil
}

// writerWaits says whether a Write on the stream waits for its data to be
// sent, as one given more than the stream keeps for sending does.
func (s *SendStream) writerWaits() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.dataForWriting != nil
}

// holdBack has what the stream was given from its latest Write or Close on
// wait for letGo; what it was given before still goes, a stream's earlier
// data still to go among it. A Write or Close given while a bundle is open
// held itself already (heldFromHere); one given before the bundle opened
// may have gone in part, which no hold can call back.
func (s *SendStream) holdBack() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.held, s.heldAt = true, max(s.wroteAt, s.writeOffset)
}

// bundleKeeper is a stream's sender that keeps the connection's write
// bundles: the connection, and the sender of either half of a stream.
type bundleKeeper interface{ writeBundles() *bundling }

func (c *Conn) writeBundles() *bundling { return &c.bundling }

func (s *uniStreamSender) writeBundles() *bundling {
	if k, ok := s.streamSender.(bundleKeeper); ok {
		return k.writeBundles()
	}
	return nil
}

// heldFromHere holds what the latest Write or Close gave, from wroteAt on,
// while a write bundle is open, before the stream's mutex lets a packet see
// it. A stream already in the framer's queue, for what it was given before
// (a control stream's SETTINGS not yet sent, as a connection's first request
// may find it), was otherwise open to a packet packed between that Write and
// onHasStreamData's hold: the PRIORITY_UPDATE went in it, without the
// request it was bundled with. A bundle that closed or spilled meanwhile lets
// it go in hold. It is called with the mutex held.
func (s *SendStream) heldFromHere() {
	if s.held {
		return
	}
	if k, ok := s.sender.(bundleKeeper); ok {
		if b := k.writeBundles(); b != nil && b.open.Load() > 0 {
			s.held, s.heldAt = true, s.wroteAt
		}
	}
}

// letGo lets what the stream holds back go.
func (s *SendStream) letGo() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.held = false
}

var errOpportunistic = errors.New("write on a stream that sends opportunistically")

// BundleOpportunistically has str send what source gives it, and only in
// packets the connection sends for something else: whenever it sends a packet
// that carries an ACK, a DATAGRAM or other new frames, it asks source, on its
// own goroutine, for what to send, and what source appends to its argument
// goes out at once, ahead of the other streams' new frames, as quiche bundles
// its QPACK decoder stream's data (QuicSpdySession::MaybeBundleOpportunistically,
// which its packet creator calls before new data and SendAllPendingAcks before
// an ACK). source is not asked again while what it gave before is still to
// go. source must not block nor call into the connection, and str must not be
// written to after.
func (c *Conn) BundleOpportunistically(str *SendStream, source func([]byte) []byte) {
	str.mutex.Lock()
	str.source = source
	str.mutex.Unlock()
	c.framer.AddOpportunisticSource(str.StreamID(), str)
}

// takeOpportunistic asks the stream's source for what to send, and says
// whether the stream has something to send: what the source gave, or what it
// gave before and is still to go.
func (s *SendStream) takeOpportunistic() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.source == nil || s.shutdownErr != nil || s.resetErr != nil || s.finishedWriting {
		return false
	}
	if s.dataForWriting != nil || s.nextFrame != nil {
		return true
	}
	if b := s.source(nil); len(b) > 0 {
		s.dataForWriting = b
		return true
	}
	return false
}

// opportunisticSource is a stream whose data goes only in packets sent for
// something else.
type opportunisticSource interface {
	streamFrameGetter
	takeOpportunistic() bool
}

// AddOpportunisticSource has the framer ask str for what to send whenever a
// packet goes out anyway (BundleOpportunistically).
func (f *framer) AddOpportunisticSource(id protocol.StreamID, str opportunisticSource) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.sources == nil {
		f.sources = make(map[protocol.StreamID]opportunisticSource)
	}
	f.sources[id] = str
	f.sourceCount.Store(int32(len(f.sources)))
}

// BundleOpportunistically makes the streams whose source has something to
// send active, ahead of the others, and says whether any has: the packet being
// packed goes out anyway, and carries their data first.
func (f *framer) BundleOpportunistically() bool {
	if f.sourceCount.Load() == 0 {
		return false
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	var ids []protocol.StreamID
	for id, str := range f.sources {
		if _, ok := f.activeStreams[id]; ok {
			continue
		}
		if str.takeOpportunistic() {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return false
	}
	slices.Sort(ids)
	var queue ringbuffer.RingBuffer[protocol.StreamID]
	for _, id := range ids {
		queue.PushBack(id)
		f.activeStreams[id] = f.sources[id]
	}
	for !f.streamQueue.Empty() {
		queue.PushBack(f.streamQueue.PopFront())
	}
	f.streamQueue = queue
	return true
}
