package quic

import (
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	tls "github.com/igor-lemon/utls"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/testdata"
	"github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	"github.com/stretchr/testify/require"
)

// How a connection puts its streams' writes in packets, as quiche does:
// the writes of a task under one flush (BundleWrites, quiche's
// ScopedPacketFlusher), a stream's data only in packets sent for something
// else (BundleOpportunistically, quiche's MaybeBundleOpportunistically), and
// a peer's RESET_STREAM handled while its frame is processed
// (SetResetHandler, quiche's OnStreamReset).

// sentPackets is a client's qlog trace that keeps every packet it sends and
// gets, in order.
type sentPackets struct {
	mu     sync.Mutex
	events []any // qlog.PacketSent or qlog.PacketReceived
}

func (h *sentPackets) AddProducer() qlogwriter.Recorder { return h }
func (h *sentPackets) SupportsSchemas(string) bool      { return true }
func (h *sentPackets) Close() error                     { return nil }

func (h *sentPackets) RecordEvent(e qlogwriter.Event) {
	switch e.(type) {
	case qlog.PacketSent, qlog.PacketReceived:
		h.mu.Lock()
		h.events = append(h.events, e)
		h.mu.Unlock()
	}
}

// sent are the 1-RTT packets the client sent, in order.
func (h *sentPackets) sent() []qlog.PacketSent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []qlog.PacketSent
	for _, e := range h.events {
		if p, ok := e.(qlog.PacketSent); ok && p.Header.PacketType == qlog.PacketType1RTT {
			out = append(out, p)
		}
	}
	return out
}

// streamFrames are the STREAM frames of the streams ids a packet carries, in
// its order.
func streamFrames(frames []qlog.Frame, ids ...StreamID) []*qlog.StreamFrame {
	var out []*qlog.StreamFrame
	for _, f := range frames {
		if s, ok := f.Frame.(*qlog.StreamFrame); ok && slices.Contains(ids, s.StreamID) {
			out = append(out, s)
		}
	}
	return out
}

// carrying are the client's packets that carry a STREAM frame of ids.
func (h *sentPackets) carrying(ids ...StreamID) []qlog.PacketSent {
	var out []qlog.PacketSent
	for _, p := range h.sent() {
		if len(streamFrames(p.Frames, ids...)) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// bundleConn is a client connection, whose packets trace keeps, to a
// loopback server whose connection is given to serve.
func bundleConn(t *testing.T, serve func(*Conn)) (*Conn, *sentPackets) {
	t.Helper()
	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"h3"}
	// no path MTU probe of either side's, which would draw an ACK
	ln, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{MaxIncomingUniStreams: 100, DisablePathMTUDiscovery: true})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		serve(conn)
	}()
	trace := &sentPackets{}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &Transport{Conn: udp}
	t.Cleanup(func() { tr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, ln.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&Config{DisablePathMTUDiscovery: true, Tracer: func(context.Context, bool, ConnectionID) qlogwriter.Trace { return trace }})
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	// handshake confirmed: no packet but the 1-RTT ones after
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("no handshake")
	}
	time.Sleep(50 * time.Millisecond)
	return conn, trace
}

// drain reads every unidirectional stream the server's connection gets.
func drain(conn *Conn) {
	for {
		str, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go io.Copy(io.Discard, str)
	}
}

// uniStreams opens n unidirectional streams of the client's.
func uniStreams(t *testing.T, conn *Conn, n int) []*SendStream {
	t.Helper()
	var out []*SendStream
	for range n {
		str, err := conn.OpenUniStreamSync(context.Background())
		require.NoError(t, err)
		out = append(out, str)
	}
	return out
}

// waitFor waits up to two seconds for cond.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWhatABundleHoldsGoesTogetherInTheOrderItWasGiven(t *testing.T) {
	conn, trace := bundleConn(t, drain)
	s := uniStreams(t, conn, 3)
	a, b, c := s[0], s[1], s[2]
	bundle := conn.BundleWrites()
	// given A, C and B's FIN, minutes apart as a packet goes: nothing sent
	_, err := a.Write([]byte("a"))
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	_, err = c.Write([]byte("cc"))
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	_, err = b.Write([]byte("bbb"))
	require.NoError(t, err)
	require.NoError(t, b.Close())
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, trace.carrying(a.StreamID(), b.StreamID(), c.StreamID()), "sent before the flush")
	// flushed: one packet, A's, C's then B's with its FIN
	bundle.Flush()
	bundle.Flush()
	waitFor(t, func() bool { return len(trace.carrying(a.StreamID())) > 0 }, "nothing sent after the flush")
	got := trace.carrying(a.StreamID(), b.StreamID(), c.StreamID())
	require.Len(t, got, 1)
	frames := streamFrames(got[0].Frames, a.StreamID(), b.StreamID(), c.StreamID())
	require.Len(t, frames, 3)
	require.Equal(t, []StreamID{a.StreamID(), c.StreamID(), b.StreamID()},
		[]StreamID{frames[0].StreamID, frames[1].StreamID, frames[2].StreamID})
	require.True(t, frames[2].Fin)
	// with no bundle, each write as it comes
	s = uniStreams(t, conn, 2)
	for _, str := range s {
		_, err := str.Write([]byte("x"))
		require.NoError(t, err)
		time.Sleep(30 * time.Millisecond)
	}
	waitFor(t, func() bool { return len(trace.carrying(s[1].StreamID())) > 0 }, "nothing sent")
	require.Len(t, trace.carrying(s[0].StreamID(), s[1].StreamID()), 2)
}

func TestBundlesNestAndANewOneHoldsAgain(t *testing.T) {
	conn, trace := bundleConn(t, drain)
	s := uniStreams(t, conn, 2)
	outer := conn.BundleWrites()
	inner := conn.BundleWrites()
	require.Equal(t, outer.Spilled(), inner.Spilled())
	_, err := s[0].Write([]byte("a"))
	require.NoError(t, err)
	inner.Flush()
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, trace.carrying(s[0].StreamID()), "sent while a bundle was open")
	outer.Flush()
	waitFor(t, func() bool { return len(trace.carrying(s[0].StreamID())) > 0 }, "nothing sent")
	// a bundle taken after holds again, and has not spilled
	next := conn.BundleWrites()
	select {
	case <-next.Spilled():
		t.Fatal("a new bundle spilled")
	default:
	}
	_, err = s[1].Write([]byte("b"))
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, trace.carrying(s[1].StreamID()), "sent while a bundle was open")
	next.Flush()
	waitFor(t, func() bool { return len(trace.carrying(s[1].StreamID())) > 0 }, "nothing sent")
}

func TestAWriteThatWaitsSpillsTheBundle(t *testing.T) {
	conn, trace := bundleConn(t, drain)
	s := uniStreams(t, conn, 3)
	a, b, c := s[0], s[1], s[2]
	bundle := conn.BundleWrites()
	_, err := a.Write([]byte("a"))
	require.NoError(t, err)
	// more than a stream keeps for sending: the write waits for it to be
	// sent, which the bundle lets happen, A's first
	big := bytes.Repeat([]byte("b"), 10*int(protocol.MaxPacketBufferSize))
	_, err = b.Write(big)
	require.NoError(t, err)
	select {
	case <-bundle.Spilled():
	default:
		t.Fatal("not spilled")
	}
	waitFor(t, func() bool { return len(trace.carrying(b.StreamID())) > 0 }, "nothing sent")
	first := trace.carrying(a.StreamID(), b.StreamID())[0]
	require.Equal(t, a.StreamID(), streamFrames(first.Frames, a.StreamID(), b.StreamID())[0].StreamID)
	// and it holds nothing more back
	_, err = c.Write([]byte("c"))
	require.NoError(t, err)
	waitFor(t, func() bool { return len(trace.carrying(c.StreamID())) > 0 }, "a write after the spill was held back")
	bundle.Flush()
}

func TestAStreamThatSendsOpportunisticallyGoesOnlyWithOtherPackets(t *testing.T) {
	var mu sync.Mutex
	var pending []byte
	keep := func(b string) {
		mu.Lock()
		pending = append(pending, b...)
		mu.Unlock()
	}
	source := func(b []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		b = append(b, pending...)
		pending = nil
		return b
	}
	speak := make(chan string)
	conn, trace := bundleConn(t, func(conn *Conn) {
		go drain(conn)
		// the server's word, which the client acknowledges
		for w := range speak {
			str, err := conn.OpenUniStreamSync(context.Background())
			if err != nil {
				return
			}
			_, _ = str.Write([]byte(w))
			_ = str.Close()
		}
	})
	t.Cleanup(func() { close(speak) })
	s := uniStreams(t, conn, 2)
	opp, other := s[0], s[1]
	conn.BundleOpportunistically(opp, source)
	_, err := opp.Write([]byte("x"))
	require.ErrorIs(t, err, errOpportunistic)
	keep("hello")
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, trace.carrying(opp.StreamID()), "sent alone")
	// another stream's write: its packet carries it, first
	_, err = other.Write([]byte("w"))
	require.NoError(t, err)
	waitFor(t, func() bool { return len(trace.carrying(other.StreamID())) > 0 }, "nothing sent")
	p := trace.carrying(opp.StreamID(), other.StreamID())
	require.Len(t, p, 1)
	frames := streamFrames(p[0].Frames, opp.StreamID(), other.StreamID())
	require.Equal(t, []StreamID{opp.StreamID(), other.StreamID()}, []StreamID{frames[0].StreamID, frames[1].StreamID})
	require.Equal(t, int64(len("hello")), frames[0].Length)
	// an ACK: the client's for the server's words carries it
	keep("again")
	speak <- "one"
	speak <- "two"
	waitFor(t, func() bool { return len(trace.carrying(opp.StreamID())) == 2 }, "not sent with the ACK")
	last := trace.carrying(opp.StreamID())[1]
	_, acked := last.Frames[0].Frame.(*qlog.AckFrame)
	require.True(t, acked, "in a packet of no ACK: %v", last.Frames)
	frames = streamFrames(last.Frames, opp.StreamID())
	require.Equal(t, int64(len("hello")), frames[0].Offset)
	require.Equal(t, int64(len("again")), frames[0].Length)
	// a source with nothing: the ACKs go alone
	speak <- "three"
	speak <- "four"
	time.Sleep(100 * time.Millisecond)
	require.Len(t, trace.carrying(opp.StreamID()), 2)
}

func TestAResetHandlerRunsBeforeThePacketThatAcknowledgesTheReset(t *testing.T) {
	var mu sync.Mutex
	var pending []byte
	var calls []bool
	source := func(b []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		b = append(b, pending...)
		pending = nil
		return b
	}
	reset := make(chan struct{})
	conn, trace := bundleConn(t, func(conn *Conn) {
		go drain(conn)
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		<-reset
		// alone, after the client acknowledged all: its ACK is delayed
		str.CancelWrite(0x200)
	})
	opp := uniStreams(t, conn, 1)[0]
	conn.BundleOpportunistically(opp, source)
	str, err := conn.OpenStreamSync(context.Background())
	require.NoError(t, err)
	str.SetResetHandler(func(finReceived bool) {
		mu.Lock()
		calls = append(calls, finReceived)
		pending = append(pending, "cancelled"...)
		mu.Unlock()
	})
	_, err = str.Write([]byte("request"))
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	close(reset)
	_, err = str.Read(make([]byte, 1))
	var serr *StreamError
	require.ErrorAs(t, err, &serr)
	require.True(t, serr.Remote)
	waitFor(t, func() bool { return len(trace.carrying(opp.StreamID())) > 0 }, "nothing sent")
	mu.Lock()
	require.Equal(t, []bool{false}, calls)
	mu.Unlock()
	// the packet that acknowledges the reset's carries what the handler gave
	var resetAt protocol.PacketNumber = -1
	trace.mu.Lock()
	events := slices.Clone(trace.events)
	trace.mu.Unlock()
	for _, e := range events {
		switch p := e.(type) {
		case qlog.PacketReceived:
			for _, f := range p.Frames {
				if r, ok := f.Frame.(*qlog.ResetStreamFrame); ok && r.StreamID == str.StreamID() {
					resetAt = p.Header.PacketNumber
				}
			}
		case qlog.PacketSent:
			if resetAt < 0 || len(p.Frames) == 0 {
				continue
			}
			ack, ok := p.Frames[0].Frame.(*qlog.AckFrame)
			if !ok || !ack.AcksPacket(resetAt) {
				continue
			}
			require.Len(t, streamFrames(p.Frames, opp.StreamID()), 1, "the reset's ACK carries nothing of the handler's")
			return
		}
	}
	t.Fatal("the reset was not acknowledged")
}
