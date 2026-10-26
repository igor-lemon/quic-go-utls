package http3

import (
	"bytes"
	"context"
	"io"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	"github.com/igor-lemon/utls/behavior"

	"github.com/igor-lemon/quic-go-utls"
	quicqlog "github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	"github.com/igor-lemon/quic-go-utls/quicvarint"

	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

// How an HTTP/3 client puts its writes in packets, as its profile says.
// Chrome 155's (quiche at its DEPS revision, Chromium 155.0.8059.85, measured
// on ../net-fp-server's bench/h3 and bench/h3alps): a request's
// PRIORITY_UPDATE, QPACK encoder instructions and HEADERS with its FIN in one
// packet, as QuicHttpStream::DoLoop writes them under one ScopedPacketFlusher
// (h3.request_writes one-flush), and the QPACK decoder's instructions only in
// packets sent for something else, a server's reset's Stream Cancellation in
// the packet that acknowledges it (h3.qpack.decoder_writes opportunistic).

// packetsBoth is a server's qlog recorder that keeps every packet it gets,
// and when, and every packet it sends.
type packetsBoth struct {
	mu   sync.Mutex
	got  []quicqlog.PacketReceived
	at   []time.Time
	sent []quicqlog.PacketSent
}

func (h *packetsBoth) RecordEvent(e qlogwriter.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch e := e.(type) {
	case quicqlog.PacketReceived:
		h.got = append(h.got, e)
		h.at = append(h.at, time.Now())
	case quicqlog.PacketSent:
		h.sent = append(h.sent, e)
	}
}

func (h *packetsBoth) Close() error { return nil }

// carrying is the first packet heard that carries a STREAM frame of id at
// offset, and when it came.
func (h *packetsBoth) carrying(id quic.StreamID, offset int64) (*quicqlog.PacketReceived, time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, p := range h.got {
		for _, f := range p.Frames {
			if s, ok := f.Frame.(*quicqlog.StreamFrame); ok && s.StreamID == id && s.Offset == offset {
				return &h.got[i], h.at[i]
			}
		}
	}
	return nil, time.Time{}
}

// resetSent is the packet number the server's RESET_STREAM of id went in.
func (h *packetsBoth) resetSent(id quic.StreamID) quicqlog.PacketNumber {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.sent {
		for _, f := range p.Frames {
			if r, ok := f.Frame.(*quicqlog.ResetStreamFrame); ok && r.StreamID == id {
				return p.Header.PacketNumber
			}
		}
	}
	return -1
}

// streamsOf are the streams of a packet's STREAM frames, in its order, and
// whether its last one ends its stream.
func streamsOf(p *quicqlog.PacketReceived) ([]quic.StreamID, bool) {
	var ids []quic.StreamID
	var fin bool
	for _, f := range p.Frames {
		if s, ok := f.Frame.(*quicqlog.StreamFrame); ok {
			ids = append(ids, s.StreamID)
			fin = s.Fin
		}
	}
	return ids, fin
}

// qpackSettings is a control stream of SETTINGS: a QPACK table of 4096 and
// 100 blocked streams.
var qpackSettings = []byte{0x00, 0x04, 0x06, 0x01, 0x50, 0x00, 0x07, 0x40, 0x64}

// bundleServer is a QUIC server that keeps what it hears in heard, says
// qpackSettings on its control stream, and gives each request stream to
// serve, with its connection.
func bundleServer(t *testing.T, heard *packetsBoth, serve func(*quic.Conn, *quic.Stream)) string {
	t.Helper()
	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), &quic.Config{
		// no path MTU probe, which would draw an ACK
		DisablePathMTUDiscovery: true,
		Tracer:                  func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return &qlogTrace{recorder: heard} },
	})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				control, err := conn.OpenUniStreamSync(context.Background())
				if err != nil {
					return
				}
				_, _ = control.Write(qpackSettings)
				go func() {
					for {
						str, err := conn.AcceptUniStream(context.Background())
						if err != nil {
							return
						}
						go io.Copy(io.Discard, str)
					}
				}()
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go serve(conn, str)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// answer reads a request to its end and answers it 200.
func answer(_ *quic.Conn, str *quic.Stream) {
	_, _ = io.Copy(io.Discard, str)
	var block bytes.Buffer
	_ = qpack.NewEncoder(&block).WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
	frame := quicvarint.Append(quicvarint.Append(nil, 1), uint64(block.Len()))
	_, _ = str.Write(append(frame, block.Bytes()...))
	_ = str.Close()
}

// bundlePolicy is a client whose QPACK encoder inserts from the first
// section, decoder takes a table and whose requests say their priority, with
// values laid over it.
func bundlePolicy(t *testing.T, values map[string]any) behavior.Policy {
	t.Helper()
	all := map[string]any{
		"h3.priority_updates":              "per-request",
		"h3.control_order":                 []string{"settings", "grease"},
		"h3.priority_value":                "u=0, i",
		"h3.qpack.encoder_strategy":        "insert",
		"h3.qpack.encoder_table_bytes":     65536,
		"h3.qpack.encoder_warmup_sections": 0,
		"h3.qpack.decoder_feedback":        "on-section",
		"h3.qpack.streams":                 "deferred",
		"h3.qpack.stream_order":            []int{3, 2},
	}
	maps.Copy(all, values)
	pol := controlPolicy(all)
	for k, v := range values {
		if v == nil {
			delete(pol, k)
		}
	}
	require.NoError(t, pol.Validate())
	return pol
}

// bundleClient is a client connection wearing pol to addr, once it has the
// server's SETTINGS.
func bundleClient(t *testing.T, addr string, pol behavior.Policy) *ClientConn {
	t.Helper()
	tr := &Transport{Behavior: pol, AdditionalSettings: map[uint64]uint64{1: 65536, 7: 100}, PriorityParam: 0xf0700}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := getTLSClientConfig()
	cfg.NextProtos = []string{NextProtoH3}
	conn, err := quic.DialAddr(ctx, addr, cfg, &quic.Config{DisablePathMTUDiscovery: true})
	require.NoError(t, err)
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	cc := tr.NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no SETTINGS")
	}
	return cc
}

// asked is a GET of fields the encoder inserts.
func asked(t *testing.T, ctx context.Context, addr string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "a client of the bundling tests")
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	return req
}

func TestARequestsWritesGoInOnePacketAsItsProfileSays(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		together bool
	}{
		{"one-flush", true},
		{"as-written", false},
		{"", false},
	} {
		heard := &packetsBoth{}
		addr := bundleServer(t, heard, answer)
		values := map[string]any{"h3.request_writes": tc.mode}
		if tc.mode == "" {
			values["h3.request_writes"] = nil
		}
		cc := bundleClient(t, addr, bundlePolicy(t, values))
		// the PRIORITY_UPDATE written, and the request a while after: one
		// flush holds it
		priority := cc.requestWriter.beforeHeaders
		cc.requestWriter.beforeHeaders = func(r *http.Request, id quic.StreamID) error {
			err := priority(r, id)
			time.Sleep(30 * time.Millisecond)
			return err
		}
		// and its FIN a while after it was written: in the flush too
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			WroteRequest: func(httptrace.WroteRequestInfo) { time.Sleep(30 * time.Millisecond) },
		})
		res, err := cc.RoundTrip(asked(t, ctx, addr))
		require.NoError(t, err, tc.mode)
		require.Equal(t, 200, res.StatusCode)
		cancel()
		headers, _ := heard.carrying(0, 0)
		require.NotNil(t, headers, tc.mode)
		ids, fin := streamsOf(headers)
		encoder, _ := heard.carrying(10, 0)
		require.NotNil(t, encoder, "%s: no encoder instruction", tc.mode)
		if tc.together {
			// Chrome's: STREAM(2) STREAM(10) STREAM(0, fin)
			require.Equal(t, []quic.StreamID{2, 10, 0}, ids, tc.mode)
			require.True(t, fin, "%s: no FIN with the HEADERS", tc.mode)
			continue
		}
		require.NotContains(t, ids, quic.StreamID(2), "%s: the PRIORITY_UPDATE waited for the request", tc.mode)
	}
}

func TestARequestWithABodyFlushesItsHeadersFirst(t *testing.T) {
	heard := &packetsBoth{}
	addr := bundleServer(t, heard, answer)
	cc := bundleClient(t, addr, bundlePolicy(t, map[string]any{"h3.request_writes": "one-flush"}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, writer := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+"/", body)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := cc.RoundTrip(req)
		done <- err
	}()
	// the HEADERS go, though the body is still to come
	require.Eventually(t, func() bool { p, _ := heard.carrying(0, 0); return p != nil }, 2*time.Second, 5*time.Millisecond)
	headers, _ := heard.carrying(0, 0)
	ids, fin := streamsOf(headers)
	require.Equal(t, []quic.StreamID{2, 10, 0}, ids)
	require.False(t, fin)
	_, _ = writer.Write([]byte("body"))
	require.NoError(t, writer.Close())
	require.NoError(t, <-done)
}

func TestARequestSentHeaderFirstIsBundledToo(t *testing.T) {
	heard := &packetsBoth{}
	addr := bundleServer(t, heard, func(*quic.Conn, *quic.Stream) {})
	cc := bundleClient(t, addr, bundlePolicy(t, map[string]any{"h3.request_writes": "one-flush"}))
	priority := cc.requestWriter.beforeHeaders
	cc.requestWriter.beforeHeaders = func(r *http.Request, id quic.StreamID) error {
		err := priority(r, id)
		time.Sleep(30 * time.Millisecond)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SendRequestHeader(asked(t, ctx, addr)))
	require.Eventually(t, func() bool { p, _ := heard.carrying(0, 0); return p != nil }, 2*time.Second, 5*time.Millisecond)
	headers, _ := heard.carrying(0, 0)
	ids, fin := streamsOf(headers)
	require.Equal(t, []quic.StreamID{2, 10, 0}, ids)
	require.False(t, fin, "its FIN is the caller's to write")
}

// cancellation is the client's packet that carries its decoder stream's
// first bytes, a Stream Cancellation of stream 0 after the stream's type, and
// the ACK it begins with.
func cancellation(t *testing.T, heard *packetsBoth) (*quicqlog.PacketReceived, *quicqlog.AckFrame) {
	t.Helper()
	var p *quicqlog.PacketReceived
	require.Eventually(t, func() bool { p, _ = heard.carrying(6, 0); return p != nil }, 2*time.Second, 5*time.Millisecond,
		"no Stream Cancellation")
	ack, _ := p.Frames[0].Frame.(*quicqlog.AckFrame)
	return p, ack
}

// resetAlone is the ACK a client wearing pol sends with its Stream
// Cancellation of a request a quiet server resets, the reset alone in its
// packet, as one that cannot decode its headers sends it. A server of
// quic-go's skips a packet number now and then, which the client
// acknowledges at once: such a run says nothing of when the ACK goes, and is
// run again.
func resetAlone(t *testing.T, pol behavior.Policy) *quicqlog.AckFrame {
	t.Helper()
	for range 3 {
		heard := &packetsBoth{}
		addr := bundleServer(t, heard, func(_ *quic.Conn, str *quic.Stream) {
			time.Sleep(100 * time.Millisecond)
			str.CancelWrite(quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed))
		})
		cc := bundleClient(t, addr, pol)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := cc.RoundTrip(asked(t, ctx, addr))
		require.Error(t, err)
		cancel()
		_, ack := cancellation(t, heard)
		require.NotNil(t, ack)
		require.True(t, ack.AcksPacket(heard.resetSent(0)), "the reset not acknowledged with it")
		if len(ack.AckRanges) == 1 {
			return ack
		}
	}
	t.Fatal("a packet number skipped in every run")
	return nil
}

func TestAStreamCancellationGoesWithTheClientsNextACKAsItsProfileSays(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		delayed bool // with the client's ACK, delayed as one of a lone packet is
	}{
		{"opportunistic", true},
		{"as-written", false},
		{"", false},
	} {
		// nothing of the client's own after the reset (Chrome's read-side)
		values := map[string]any{"h3.qpack.decoder_writes": tc.mode, "h3.peer_reset": "read-side"}
		if tc.mode == "" {
			values["h3.qpack.decoder_writes"] = nil
		}
		ack := resetAlone(t, bundlePolicy(t, values))
		// the client's own clock: a delayed ACK's 25 ms, or at once
		require.Equal(t, tc.delayed, ack.DelayTime >= 15*time.Millisecond, "%s: acknowledged %s after the reset", tc.mode, ack.DelayTime)
	}
}

func TestAStreamCancellationRidesTheACKThatAcknowledgesTheReset(t *testing.T) {
	heard := &packetsBoth{}
	// the reset, and more of the server's at once: the client acknowledges
	// both at once, and then has nothing more to send
	addr := bundleServer(t, heard, func(conn *quic.Conn, str *quic.Stream) {
		time.Sleep(100 * time.Millisecond)
		str.CancelWrite(quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed))
		more, err := conn.OpenStreamSync(context.Background())
		if err == nil {
			_, _ = more.Write(bytes.Repeat([]byte{1}, 4000))
		}
	})
	cc := bundleClient(t, addr, bundlePolicy(t, map[string]any{"h3.qpack.decoder_writes": "opportunistic", "h3.peer_reset": "read-side"}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cc.RoundTrip(asked(t, ctx, addr))
	require.Error(t, err)
	p, ack := cancellation(t, heard)
	require.NotNil(t, ack)
	require.True(t, ack.AcksPacket(heard.resetSent(0)))
	require.Less(t, ack.DelayTime, 15*time.Millisecond)
	ids, _ := streamsOf(p)
	require.Equal(t, []quic.StreamID{6}, ids)
}

func TestAStreamCancellationIsMadeAsTheResetIsTaken(t *testing.T) {
	heard := &packetsBoth{}
	addr := bundleServer(t, heard, func(_ *quic.Conn, str *quic.Stream) {
		time.Sleep(100 * time.Millisecond)
		str.CancelWrite(quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed))
	})
	cc := bundleClient(t, addr, bundlePolicy(t, map[string]any{"h3.qpack.decoder_writes": "opportunistic", "h3.peer_reset": "read-side"}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SendRequestHeader(asked(t, ctx, addr)))
	require.NoError(t, str.Close())
	// its answer never read: the reset's Stream Cancellation all the same,
	// with the reset's ACK, as quiche makes it processing the frame
	_, ack := cancellation(t, heard)
	require.NotNil(t, ack)
	require.True(t, ack.AcksPacket(heard.resetSent(0)))
}

func TestAResetAfterTheFINCancelsNoStream(t *testing.T) {
	heard := &packetsBoth{}
	addr := bundleServer(t, heard, func(*quic.Conn, *quic.Stream) {})
	cc := bundleClient(t, addr, bundlePolicy(t, map[string]any{"h3.qpack.decoder_writes": "opportunistic"}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	hstr := str.str.datagramStream.(*stateTrackingStream)
	// its FIN came: the decode ends, and no Stream Cancellation is kept
	hstr.qpackReset(true)
	require.ErrorIs(t, str.decodeContext.Err(), context.Canceled)
	cc.conn.qpack.decoderWriter.mu.Lock()
	require.Empty(t, cc.conn.qpack.decoderWriter.pending)
	cc.conn.qpack.decoderWriter.mu.Unlock()
	// nor after, when its reading fails
	hstr.qpackAbandon()
	cc.conn.qpack.decoderWriter.mu.Lock()
	require.Empty(t, cc.conn.qpack.decoderWriter.pending)
	cc.conn.qpack.decoderWriter.mu.Unlock()
	// a stream of no connection of the client's
	(&stateTrackingStream{clearer: (*fakeClearer)(nil)}).qpackReset(false)
}

type fakeClearer struct{}

func (*fakeClearer) clearStream(quic.StreamID) {}

// quietPair is a client and server connection that probe no path MTU, once
// what follows their handshake is acknowledged.
func quietPair(t *testing.T) (client, server *quic.Conn) {
	t.Helper()
	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), &quic.Config{DisablePathMTUDiscovery: true})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err = quic.DialEarly(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), &quic.Config{DisablePathMTUDiscovery: true})
	require.NoError(t, err)
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err = ln.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { server.CloseWithError(0, "") })
	<-client.HandshakeComplete()
	time.Sleep(100 * time.Millisecond)
	return client, server
}

func TestAnOpportunisticWriterKeepsItsInstructionsForTheNextPacket(t *testing.T) {
	client, server := quietPair(t)
	pol := bundlePolicy(t, map[string]any{"h3.qpack.decoder_writes": "opportunistic", "h3.qpack.streams": "lazy"})
	c := newConnection(client.Context(), client, false, false, nil, 0)
	// what it keeps, given to its source: the stream's type before the first
	w := newQPACKInstructionWriter(c, 3, pol)
	w.opportunistic = true
	w.start.Do(func() {})
	require.Equal(t, []byte("x"), w.take([]byte("x")))
	require.NoError(t, w.send([]byte{0x40}))
	require.NoError(t, w.send([]byte{0x41}))
	require.Equal(t, []byte{0x03, 0x40, 0x41}, w.take(nil))
	require.Empty(t, w.take(nil))
	require.NoError(t, w.send([]byte{0x42}))
	require.Equal(t, []byte{0x42}, w.take(nil))
	// a lazy writer's stream opened as the first comes, which goes with the
	// client's next packet, and not before
	w = newQPACKInstructionWriter(c, 3, pol)
	w.opportunistic = true
	require.NoError(t, w.send([]byte{0x40}))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err := server.AcceptUniStream(ctx)
	cancel()
	require.ErrorIs(t, err, context.DeadlineExceeded, "sent on its own")
	other, err := client.OpenUniStreamSync(context.Background())
	require.NoError(t, err)
	_, err = other.Write([]byte{0x21})
	require.NoError(t, err)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var got []byte
	for range 2 {
		str, err := server.AcceptUniStream(ctx)
		require.NoError(t, err)
		b := make([]byte, 2)
		if n, _ := io.ReadAtLeast(str, b, 1); b[0] == 0x03 {
			got = b[:n]
			if n == 1 {
				_, err = io.ReadFull(str, b[1:])
				require.NoError(t, err)
				got = b
			}
		}
	}
	require.Equal(t, []byte{0x03, 0x40}, got)
	// as much as an engine keeps, and no more: the connection closes
	w2 := newQPACKInstructionWriter(c, 3, pol)
	w2.opportunistic = true
	w2.start.Do(func() {})
	require.NoError(t, w2.send(make([]byte, qpackPendingBytes)))
	require.Len(t, w2.take(nil), qpackPendingBytes+1)
	require.Error(t, w.send(make([]byte, qpackPendingBytes+1)))
	w.mu.Lock()
	require.Empty(t, w.pending, "kept what it refused")
	w.mu.Unlock()
	select {
	case <-client.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the connection was not closed")
	}
	require.Error(t, w.send([]byte{0x43}))
	// a lazy writer whose stream cannot be opened closes it too
	w = newQPACKInstructionWriter(c, 3, pol)
	w.opportunistic = true
	w.run()
}

func TestAnInstructionWriterSaysWhatItWrote(t *testing.T) {
	client, server := newConnPairWithRecorder(t, nil, nil)
	go func() {
		for {
			str, err := server.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go io.Copy(io.Discard, str)
		}
	}()
	c := newConnection(client.Context(), client, false, false, nil, 0)
	w := newQPACKInstructionWriter(c, 2, controlPolicy(nil))
	queued, idle := w.mark()
	require.Zero(t, queued)
	require.True(t, idle)
	require.False(t, w.ready(), "a lazy writer's stream is still to open")
	require.NoError(t, w.send([]byte{0x3f, 0xe1, 0x1f}))
	queued, _ = w.mark()
	require.Equal(t, uint64(1), queued)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w.waitWritten(ctx, 1, nil)
	_, idle = w.mark()
	require.True(t, idle)
	require.True(t, w.ready())
	// a wait ends with its request, its bundle's spill or its connection,
	// each while the others go on
	waited := func(ctx context.Context, spilled <-chan struct{}, end func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			w.waitWritten(ctx, 5, spilled)
			close(done)
		}()
		end()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("still waiting")
		}
	}
	spilled := make(chan struct{})
	waited(context.Background(), spilled, func() { close(spilled) })
	ended, stop := context.WithCancel(context.Background())
	waited(ended, nil, stop)
	// a deferred writer's stream is reserved
	require.True(t, (&qpackInstructionWriter{reservationReady: make(chan struct{})}).ready())
	waited(context.Background(), nil, func() { require.NoError(t, client.CloseWithError(0, "")) })
}

func TestAnEagerOpportunisticDecoderSaysItsTypeAtOnce(t *testing.T) {
	heard := &packetsBoth{}
	addr := bundleServer(t, heard, func(_ *quic.Conn, str *quic.Stream) {
		time.Sleep(100 * time.Millisecond)
		str.CancelWrite(quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed))
	})
	cc := bundleClient(t, addr, bundlePolicy(t, map[string]any{"h3.qpack.decoder_writes": "opportunistic",
		"h3.qpack.streams": "eager", "h3.peer_reset": "read-side"}))
	// its type went at setup; its Stream Cancellation after, with the ACK
	// of the reset
	require.Eventually(t, func() bool { p, _ := heard.carrying(6, 0); return p != nil }, 2*time.Second, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cc.RoundTrip(asked(t, ctx, addr))
	require.Error(t, err)
	var p *quicqlog.PacketReceived
	require.Eventually(t, func() bool { p, _ = heard.carrying(6, 1); return p != nil }, 2*time.Second, 5*time.Millisecond)
	ack, ok := p.Frames[0].Frame.(*quicqlog.AckFrame)
	require.True(t, ok)
	require.True(t, ack.AcksPacket(heard.resetSent(0)))
	// the Stream Cancellation alone, its stream's type not said again
	for _, f := range p.Frames {
		if s, ok := f.Frame.(*quicqlog.StreamFrame); ok && s.StreamID == 6 {
			require.Equal(t, int64(1), s.Length)
		}
	}
	// what it keeps, without its type again
	w := cc.conn.qpack.decoderWriter
	require.NoError(t, w.send([]byte{0x40}))
	require.Equal(t, []byte{0x40}, w.take(nil))
}

func TestAWriteHeadersSaysWhatToWaitFor(t *testing.T) {
	heard := &packetsBoth{}
	addr := bundleServer(t, heard, func(*quic.Conn, *quic.Stream) {})
	cc := bundleClient(t, addr, bundlePolicy(t, nil))
	rw := cc.requestWriter
	ctx := context.Background()
	// instructions queued to an idle writer with its stream reserved
	written, err := rw.writeHeaders(&bytes.Buffer{}, asked(t, ctx, addr), false, 0, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(1), written)
	// none queued: the same fields, in the table now
	rw.instructions.waitWritten(ctx, written, nil)
	written, err = rw.writeHeaders(&bytes.Buffer{}, asked(t, ctx, addr), false, 4, nil)
	require.NoError(t, err)
	require.Zero(t, written)
	// a writer with others to write first
	rw.instructions.progress.Lock()
	rw.instructions.queued++
	rw.instructions.progress.Unlock()
	req := asked(t, ctx, addr)
	req.Header.Set("X-New", "a field not in the table")
	written, err = rw.writeHeaders(&bytes.Buffer{}, req, false, 8, nil)
	require.NoError(t, err)
	require.Zero(t, written)
	// no dynamic encoder's
	written, err = newRequestWriter().writeHeaders(&bytes.Buffer{}, req, false, 12, nil)
	require.NoError(t, err)
	require.Zero(t, written)
	// a lazy writer whose stream is still to be opened
	lazy := newRequestWriterWithPseudoHeaderOrder(nil, 0)
	lazy.behavior = bundlePolicy(t, map[string]any{"h3.qpack.streams": "lazy"})
	w := newQPACKInstructionWriter(cc.conn, 2, lazy.behavior)
	w.start.Do(func() {}) // never opened
	lazy.instructions = w
	lazy.dynamic = newDynamicQPACKEncoder("insert", "shorter", "shorter", nil, w.send)
	lazy.dynamic.budget = 65536
	lazy.dynamic.configure(4096, 100)
	written, err = lazy.writeHeaders(&bytes.Buffer{}, asked(t, ctx, addr), false, 0, nil)
	require.NoError(t, err)
	require.Zero(t, written)
	queued, _ := w.mark()
	require.Equal(t, uint64(1), queued, "nothing queued: no case of a writer to open")
	_ = slices.Clone([]int{})
}
