package http3

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	tls "github.com/igor-lemon/utls"

	"github.com/igor-lemon/quic-go-utls"
	quicqlog "github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"

	"github.com/stretchr/testify/require"
)

// An HTTP/3 client after its handshake, as its profile says. Chrome 155's
// (quiche at its DEPS revision, measured on ../net-fp-server's bench/h3 and
// bench/h3alps): its control stream in the datagram that carries its
// Finished (QuicSpdySession::SendInitialData once encryption is
// established), and only the read side of a request stream closed when the
// server resets it (QuicStream::OnStreamReset of IETF QUIC).

// heardFrames is a server's qlog recorder that keeps every packet it gets
// from its client.
type heardFrames struct {
	mu      sync.Mutex
	packets []quicqlog.PacketReceived
}

func (h *heardFrames) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(quicqlog.PacketReceived); ok {
		h.mu.Lock()
		h.packets = append(h.packets, p)
		h.mu.Unlock()
	}
}

func (h *heardFrames) Close() error { return nil }

func (h *heardFrames) heard() []quicqlog.PacketReceived {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]quicqlog.PacketReceived(nil), h.packets...)
}

// listenHearing is a QUIC server whose connections keep what their clients
// send in heard, each request stream it accepts given to serve.
func listenHearing(t *testing.T, heard *heardFrames, serve func(*quic.Stream)) string {
	t.Helper()
	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), &quic.Config{
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return &qlogTrace{recorder: heard} },
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
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go serve(str)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// lateDial is a transport's dial that returns its connection 30 ms after the
// handshake, as a busy dialer could.
func lateDial(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	conn, err := quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
	time.Sleep(30 * time.Millisecond)
	return conn, err
}

func TestTheControlStreamGoesWithTheFinishedAsItsProfileSays(t *testing.T) {
	for _, tc := range []struct {
		mode string
		with bool
	}{
		{"with-finished", true},
		{"after-handshake", false},
		{"", false},
	} {
		heard := &heardFrames{}
		addr := listenHearing(t, heard, func(*quic.Stream) {})
		pol := controlPolicy(nil)
		if tc.mode != "" {
			pol = controlPolicy(map[string]any{"h3.control_stream": tc.mode})
		}
		require.NoError(t, pol.Validate())
		tr := &Transport{Behavior: pol, TLSClientConfig: getTLSClientConfig(), Dial: lateDial}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		require.NoError(t, tr.Preconnect(ctx, addr))
		cancel()
		time.Sleep(50 * time.Millisecond)
		require.NoError(t, tr.Close())
		// the datagram whose Handshake packet carries the Finished, and the
		// one the control stream's first bytes came in
		got := heard.heard()
		finished := map[quicqlog.DatagramID]bool{}
		var control *quicqlog.PacketReceived
		for i, p := range got {
			for _, f := range p.Frames {
				switch f := f.Frame.(type) {
				case *quicqlog.CryptoFrame:
					if p.Header.PacketType == quicqlog.PacketTypeHandshake {
						finished[p.DatagramID] = true
					}
				case *quicqlog.StreamFrame:
					if f.StreamID == 2 && f.Offset == 0 && control == nil {
						control = &got[i]
					}
				}
			}
		}
		require.NotEmpty(t, finished, tc.mode)
		require.NotNil(t, control, "%s: no control stream", tc.mode)
		require.Equal(t, tc.with, finished[control.DatagramID], "%s: the control stream with the Finished", tc.mode)
		// one control stream, and no other stream of the client's (its
		// QPACK streams wait for something to say)
		uni := map[quic.StreamID]bool{}
		for _, p := range got {
			for _, f := range p.Frames {
				if f, ok := f.Frame.(*quicqlog.StreamFrame); ok {
					uni[f.StreamID] = true
				}
			}
		}
		require.Equal(t, map[quic.StreamID]bool{2: true}, uni, tc.mode)
	}
}

func TestAControlStreamTheServerLeavesNoRoomForClosesTheConnection(t *testing.T) {
	for _, mode := range []string{"with-finished", "after-handshake"} {
		ln, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), &quic.Config{MaxIncomingUniStreams: -1})
		require.NoError(t, err)
		closed := make(chan error, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			<-conn.Context().Done()
			closed <- context.Cause(conn.Context())
		}()
		pol := controlPolicy(map[string]any{"h3.control_stream": mode})
		tr := &Transport{Behavior: pol, TLSClientConfig: getTLSClientConfig()}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = tr.Preconnect(ctx, ln.Addr().String())
		select {
		case err := <-closed:
			// the client's close: H3_INTERNAL_ERROR, or, where it went
			// before the server had the client's Finished (with-finished
			// opens the stream as the handshake completes), in a Handshake
			// packet, where RFC 9000 makes it the transport's
			// APPLICATION_ERROR
			var aerr *quic.ApplicationError
			var terr *quic.TransportError
			switch {
			case errors.As(err, &aerr):
				require.True(t, aerr.Remote, mode)
				require.Equal(t, quic.ApplicationErrorCode(ErrCodeInternalError), aerr.ErrorCode, mode)
			case errors.As(err, &terr):
				require.True(t, terr.Remote, mode)
				require.Equal(t, quic.ApplicationErrorErrorCode, terr.ErrorCode, mode)
			default:
				t.Fatalf("%s: the server's connection ended with %v", mode, err)
			}
		case <-ctx.Done():
			t.Fatalf("%s: the connection was not closed", mode)
		}
		cancel()
		require.NoError(t, tr.Close())
		require.NoError(t, ln.Close())
	}
}

func TestAClientConnectionMadeAsTheHandshakeCompletedIsTakenOnce(t *testing.T) {
	var made int
	newConn := func(*quic.Conn) clientConn { made++; return &ClientConn{} }
	// made on the connection's goroutine, then taken by its dial
	e := &earlyClientConn{make: newConn}
	e.made(nil)
	require.NotNil(t, e.take())
	require.Equal(t, 1, made)
	// its dial took none first (DialEarly returned before the handshake
	// completed, with 0-RTT): none is made after
	e = &earlyClientConn{make: newConn}
	require.Nil(t, e.take())
	e.made(nil)
	require.Equal(t, 1, made)
	require.Nil(t, e.take())
	// a dial of no early connection
	require.Nil(t, (*earlyClientConn)(nil).take())
}

// resetsHeard are the RESET_STREAM frames a server heard of request streams.
func resetsHeard(packets []quicqlog.PacketReceived) []*quicqlog.ResetStreamFrame {
	var resets []*quicqlog.ResetStreamFrame
	for _, p := range packets {
		for _, f := range p.Frames {
			if r, ok := f.Frame.(*quicqlog.ResetStreamFrame); ok && r.StreamID%4 == 0 {
				resets = append(resets, r)
			}
		}
	}
	return resets
}

func TestAStreamItsServerResetsHasItsReadSideClosedAsItsProfileSays(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		sending bool    // the request's body still being sent
		partial bool    // the server resets after a part of its HEADERS
		code    ErrCode // of the client's RESET_STREAM
		reset   bool    // whether it sends one
		why     string  // what the case is
	}{
		{mode: "read-side", why: "a request sent whole: nothing"},
		{mode: "read-side", sending: true, reset: true, code: ErrCodeRequestCanceled, why: "a request still sending: cancelled"},
		{mode: "frame-error", reset: true, code: ErrCodeFrameError, why: "quic-go's, said"},
		{mode: "", reset: true, code: ErrCodeFrameError, why: "quic-go's"},
		{mode: "", sending: true, reset: true, code: ErrCodeFrameError, why: "quic-go's, still sending"},
		{mode: "read-side", partial: true, why: "a reset within the answer's HEADERS: nothing"},
		{mode: "", partial: true, reset: true, code: ErrCodeRequestIncomplete, why: "quic-go's, within the HEADERS"},
	} {
		heard := &heardFrames{}
		// the server resets each request stream as it gets it, as one
		// that cannot decode its headers does
		addr := listenHearing(t, heard, func(str *quic.Stream) {
			if tc.partial {
				// HEADERS of 10 bytes, 2 of them, then the reset
				_, _ = str.Write([]byte{0x01, 0x0a, 0x00, 0x00})
				time.Sleep(20 * time.Millisecond)
			}
			str.CancelWrite(quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed))
		})
		pol := controlPolicy(nil)
		if tc.mode != "" {
			pol = controlPolicy(map[string]any{"h3.peer_reset": tc.mode})
		}
		require.NoError(t, pol.Validate())
		tr := &Transport{Behavior: pol, TLSClientConfig: getTLSClientConfig()}
		var body io.ReadCloser
		var writer *io.PipeWriter
		method := http.MethodGet
		if tc.sending {
			body, writer = io.Pipe()
			method = http.MethodPost
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, method, "https://"+addr+"/", body)
		require.NoError(t, err)
		_, err = tr.RoundTrip(req)
		var serr *Error
		require.ErrorAs(t, err, &serr, tc.why)
		require.Equal(t, ErrCodeQPACKDecompressionFailed, serr.ErrorCode, tc.why)
		require.True(t, serr.Remote, tc.why)
		time.Sleep(100 * time.Millisecond)
		if writer != nil {
			writer.Close()
		}
		cancel()
		require.NoError(t, tr.Close())
		resets := resetsHeard(heard.heard())
		if !tc.reset {
			require.Empty(t, resets, tc.why)
			continue
		}
		require.Len(t, resets, 1, tc.why)
		require.Equal(t, quic.StreamErrorCode(tc.code), resets[0].ErrorCode, tc.why)
	}
}

func TestAReadTheClientCancelledIsNoResetOfItsServer(t *testing.T) {
	heard := &heardFrames{}
	// a server that never answers
	addr := listenHearing(t, heard, func(*quic.Stream) {})
	tr := &Transport{Behavior: controlPolicy(map[string]any{"h3.peer_reset": "read-side"})}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := getTLSClientConfig()
	cfg.NextProtos = []string{NextProtoH3}
	conn, err := quic.DialAddr(ctx, addr, cfg, &quic.Config{})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	cc := tr.NewClientConn(conn)
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	require.NoError(t, err)
	// the request's send side left open, its read cancelled by the client
	require.NoError(t, str.SendRequestHeader(req))
	go func() {
		time.Sleep(50 * time.Millisecond)
		str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
	}()
	_, err = str.ReadResponse()
	require.Error(t, err)
	time.Sleep(100 * time.Millisecond)
	// its own doing, not the server's reset: both sides cancelled, as quic-go
	// cancels them
	resets := resetsHeard(heard.heard())
	require.Len(t, resets, 1)
	require.Equal(t, quic.StreamErrorCode(ErrCodeFrameError), resets[0].ErrorCode)
}
