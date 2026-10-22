package http3

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptest"
	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/quic-go-utls/testutils/events"
	"github.com/stretchr/testify/require"
)

// Pause the actual initialization goroutine before its control-stream Write.
// This makes the original race deterministic without replacing the request path.
type pausedSettingsRecorder struct {
	events.Recorder
	entered, release chan struct{}
	once             sync.Once
}

func (r *pausedSettingsRecorder) RecordEvent(e qlogwriter.Event) {
	if f, ok := e.(qlog.FrameCreated); ok {
		if _, ok := f.Frame.Frame.(qlog.SettingsFrame); ok {
			r.once.Do(func() { close(r.entered); <-r.release })
		}
	}
	r.Recorder.RecordEvent(e)
}

func TestClientSettingsBeforeEveryRequestAPI(t *testing.T) {
	for _, mode := range []string{"roundtrip", "zero-rtt", "open-stream"} {
		t.Run(mode, func(t *testing.T) {
			rec := &pausedSettingsRecorder{entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			unblock := func() { release.Do(func() { close(rec.release) }) }
			t.Cleanup(unblock)
			client, server := newConnPairWithRecorder(t, rec, nil)
			cc := (&Transport{}).NewClientConn(client)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			select {
			case <-rec.entered:
			case <-ctx.Done():
				t.Fatal("setup did not reach actual SETTINGS write")
			}
			run := func(ctx context.Context) error {
				req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/", nil).WithContext(ctx)
				if mode == "zero-rtt" {
					req.Method = MethodGet0RTT
				}
				if mode == "open-stream" {
					str, err := cc.OpenRequestStream(ctx)
					if err != nil {
						return err
					}
					if err = str.SendRequestHeader(req); err != nil {
						return err
					}
					return str.Close()
				}
				rsp, err := cc.RoundTrip(req)
				if err != nil {
					return err
				}
				defer rsp.Body.Close()
				_, err = io.Copy(io.Discard, rsp.Body)
				return err
			}
			const concurrent = 8
			done := make(chan error, concurrent)
			for i := 0; i < concurrent; i++ {
				go func() { done <- run(ctx) }()
			}
			// The first request must not put bytes on a bidirectional stream while
			// SETTINGS setup is paused. The old implementation fails this assertion.
			probe, stop := context.WithTimeout(ctx, 30*time.Millisecond)
			_, err := server.AcceptStream(probe)
			stop()
			require.ErrorIs(t, err, context.DeadlineExceeded)
			canceled, stopCanceled := context.WithCancel(ctx)
			stopCanceled()
			require.ErrorIs(t, run(canceled), context.Canceled)
			unblock()
			ctrl, err := server.AcceptUniStream(ctx)
			require.NoError(t, err)
			typ, err := quicvarint.Read(quicvarint.NewReader(ctrl))
			require.NoError(t, err)
			require.EqualValues(t, streamTypeControlStream, typ)
			frame, err := (&frameParser{r: ctrl}).ParseNext(nil)
			require.NoError(t, err)
			require.IsType(t, &settingsFrame{}, frame)
			for i := 0; i < concurrent; i++ {
				str, err := server.AcceptStream(ctx)
				require.NoError(t, err)
				frame, err := (&frameParser{r: str}).ParseNext(nil)
				require.NoError(t, err)
				require.IsType(t, &headersFrame{}, frame)
				if mode != "open-stream" {
					_, err = str.Write(encodeResponse(t, 200))
					require.NoError(t, err)
					require.NoError(t, str.Close())
				}
			}
			for i := 0; i < concurrent; i++ {
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("requests failed to resume after local SETTINGS")
				}
			}
		})
	}
}

func TestClientSettingsWaitStopsOnConnectionClose(t *testing.T) {
	rec := &pausedSettingsRecorder{entered: make(chan struct{}), release: make(chan struct{})}
	client, _ := newConnPairWithRecorder(t, rec, nil)
	t.Cleanup(func() { close(rec.release) })
	cc := (&Transport{}).NewClientConn(client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-rec.entered:
	case <-ctx.Done():
		t.Fatal("setup did not pause")
	}
	require.NoError(t, client.CloseWithError(123, "test close"))
	_, err := cc.OpenRequestStream(ctx)
	var appErr *quic.ApplicationError
	require.True(t, errors.As(err, &appErr), "connection cause must stop the setup wait: %v", err)
	require.EqualValues(t, 123, appErr.ErrorCode)
}

func TestClientSettingsSetupFailurePreventsRequests(t *testing.T) {
	client, _ := newConnPair(t)
	// Locally exhaust the peer's uni-stream allowance before creating HTTP/3.
	for {
		if _, err := client.OpenUniStream(); err != nil {
			break
		}
	}
	cc := (&Transport{}).NewClientConn(client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-cc.setupComplete:
	case <-ctx.Done():
		t.Fatal("setup failed to report its error")
	}
	require.Error(t, cc.setupErr)
	_, err := cc.OpenRequestStream(ctx)
	require.Error(t, err)
	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/", nil).WithContext(ctx)
	_, err = cc.RoundTrip(req)
	require.Error(t, err)
}
