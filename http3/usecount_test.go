package http3

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptest"
	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestARequestGivenUpWhileItsConnectionIsDialedCountsItselfOut: a request
// whose context ends while its connection is being dialed leaves the
// connection unused, so that CloseIdleConnections closes it.
func TestARequestGivenUpWhileItsConnectionIsDialedCountsItselfOut(t *testing.T) {
	let := make(chan struct{})
	var server atomic.Pointer[quic.Conn]
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			<-let
			client, s := newConnPair(t)
			server.Store(s)
			return client, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return NewMockClientConn(gomock.NewController(t)) },
	}
	defer tr.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := tr.RoundTrip(httptest.NewRequest(http.MethodGet, "https://quic-go.org", nil).WithContext(ctx))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	close(let)
	// The dial ends; nothing uses its connection.
	require.Eventually(t, func() bool { return server.Load() != nil }, time.Second, 5*time.Millisecond)
	for _, cl := range tr.clients {
		<-cl.dialing
		require.Zero(t, cl.useCount.Load())
	}
	tr.CloseIdleConnections()
	require.True(t, closedWithin(server.Load(), time.Second), "an idle connection was left up")
}
