package http3

import (
	"context"
	"errors"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestTransportSaysWhetherItHasAConnection(t *testing.T) {
	conn, _ := newConnPair(t)
	let := make(chan struct{})
	dialing := make(chan struct{})
	tr := &Transport{
		Dial: func(_ context.Context, hostname string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			if hostname == "refused.net:443" {
				return nil, errors.New("refused")
			}
			close(dialing)
			<-let
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return NewMockClientConn(gomock.NewController(t)) },
	}
	defer tr.Close()
	require.False(t, tr.HasConn("quic-go.net:443"))
	done := make(chan error, 1)
	go func() { done <- tr.Preconnect(context.Background(), "quic-go.net:443") }()
	<-dialing
	// One being dialed is none yet.
	require.False(t, tr.HasConn("quic-go.net:443"))
	close(let)
	require.NoError(t, <-done)
	require.True(t, tr.HasConn("quic-go.net:443"))
	require.False(t, tr.HasConn("other.net:443"))
	// One whose dial failed is none.
	require.Error(t, tr.Preconnect(context.Background(), "refused.net:443"))
	tr.mutex.Lock()
	tr.clients["refused.net:443"] = &roundTripperWithCount{dialing: closedChannel(), dialErr: errors.New("refused"), cancel: func() {}}
	tr.mutex.Unlock()
	require.False(t, tr.HasConn("refused.net:443"))
	// One that closed is none.
	require.NoError(t, conn.CloseWithError(0, ""))
	require.Eventually(t, func() bool { return !tr.HasConn("quic-go.net:443") }, time.Second, 5*time.Millisecond)
}

func closedChannel() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}
