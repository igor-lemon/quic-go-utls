package http3

import (
	"context"
	"testing"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptest"
	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAConnectionThatWentAwayIsDialedAnew(t *testing.T) {
	var dialed []*quic.Conn
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			conn, _ := newConnPair(t)
			dialed = append(dialed, conn)
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return NewMockClientConn(gomock.NewController(t)) },
	}
	defer tr.Close()
	require.NoError(t, tr.Preconnect(context.Background(), "quic-go.net:443"))
	// The connection goes away, as one idle past its timeout does.
	require.NoError(t, dialed[0].CloseWithError(0, ""))
	<-dialed[0].Context().Done()
	require.NoError(t, tr.Preconnect(context.Background(), "quic-go.net:443"))
	require.Len(t, dialed, 2)
	require.True(t, tr.HasConn("quic-go.net:443"))
	// A request for a cached connection is sent on none that went away.
	require.NoError(t, dialed[1].CloseWithError(0, ""))
	<-dialed[1].Context().Done()
	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net", nil)
	_, err := tr.RoundTripOpt(req, RoundTripOpt{OnlyCachedConn: true})
	require.ErrorIs(t, err, ErrNoCachedConn)
	require.Len(t, dialed, 2)
}

func TestARequestThatFailedForgetsItsOwnConnectionAlone(t *testing.T) {
	tr := &Transport{}
	before := &roundTripperWithCount{dialing: closedChannel(), cancel: func() {}}
	now := &roundTripperWithCount{dialing: closedChannel(), cancel: func() {}}
	tr.removeClient("quic-go.net:443", before)
	tr.clients = map[string]*roundTripperWithCount{"quic-go.net:443": now}
	tr.removeClient("quic-go.net:443", before)
	require.Same(t, now, tr.clients["quic-go.net:443"])
	tr.removeClient("quic-go.net:443", now)
	require.Empty(t, tr.clients)
}

func TestAConnectionBeingDialedIsJoined(t *testing.T) {
	conn, _ := newConnPair(t)
	let := make(chan struct{})
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			<-let
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return NewMockClientConn(gomock.NewController(t)) },
	}
	defer tr.Close()
	first, _, err := tr.getClient(context.Background(), "quic-go.net:443", false)
	require.NoError(t, err)
	// Still being dialed: not gone, and joined.
	second, _, err := tr.getClient(context.Background(), "quic-go.net:443", false)
	require.NoError(t, err)
	require.Same(t, first, second)
	close(let)
	<-first.dialing
	first.useCount.Add(-2)
}
