package http3

import (
	"context"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptest"
	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// failingTransport is a transport whose every request fails on its stream,
// its connections up, and the server ends of the connections it dialed.
func failingTransport(t *testing.T) (*Transport, *[]*quic.Conn) {
	var servers []*quic.Conn
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			client, server := newConnPair(t)
			servers = append(servers, server)
			return client, nil
		},
		newClientConn: func(*quic.Conn) clientConn {
			cc := NewMockClientConn(gomock.NewController(t))
			cc.EXPECT().RoundTrip(gomock.Any()).Return(nil, assert.AnError).AnyTimes()
			return cc
		},
	}
	return tr, &servers
}

func closedWithin(conn *quic.Conn, d time.Duration) bool {
	select {
	case <-conn.Context().Done():
		return true
	case <-time.After(d):
		return false
	}
}

// TestAConnectionARequestFailedOnIsClosedAfterAll: a request whose stream
// failed lets go of its connection, which stays up; the transport's Close,
// and CloseIdleConnections once nothing uses it, still close it. Before,
// nothing did: it went on until its idle timeout, no CONNECTION_CLOSE sent.
func TestAConnectionARequestFailedOnIsClosedAfterAll(t *testing.T) {
	for _, closing := range []string{"Close", "CloseIdleConnections"} {
		tr, servers := failingTransport(t)
		_, err := tr.RoundTrip(httptest.NewRequest(http.MethodGet, "https://quic-go.org", nil))
		require.ErrorIs(t, err, assert.AnError)
		require.Len(t, *servers, 1)
		require.False(t, closedWithin((*servers)[0], 50*time.Millisecond), "closed as its request failed")
		// The next request dials anew, as before.
		_, err = tr.RoundTrip(httptest.NewRequest(http.MethodGet, "https://quic-go.org", nil))
		require.ErrorIs(t, err, assert.AnError)
		require.Len(t, *servers, 2)
		if closing == "Close" {
			require.NoError(t, tr.Close())
		} else {
			tr.CloseIdleConnections()
		}
		for i, server := range *servers {
			require.True(t, closedWithin(server, time.Second), "%s left connection %d up", closing, i)
		}
		require.Empty(t, tr.retired)
		tr.Close()
	}
}

// A connection in use stays up through CloseIdleConnections, as one in the
// pool does, and one gone already is forgotten.
func TestARetiredConnectionInUseOrGoneIsLeftAsItIs(t *testing.T) {
	tr, servers := failingTransport(t)
	defer tr.Close()
	_, err := tr.RoundTrip(httptest.NewRequest(http.MethodGet, "https://quic-go.org", nil))
	require.ErrorIs(t, err, assert.AnError)
	var cl *roundTripperWithCount
	for c := range tr.retired {
		cl = c
	}
	require.NotNil(t, cl)
	cl.useCount.Add(1)
	tr.CloseIdleConnections()
	require.False(t, closedWithin((*servers)[0], 50*time.Millisecond), "a connection in use was closed")
	require.Contains(t, tr.retired, cl)
	require.NoError(t, cl.conn.CloseWithError(0, ""))
	<-cl.conn.Context().Done()
	tr.CloseIdleConnections()
	require.NotContains(t, tr.retired, cl)
}

// A request whose connection ended under it lets go of a connection gone,
// which there is nothing to close of.
func TestAConnectionThatEndedUnderARequestIsNotKeptToBeClosed(t *testing.T) {
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			client, _ := newConnPair(t)
			return client, nil
		},
		newClientConn: func(conn *quic.Conn) clientConn {
			cc := NewMockClientConn(gomock.NewController(t))
			cc.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(*http.Request) (*http.Response, error) {
				conn.CloseWithError(0, "")
				<-conn.Context().Done()
				return nil, assert.AnError
			})
			return cc
		},
	}
	defer tr.Close()
	_, err := tr.RoundTrip(httptest.NewRequest(http.MethodGet, "https://quic-go.org", nil))
	require.ErrorIs(t, err, assert.AnError)
	require.Empty(t, tr.retired)
	require.Empty(t, tr.clients)
}
