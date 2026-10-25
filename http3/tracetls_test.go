package http3

import (
	"net"
	"testing"

	"github.com/igor-lemon/fhttp/httptrace"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
)

func TestATracedConnectionSaysItsTLS(t *testing.T) {
	conn, _ := newConnPair(t)
	var got net.Conn
	traceGotConn(&httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { got = info.Conn }}, conn, false)
	state, ok := got.(interface{ ConnectionState() tls.ConnectionState })
	require.True(t, ok)
	require.Equal(t, conn.ConnectionState().TLS.NegotiatedProtocol, state.ConnectionState().NegotiatedProtocol)
	require.Equal(t, uint16(tls.VersionTLS13), state.ConnectionState().Version)
}
