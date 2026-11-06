package http3

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
)

// TestAServersBidirectionalStreamClosesTheConnectionAsQuicheDoes: a server
// may open no bidirectional stream of HTTP/3's; Chrome's client closes the
// connection with H3_STREAM_CREATION_ERROR and its reason.
func TestAServersBidirectionalStreamClosesTheConnectionAsQuicheDoes(t *testing.T) {
	client, server := newConnPair(t)
	p := behavior.Generic()
	p["h3.server_bidi_stream_close_reason"] = json.RawMessage(`"154:Server created bidirectional stream."`)
	_ = newClientConn(client, false, nil, nil, nil, false, 0, nil, nil, -1, true, nil, p)
	str, err := server.OpenStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("probe"))
	require.NoError(t, err)
	select {
	case <-server.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a server's bidirectional stream was taken")
	}
	var remote *quic.ApplicationError
	require.ErrorAs(t, context.Cause(server.Context()), &remote)
	require.EqualValues(t, ErrCodeStreamCreationError, remote.ErrorCode)
	require.Equal(t, "154:Server created bidirectional stream.", remote.ErrorMessage)
}

// Without the profile's reason, as before: the stream is passed over and the
// connection stays.
func TestAServersBidirectionalStreamIsPassedOverWithoutAReason(t *testing.T) {
	client, server := newConnPair(t)
	_ = newClientConn(client, false, nil, nil, nil, false, 0, nil, nil, -1, true, nil, behavior.Generic())
	str, err := server.OpenStream()
	require.NoError(t, err)
	_, err = str.Write([]byte("probe"))
	require.NoError(t, err)
	select {
	case <-server.Context().Done():
		t.Fatalf("closed: %v", context.Cause(server.Context()))
	case <-time.After(300 * time.Millisecond):
	}
}
