package http3

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
)

func TestA13DraftDatagramErrorTemplateOnWire(t *testing.T) {
	client, server := newConnPairWithDatagrams(t, nil, nil)
	p := behavior.Generic()
	p["h3.datagram_setting_error_reason"] = json.RawMessage(`"setting {id}: bad {value}"`)
	cc := newClientConn(client, true, map[uint64]uint64{51: 1, 16765559: 1}, []uint64{51, 16765559}, nil, false, 0, nil, nil, -1, true, nil, p)
	stream, err := server.OpenUniStream()
	require.NoError(t, err)
	payload := quicvarint.Append(nil, 16765559)
	payload = quicvarint.Append(payload, 2)
	raw := quicvarint.Append([]byte{0, 4}, uint64(len(payload)))
	raw = append(raw, payload...)
	_, err = stream.Write(raw)
	require.NoError(t, err)
	select {
	case <-server.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("invalid advertised setting not rejected")
	}
	var remote *quic.ApplicationError
	require.ErrorAs(t, context.Cause(server.Context()), &remote)
	require.EqualValues(t, 0x109, remote.ErrorCode)
	require.Equal(t, "setting 16765559: bad 2", remote.ErrorMessage)
	_ = cc
}
