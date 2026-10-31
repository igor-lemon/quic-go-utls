package http3

import (
	"context"
	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/stretchr/testify/require"
)

// These are literal protocol bytes, not the production SETTINGS encoder.
// The client announces both versions, the peer announces only draft-08.
func TestA13AdvertisedDraftDatagramsActuallyReceive(t *testing.T) {
	for _, check := range []string{"negotiation", "payload"} {
		t.Run(check, func(t *testing.T) {
			client, server := newConnPairWithDatagrams(t, nil, nil)
			cc := newClientConn(client, true, map[uint64]uint64{51: 1, 16765559: 1}, []uint64{51, 16765559}, nil, false, 0, nil, nil, -1, true, nil, behavior.Generic())
			c := cc.conn
			payload := quicvarint.Append(nil, 51)
			payload = quicvarint.Append(payload, 1)
			payload = quicvarint.Append(payload, 16765559)
			payload = quicvarint.Append(payload, 1)
			raw := []byte{0, 4}
			raw = quicvarint.Append(raw, uint64(len(payload)))
			raw = append(raw, payload...)
			peerLocal, err := server.AcceptUniStream(context.Background())
			require.NoError(t, err)
			seen := make([]byte, len(raw))
			_, err = io.ReadFull(peerLocal, seen)
			require.NoError(t, err)
			require.Equal(t, raw, seen)
			remote, err := server.OpenUniStream()
			require.NoError(t, err)
			payload = quicvarint.Append(nil, 16765559)
			payload = quicvarint.Append(payload, 1)
			raw = []byte{0, 4}
			raw = quicvarint.Append(raw, uint64(len(payload)))
			raw = append(raw, payload...)
			_, err = remote.Write(raw)
			require.NoError(t, err)
			select {
			case <-c.ReceivedSettings():
			case <-time.After(time.Second):
				t.Fatal("SETTINGS not received")
			}
			if check == "negotiation" {
				require.True(t, c.Settings().EnableDatagrams, "both parties advertised draft-08")
				return
			}
			str, err := cc.OpenRequestStream(context.Background())
			require.NoError(t, err)
			req, err := http.NewRequest("GET", "https://owned.test/", nil)
			require.NoError(t, err)
			err = str.SendRequestHeader(req)
			require.NoError(t, err)
			_, err = server.AcceptStream(context.Background())
			require.NoError(t, err)
			require.NoError(t, server.SendDatagram([]byte{0, 'p', 'r', 'o', 'o', 'f'}))
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			got, err := str.ReceiveDatagram(ctx)
			require.NoError(t, err, "advertised draft capability must receive actual datagrams")
			require.Equal(t, []byte("proof"), got)
		})
	}
}
