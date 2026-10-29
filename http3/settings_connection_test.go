package http3

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
)

func readConnectionSetting(t *testing.T, server *quic.Conn) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	str, err := server.AcceptUniStream(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SetReadDeadline(time.Now().Add(2*time.Second)))
	reader := quicvarint.NewReader(str)
	typ, err := quicvarint.Read(reader)
	require.NoError(t, err)
	require.Zero(t, typ)
	frame, err := (&frameParser{r: str}).ParseNext(nil)
	require.NoError(t, err)
	return frame.(*settingsFrame).Other[0x21]
}

func TestConnectionSettingsFactoryDirectAndDefault(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprint(direct), func(t *testing.T) {
			var calls uint64
			tr := &Transport{SettingsForConnection: func() (map[uint64]uint64, []uint64) { calls++; return map[uint64]uint64{0x21: calls}, []uint64{0x21} }}
			require.NoError(t, tr.init())
			for i := uint64(1); i <= 3; i++ {
				client, server := newConnPair(t)
				if direct {
					tr.NewClientConn(client)
				} else {
					tr.newClientConn(client)
				}
				require.Equal(t, i, readConnectionSetting(t, server))
			}
			require.EqualValues(t, 3, calls)
		})
	}
}

func TestConnectionSettingsFactoryPoolReuseAndRedial(t *testing.T) {
	var calls atomic.Uint64
	var peer *quic.Conn
	var local *quic.Conn
	tr := &Transport{SettingsForConnection: func() (map[uint64]uint64, []uint64) {
		n := calls.Add(1)
		return map[uint64]uint64{0x21: n}, []uint64{0x21}
	}}
	tr.Dial = func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
		local, peer = newConnPair(t)
		server := peer
		go func() {
			control, err := server.OpenUniStreamSync(context.Background())
			if err != nil {
				return
			}
			_, _ = control.Write([]byte{0, 4, 0})
			for {
				stream, err := server.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					_, _ = io.Copy(io.Discard, stream)
					_, _ = stream.Write([]byte{1, 3, 0, 0, 0xd9})
					_ = stream.Close()
				}()
			}
		}()
		return local, nil
	}
	defer tr.Close()
	for conn := uint64(1); conn <= 3; conn++ {
		for request := 0; request < 2; request++ {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			req, err := http.NewRequestWithContext(ctx, "GET", "https://settings.test/", nil)
			require.NoError(t, err)
			response, err := tr.RoundTrip(req)
			require.NoError(t, err)
			_, err = io.ReadAll(response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			cancel()
			require.Equal(t, conn, calls.Load(), "factory must run once per actual connection")
			if request == 0 {
				require.Equal(t, conn, readConnectionSetting(t, peer))
			}
		}
		require.NoError(t, peer.CloseWithError(0, "test redial"))
		select {
		case <-local.Context().Done():
		case <-time.After(2 * time.Second):
			t.Fatal("client never observed peer close")
		}
	}
}

func TestConnectionSettingsCopiesStaticAndFactoryInputs(t *testing.T) {
	source, order := map[uint64]uint64{0x21: 7}, []uint64{0x21}
	for _, factory := range []bool{false, true} {
		tr := &Transport{AdditionalSettings: source, AdditionalSettingsOrder: order}
		if factory {
			tr.SettingsForConnection = func() (map[uint64]uint64, []uint64) { return source, order }
		}
		settings, ordered := tr.settingsForConnection()
		settings[0x21] = 99
		ordered[0] = 99
		require.EqualValues(t, 7, source[0x21])
		require.EqualValues(t, 0x21, order[0])
	}
}
