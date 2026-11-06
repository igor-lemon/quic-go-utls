package http3

import (
	"context"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
)

// TestARequestWaitingForAHandshakeEndsWithItsConnection: a request on a
// connection still shaking hands, as a 0-RTT one is, waits for the handshake
// no longer than the connection lasts: a handshake that fails completes never.
func TestARequestWaitingForAHandshakeEndsWithItsConnection(t *testing.T) {
	udp := newUDPConnLocalhost(t)
	ln, err := quic.ListenEarly(udp, getTLSConfig(), &quic.Config{Allow0RTT: true})
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() { <-conn.Context().Done() }()
		}
	}()
	cfg := getTLSClientConfig()
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A session to resume, with early data, from a first connection.
	first, err := quic.DialAddr(ctx, ln.Addr().String(), cfg, &quic.Config{})
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, first.CloseWithError(0, ""))
	// The server goes: the next connection's handshake completes never.
	require.NoError(t, ln.Close())
	require.NoError(t, udp.Close())
	conn, err := quic.DialAddrEarly(ctx, ln.Addr().String(), cfg, &quic.Config{})
	require.NoError(t, err)
	select {
	case <-conn.HandshakeComplete():
		t.Fatal("the handshake completed")
	default:
	}
	cc := newClientConn(conn, false, nil, nil, nil, false, 0, nil, nil, -1, true, nil, behavior.Generic())
	done := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
		_, err := cc.RoundTrip(req)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, conn.CloseWithError(0, ""))
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the request went on waiting for a handshake its connection's end ended")
	}
}
