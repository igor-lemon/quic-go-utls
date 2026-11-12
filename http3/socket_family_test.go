package http3

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/internal/testdata"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
)

// A Transport without Dial dials a server from a UDP socket of the server's
// address family. A dual-stack socket may be given a port another socket
// holds at a specific IPv4 address (macOS hands it out), and a datagram from
// a server at that address then goes to the other socket: the handshake
// hears nothing, and fails as idle (a release run of 2026-11-12 on macOS,
// another test binary's socket at 127.0.0.1 holding the client's port).

// handshakes is a QUIC listener at ip that completes every handshake and
// keeps the connection until the test ends; it says where it listens.
func handshakes(t *testing.T, ip net.IP) (string, bool) {
	t.Helper()
	conf := testdata.GetTLSConfig()
	conf.NextProtos = []string{NextProtoH3}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		return "", false
	}
	tr := &quic.Transport{Conn: udp}
	ln, err := tr.Listen(conf, &quic.Config{})
	require.NoError(t, err)
	t.Cleanup(func() {
		ln.Close()
		tr.Close()
		udp.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.CloseWithError(0, "") })
		}
	}()
	return udp.LocalAddr().String(), true
}

// socketTransport is a Transport of no Dial whose sockets listened says.
func socketTransport(listened *[]string, mu *sync.Mutex) *Transport {
	return &Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: 2 * time.Second},
		listenUDP: func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
			mu.Lock()
			*listened = append(*listened, network+" "+laddr.String())
			mu.Unlock()
			return net.ListenUDP(network, laddr)
		},
	}
}

func TestATransportDialsEachServerFromASocketOfItsAddressFamily(t *testing.T) {
	var mu sync.Mutex
	var listened []string
	tr := socketTransport(&listened, &mu)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, _ := handshakes(t, net.IPv4(127, 0, 0, 1))
	second, _ := handshakes(t, net.IPv4(127, 0, 0, 1))
	require.NoError(t, tr.Preconnect(ctx, first))
	require.NoError(t, tr.Preconnect(ctx, second))
	// one socket of IPv4 alone, for both
	require.Equal(t, []string{"udp4 0.0.0.0:0"}, listened)
	four := tr.sockets[0]
	require.NotNil(t, four)
	require.Nil(t, tr.sockets[1])
	require.Equal(t, "0.0.0.0", four.Conn.LocalAddr().(*net.UDPAddr).IP.String())
	if six, ok := handshakes(t, net.IPv6loopback); ok {
		require.NoError(t, tr.Preconnect(ctx, six))
		require.Equal(t, []string{"udp4 0.0.0.0:0", "udp6 [::]:0"}, listened)
		require.Same(t, four, tr.sockets[0])
		require.NotNil(t, tr.sockets[1])
	} else {
		t.Log("no IPv6 loopback address here: the socket of IPv6 is not dialed")
	}
	// closed with the Transport, and none made after
	sockets := tr.sockets
	require.NoError(t, tr.Close())
	for _, socket := range sockets {
		if socket != nil {
			_, err := socket.Conn.WriteTo([]byte{0}, four.Conn.LocalAddr())
			require.ErrorIs(t, err, net.ErrClosed)
		}
	}
	_, err := tr.socketFor(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	require.ErrorIs(t, err, ErrTransportClosed)
	require.Equal(t, [2]*quic.Transport{}, tr.sockets)
}

func TestASocketThatCannotBeMadeFailsItsDialAlone(t *testing.T) {
	refused := errors.New("no socket")
	var fail atomic.Bool
	fail.Store(true)
	tr := &Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: 2 * time.Second},
		listenUDP: func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
			if fail.Load() {
				return nil, refused
			}
			return net.ListenUDP(network, laddr)
		},
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, _ := handshakes(t, net.IPv4(127, 0, 0, 1))
	require.ErrorIs(t, tr.Preconnect(ctx, addr), refused)
	require.Nil(t, tr.sockets[0])
	// the next dial makes it
	fail.Store(false)
	require.NoError(t, tr.Preconnect(ctx, addr))
	require.NotNil(t, tr.sockets[0])
}

func TestAServerIsHeardWhereOtherSocketsHoldPortsAtItsAddress(t *testing.T) {
	// sockets at 127.0.0.1 another program could hold: a dual-stack socket
	// is given one of their ports about as often as they hold the range
	var held []*net.UDPConn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for range 2000 {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			break
		}
		held = append(held, c)
	}
	require.NotEmpty(t, held)
	addr, _ := handshakes(t, net.IPv4(127, 0, 0, 1))
	for i := range 40 {
		tr := &Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			QUICConfig:      &quic.Config{HandshakeIdleTimeout: time.Second},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := tr.Preconnect(ctx, addr)
		cancel()
		port := 0
		if tr.sockets[0] != nil {
			port = tr.sockets[0].Conn.LocalAddr().(*net.UDPAddr).Port
		}
		require.NoError(t, tr.Close())
		require.NoError(t, err, "dial %d from port %d", i, port)
	}
}
