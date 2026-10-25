package quic

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/testdata"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/stretchr/testify/require"
)

// recordingConn is a client's socket that keeps every datagram it writes.
type recordingConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *recordingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

func (c *recordingConn) datagrams() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.sent...)
}

// verified is a handshake whose client asked verify of it as it ended: what
// its dial returned, the datagrams it sent, how the server's connection
// ended and whether the server's handshake was done.
type verified struct {
	err        error
	sent       [][]byte
	serverErr  error
	serverDone bool
}

func dialVerified(t *testing.T, verify func(ConnectionState) error, early string) verified {
	t.Helper()
	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"h3"}
	ln, err := ListenAddrEarly("127.0.0.1:0", serverTLS, &Config{HandshakeIdleTimeout: 500 * time.Millisecond, MaxIdleTimeout: 500 * time.Millisecond})
	require.NoError(t, err)
	defer ln.Close()
	var v verified
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		<-conn.Context().Done()
		v.serverErr = context.Cause(conn.Context())
		select {
		case <-conn.HandshakeComplete():
			v.serverDone = true
		default:
		}
	}()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	rec := &recordingConn{PacketConn: udp}
	tr := &Transport{Conn: rec}
	defer tr.Close()
	pol := behavior.Legacy()
	if early != "" {
		pol["quic.close_early_application"] = json.RawMessage(`"` + early + `"`)
	}
	require.NoError(t, pol.Validate())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, v.err = tr.Dial(ctx, ln.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&Config{VerifyHandshake: verify, Behavior: pol, InitialPacketSize: 1250})
	<-served
	v.sent = rec.datagrams()
	return v
}

// coalesced are the packet types of a datagram, in order: Initial,
// Handshake, and "1-RTT" for a short header, which ends it.
func coalesced(t *testing.T, d []byte) []string {
	t.Helper()
	var types []string
	for len(d) > 0 {
		if !wire.IsLongHeaderPacket(d[0]) {
			return append(types, "1-RTT")
		}
		hdr, _, rest, err := wire.ParsePacket(d)
		require.NoError(t, err)
		types = append(types, hdr.Type.String())
		d = rest
	}
	return types
}

func TestAHandshakeItsClientRefusesIsClosedBeforeItsFinishedGoes(t *testing.T) {
	var asked ConnectionState
	v := dialVerified(t, func(cs ConnectionState) error {
		asked = cs
		return &TransportError{ErrorCode: 10, FrameType: 6, ErrorMessage: "28:Error processing ALPS data: DATA frame forbidden"}
	}, "")
	require.Equal(t, "h3", asked.TLS.NegotiatedProtocol, "asked once the handshake is done")
	var te *TransportError
	require.ErrorAs(t, v.err, &te)
	require.False(t, te.Remote)
	require.Equal(t, TransportErrorCode(10), te.ErrorCode)
	require.ErrorAs(t, v.serverErr, &te)
	require.True(t, te.Remote)
	require.Equal(t, TransportErrorCode(10), te.ErrorCode)
	require.EqualValues(t, 6, te.FrameType)
	require.Equal(t, "28:Error processing ALPS data: DATA frame forbidden", te.ErrorMessage)
	require.False(t, v.serverDone, "the server never had the client's Finished")
	// the close goes in every packet the client has keys for, the datagram
	// as long as its Initials, the 1-RTT packet's tag counted
	last := v.sent[len(v.sent)-1]
	require.Equal(t, []string{"Initial", "Handshake", "1-RTT"}, coalesced(t, last))
	require.Len(t, last, 1250)
	hdr, _, _, err := wire.ParsePacket(v.sent[0])
	require.NoError(t, err)
	_, payload := openClientInitial(t, hdr.DestConnectionID, last)
	parser := wire.NewFrameParser(false, false, false)
	ft, n, err := parser.ParseType(payload, protocol.EncryptionInitial)
	require.NoError(t, err)
	require.Equal(t, wire.FrameTypeConnectionClose, ft)
	f, m, err := parser.ParseLessCommonFrame(ft, payload[n:], protocol.Version1)
	require.NoError(t, err)
	cc := f.(*wire.ConnectionCloseFrame)
	require.False(t, cc.IsApplicationError)
	require.Equal(t, "28:Error processing ALPS data: DATA frame forbidden", cc.ReasonPhrase)
	require.Equal(t, make([]byte, len(payload)-n-m), payload[n+m:], "then padding")
	// and a handshake the client takes is done as before
	v = dialVerified(t, func(ConnectionState) error { return nil }, "")
	require.NoError(t, v.err)
}

func TestAnApplicationCloseGoesInTheInitialAsAProfileSays(t *testing.T) {
	refuse := func(ConnectionState) error {
		return &ApplicationError{ErrorCode: 0x109, ErrorMessage: "207:Received SETTINGS_H3_DATAGRAM with invalid value 2"}
	}
	initialClose := func(v verified) *wire.ConnectionCloseFrame {
		hdr, _, _, err := wire.ParsePacket(v.sent[0])
		require.NoError(t, err)
		_, payload := openClientInitial(t, hdr.DestConnectionID, v.sent[len(v.sent)-1])
		parser := wire.NewFrameParser(false, false, false)
		// read as a 1-RTT packet's: quic-go's parser refuses an application
		// close in an Initial, as the server here does
		ft, n, err := parser.ParseType(payload, protocol.Encryption1RTT)
		require.NoError(t, err)
		f, _, err := parser.ParseLessCommonFrame(ft, payload[n:], protocol.Version1)
		require.NoError(t, err)
		return f.(*wire.ConnectionCloseFrame)
	}
	// as quiche sends it: the application's, in the Initial too, which the
	// server refuses as a frame not allowed there
	v := dialVerified(t, refuse, "application")
	var ae *ApplicationError
	require.ErrorAs(t, v.err, &ae)
	var te *TransportError
	require.ErrorAs(t, v.serverErr, &te)
	require.Equal(t, FrameEncodingError, te.ErrorCode)
	cc := initialClose(v)
	require.True(t, cc.IsApplicationError)
	require.EqualValues(t, 0x109, cc.ErrorCode)
	require.Equal(t, "207:Received SETTINGS_H3_DATAGRAM with invalid value 2", cc.ReasonPhrase)
	// as RFC 9000 says (section 10.2.3), and quic-go: APPLICATION_ERROR, no reason
	for _, early := range []string{"transport", ""} {
		v = dialVerified(t, refuse, early)
		cc = initialClose(v)
		require.False(t, cc.IsApplicationError, early)
		require.EqualValues(t, 0xc, cc.ErrorCode, early)
		require.Empty(t, cc.ReasonPhrase, early)
		// the server reads the Initial's first, and goes no further
		var te *TransportError
		require.True(t, errors.As(v.serverErr, &te), "%s: %v", early, v.serverErr)
		require.Equal(t, ApplicationErrorErrorCode, te.ErrorCode, early)
		require.True(t, te.Remote, early)
	}
}

func TestAHandshakeAbandonedSaysNothingToItsServer(t *testing.T) {
	v := dialVerified(t, func(ConnectionState) error { return ErrHandshakeAbandoned }, "")
	require.ErrorIs(t, v.err, ErrHandshakeAbandoned)
	var idle *IdleTimeoutError
	require.True(t, errors.As(v.serverErr, &idle), "the server waited its idle timeout out: %v", v.serverErr)
	// nothing went after the first flight: no close, no Finished
	hdr, _, _, err := wire.ParsePacket(v.sent[0])
	require.NoError(t, err)
	for _, d := range v.sent {
		require.Equal(t, []string{"Initial"}, coalesced(t, d))
		_, payload := openClientInitial(t, hdr.DestConnectionID, d)
		parser := wire.NewFrameParser(false, false, false)
		ft, _, err := parser.ParseType(payload, protocol.EncryptionInitial)
		require.NoError(t, err)
		require.NotEqual(t, wire.FrameTypeConnectionClose, ft)
	}
}
