package quic

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"

	"github.com/igor-lemon/quic-go-utls/internal/testdata"
	"github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	"github.com/stretchr/testify/require"
)

// A client's packets after its handshake, as its profile says. Chrome 155's
// (quiche at its DEPS revision, measured on ../net-fp-server's bench/h3): no
// ECN mark, no path MTU probe, the server's first connection ID kept until
// the server retires it; and what Config.InitialData writes goes in the
// datagram that carries the client's Finished.

// heardPackets is a server's qlog trace that keeps every packet it gets.
type heardPackets struct {
	mu      sync.Mutex
	packets []qlog.PacketReceived
}

func (h *heardPackets) AddProducer() qlogwriter.Recorder { return h }
func (h *heardPackets) SupportsSchemas(string) bool      { return true }
func (h *heardPackets) Close() error                     { return nil }

func (h *heardPackets) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.PacketReceived); ok {
		h.mu.Lock()
		h.packets = append(h.packets, p)
		h.mu.Unlock()
	}
}

func (h *heardPackets) heard() []qlog.PacketReceived {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]qlog.PacketReceived(nil), h.packets...)
}

// afterHandshake is what a loopback server heard of a client wearing pol,
// whose InitialData, when there is one, is asked on the connection, from its
// dial to hold after the handshake.
func afterHandshake(t *testing.T, pol behavior.Policy, initialData func(*Conn), hold time.Duration) []qlog.PacketReceived {
	t.Helper()
	require.NoError(t, pol.Validate())
	heard := &heardPackets{}
	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"h3"}
	ln, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{
		Tracer: func(context.Context, bool, ConnectionID) qlogwriter.Trace { return heard },
	})
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		<-conn.Context().Done()
	}()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &Transport{Conn: udp}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, ln.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		&Config{Behavior: pol, InitialPacketSize: 1250, InitialData: initialData})
	require.NoError(t, err)
	time.Sleep(hold)
	require.NoError(t, conn.CloseWithError(0, ""))
	return heard.heard()
}

// afterPolicy is quic-go's ways with set laid over them.
func afterPolicy(set map[string]string) behavior.Policy {
	p := behavior.Legacy()
	for k, v := range set {
		p[k] = json.RawMessage(v)
	}
	return p
}

// sawFrame is whether one of the packets carries a frame f says it is.
func sawFrame(packets []qlog.PacketReceived, f func(any) bool) bool {
	for _, p := range packets {
		for _, frame := range p.Frames {
			if f(frame.Frame) {
				return true
			}
		}
	}
	return false
}

func retire(f any) bool { _, ok := f.(*qlog.RetireConnectionIDFrame); return ok }

// largest is the length of the largest packet heard.
func largest(packets []qlog.PacketReceived) int {
	var n int
	for _, p := range packets {
		n = max(n, p.Raw.Length)
	}
	return n
}

// marked are the 1-RTT packets heard marked ECT(0).
func marked(packets []qlog.PacketReceived) int {
	var n int
	for _, p := range packets {
		if p.Header.PacketType == qlog.PacketType1RTT && p.ECN == qlog.ECT0 {
			n++
		}
	}
	return n
}

func TestAClientMarksProbesAndChangesItsConnectionIDAsItsProfileSays(t *testing.T) {
	// quic-go's: ECT(0) where the socket can, path MTU probes larger than the
	// first packets once the handshake is confirmed, and the server's
	// connection ID retired at once for its next
	legacy := afterHandshake(t, afterPolicy(nil), nil, 300*time.Millisecond)
	require.True(t, sawFrame(legacy, retire), "quic-go's retires the server's first connection ID")
	require.Greater(t, largest(legacy), 1250, "quic-go's probes the path MTU")
	ecn := marked(legacy) > 0
	if !ecn {
		t.Log("this host's sockets mark no ECN: the marks are not compared")
	}
	// Chrome's: none of it
	chrome := afterHandshake(t, afterPolicy(map[string]string{"quic.ecn": `"none"`, "quic.mtu_probes": `"none"`,
		"quic.connection_id_change": `"when-retired"`}), nil, 300*time.Millisecond)
	require.NotEmpty(t, chrome)
	require.False(t, sawFrame(chrome, retire), "the server's first connection ID kept")
	require.LessOrEqual(t, largest(chrome), 1250, "no path MTU probe")
	require.Zero(t, marked(chrome), "no ECN mark")
	// each choice alone: the others as quic-go's
	for _, tc := range []struct {
		key, value          string
		retires, probes, ec bool
	}{
		{"quic.ecn", `"none"`, true, true, false},
		{"quic.mtu_probes", `"none"`, true, false, ecn},
		{"quic.connection_id_change", `"when-retired"`, false, true, ecn},
		{"quic.ecn", `"ect0"`, true, true, ecn},
		{"quic.mtu_probes", `"search"`, true, true, ecn},
		{"quic.connection_id_change", `"after-handshake"`, true, true, ecn},
	} {
		got := afterHandshake(t, afterPolicy(map[string]string{tc.key: tc.value}), nil, 300*time.Millisecond)
		require.Equal(t, tc.retires, sawFrame(got, retire), "%s %s: a RETIRE_CONNECTION_ID", tc.key, tc.value)
		require.Equal(t, tc.probes, largest(got) > 1250, "%s %s: a path MTU probe", tc.key, tc.value)
		require.Equal(t, tc.ec, marked(got) > 0, "%s %s: ECN marks", tc.key, tc.value)
	}
}

func TestWhatInitialDataWritesGoesWithTheFinished(t *testing.T) {
	var asked int
	var streamID StreamID
	got := afterHandshake(t, afterPolicy(nil), func(c *Conn) {
		asked++
		select {
		case <-c.HandshakeComplete():
			t.Error("asked after the connection said its handshake was done")
		default:
		}
		str, err := c.OpenUniStream()
		require.NoError(t, err, "the server's stream limits are in")
		streamID = str.StreamID()
		_, err = str.Write([]byte("control"))
		require.NoError(t, err)
	}, 50*time.Millisecond)
	require.Equal(t, 1, asked)
	// the datagram whose Handshake packet carries the Finished carries a 1-RTT
	// packet with what was written, from its first byte
	finished := map[qlog.DatagramID]bool{}
	for _, p := range got {
		if p.Header.PacketType != qlog.PacketTypeHandshake {
			continue
		}
		for _, f := range p.Frames {
			if _, ok := f.Frame.(*qlog.CryptoFrame); ok {
				finished[p.DatagramID] = true
			}
		}
	}
	require.NotEmpty(t, finished)
	var with bool
	for _, p := range got {
		for _, f := range p.Frames {
			if s, ok := f.Frame.(*qlog.StreamFrame); ok && s.StreamID == streamID && s.Offset == 0 {
				with = with || p.Header.PacketType == qlog.PacketType1RTT && finished[p.DatagramID]
			}
		}
	}
	require.True(t, with, "the stream's data in the Finished's datagram")
}
