package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/handshake"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
)

// silentServer reads every datagram sent to it and answers none, but for
// what answer says to the first.
type silentServer struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  [][]byte
}

func newSilentServer(t *testing.T, answer func(first []byte) []byte) *silentServer {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	s := &silentServer{conn: c}
	t.Cleanup(func() { c.Close() })
	go func() {
		for {
			b := make([]byte, 2000)
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.got = append(s.got, b[:n])
			first := len(s.got) == 1
			s.mu.Unlock()
			if first && answer != nil {
				c.WriteToUDP(answer(b[:n]), from)
			}
		}
	}()
	return s
}

func (s *silentServer) datagrams() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte{}, s.got...)
}

// openClientInitial is the number and payload of the client's Initial at the
// start of a datagram, opened with the Initial keys of odcid.
func openClientInitial(t *testing.T, odcid protocol.ConnectionID, data []byte) (protocol.PacketNumber, []byte) {
	t.Helper()
	data = append([]byte{}, data...)
	hdr, _, _, err := wire.ParsePacket(data)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketTypeInitial, hdr.Type)
	_, opener := handshake.NewInitialAEAD(odcid, protocol.PerspectiveServer, protocol.Version1)
	pnOffset := int(hdr.ParsedLen())
	// as the unpacker does: four bytes unmasked, those past the number put back
	saved := append([]byte{}, data[pnOffset:pnOffset+4]...)
	opener.DecryptHeader(data[pnOffset+4:pnOffset+20], &data[0], data[pnOffset:pnOffset+4])
	ext, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	start := int(ext.ParsedLen())
	copy(data[start:pnOffset+4], saved[ext.PacketNumberLen:])
	payload, err := opener.Open(nil, data[start:pnOffset+int(hdr.Length)], ext.PacketNumber, data[:start])
	require.NoError(t, err)
	return ext.PacketNumber, payload
}

func idlePolicy(t *testing.T, close bool) *Config {
	p := chromeHandshakePolicy(t)
	set := map[string]string{"quic.pto_initial_rtt_ms": "20", "quic.pto_no_sample_multiplier": "3", "quic.pto_no_sample_min_ms": "10",
		"quic.pto_rttvar_multiplier": "2", "quic.handshake_idle_timeout_ms": "400", "quic.handshake_timeout_ms": "10000",
		"quic.alarm_slack_ms": "50"}
	if close {
		set["quic.idle_close"] = `"after-pto"`
		set["quic.idle_close_code"] = "0"
		set["quic.idle_close_reason"] = `"25:No recent network activity after {elapsed}. Timeout:{timeout}"`
		set["quic.handshake_idle_close_reason"] = `"25:No recent network activity after {elapsed}. Timeout:{timeout} num_undecryptable_packets: {undecryptable_count} {{{undecryptable}}}"`
		set["quic.undecryptable_level_names"] = `["ENCRYPTION_INITIAL","ENCRYPTION_HANDSHAKE","ENCRYPTION_ZERO_RTT","ENCRYPTION_FORWARD_SECURE"]`
	}
	for k, v := range set {
		p[k] = []byte(v)
	}
	require.NoError(t, p.Validate())
	return &Config{Behavior: p, InitialPacketSize: 1250}
}

func dialSilent(t *testing.T, s *silentServer, conf *Config) error {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &Transport{Conn: c}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = tr.Dial(ctx, s.conn.LocalAddr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, conf)
	return err
}

// lastFrames are the frames of the last datagram's Initial and the Initial
// keys' DCID.
func closeOf(t *testing.T, got [][]byte) (protocol.PacketNumber, *wire.ConnectionCloseFrame, []byte) {
	t.Helper()
	hdr, _, _, err := wire.ParsePacket(got[0])
	require.NoError(t, err)
	pn, payload := openClientInitial(t, hdr.DestConnectionID, got[len(got)-1])
	parser := wire.NewFrameParser(false, false, false)
	ft, n, err := parser.ParseType(payload, protocol.EncryptionInitial)
	require.NoError(t, err)
	if ft != wire.FrameTypeConnectionClose {
		return pn, nil, payload
	}
	f, m, err := parser.ParseLessCommonFrame(ft, payload[n:], protocol.Version1)
	require.NoError(t, err)
	return pn, f.(*wire.ConnectionCloseFrame), payload[n+m:]
}

func TestASilentServerIsToldTheIdleTimeoutAsChromeTellsIt(t *testing.T) {
	s := newSilentServer(t, nil)
	start := time.Now()
	err := dialSilent(t, s, idlePolicy(t, true))
	require.ErrorIs(t, err, qerr.ErrIdleTimeout)
	var idle *idleClose
	require.ErrorAs(t, err, &idle)
	require.True(t, idle.Timeout())
	require.False(t, idle.Temporary())
	require.Equal(t, qerr.ErrIdleTimeout.Error(), idle.Error())
	// the idle time and the alarm's slack after it
	require.GreaterOrEqual(t, time.Since(start), 450*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	got := s.datagrams()
	pn, ccf, rest := closeOf(t, got)
	require.NotNil(t, ccf, "the last datagram closes the connection")
	require.False(t, ccf.IsApplicationError)
	require.Zero(t, ccf.ErrorCode)
	require.Zero(t, ccf.FrameType)
	require.Regexp(t, regexp.MustCompile(`^25:No recent network activity after \d+us\. Timeout:400ms num_undecryptable_packets: 0 \{\}$`), ccf.ReasonPhrase)
	require.Equal(t, make([]byte, len(rest)), rest, "then padding")
	require.Equal(t, 1250, len(got[len(got)-1]))
	// the first flight from 1, probes after a number skipped each, the close
	// at the next number
	hdr, _, _, err := wire.ParsePacket(got[0])
	require.NoError(t, err)
	var pns []protocol.PacketNumber
	for _, d := range got {
		n, _ := openClientInitial(t, hdr.DestConnectionID, d)
		pns = append(pns, n)
	}
	require.Equal(t, protocol.PacketNumber(1), pns[0])
	probes := 0
	for i := 1; i < len(pns)-1; i++ {
		switch pns[i] - pns[i-1] {
		case 1:
			require.Zero(t, probes, "the first flight's packets come first: %v", pns)
		case 2:
			probes++
		default:
			t.Fatalf("numbers %v", pns)
		}
	}
	require.GreaterOrEqual(t, probes, 1)
	require.Equal(t, pns[len(pns)-2]+1, pn)
}

func TestTheReasonListsThePacketsKeptUndecrypted(t *testing.T) {
	// a Handshake packet before the server's Initial: kept until there are
	// keys to read it
	var sent int
	s := newSilentServer(t, func(first []byte) []byte {
		hdr, _, _, err := wire.ParsePacket(first)
		require.NoError(t, err)
		b := []byte{0xe0, 0, 0, 0, 1, byte(hdr.SrcConnectionID.Len())}
		b = append(b, hdr.SrcConnectionID.Bytes()...)
		b = append(b, 0) // no source ID
		b = quicvarint.Append(b, 40)
		b = append(b, make([]byte, 40)...)
		sent = len(b)
		return b
	})
	err := dialSilent(t, s, idlePolicy(t, true))
	require.ErrorIs(t, err, qerr.ErrIdleTimeout)
	time.Sleep(50 * time.Millisecond)
	_, ccf, _ := closeOf(t, s.datagrams())
	require.NotNil(t, ccf)
	require.Contains(t, ccf.ReasonPhrase, fmt.Sprintf("num_undecryptable_packets: 1 {[ENCRYPTION_HANDSHAKE, %d]}", sent))
}

func TestQuicGoEndsAnIdleHandshakeSilently(t *testing.T) {
	s := newSilentServer(t, nil)
	err := dialSilent(t, s, idlePolicy(t, false))
	require.ErrorIs(t, err, qerr.ErrIdleTimeout)
	var idle *idleClose
	require.False(t, errors.As(err, &idle))
	time.Sleep(50 * time.Millisecond)
	_, ccf, _ := closeOf(t, s.datagrams())
	require.Nil(t, ccf, "the last datagram is a probe")
}

func TestTheLevelOfAKeptPacket(t *testing.T) {
	require.Equal(t, 0, levelIndex(qlog.PacketTypeInitial))
	require.Equal(t, 1, levelIndex(qlog.PacketTypeHandshake))
	require.Equal(t, 2, levelIndex(qlog.PacketType0RTT))
	require.Equal(t, 3, levelIndex(qlog.PacketType1RTT))
}

func TestAnIdleHandshakeEndsOnlyOnceItsSlackHasPassed(t *testing.T) {
	// a probe at 325 ms, between the idle time (300 ms) and its slack's end
	// (350 ms): it wakes the connection, which goes on until the slack ends
	s := newSilentServer(t, nil)
	conf := idlePolicy(t, true)
	for k, v := range map[string]string{"quic.pto_initial_rtt_ms": "25", "quic.handshake_idle_timeout_ms": "300",
		"quic.handshake_idle_close_reason": `"{elapsed}"`, "quic.undecryptable_level_names": ""} {
		if v == "" {
			delete(conf.Behavior, k)
		} else {
			conf.Behavior[k] = []byte(v)
		}
	}
	require.NoError(t, conf.Behavior.Validate())
	require.ErrorIs(t, dialSilent(t, s, conf), qerr.ErrIdleTimeout)
	time.Sleep(50 * time.Millisecond)
	_, ccf, _ := closeOf(t, s.datagrams())
	require.NotNil(t, ccf)
	elapsed, err := time.ParseDuration(ccf.ReasonPhrase)
	require.NoError(t, err)
	require.GreaterOrEqual(t, elapsed, 350*time.Millisecond, "closed %s after the last packet", elapsed)
}
