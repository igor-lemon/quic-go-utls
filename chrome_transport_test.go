package quic

import (
	"bytes"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
	"time"
)

func TestChromeActiveCIDLimitIsEnforced(t *testing.T) {
	m := newConnIDManager(protocol.ParseConnectionID([]byte{9}), func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
	m.maxActiveConnectionIDs = 2
	f := &wire.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID([]byte{1})}
	require.NoError(t, m.Add(f))
	require.NoError(t, m.Add(f)) // retransmission is not another active ID
	require.ErrorIs(t, m.Add(&wire.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: protocol.ParseConnectionID([]byte{2})}), &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError})
}
func TestReceiveChromeSizedUDPOnBothSocketPaths(t *testing.T) {
	for _, basic := range []bool{true, false} {
		t.Run(map[bool]string{true: "basic", false: "OOB"}[basic], func(t *testing.T) {
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			defer udp.Close()
			require.NoError(t, udp.SetReadDeadline(time.Now().Add(time.Second)))
			sender, err := net.DialUDP("udp4", nil, udp.LocalAddr().(*net.UDPAddr))
			require.NoError(t, err)
			defer sender.Close()
			data := bytes.Repeat([]byte{0x42}, 1472)
			_, err = sender.Write(data)
			require.NoError(t, err)
			var conn rawConn
			if basic {
				conn = &basicConn{PacketConn: udp}
			} else {
				conn, err = wrapConn(udp)
				require.NoError(t, err)
			}
			p, err := conn.ReadPacket()
			require.NoError(t, err)
			defer p.buffer.Release()
			require.Equal(t, data, p.data) // exact tail must survive, not just first1452bytes
		})
	}
}
func TestChromeConfigSurvivesPopulation(t *testing.T) {
	c := populateConfig(&Config{ChromeBehavior: true})
	require.True(t, c.ChromeBehavior)
	require.True(t, c.Clone().ChromeBehavior)
	require.False(t, populateConfig(nil).ChromeBehavior)
	// Receive capacity must not raise the transmit initial-size ceiling.
	require.EqualValues(t, 1452, protocol.MaxPacketBufferSize)
}
