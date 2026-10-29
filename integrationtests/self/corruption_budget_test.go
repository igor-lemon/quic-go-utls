package self_test

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	quicproxy "github.com/igor-lemon/quic-go-utls/integrationtests/tools/proxy"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/stretchr/testify/require"
)

// Five corrupt Initials consume the original flight and two two-probe PTOs.
// A correct handshake can therefore need the next exponentially backed-off PTO.
func TestMITCorruptionHandshakeBudget(t *testing.T) {
	server, client := getTransportsForMITMTest(t)
	var count atomic.Int32
	callback := func(dir quicproxy.Direction, _, _ net.Addr, b []byte) bool {
		if dir != quicproxy.DirectionOutgoing || !wire.IsLongHeaderPacket(b[0]) {
			return false
		}
		hdr, packet, _, err := wire.ParsePacket(b)
		if err != nil || hdr.Type != protocol.PacketTypeInitial || count.Load() >= 5 {
			return false
		}
		count.Add(1)
		packet[len(packet)-1] ^= 1
		_, err = server.WriteTo(b, client.Conn.LocalAddr())
		if err != nil {
			t.Errorf("corrupt packet write: %v", err)
		}
		return true
	}
	t.Cleanup(func() { t.Logf("corrupted Initials: %d", count.Load()) })
	runMITMTest(t, server, client, scaleDuration(5*time.Millisecond), callback, scaleDuration(2*protocol.DefaultHandshakeIdleTimeout))
	require.EqualValues(t, 5, count.Load())
}
