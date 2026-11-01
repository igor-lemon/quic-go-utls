package quic

import (
	"sync/atomic"
	"testing"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
)

func TestNetworkReceiveObservationCountsArrivalBeforeProcessing(t *testing.T) {
	var bytes atomic.Int64
	tc := newServerTestConnection(t, nil, &Config{NetworkObserver: func(e NetworkEvent) { bytes.Add(int64(e.ReceivedBytes)) }}, false)
	packet := getVersionNegotiationPacket(protocol.ParseConnectionID([]byte{1}), protocol.ParseConnectionID([]byte{2}), []protocol.Version{protocol.Version1})
	size := int64(packet.Size())
	tc.conn.handlePacket(packet)
	if bytes.Load() != size {
		t.Fatal("arrival was deferred until protocol processing", bytes.Load(), size)
	}
	tc.conn.receivedPacketMx.Lock()
	queued := tc.conn.receivedPackets.PopFront()
	tc.conn.receivedPacketMx.Unlock()
	if _, err := tc.conn.handleOnePacket(queued, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Load() != size {
		t.Fatal("processing counted arrival twice", bytes.Load(), size)
	}
	// Reprocessing a buffered packet is not another socket read. The server
	// ignores this VN packet, so no key material or peer behavior is mocked.
	replay := getVersionNegotiationPacket(protocol.ParseConnectionID([]byte{1}), protocol.ParseConnectionID([]byte{2}), []protocol.Version{protocol.Version1})
	if _, err := tc.conn.handleOnePacket(replay, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Load() != size {
		t.Fatal("buffer replay invented receive bytes", bytes.Load(), size)
	}
}
func TestNetworkReceiveObservationIncludesQueueDroppedDatagrams(t *testing.T) {
	var bytes atomic.Int64
	tc := newServerTestConnection(t, nil, &Config{NetworkObserver: func(e NetworkEvent) { bytes.Add(int64(e.ReceivedBytes)) }}, false)
	for i := 0; i < protocol.MaxConnUnprocessedPackets+1; i++ {
		tc.conn.handlePacket(receivedPacket{data: []byte{0x40}})
	}
	if bytes.Load() != int64(protocol.MaxConnUnprocessedPackets+1) {
		t.Fatal("queue drop lost actual receive bytes", bytes.Load())
	}
}
