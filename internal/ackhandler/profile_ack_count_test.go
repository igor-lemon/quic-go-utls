package ackhandler

import (
	"github.com/igor-lemon/quic-go-utls/internal/monotime"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"reflect"
	"testing"
	"time"
)

func TestProfileInitialACKPacketCountChangesEmission(t *testing.T) {
	for _, limit := range []int{1, 3} {
		h := NewReceivedPacketHandler(utils.DefaultLogger)
		setter := reflect.ValueOf(h).MethodByName("SetInitialACKPolicy")
		if setter.IsValid() {
			setter.Call([]reflect.Value{reflect.ValueOf(limit), reflect.ValueOf(protocol.PacketNumber(1))})
		}
		now := monotime.Now()
		for i := 0; i < limit; i++ {
			if err := h.ReceivedPacket(protocol.PacketNumber(i), protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
				t.Fatal(err)
			}
			ack := h.GetAckFrame(protocol.Encryption1RTT, now.Add(time.Microsecond), true)
			if (ack != nil) != (i == limit-1) {
				t.Errorf("limit%d packet%d ACK=%v", limit, i, ack != nil)
			}
		}
	}
}

func TestProfileReorderingThresholdChangesGapACK(t *testing.T) {
	for _, limit := range []protocol.PacketNumber{1, 2} {
		h := NewReceivedPacketHandler(utils.DefaultLogger)
		h.SetInitialACKPolicy(100, limit)
		now := monotime.Now()
		if err := h.ReceivedPacket(10, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
			t.Fatal(err)
		}
		if h.GetAckFrame(protocol.Encryption1RTT, now, false) == nil {
			t.Fatal("baseline ACK absent")
		}
		if err := h.ReceivedPacket(12, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
			t.Fatal(err)
		}
		if got := h.GetAckFrame(protocol.Encryption1RTT, now, true) != nil; got != (limit == 1) {
			t.Fatalf("reordering%d queued=%v", limit, got)
		}
	}
}
