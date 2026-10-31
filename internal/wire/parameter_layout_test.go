package wire

import (
	"encoding/json"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestParameterLayoutUsesProfileWithoutChangingEncodedValues(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, length := range []int{0, 16} {
			p := behavior.Generic()
			order := []string{"grease", "1", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "14", "15", "17", "32", "6745883625174385", "4278509083"}
			if reverse {
				slices.Reverse(order)
			}
			p["quic.parameter_order"], _ = json.Marshal(order)
			p["quic.grease_parameter_length_rule"] = json.RawMessage(`"byte-modulo"`)
			p["quic.grease_parameter_length_min"], _ = json.Marshal(length)
			p["quic.grease_parameter_length_max"], _ = json.Marshal(length)
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			params := TransportParameters{Behavior: p, InitialMaxData: 786432, InitialMaxStreamDataBidiLocal: 524288, InitialMaxStreamDataBidiRemote: 524288, InitialMaxStreamDataUni: 524288, MaxBidiStreamNum: 0, MaxUniStreamNum: 100, MaxIdleTimeout: 30 * time.Second, MaxUDPPayloadSize: 1452, MaxAckDelay: 26 * time.Millisecond, AckDelayExponent: 3, ActiveConnectionIDLimit: 4, InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}), MaxDatagramFrameSize: 16383}
			raw := params.Marshal(protocol.PerspectiveClient)
			var seen []string
			for rest := raw; len(rest) > 0; {
				id, n, err := quicvarint.Parse(rest)
				if err != nil {
					t.Fatal(err)
				}
				rest = rest[n:]
				size, n, err := quicvarint.Parse(rest)
				if err != nil || size > uint64(len(rest)-n) {
					t.Fatal("length", err)
				}
				rest = rest[n:]
				name := strconv.FormatUint(id, 10)
				if id >= 27 && (id-27)%31 == 0 {
					name = "grease"
					if int(size) != length {
						t.Errorf("GREASE length=%d want%d", size, length)
					}
				}
				seen = append(seen, name)
				rest = rest[size:]
			}
			want := []string{}
			for _, slot := range order {
				if slices.Contains(seen, slot) {
					want = append(want, slot)
				}
			}
			if !slices.Equal(seen, want) {
				t.Fatalf("parameter order=%v want%v", seen, want)
			}
			var peer TransportParameters
			if err := peer.Unmarshal(raw, protocol.PerspectiveClient); err != nil {
				t.Fatal(err)
			}
			if peer.InitialMaxData != 786432 || peer.InitialSourceConnectionID != params.InitialSourceConnectionID || peer.MaxDatagramFrameSize != 16383 {
				t.Fatal("values changed", peer)
			}
		}
	}
}
