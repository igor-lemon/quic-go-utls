package wire

import (
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func parameterIDs(t *testing.T, b []byte) []uint64 {
	t.Helper()
	var ids []uint64
	for len(b) > 0 {
		id, n, e := quicvarint.Parse(b)
		require.NoError(t, e)
		b = b[n:]
		l, n, e := quicvarint.Parse(b)
		require.NoError(t, e)
		b = b[n:]
		require.GreaterOrEqual(t, len(b), int(l))
		b = b[l:]
		ids = append(ids, id)
	}
	return ids
}
func TestChromeParametersPreserveValuesAndFreshOrder(t *testing.T) {
	p := TransportParameters{ChromeBehavior: true, MaxAckDelay: 25 * time.Millisecond, ActiveConnectionIDLimit: 2, MaxUDPPayloadSize: 1472, MaxDatagramFrameSize: 65536, AckDelayExponent: 3}
	orders := map[string]bool{}
	grease := map[uint64]bool{}
	for range 16 {
		b := p.Marshal(protocol.PerspectiveClient)
		var parsed TransportParameters
		require.NoError(t, parsed.Unmarshal(b, protocol.PerspectiveClient))
		require.EqualValues(t, 1472, parsed.MaxUDPPayloadSize)
		require.EqualValues(t, 65536, parsed.MaxDatagramFrameSize)
		require.Equal(t, 25*time.Millisecond, parsed.MaxAckDelay)
		require.EqualValues(t, 2, parsed.ActiveConnectionIDLimit)
		require.Zero(t, parsed.InitialSourceConnectionID.Len())
		ids := parameterIDs(t, b)
		require.NotContains(t, ids, uint64(11))
		require.NotContains(t, ids, uint64(14))
		require.Contains(t, ids, uint64(15))
		n := 0
		for _, id := range ids {
			if id%31 == 27 {
				n++
				grease[id] = true
				require.Less(t, id, uint64(1)<<62)
			}
		}
		require.Equal(t, 1, n)
		orders[string(b)] = true
	}
	require.Greater(t, len(grease), 1) // rejects a captured/fixed GREASE ID
	// Compare actual identifier permutations rather than randomized values.
	distinct := map[string]bool{}
	for range 16 {
		ids := parameterIDs(t, p.Marshal(protocol.PerspectiveClient))
		normalized := []byte{}
		for _, id := range ids {
			if id%31 != 27 {
				normalized = append(normalized, byte(id))
			}
		}
		distinct[string(normalized)] = true
	}
	require.Greater(t, len(distinct), 1)
}
func TestShufflePreservesUnknownEncodedTLVs(t *testing.T) {
	b := []byte{0x40, 0x31, 0x03, 0xaa, 0xbb, 0xcc, 0x02, 0x00}
	// Includes a deliberately nonminimal type encoding and unknown contents.
	for range 8 {
		out := shuffleTransportParameters(b)
		require.Contains(t, [][]byte{b, append(append([]byte{}, b[6:]...), b[:6]...)}, out)
	}
}
