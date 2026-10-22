package wire

import (
	"encoding/binary"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/stretchr/testify/require"
	"testing"
)

func infoParameter(values ...uint32) []byte {
	b := []byte{17}
	b = quicvarint.Append(b, uint64(4*len(values)))
	for _, v := range values {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}
func TestVersionInformationParsing(t *testing.T) {
	base := (&TransportParameters{ActiveConnectionIDLimit: 2}).Marshal(protocol.PerspectiveClient)
	for _, test := range []struct {
		name           string
		raw            []byte
		client, server bool
	}{
		{"empty", []byte{17, 0}, false, false}, {"short", []byte{17, 3, 1, 2, 3}, false, false}, {"odd", []byte{17, 5, 0, 0, 0, 1, 1}, false, false},
		{"zeroChosen", infoParameter(0, 1), false, false}, {"zeroAvailable", infoParameter(1, 0), false, false},
		{"chosenOnly", infoParameter(1), false, true}, {"chosenNotAvailable", infoParameter(1, 2), false, true},
		{"valid", infoParameter(1, 1), true, true}, {"reserved", infoParameter(1, 0x9acada7a, 1), true, true},
		{"duplicateParameter", append(infoParameter(1, 1), infoParameter(1, 1)...), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, actor := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
				payload := append([]byte{}, base...)
				if actor == protocol.PerspectiveServer {
					payload = append(payload, 0, 0)
				} // original destination CID
				payload = append(payload, test.raw...)
				var p TransportParameters
				err := p.Unmarshal(payload, actor)
				valid := test.client
				if actor == protocol.PerspectiveServer {
					valid = test.server
				}
				if valid {
					require.NoError(t, err)
					require.NotNil(t, p.VersionInformation)
				} else {
					var e *qerr.TransportError
					require.ErrorAs(t, err, &e)
					require.Equal(t, qerr.TransportParameterError, e.ErrorCode)
				}
			}
		})
	}
}
func TestVersionInformationRoundTripAndOmission(t *testing.T) {
	var p TransportParameters
	require.NoError(t, p.Unmarshal((&TransportParameters{ActiveConnectionIDLimit: 2}).Marshal(protocol.PerspectiveClient), protocol.PerspectiveClient))
	require.Nil(t, p.VersionInformation)
	for range 16 {
		info := &VersionInformation{ChosenVersion: 1, AvailableVersions: protocol.GetGreasedVersions([]protocol.Version{1})}
		b := (&TransportParameters{ActiveConnectionIDLimit: 2, VersionInformation: info}).Marshal(protocol.PerspectiveClient)
		require.NoError(t, p.Unmarshal(b, protocol.PerspectiveClient))
		require.Equal(t, info, p.VersionInformation)
	}
	require.NoError(t, p.Unmarshal((&TransportParameters{ActiveConnectionIDLimit: 2}).Marshal(protocol.PerspectiveClient), protocol.PerspectiveClient))
	require.Nil(t, p.VersionInformation)
}

func TestChromeServerVersionInformationZeroAvailable(t *testing.T) {
	base := (&TransportParameters{ActiveConnectionIDLimit: 2}).Marshal(protocol.PerspectiveClient)
	base = append(base, 0, 0) // server original destination CID
	var p TransportParameters
	p.ChromeBehavior = true
	require.NoError(t, p.Unmarshal(append(append([]byte{}, base...), infoParameter(1, 0)...), protocol.PerspectiveServer))
	require.Equal(t, []protocol.Version{0}, p.VersionInformation.AvailableVersions)
	// The profile does not accept a zero Chosen Version.
	require.Error(t, p.Unmarshal(append(append([]byte{}, base...), infoParameter(0, 1)...), protocol.PerspectiveServer))
}
