package quic

import (
	"encoding/binary"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestInitialCryptoStreamECHWithoutSNI(t *testing.T) {
	skipIfDisableScramblingEnvSet(t)
	hello := append([]byte(nil), getClientHello(t, "")...)
	p := 4 + 2 + 32
	p += 1 + int(hello[p])
	p += 2 + int(binary.BigEndian.Uint16(hello[p:]))
	p += 1 + int(hello[p])
	n := binary.BigEndian.Uint16(hello[p:])
	hello = append(hello, 0xfe, 0x0d, 0, 1, 0)
	binary.BigEndian.PutUint16(hello[p:], n+5)
	size := len(hello) - 4
	hello[1] = byte(size >> 16)
	hello[2] = byte(size >> 8)
	hello[3] = byte(size)
	sni, _, ech, err := findSNIAndECH(hello)
	require.NoError(t, err)
	require.Equal(t, -1, sni)
	require.Positive(t, ech)
	stream := newInitialCryptoStream(true)
	_, err = stream.Write(hello)
	require.NoError(t, err)
	require.True(t, stream.HasData(), "ECH-only hello must not remain behind an unused SNI cut")
	segments := map[protocol.ByteCount][]byte{}
	for i := 0; stream.HasData(); i++ {
		require.Less(t, i, 10)
		frame := stream.PopCryptoFrame(protocol.MaxByteCount)
		require.NotNil(t, frame)
		require.NotEmpty(t, frame.Data)
		segments[frame.Offset] = frame.Data
	}
	require.Equal(t, hello, reassembleCryptoData(t, segments))
}
