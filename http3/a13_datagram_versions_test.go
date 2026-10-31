package http3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
)

func TestA13DatagramVersionIntersectionAndErrorCodes(t *testing.T) {
	for _, local := range []uint8{0, datagramRFC, datagramDraft08, datagramRFC | datagramDraft08} {
		for _, peer := range []uint8{0, datagramRFC, datagramDraft08, datagramRFC | datagramDraft08} {
			t.Run(fmt.Sprintf("local%d-peer%d", local, peer), func(t *testing.T) {
				client, server := newConnPairWithDatagrams(t, nil, nil)
				settings := map[uint64]uint64{settingDatagram: 0, settingDatagramDraft08: 0}
				if local&datagramRFC != 0 {
					settings[settingDatagram] = 1
				}
				if local&datagramDraft08 != 0 {
					settings[settingDatagramDraft08] = 1
				}
				cc := newClientConn(client, true, settings, []uint64{settingDatagram, settingDatagramDraft08}, nil, false, 0, nil, nil, -1, true, nil, behavior.Generic())
				// Read exactly the actual local SETTINGS, then send the independent peer's.
				localStream, err := server.AcceptUniStream(context.Background())
				require.NoError(t, err)
				r := quicvarint.NewReader(localStream)
				typ, err := quicvarint.Read(r)
				require.NoError(t, err)
				require.Zero(t, typ)
				typ, err = quicvarint.Read(r)
				require.NoError(t, err)
				require.EqualValues(t, 4, typ)
				size, err := quicvarint.Read(r)
				require.NoError(t, err)
				raw := make([]byte, size)
				_, err = io.ReadFull(r, raw)
				require.NoError(t, err)
				parsed := map[uint64]uint64{}
				br := bytes.NewReader(raw)
				for br.Len() > 0 {
					id, err := quicvarint.Read(br)
					require.NoError(t, err)
					v, err := quicvarint.Read(br)
					require.NoError(t, err)
					parsed[id] = v
				}
				require.Equal(t, settings, parsed)
				var p []byte
				for _, item := range []struct {
					id   uint64
					flag uint8
				}{{settingDatagram, datagramRFC}, {settingDatagramDraft08, datagramDraft08}} {
					if peer&item.flag != 0 {
						p = quicvarint.Append(p, item.id)
						p = quicvarint.Append(p, 1)
					}
				}
				b := []byte{0, 4}
				b = quicvarint.Append(b, uint64(len(p)))
				b = append(b, p...)
				remote, err := server.OpenUniStream()
				require.NoError(t, err)
				_, err = remote.Write(b)
				require.NoError(t, err)
				select {
				case <-cc.conn.ReceivedSettings():
				case <-time.After(time.Second):
					t.Fatal("missing peer settings")
				}
				common := local & peer
				expected := uint32(0)
				if common&datagramRFC != 0 {
					expected = uint32(datagramRFC)
				} else if common&datagramDraft08 != 0 {
					expected = uint32(datagramDraft08)
				}
				require.Equal(t, expected, cc.conn.negotiatedDatagramMode.Load())
				if expected == 0 {
					require.ErrorContains(t, cc.conn.sendDatagram(0, []byte("forbidden")), "not negotiated")
					return
				}
				// A malformed QUIC DATAGRAM proves that the negotiated protocol's error
				// code is used on the authenticated wire, not just an accessor.
				require.NoError(t, server.SendDatagram(nil))
				select {
				case <-server.Context().Done():
				case <-time.After(time.Second):
					t.Fatal("malformed datagram not rejected")
				}
				code := uint64(0x33)
				if expected == uint32(datagramDraft08) {
					code = 0x4a1268
				}
				require.ErrorIs(t, context.Cause(server.Context()), &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(code)})
			})
		}
	}
}

func TestA13DraftDatagramValidationAndPendingNegotiation(t *testing.T) {
	client, _ := newConnPairWithDatagrams(t, nil, nil)
	c := newConnection(client.Context(), client, true, false, nil, 0)
	require.ErrorContains(t, c.sendDatagram(0, []byte("forbidden")), "incomplete")
	for _, asSaid := range []bool{false, true} {
		for _, entries := range [][][2]uint64{{{16765559, 2}}, {{16765559, 1}, {16765559, 1}}} {
			var body []byte
			for _, v := range entries {
				body = quicvarint.Append(body, v[0])
				body = quicvarint.Append(body, v[1])
			}
			wire := quicvarint.Append([]byte{4}, uint64(len(body)))
			wire = append(wire, body...)
			fp := frameParser{r: bytes.NewReader(wire), booleansAsSaid: asSaid, draftDatagrams: true}
			_, err := fp.ParseNext(nil)
			require.Error(t, err)
		}
	}
	require.Zero(t, localDatagramModes(false, map[uint64]uint64{51: 1, 16765559: 1}))
}

func TestA13UnselectedDraftSettingsRemainUnknown(t *testing.T) {
	payload := quicvarint.Append(nil, 16765559)
	payload = quicvarint.Append(payload, 2)
	wire := quicvarint.Append([]byte{4}, uint64(len(payload)))
	wire = append(wire, payload...)
	fp := frameParser{r: bytes.NewReader(wire)}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	sf := f.(*settingsFrame)
	require.False(t, sf.DatagramDraft08)
	require.EqualValues(t, 2, sf.Other[16765559])
}
