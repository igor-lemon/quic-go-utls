package http3

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
)

func controlPolicy(values map[string]any) behavior.Policy {
	p := behavior.Legacy()
	for k, v := range values {
		p[k], _ = json.Marshal(v)
	}
	return p
}

// Test the original encoded bytes and N/length relationship, including a JSON
// vector different from the measured browser's. A random byte itself need not
// be unique; freshness is tested over a large collection of nonempty payloads.
func TestGREASEPayloadUsesJSONVectorAndFreshBytes(t *testing.T) {
	for _, lengths := range [][]uint64{{0, 1, 2, 3}, {3, 5}, {0}} {
		p := controlPolicy(map[string]any{"h3.grease_payload_lengths": lengths})
		require.NoError(t, p.Validate())
		seen := map[string]bool{}
		for range 512 {
			r := bytes.NewReader(appendGreaseFramePolicy(nil, p))
			typ, err := quicvarint.Read(r)
			require.NoError(t, err)
			n := (typ - 33) / 31
			require.EqualValues(t, 2, typ%31)
			size, err := quicvarint.Read(r)
			require.NoError(t, err)
			require.Equal(t, lengths[n%uint64(len(lengths))], size)
			payload, err := io.ReadAll(r)
			require.NoError(t, err)
			require.Len(t, payload, int(size))
			if size > 0 {
				seen[string(payload)] = true
			}
		}
		if len(lengths) > 1 {
			require.Greater(t, len(seen), 16, "payload bytes became static")
		}
	}
}

// Both public paths must emit one update per actual request stream. The peer
// reads the real control stream; checking a helper's bytes is insufficient.
func TestH3ControlPolicyOnLiveRequests(t *testing.T) {
	for _, direct := range []bool{false, true} {
		for _, mode := range []string{"per-request", "initial", "disabled"} {
			name := mode + "/roundtrip"
			if direct {
				name = mode + "/direct"
			}
			t.Run(name, func(t *testing.T) {
				order := []string{"settings", "grease"}
				if mode == "initial" {
					order = []string{"settings", "priority", "grease"}
				}
				p := controlPolicy(map[string]any{"h3.control_order": order, "h3.priority_updates": mode, "h3.priority_source": "header", "h3.grease_payload_lengths": []uint64{0, 1, 2, 3}})
				require.NoError(t, p.Validate())
				raw, peer := newConnPair(t)
				tr := &Transport{Behavior: p, SendGreaseFrames: true, PriorityParam: 0xf0700}
				client := tr.NewClientConn(raw)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				serverControl, err := peer.OpenUniStreamSync(ctx)
				require.NoError(t, err)
				_, err = serverControl.Write([]byte{0, 4, 0})
				require.NoError(t, err)
				errs := make(chan error, 1)
				go func() {
					for range 3 {
						s, e := peer.AcceptStream(ctx)
						if e != nil {
							errs <- e
							return
						}
						r := quicvarint.NewReader(s)
						_, e = quicvarint.Read(r)
						if e != nil {
							errs <- e
							return
						}
						n, e := quicvarint.Read(r)
						if e == nil {
							_, e = io.CopyN(io.Discard, r, int64(n))
						}
						if e != nil {
							errs <- e
							return
						}
						_, e = s.Write([]byte{1, 3, 0, 0, 0xd9})
						if e == nil {
							e = s.Close()
						}
						if e != nil {
							errs <- e
							return
						}
					}
					errs <- nil
				}()
				values := []string{"u=0, i", "u=1, i", "u=4"}
				for i, value := range values {
					req, err := http.NewRequestWithContext(ctx, "GET", "https://localhost/path", nil)
					require.NoError(t, err)
					// Both canonical and preserved lowercase header maps occur in callers.
					if i == 1 {
						req.Header["priority"] = []string{value}
					} else {
						req.Header.Set("Priority", value)
					}
					if direct {
						s, e := client.OpenRequestStream(ctx)
						require.NoError(t, e)
						require.NoError(t, s.SendRequestHeader(req))
						require.NoError(t, s.Close())
						rsp, e := s.ReadResponse()
						require.NoError(t, e)
						require.NoError(t, rsp.Body.Close())
					} else {
						rsp, e := client.RoundTrip(req)
						require.NoError(t, e)
						require.NoError(t, rsp.Body.Close())
					}
				}
				require.NoError(t, <-errs)
				control, err := peer.AcceptUniStream(ctx)
				require.NoError(t, err)
				require.NoError(t, control.SetReadDeadline(time.Now().Add(3*time.Second)))
				r := quicvarint.NewReader(control)
				kind, err := quicvarint.Read(r)
				require.NoError(t, err)
				require.EqualValues(t, 0, kind)
				read := func() (uint64, []byte) {
					typ, e := quicvarint.Read(r)
					require.NoError(t, e)
					n, e := quicvarint.Read(r)
					require.NoError(t, e)
					b := make([]byte, n)
					_, e = io.ReadFull(r, b)
					require.NoError(t, e)
					return typ, b
				}
				typ, _ := read()
				require.EqualValues(t, 4, typ)
				if mode == "initial" {
					typ, b := read()
					require.EqualValues(t, 0xf0700, typ)
					require.Equal(t, append([]byte{0}, []byte(p.Text("h3.priority_value"))...), b)
				}
				typ, b := read()
				require.EqualValues(t, 2, typ%31)
				require.Len(t, b, int(((typ-33)/31)%4))
				if mode == "per-request" {
					for i, value := range values {
						typ, b := read()
						require.EqualValues(t, 0xf0700, typ)
						rr := bytes.NewReader(b)
						id, e := quicvarint.Read(rr)
						require.NoError(t, e)
						require.EqualValues(t, 4*i, id)
						v, e := io.ReadAll(rr)
						require.NoError(t, e)
						require.Equal(t, value, string(v))
					}
				}
				// At connection end no hidden initial stream-zero update may remain.
				require.NoError(t, raw.CloseWithError(quic.ApplicationErrorCode(0), ""))
				_, err = quicvarint.Read(r)
				require.Error(t, err)
			})
		}
	}
}
