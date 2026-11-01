package http3

import (
	"bytes"
	"context"
	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/quic-go/qpack"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTP3ResponseObservationTracksBodyOwnership(t *testing.T) {
	for _, api := range []string{"roundtrip", "stream"} {
		for _, ending := range []string{"eof", "close", "drain", "empty"} {
			t.Run(api+"-"+ending, func(t *testing.T) {
				client, server := newConnPairWithNetworkObserver(t, nil, nil, nil)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var starts, headers, done, body atomic.Int64
				trace := &httptrace.ClientTrace{WriteHeadersStart: func(string) { starts.Add(1) }, GotResponseHeaders: func(string, int) { headers.Add(1) }, GotResponseBodyBytes: func(_ string, n int) { body.Add(int64(n)) }, GotResponseBodyDone: func(m string) {
					if m != "GET" {
						t.Error(m)
					}
					done.Add(1)
				}}
				req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", "https://quic-go.net/", nil)
				tr := (&Transport{}).NewClientConn(client)
				result := make(chan *http.Response, 1)
				errors := make(chan error, 1)
				go func() {
					var res *http.Response
					var err error
					if api == "roundtrip" {
						res, err = tr.RoundTrip(req)
					} else {
						var s *RequestStream
						s, err = tr.OpenRequestStream(req.Context())
						if err == nil {
							err = s.SendRequestHeader(req)
							if err == nil {
								s.Close()
								res, err = s.ReadResponse()
							}
						}
					}
					if err != nil {
						errors <- err
					} else {
						result <- res
					}
				}()
				str, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				decodeHeader(t, str)
				var b bytes.Buffer
				enc := qpack.NewEncoder(&b)
				status := "200"
				if ending == "empty" {
					status = "204"
				}
				if err := enc.WriteField(qpack.HeaderField{Name: ":status", Value: status}); err != nil {
					t.Fatal(err)
				}
				if ending != "empty" {
					if err := enc.WriteField(qpack.HeaderField{Name: "content-length", Value: "4"}); err != nil {
						t.Fatal(err)
					}
				}
				wire := quicvarint.Append(nil, 1)
				wire = quicvarint.Append(wire, uint64(b.Len()))
				wire = append(wire, b.Bytes()...)
				if ending != "empty" {
					wire = append(wire, 0, 2, 'o', 'k')
				}
				if _, err := str.Write(wire); err != nil {
					t.Fatal(err)
				}
				var res *http.Response
				select {
				case res = <-result:
				case err := <-errors:
					t.Fatal(err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if starts.Load() != 1 || headers.Load() != 1 {
					t.Fatal("timings", starts.Load(), headers.Load())
				}
				if ending == "empty" {
					if done.Load() != 1 {
						t.Fatal("empty not complete")
					}
					str.Close()
					res.Body.Close()
					return
				}
				if done.Load() != 0 {
					t.Fatal("unread body completed at headers")
				}
				prefix := make([]byte, 2)
				if _, err := io.ReadFull(res.Body, prefix); err != nil || string(prefix) != "ok" {
					t.Fatal(prefix, err)
				}
				if done.Load() != 0 {
					t.Fatal("positive nonterminal read completed body")
				}
				switch ending {
				case "eof":
					if _, err := str.Write([]byte{0, 2, 'a', 'y'}); err != nil {
						t.Fatal(err)
					}
					str.Close()
					b, err := io.ReadAll(res.Body)
					if err != nil || string(b) != "ay" {
						t.Fatal(string(b), err)
					}
				case "close":
					res.Body.Close()
					str.CancelWrite(0)
				case "drain":
					drained := http.DrainBody(ctx, res, 16, time.Second, 0)
					if done.Load() != 1 {
						t.Fatal("detached ownership remained active")
					}
					select {
					case <-drained:
						t.Fatal("held body already drained")
					default:
					}
					if _, err := str.Write([]byte{0, 2, 'a', 'y'}); err != nil {
						t.Fatal(err)
					}
					str.Close()
					select {
					case <-drained:
					case <-ctx.Done():
						t.Fatal("drain timeout")
					}
				}
				if done.Load() != 1 {
					t.Fatal("completion count", done.Load())
				}
				res.Body.Close()
				if done.Load() != 1 {
					t.Fatal("duplicate completion")
				}
				if ending == "eof" && body.Load() != 4 {
					t.Fatal("encoded activity", body.Load())
				}
			})
		}
	}
}
