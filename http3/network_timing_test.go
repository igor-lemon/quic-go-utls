package http3

import (
	"bytes"
	"context"
	"fmt"
	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/quic-go/qpack"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestHeaderTimingWaitsForCompleteFinalHTTP3Headers(t *testing.T) {
	var received, samples atomic.Int64
	client, server := newConnPairWithNetworkObserver(t, nil, nil, func(e quic.NetworkEvent) {
		if e.RemoteAddr == nil {
			t.Error("missing actual peer")
		}
		if e.ReceivedBytes > 0 {
			received.Add(int64(e.ReceivedBytes))
		}
		if e.RTT > 0 {
			samples.Add(1)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var starts, ends, bodyBytes atomic.Int64
	first := make(chan struct{}, 1)
	tr := (&Transport{}).NewClientConn(client)
	trace := &httptrace.ClientTrace{WriteHeadersStart: func(method string) {
		if method != "GET" {
			t.Error("start method", method)
		}
		starts.Add(1)
	}, GotResponseHeaders: func(method string, status int) {
		if method != "GET" || status != 200 {
			t.Error("final event", method, status)
		}
		ends.Add(1)
	}, GotFirstResponseByte: func() { first <- struct{}{} }, GotResponseBodyBytes: func(method string, n int) {
		if method != "GET" {
			t.Error("body method", method)
		}
		bodyBytes.Add(int64(n))
	}}
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", "https://quic-go.net/", nil)
	done := make(chan error, 1)
	go func() {
		res, e := tr.RoundTrip(req)
		if e == nil {
			b, re := io.ReadAll(res.Body)
			res.Body.Close()
			if re != nil {
				e = re
			} else if string(b) != "ok" {
				e = fmt.Errorf("body=%q", b)
			}
		}
		done <- e
	}()
	str, e := server.AcceptStream(ctx)
	if e != nil {
		t.Fatal(e)
	}
	decodeHeader(t, str)
	frame := func(status string) []byte {
		var b bytes.Buffer
		enc := qpack.NewEncoder(&b)
		if e := enc.WriteField(qpack.HeaderField{Name: ":status", Value: status}); e != nil {
			t.Fatal(e)
		}
		if e := enc.WriteField(qpack.HeaderField{Name: "x-held", Value: "complete"}); e != nil {
			t.Fatal(e)
		}
		payload := b.Bytes()
		out := quicvarint.Append(nil, 1)
		out = quicvarint.Append(out, uint64(len(payload)))
		return append(out, payload...)
	}
	if _, e = str.Write(frame("103")); e != nil {
		t.Fatal(e)
	}
	final := frame("200")
	if _, e = str.Write(final[:len(final)-1]); e != nil {
		t.Fatal(e)
	}
	select {
	case <-first:
	case <-ctx.Done():
		t.Fatal("missing first byte", ctx.Err())
	}
	if ends.Load() != 0 {
		t.Fatal("first byte/103/incomplete final block generated final headers event")
	}
	if _, e = str.Write(final[len(final)-1:]); e != nil {
		t.Fatal(e)
	}
	data := quicvarint.Append(nil, 0)
	data = quicvarint.Append(data, 2)
	data = append(data, []byte("ok")...)
	if _, e = str.Write(data); e != nil {
		t.Fatal(e)
	}
	str.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if received.Load() <= 2 || samples.Load() == 0 {
		t.Error("missing transport receive/RTT events", received.Load(), samples.Load())
	}
	if starts.Load() != 1 || ends.Load() != 1 || bodyBytes.Load() != 2 {
		t.Fatal("event counts", starts.Load(), ends.Load(), bodyBytes.Load())
	}
}
