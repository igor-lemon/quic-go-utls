package http3

import (
	"bytes"
	"context"
	"errors"
	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"github.com/quic-go/qpack"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestQPACKDraining128AndAcknowledgmentPins(t *testing.T) {
	for _, percent := range []uint64{0, 25, 100} {
		var wire bytes.Buffer
		e := newDynamicQPACKEncoder("insert", "shorter", "shorter", nil, func(b []byte) error { wire.Write(b); return nil })
		e.budget = 128
		e.drainingPercent = percent
		e.configure(128, 1)
		fields := []qpack.HeaderField{{Name: ":authority", Value: "127.0.0.1:12345"}, {Name: ":path", Value: "/data?i=1"}}
		first, err := e.encode(0, fields)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, []byte{3, 0, 0x81, 0x80}) {
			t.Fatalf("first %x", first)
		}
		fields[1].Value = "/data?i=2"
		// Neither an unacknowledged insertion nor its live reference may be evicted.
		_, err = e.encode(4, fields)
		if err != nil {
			t.Fatal(err)
		}
		if e.table.inserted != 2 {
			t.Fatal("evicted unacknowledged insertion")
		}
		// ACK both outstanding sections (the second can reference known entries only
		// when blocked credit is exhausted). Only stream0 has references in this case.
		if err = e.feedback(bytes.NewReader([]byte{0x80})); err != io.EOF {
			t.Fatal(err)
		}
		if len(e.outstanding[4]) > 0 {
			if err = e.feedback(bytes.NewReader([]byte{0x84})); err != io.EOF {
				t.Fatal(err)
			}
		}
		wire.Reset()
		got, err := e.encode(8, fields)
		if err != nil {
			t.Fatal(err)
		}
		if percent == 0 {
			if e.table.inserted != 2 {
				t.Fatal("disabled draining changed table")
			}
		} else {
			if e.table.inserted != 4 || len(e.table.entries) != 2 || e.table.entries[0].id != 2 {
				t.Fatalf("draining%d table %+v", percent, e.table)
			}
			if !bytes.Equal(got[len(got)-1:], []byte{0x80}) || !bytes.HasPrefix(wire.Bytes(), []byte{0xc0}) {
				t.Fatalf("draining output %x / %x", got, wire.Bytes())
			}
		}
	}
}
func TestQPACKDrainingDuplicatesWithoutEvictingSource(t *testing.T) {
	e := newDynamicQPACKEncoder("insert", "shorter", "shorter", nil, func([]byte) error { return nil })
	e.budget = 128
	e.drainingPercent = 100
	e.configure(128, 4)
	fields := []qpack.HeaderField{{Name: "x", Value: "a"}}
	if _, err := e.encode(0, fields); err != nil {
		t.Fatal(err)
	}
	if err := e.feedback(bytes.NewReader([]byte{0x80})); err != io.EOF {
		t.Fatal(err)
	}
	got, err := e.encode(4, fields)
	if err != nil || e.table.inserted != 2 || !bytes.Equal(got, []byte{3, 0, 0x80}) {
		t.Fatalf("duplicate %x %+v %v", got, e.table, err)
	}
}
func TestH3ProtocolReplaySafety(t *testing.T) {
	p := behavior.Legacy()
	p["h3.retry_methods"] = []byte(`["GET","HEAD","PUT","POST"]`)
	p["h3.retry_application_errors"] = []byte(`[512,513,514]`)
	p["h3.retry_transport_errors"] = []byte(`[10]`)
	tr := Transport{Behavior: p}
	req, _ := http.NewRequest("GET", "https://example.invalid", nil)
	for _, tt := range []struct {
		e    error
		want bool
	}{
		{&quic.TransportError{ErrorCode: 10}, true}, {&quic.ApplicationError{ErrorCode: 10}, false},
		{&quic.ApplicationError{ErrorCode: 512}, true}, {&Error{ErrorCode: 514}, true},
		{qpackFailure(ErrCodeQPACKEncoderStreamError, errors.New("encoder")), true},
		{&quic.ApplicationError{ErrorCode: 260}, false}, {errors.New("unknown"), false},
	} {
		if got := tr.retryProtocolError(tt.e, req); got != tt.want {
			t.Fatalf("%T %v", tt.e, got)
		}
	}
	req.Method = "POST"
	if tr.retryProtocolError(&quic.ApplicationError{ErrorCode: 512}, req) {
		t.Fatal("unsafe replay")
	}
	req.Method = "GET"
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	if tr.retryProtocolError(&quic.ApplicationError{ErrorCode: 512}, req.WithContext(ctx)) {
		t.Fatal("cancelled replay")
	}
	req, _ = http.NewRequest("PUT", "https://example.invalid", strings.NewReader("exact body"))
	again, err := replayH3Request(req)
	if err != nil || again == req {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(again.Body)
	again.Body.Close()
	if string(b) != "exact body" {
		t.Fatal(string(b))
	}
	req.GetBody = nil
	if _, err := replayH3Request(req); err == nil {
		t.Fatal("non-replayable body")
	}
	req.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("rewind failed") }
	if _, err := replayH3Request(req); err == nil {
		t.Fatal("rewind error ignored")
	}
}

type rejectedQPACKClient struct{ calls *atomic.Int32 }

func (m rejectedQPACKClient) OpenRequestStream(context.Context) (*RequestStream, error) {
	panic("unused")
}
func (m rejectedQPACKClient) RoundTrip(*http.Request) (*http.Response, error) {
	m.calls.Add(1)
	return nil, &Error{ErrorCode: ErrCodeRequestRejected}
}

func TestH3UnprocessedRetryBudget(t *testing.T) {
	for _, n := range []int{1, 2, 4} {
		conn, _ := newConnPair(t)
		p := behavior.Legacy()
		p["h3.retry_unprocessed_attempts"] = []byte(strconv.Itoa(n))
		req, _ := http.NewRequest("GET", "https://example.invalid", nil)
		var calls, dials atomic.Int32
		tr := Transport{Behavior: p, Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			dials.Add(1)
			return conn, nil
		}, newClientConn: func(*quic.Conn) clientConn { return rejectedQPACKClient{&calls} }}
		_, err := tr.RoundTrip(req)
		if err == nil || calls.Load() != int32(n) || dials.Load() != int32(n) {
			t.Fatalf("JSON budget%d: calls%d dials%d err%v", n, calls.Load(), dials.Load(), err)
		}
		tr.Close()
	}
}
