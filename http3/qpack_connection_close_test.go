package http3

import (
	"context"
	"errors"
	"github.com/quic-go/qpack"
	"io"
	"reflect"
	"testing"
	"time"
)

func TestQPACKBufferedSectionSurvivesConnectionClose(t *testing.T) {
	connection, closeConnection := context.WithCancel(context.Background())
	closeConnection()
	for range 100 {
		session := &qpackSession{conn: &Conn{ctx: connection}, decoder: newDynamicQPACKDecoder(64, 1, nil)}
		decode := session.decode(context.Background(), 0, []byte{0, 0, 0xd9}, 4096)
		got, err := decode()
		if err != nil || got != (qpack.HeaderField{Name: ":status", Value: "200"}) {
			t.Fatalf("buffered static field=%v err=%v", got, err)
		}
		if _, err = decode(); err != io.EOF {
			t.Fatalf("end=%v", err)
		}
	}
}
func TestQPACKConnectionCloseKeepsRequestCancellationAndBounds(t *testing.T) {
	connection, closeConnection := context.WithCancel(context.Background())
	closeConnection()
	request, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	d := newDynamicQPACKDecoder(64, 1, nil)
	if _, err := d.decodeWithConnection(request, connection, 0, []byte{0, 0, 0xd9}, 4096); !errors.Is(err, context.Canceled) {
		t.Fatalf("request cancellation=%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := d.decodeWithConnection(ctx, connection, 4, []byte{2, 0, 0x80}, 4096); !errors.Is(err, context.Canceled) {
		t.Fatalf("missing inserts on terminal connection=%v", err)
	}
	d.mu.Lock()
	blocked := len(d.blocked)
	d.mu.Unlock()
	if blocked != 0 {
		t.Fatalf("blocked credit leaked: %d", blocked)
	}
	if _, err := d.decodeWithConnection(context.Background(), connection, 0, []byte{0, 0, 0xd9}, 1); err == nil {
		t.Fatal("terminal connection bypassed field size limit")
	}
	if _, err := d.decodeWithConnection(context.Background(), connection, 0, []byte{0, 0, 0xff}, 4096); err == nil {
		t.Fatal("terminal connection bypassed malformed-block validation")
	}
}
func TestQPACKReadyDynamicSectionKeepsLiveFeedbackFailures(t *testing.T) {
	for _, closed := range []bool{false, true} {
		connection, closeConnection := context.WithCancel(context.Background())
		refused := errors.New("live feedback failed")
		calls := 0
		d := newDynamicQPACKDecoder(64, 1, func([]byte) error { calls++; return refused })
		if err := dynamicInstructions(d, []byte{0x3f, 0x21, 0x41, 'x', 1, 'a'}); err != nil {
			t.Fatal(err)
		}
		if closed {
			closeConnection()
		}
		got, err := d.decodeWithConnection(context.Background(), connection, 4, []byte{2, 0, 0x80}, 4096)
		closeConnection()
		if closed {
			if err != nil || !reflect.DeepEqual(got, []qpack.HeaderField{{Name: "x", Value: "a"}}) {
				t.Fatalf("buffered dynamic section=%v %v", got, err)
			}
			if calls != 0 {
				t.Fatalf("feedback attempted on already terminal connection: %d", calls)
			}
		} else if !errors.Is(err, refused) || calls != 1 {
			t.Fatalf("live feedback lost: %v calls=%d", err, calls)
		}
	}
}
