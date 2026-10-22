package http3

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/qpack"
)

func dynamicInstructions(d *dynamicQPACKDecoder, b []byte) error {
	r := bufio.NewReader(bytes.NewReader(b))
	for r.Buffered() > 0 || func() bool { _, e := r.Peek(1); return e == nil }() {
		if e := d.instruction(r); e != nil {
			return e
		}
	}
	return nil
}
func TestDynamicQPACKRepresentations(t *testing.T) {
	var feedback bytes.Buffer
	d := newDynamicQPACKDecoder(128, 2, func(b []byte) error { feedback.Write(b); return nil })
	// Capacity=128, literal insertion, static name reference, dynamic name ref,
	// duplicate. These are independent literal RFC9204 instruction encodings.
	instructions := []byte{0x3f, 0x61, 0x41, 'x', 0x01, 'a', 0xc0, 0x01, 'b', 0x80, 0x01, 'c', 0x00}
	if err := dynamicInstructions(d, instructions); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		block []byte
		want  qpack.HeaderField
	}{
		{[]byte{5, 0, 0x80}, qpack.HeaderField{Name: ":authority", Value: "c"}},
		{[]byte{5, 0x80, 0x10}, qpack.HeaderField{Name: ":authority", Value: "c"}},
		{[]byte{5, 0, 0x40, 0x01, 'z'}, qpack.HeaderField{Name: ":authority", Value: "z"}},
		{[]byte{5, 0x80, 0x00, 0x01, 'z'}, qpack.HeaderField{Name: ":authority", Value: "z"}},
	} {
		got, err := d.decode(context.Background(), 0, tt.block, 4096)
		if err != nil || !reflect.DeepEqual(got, []qpack.HeaderField{tt.want}) {
			t.Fatalf("%x => %v %v", tt.block, got, err)
		}
	}
	if !bytes.Equal(feedback.Bytes(), []byte{0x80, 0x80, 0x80, 0x80}) {
		t.Fatalf("ACK %x", feedback.Bytes())
	}
}
func TestDynamicQPACKBlockingAndCancellation(t *testing.T) {
	d := newDynamicQPACKDecoder(64, 1, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, e := d.decode(ctx, 4, []byte{2, 0, 0x80}, 4096); result <- e }()
	for {
		d.mu.Lock()
		blocked := len(d.blocked)
		d.mu.Unlock()
		if blocked == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("no blocked section")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, e := d.decode(ctx, 8, []byte{2, 0, 0x80}, 4096); e == nil {
		t.Fatal("blocked limit ignored")
	}
	if e := dynamicInstructions(d, []byte{0x3f, 0x21, 0x41, 'x', 0x01, 'a'}); e != nil {
		t.Fatal(e)
	}
	if e := <-result; e != nil {
		t.Fatal(e)
	}
	child, stop := context.WithCancel(ctx)
	go func() { _, e := d.decode(child, 12, []byte{3, 0, 0x80}, 4096); result <- e }()
	stop()
	if e := <-result; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestDynamicQPACKPartialInstructionDoesNotLockTable(t *testing.T) {
	d := newDynamicQPACKDecoder(64, 1, nil)
	r, w := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- d.readEncoder(r) }()
	if _, e := w.Write([]byte{0x41}); e != nil {
		t.Fatal(e)
	}
	decoded := make(chan error, 1)
	go func() { _, e := d.decode(context.Background(), 0, []byte{0, 0, 0xd1}, 4096); decoded <- e }()
	select {
	case e := <-decoded:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("partial QPACK instruction locked unrelated response")
	}
	w.Close()
	if e := <-done; e == nil {
		t.Fatal("missing truncation")
	}
}
func TestDynamicQPACKMalformed(t *testing.T) {
	for _, wire := range [][]byte{{0x3f, 0x22}, {0x41, 'x', 0x01, 'a'}, {0x00}, {0x80, 0}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, {0x60, 0x81, 0xff}} {
		d := newDynamicQPACKDecoder(64, 0, nil)
		if e := dynamicInstructions(d, wire); e == nil {
			t.Fatalf("accepted encoder %x", wire)
		}
	}
	for _, wire := range [][]byte{{}, {0}, {0, 0, 0x80}, {0, 0, 0x10}, {0, 0, 0xff, 0xff, 0x01}, {5, 0}, {1, 0}, {2, 0x81, 0x80}, {0, 0, 0x21, 'x', 0x81, 0xff}} {
		d := newDynamicQPACKDecoder(64, 0, nil)
		if _, e := d.decode(context.Background(), 0, wire, 4096); e == nil {
			t.Fatalf("accepted section %x", wire)
		}
	}
	for _, tt := range []struct {
		enc, total, cap, want uint64
		bad                   bool
	}{{4, 10, 100, 9, false}, {0, 0, 0, 0, false}, {7, 10, 100, 0, true}, {1, 0, 64, 0, true}, {2, 0, 64, 1, false}} {
		v, e := requiredInsertCount(tt.enc, tt.total, tt.cap)
		if (e != nil) != tt.bad || v != tt.want {
			t.Fatalf("RIC %+v: %d %v", tt, v, e)
		}
	}
}
func TestDynamicQPACKEncoderFeedbackAndEviction(t *testing.T) {
	var instructions bytes.Buffer
	e := newDynamicQPACKEncoder("reuse", "shorter", "shorter", []string{"authorization"}, func(b []byte) error { instructions.Write(b); return nil })
	e.budget = 64
	e.configure(64)
	fields := []qpack.HeaderField{{Name: "x", Value: "a"}}
	first, err := e.encode(0, fields)
	if err != nil || first[0] != 0 {
		t.Fatalf("first %x %v", first, err)
	}
	if err = e.feedback(bytes.NewReader([]byte{1})); err != io.EOF {
		t.Fatal(err)
	}
	second, err := e.encode(4, fields)
	if err != nil || !bytes.Equal(second, []byte{2, 0, 0x80}) {
		t.Fatalf("second %x %v", second, err)
	}
	// Pinned entry cannot be evicted by an unrelated insertion.
	if _, err = e.encode(8, []qpack.HeaderField{{Name: "y", Value: "b"}}); err != nil {
		t.Fatal(err)
	}
	if e.table.inserted != 1 {
		t.Fatal("evicted referenced entry")
	}
	if err = e.feedback(bytes.NewReader([]byte{0x84})); err != io.EOF {
		t.Fatal(err)
	}
	if _, err = e.encode(12, []qpack.HeaderField{{Name: "y", Value: "b"}}); err != nil {
		t.Fatal(err)
	}
	if e.table.inserted != 2 {
		t.Fatal("ACK did not release entry")
	}
	d := newDynamicQPACKDecoder(64, 0, nil)
	if err = dynamicInstructions(d, instructions.Bytes()); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{{0}, {3}, {0x80}, {0x84}} {
		if err = e.feedback(bytes.NewReader(b)); err == io.EOF {
			t.Fatalf("accepted feedback %x", b)
		}
	}
	if err = e.feedback(bytes.NewReader([]byte{0x40})); err != io.EOF {
		t.Fatalf("cancellation of stream without refs is legal: %v", err)
	}
}
func TestDynamicQPACKSensitiveAndDisabled(t *testing.T) {
	for _, mode := range []string{"disabled", "reuse"} {
		e := newDynamicQPACKEncoder(mode, "shorter", "shorter", []string{"authorization"}, func([]byte) error { return nil })
		e.budget = 128
		e.configure(128)
		b, err := e.encode(0, []qpack.HeaderField{{Name: "authorization", Value: "secret"}})
		if err != nil || b[0] != 0 || e.table.inserted != 0 {
			t.Fatalf("sensitive indexed %x %v", b, err)
		}
	}
}
func TestDynamicQPACKIndependentCorpus(t *testing.T) {
	type section struct {
		Stream              uint64
		Instructions, Block []byte
		Fields              []qpack.HeaderField
	}
	var rows []section
	b, e := os.ReadFile("testdata/lsqpack-dynamic.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &rows); e != nil {
		t.Fatal(e)
	}
	d := newDynamicQPACKDecoder(256, 16, nil)
	for i, row := range rows {
		if e := dynamicInstructions(d, row.Instructions); e != nil {
			t.Fatalf("instruction %d: %v", i, e)
		}
		got, e := d.decode(context.Background(), row.Stream, row.Block, 16384)
		if e != nil || !reflect.DeepEqual(got, row.Fields) {
			t.Fatalf("section %d: %v %v want %v", i, got, e, row.Fields)
		}
	}
}
func TestDynamicQPACKConcurrentDecoder(t *testing.T) {
	d := newDynamicQPACKDecoder(64, 100, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, e := d.decode(ctx, uint64(id*4), []byte{2, 0, 0x80}, 4096)
			if e != nil {
				t.Error(e)
			}
		}(i)
	}
	if e := dynamicInstructions(d, []byte{0x3f, 0x21, 0x41, 'x', 0x01, 'a'}); e != nil {
		t.Fatal(e)
	}
	wg.Wait()
}
func FuzzDynamicQPACKSection(f *testing.F) {
	for _, s := range [][]byte{{0, 0}, {2, 0, 0x80}, {0xff, 0xff}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		d := newDynamicQPACKDecoder(64, 0, nil)
		_, _ = d.decode(context.Background(), 0, b, 4096)
	})
}
func TestDynamicQPACKInsertionWarmupAndBlockedBudget(t *testing.T) {
	var wire bytes.Buffer
	e := newDynamicQPACKEncoder("insert", "shorter", "shorter", nil, func(b []byte) error { wire.Write(b); return nil })
	e.budget = 128
	e.configure(128, 1)
	e.warmup = 1
	fields := []qpack.HeaderField{{Name: "x-proof", Value: "some-repeated-value"}}
	cold, err := e.encode(0, fields)
	if err != nil || cold[0] != 0 || wire.Len() != 0 {
		t.Fatal("warmup ignored", err)
	}
	first, err := e.encode(4, fields)
	if err != nil || first[0] == 0 {
		t.Fatal("no dynamic reference", err)
	}
	second, err := e.encode(8, fields)
	if err != nil || second[0] != 0 {
		t.Fatal("blocked credit exceeded", err)
	}
	if err = e.feedback(bytes.NewReader([]byte{0x84})); err != io.EOF {
		t.Fatal(err)
	}
	third, err := e.encode(12, fields)
	if err != nil || third[0] == 0 {
		t.Fatal("ACK did not release blocked credit", err)
	}
	d := newDynamicQPACKDecoder(128, 1, nil)
	if err = dynamicInstructions(d, wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	for _, block := range [][]byte{first, second, third} {
		out, err := d.decode(context.Background(), 4, block, 4096)
		if err != nil || !reflect.DeepEqual(out, fields) {
			t.Fatal(out, err)
		}
	}
}
func TestDynamicQPACKInsertFeedbackDoesNotDoubleCountACK(t *testing.T) {
	var out bytes.Buffer
	d := newDynamicQPACKDecoder(64, 1, func(b []byte) error { out.Write(b); return nil })
	d.feedbackMode = "on-insert"
	if err := dynamicInstructions(d, []byte{0x3f, 0x21, 0x41, 'x', 0x01, 'a'}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.decode(context.Background(), 0, []byte{2, 0, 0x80}, 4096); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), []byte{1, 0x80}) {
		t.Fatalf("feedback %x", out.Bytes())
	}
}

func TestDynamicQPACKModuloUsesPeerMaximumNotLocalBudget(t *testing.T) {
	var instructions []byte
	e := newDynamicQPACKEncoder("insert", "shorter", "shorter", nil, func(b []byte) error { instructions = append(instructions, b...); return nil })
	e.budget = 64
	e.configure(256, 16)
	var feedback []byte
	d := newDynamicQPACKDecoder(256, 16, func(b []byte) error { feedback = append(feedback, b...); return nil })
	for i := 0; i < 40; i++ {
		fields := []qpack.HeaderField{{Name: "x", Value: fmt.Sprint(i)}}
		block, err := e.encode(uint64(i*4), fields)
		if err != nil {
			t.Fatal(err)
		}
		if err = dynamicInstructions(d, instructions); err != nil {
			t.Fatal(err)
		}
		instructions = nil
		out, err := d.decode(context.Background(), uint64(i*4), block, 4096)
		if err != nil || !reflect.DeepEqual(out, fields) {
			t.Fatalf("insert%d block%x => %v %v", i, block, out, err)
		}
		if err = e.feedback(bytes.NewReader(feedback)); err != io.EOF {
			t.Fatal(err)
		}
		feedback = nil
	}
}
