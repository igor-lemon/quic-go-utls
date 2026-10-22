package http3

import (
	"bytes"
	"context"
	"errors"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestQPACKDiagnosticClassification(t *testing.T) {
	d := newDynamicQPACKDecoder(65536, 100, nil)
	err := dynamicInstructions(d, []byte{0x3f, 0xe2, 0xff, 3})
	if !errors.Is(err, errQPACKWire) || qpackProblemKey(err, "encoder") != "h3.qpack.error_capacity_exceeded_reason" {
		t.Fatal(err)
	}
	_, err = d.decode(context.Background(), 4, []byte{0, 0, 0xd9, 0x80}, 4096)
	if !errors.Is(err, errQPACKWire) || qpackProblemKey(err, "decompression") != "h3.qpack.error_invalid_relative_index_reason" {
		t.Fatal(err)
	}
	// Static errors and post-base/required-count violations are not relative-index underflow.
	for _, block := range [][]byte{{0, 0, 0xff, 0x24}, {0, 0, 0x10}, {0, 1, 0x80}} {
		_, err = d.decode(context.Background(), 4, block, 4096)
		if err == nil || qpackProblemKey(err, "decompression") != "h3.qpack.error_decompression_reason" {
			t.Fatalf("%x %v", block, err)
		}
	}
	e := newDynamicQPACKEncoder("disabled", "never", "never", nil, nil)
	err = e.feedback(bytes.NewReader([]byte{0}))
	if qpackProblemKey(err, "decoder") != "h3.qpack.error_zero_increment_reason" {
		t.Fatal(err)
	}
	err = e.feedback(bytes.NewReader([]byte{1}))
	if qpackProblemKey(err, "decoder") != "h3.qpack.error_decoder_reason" {
		t.Fatal(err)
	}
	err = d.readEncoder(bytes.NewReader([]byte{0x41}))
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if qpackProblemKey(err, "encoder") != "h3.qpack.error_encoder_reason" {
		t.Fatal("truncation mislabeled")
	}
}
func TestQPACKDiagnosticTemplatesAndBound(t *testing.T) {
	p := behavior.Legacy()
	p["h3.qpack.error_invalid_relative_index_reason"] = []byte(`"message/{stream_id}/{detail}"`)
	if got := qpackReason(p, "h3.qpack.error_invalid_relative_index_reason", errors.New("local-cause"), 4); got != "message/4/local-cause" {
		t.Fatal(got)
	}
	p["h3.qpack.error_decompression_reason"] = []byte(`"{detail}"`)
	got := qpackReason(p, "h3.qpack.error_decompression_reason", errors.New(strings.Repeat("λ", 1000)), 0)
	if len(got) != 1024 || !utf8.ValidString(got) {
		t.Fatal("unbounded or invalid UTF8")
	}
	if got = qpackReason(p, "h3.qpack.error_decompression_reason", errors.New("a\xffb"), 0); !utf8.ValidString(got) {
		t.Fatal(got)
	}
	for key, bad := range map[string]string{"h3.qpack.error_encoder_reason": `"{stream_id}"`, "h3.qpack.error_invalid_relative_index_reason": `"{cookie}"`, "h3.qpack.error_decoder_reason": `"{"`} {
		q := p.Clone()
		q[key] = []byte(bad)
		if q.Validate() == nil {
			t.Fatal(key, bad)
		}
	}
}
