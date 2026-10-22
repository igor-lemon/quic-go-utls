package http3

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/quic-go/qpack"
)

func TestPolicyQPACKMatchesCapturedChromeStaticBlock(t *testing.T) {
	var fixture struct {
		Fields  []struct{ Name, Value string }
		Payload string
	}
	b, err := os.ReadFile("testdata/chrome155-static-qpack.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	e := newPolicyQPACKEncoder(&out)
	e.names = "shorter"
	e.values = "shorter"
	for round := 0; round < 2; round++ {
		for _, f := range fixture.Fields {
			if err = e.WriteField(qpack.HeaderField{Name: f.Name, Value: f.Value}); err != nil {
				t.Fatal(err)
			}
		}
		if got := hex.EncodeToString(out.Bytes()); got != fixture.Payload {
			t.Fatalf("round%d QPACK differs from original Chrome: %s", round, got)
		}
		if err = e.Close(); err != nil {
			t.Fatal(err)
		}
		out.Reset()
	}
}
func TestPolicyQPACKStringChoicesAndLengths(t *testing.T) {
	fields := []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":authority", Value: "example.test"}, {Name: "sec-ch-ua-mobile", Value: "?0"}, {Name: "x", Value: "="}, {Name: "x-empty", Value: ""}, {Name: "x-long-name-with-multiple-prefix-bytes", Value: string(bytes.Repeat([]byte("abcdef"), 100))}, {Name: "x-utf8", Value: "東京"}}
	outputs := map[string][]byte{}
	for _, names := range []string{"always", "shorter", "never"} {
		for _, values := range []string{"always", "shorter", "never"} {
			var out bytes.Buffer
			e := newPolicyQPACKEncoder(&out)
			e.names = names
			e.values = values
			for _, f := range fields {
				if err := e.WriteField(f); err != nil {
					t.Fatal(err)
				}
			}
			var got []qpack.HeaderField
			decode := qpack.NewDecoder().Decode(out.Bytes())
			var err error
			for {
				var f qpack.HeaderField
				f, err = decode()
				if err != nil {
					break
				}
				got = append(got, f)
			}
			if err == io.EOF {
				err = nil
			}
			if err != nil || !reflect.DeepEqual(got, fields) {
				t.Fatalf("%s/%s decoded%v: %v", names, values, got, err)
			}
			outputs[names+"/"+values] = append([]byte(nil), out.Bytes()...)
		}
	}
	if bytes.Equal(outputs["always/always"], outputs["shorter/shorter"]) || bytes.Equal(outputs["never/never"], outputs["shorter/shorter"]) {
		t.Fatal("literal coding choice ignored")
	}
	// A Huffman tie stays literal in shorter mode; an expanding '?' literal
	// must not be forced through Huffman. These are exact wire encodings.
	for _, test := range []struct{ value, hex string }{{"?0", "000050023f30"}, {"=", "000050013d"}, {"", "0000c0"}} {
		var out bytes.Buffer
		e := newPolicyQPACKEncoder(&out)
		e.names = "shorter"
		e.values = "shorter"
		if err := e.WriteField(qpack.HeaderField{Name: ":authority", Value: test.value}); err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(out.Bytes()); got != test.hex {
			t.Fatalf("%q: %s want%s", test.value, got, test.hex)
		}
	}
}

type qpackFailWriter struct{ short bool }

func (w qpackFailWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, io.ErrClosedPipe
}
func TestPolicyQPACKPropagatesSinkFailures(t *testing.T) {
	for _, short := range []bool{false, true} {
		e := newPolicyQPACKEncoder(qpackFailWriter{short: short})
		e.names = "shorter"
		e.values = "shorter"
		err := e.WriteField(qpack.HeaderField{Name: ":method", Value: "GET"})
		want := io.ErrClosedPipe
		if short {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) || e.started {
			t.Fatal(err, e.started)
		}
	}
}
