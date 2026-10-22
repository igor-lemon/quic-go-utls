package http3

import (
	"bytes"
	"io"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2/hpack"
)

// policyQPACKEncoder preserves the backend's static-table choices while making
// literal string coding an explicit profile choice. It never emits a dynamic
// reference or advertises dynamic-table support.
type policyQPACKEncoder struct {
	out           io.Writer
	started       bool
	names, values string
}

func newPolicyQPACKEncoder(out io.Writer) *policyQPACKEncoder { return &policyQPACKEncoder{out: out} }
func (e *policyQPACKEncoder) Close() error                    { e.started = false; return nil }
func (e *policyQPACKEncoder) WriteField(f qpack.HeaderField) error {
	var raw bytes.Buffer
	backend := qpack.NewEncoder(&raw)
	if err := backend.WriteField(f); err != nil {
		return err
	}
	// A static-only section has Required Insert Count=0 and Delta Base=0.
	b := raw.Bytes()[2:]
	var dst []byte
	if !e.started {
		dst = append(dst, 0, 0)
	}
	switch {
	case b[0]&0x80 != 0: // Indexed static field: no string literal.
		dst = append(dst, b...)
	case b[0]&0xc0 == 0x40: // Literal with a static name reference.
		_, n := qpackPrefix(b, 4)
		dst = append(dst, b[:n]...)
		dst = appendQPACKString(dst, 7, 0, 0x80, f.Value, e.values)
	default: // Literal name. Preserve the never-index bit from the backend.
		dst = appendQPACKString(dst, 3, 0x20|(b[0]&0x10), 0x08, f.Name, e.names)
		dst = appendQPACKString(dst, 7, 0, 0x80, f.Value, e.values)
	}
	n, err := e.out.Write(dst)
	if err == nil && n != len(dst) {
		err = io.ErrShortWrite
	}
	if err == nil {
		e.started = true
	}
	return err
}

// qpackPrefix reads the index emitted by the trusted static-only backend.
func qpackPrefix(b []byte, bits uint8) (uint64, int) {
	limit := uint64(1<<bits) - 1
	v := uint64(b[0]) & limit
	if v < limit {
		return v, 1
	}
	for i, shift := 1, uint(0); ; i, shift = i+1, shift+7 {
		v += uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
}
func appendQPACKInt(b []byte, bits uint8, tag byte, n uint64) []byte {
	limit := uint64(1<<bits) - 1
	if n < limit {
		return append(b, tag|byte(n))
	}
	b = append(b, tag|byte(limit))
	n -= limit
	for n >= 128 {
		b = append(b, byte(n&0x7f)|0x80)
		n >>= 7
	}
	return append(b, byte(n))
}
func appendQPACKString(b []byte, bits uint8, tag, huffman byte, s, mode string) []byte {
	size := hpack.HuffmanEncodeLength(s)
	use := mode == "always" || (mode == "shorter" && size < uint64(len(s)))
	if use {
		b = appendQPACKInt(b, bits, tag|huffman, size)
		return hpack.AppendHuffmanString(b, s)
	}
	b = appendQPACKInt(b, bits, tag, uint64(len(s)))
	return append(b, s...)
}
