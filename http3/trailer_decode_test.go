package http3

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

// answerWithBlockedTrailers answers 200, a body, and a trailer section that
// refers to an insert the server never sends: the client's decoding of it
// waits.
func answerWithBlockedTrailers(_ *quic.Conn, str *quic.Stream) {
	_, _ = io.Copy(io.Discard, str)
	var block bytes.Buffer
	_ = qpack.NewEncoder(&block).WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
	frame := quicvarint.Append(quicvarint.Append(nil, 1), uint64(block.Len()))
	frame = append(frame, block.Bytes()...)
	frame = append(frame, 0, 1, 'x')
	// Required Insert Count 1 (of a table of 65536: encoded 2), the entry
	// relative 0.
	trailers := []byte{0x02, 0x00, 0x80}
	frame = quicvarint.Append(quicvarint.Append(frame, 1), uint64(len(trailers)))
	_, _ = str.Write(append(frame, trailers...))
	time.Sleep(5 * time.Second)
}

// TestATrailerSectionWaitingForInsertsEndsWithItsStream: a response body let
// go of while its trailer section waits for inserts ends that wait, as the
// headers' does: the section is decoded within the stream's decoding
// context, not the request's alone.
func TestATrailerSectionWaitingForInsertsEndsWithItsStream(t *testing.T) {
	addr := bundleServer(t, &packetsBoth{}, answerWithBlockedTrailers)
	cc := bundleClient(t, addr, bundlePolicy(t, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cc.RoundTrip(asked(t, ctx, addr))
	require.NoError(t, err)
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(res.Body)
		read <- err
	}()
	select {
	case err := <-read:
		t.Fatalf("the body ended before its trailers came: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	res.Body.Close()
	select {
	case <-read:
	case <-time.After(2 * time.Second):
		t.Fatal("the trailers' decoding went on waiting after the body was let go of")
	}
}
