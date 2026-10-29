package http3

import (
	"bytes"
	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	"github.com/igor-lemon/quic-go-utls"
	"github.com/quic-go/qpack"
	"go.uber.org/mock/gomock"
	"math"
	"testing"
)

func TestResponseHeadersHaveAnAllocationBound(t *testing.T) {
	for _, limit := range []int{262144, -1, math.MaxInt} {
		t.Run(map[bool]string{true: "finite-control", false: "no-advertised-limit"}[limit >= 0], func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("peer frame length caused panic before receiving its payload: %v", p)
				}
			}()
			ctrl := gomock.NewController(t)
			str := NewMockDatagramStream(ctrl)
			str.EXPECT().StreamID().Return(quic.StreamID(0)).AnyTimes()
			str.EXPECT().CancelRead(gomock.Any()).AnyTimes()
			str.EXPECT().CancelWrite(gomock.Any()).AnyTimes()
			frame := bytes.NewReader((&headersFrame{Length: 1<<62 - 1}).Append(nil))
			str.EXPECT().Read(gomock.Any()).DoAndReturn(frame.Read).AnyTimes()
			stream := newRequestStream(newStream(str, nil, &httptrace.ClientTrace{}, nil, nil), nil, nil, qpack.NewDecoder(), true, limit, &http.Response{})
			stream.sentRequest = true
			_, err := stream.ReadResponse()
			if err == nil {
				t.Fatal("no rejection")
			}
			t.Log(err)
		})
	}
}

func TestTrailersHaveAnAllocationBound(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("peer trailer length caused panic before receiving its payload: %v", p)
		}
	}()
	c := &Conn{}
	_, err := c.decodeTrailers(bytes.NewReader(nil), 0, &headersFrame{Length: 1<<62 - 1}, -1)
	if err == nil {
		t.Fatal("no rejection")
	}
}

func TestHeaderBytesLimit(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, headerSectionSafetyLimit, math.MaxInt} {
		got := headerBytesLimit(limit)
		if got < 0 || got > headerSectionSafetyLimit || limit >= 0 && limit <= headerSectionSafetyLimit && got != limit {
			t.Fatalf("limit %d became %d", limit, got)
		}
	}
}
func TestTrailersEnforceDecodedFieldSize(t *testing.T) {
	fields := []qpack.HeaderField{{Name: "x", Value: "aaaa"}, {Name: "y", Value: "bbbb"}}
	if _, err := parseTrailers(decodeFromSlice(fields), nil, 74); err != nil {
		t.Fatal(err)
	}
	if _, err := parseTrailers(decodeFromSlice(fields), nil, 73); err == nil {
		t.Fatal("oversized decoded trailers accepted")
	}
}
