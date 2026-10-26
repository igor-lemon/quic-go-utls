package http3

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/igor-lemon/quic-go-utls"
)

const streamDatagramQueueLen = 32

// stateTrackingStream is an implementation of quic.Stream that delegates
// to an underlying stream
// it takes care of proxying send and receive errors onto an implementation of
// the errorSetter interface (intended to be occupied by a datagrammer)
// it is also responsible for clearing the stream based on its ID from its
// parent connection, this is done through the streamClearer interface when
// both the send and receive sides are closed
type stateTrackingStream struct {
	*quic.Stream

	sendDatagram func([]byte) error
	hasData      chan struct{}
	queue        [][]byte // TODO: use a ring buffer

	mx      sync.Mutex
	sendErr error
	recvErr error

	clearer      streamClearer
	qpackCancel  sync.Once
	decodeCancel context.CancelFunc
}

var _ datagramStream = &stateTrackingStream{}

type streamClearer interface {
	clearStream(quic.StreamID)
}

func newStateTrackingStream(s *quic.Stream, clearer streamClearer, sendDatagram func([]byte) error) *stateTrackingStream {
	t := &stateTrackingStream{
		Stream:       s,
		clearer:      clearer,
		sendDatagram: sendDatagram,
		hasData:      make(chan struct{}, 1),
	}

	context.AfterFunc(s.Context(), func() {
		t.closeSend(context.Cause(s.Context()))
	})

	return t
}

func (s *stateTrackingStream) closeSend(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.sendErr == nil {
		if s.recvErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.sendErr = e
	}
}

func (s *stateTrackingStream) closeReceive(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.recvErr == nil {
		if s.sendErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.recvErr = e
		s.signalHasDatagram()
	}
}

func (s *stateTrackingStream) Close() error {
	s.closeSend(errors.New("write on closed stream"))
	return s.Stream.Close()
}

// sending is whether the stream's send side is still open: neither closed,
// cancelled nor failed.
func (s *stateTrackingStream) sending() bool {
	s.mx.Lock()
	defer s.mx.Unlock()
	return s.sendErr == nil
}

func (s *stateTrackingStream) CancelWrite(e quic.StreamErrorCode) {
	s.closeSend(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelWrite(e)
}

func (s *stateTrackingStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeSend(err)
	}
	return n, err
}

func (s *stateTrackingStream) CancelRead(e quic.StreamErrorCode) {
	s.qpackAbandon()
	s.closeReceive(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelRead(e)
}

func (s *stateTrackingStream) qpackAbandon() {
	s.mx.Lock()
	complete := s.recvErr == io.EOF
	s.mx.Unlock()
	if complete {
		return
	}
	if s.decodeCancel != nil {
		s.decodeCancel()
	}
	s.qpackCancel.Do(func() {
		if c, ok := s.clearer.(*Conn); ok && c.qpack != nil {
			c.qpack.cancel(s.StreamID())
		}
	})
}

// qpackReset abandons the stream's QPACK state as the server's RESET_STREAM
// is taken, on the connection's own goroutine (quic.Stream.SetResetHandler),
// as quiche's QuicSpdyStream::OnStreamReset does while the frame is
// processed: the Stream Cancellation, sent only when the stream's FIN had not
// come, goes in the packet that acknowledges the reset, or a later one.
func (s *stateTrackingStream) qpackReset(finReceived bool) {
	if s.decodeCancel != nil {
		s.decodeCancel()
	}
	s.qpackCancel.Do(func() {
		if c, ok := s.clearer.(*Conn); ok && c.qpack != nil && !finReceived {
			c.qpack.cancel(s.StreamID())
		}
	})
}

func (s *stateTrackingStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeReceive(err)
		if err != io.EOF {
			s.qpackAbandon()
		}
	}
	return n, err
}

func (s *stateTrackingStream) SendDatagram(b []byte) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}

	return s.sendDatagram(b)
}

func (s *stateTrackingStream) signalHasDatagram() {
	select {
	case s.hasData <- struct{}{}:
	default:
	}
}

func (s *stateTrackingStream) enqueueDatagram(data []byte) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.recvErr != nil {
		return
	}
	if len(s.queue) >= streamDatagramQueueLen {
		return
	}
	s.queue = append(s.queue, data)
	s.signalHasDatagram()
}

func (s *stateTrackingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
start:
	s.mx.Lock()
	if len(s.queue) > 0 {
		data := s.queue[0]
		s.queue = s.queue[1:]
		s.mx.Unlock()
		return data, nil
	}
	if receiveErr := s.recvErr; receiveErr != nil {
		s.mx.Unlock()
		return nil, receiveErr
	}
	s.mx.Unlock()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.hasData:
	}
	goto start
}

func (s *stateTrackingStream) QUICStream() *quic.Stream {
	return s.Stream
}
