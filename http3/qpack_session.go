package http3

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
	"github.com/quic-go/qpack"
)

// Instruction writes have their own bounded queues. No table or HTTP request
// lock is held while waiting for QUIC flow control. Queue exhaustion terminates
// the connection instead of dropping a mandatory instruction or deadlocking.
type qpackInstructionWriter struct {
	conn             *Conn
	kind             uint64
	queue            chan []byte
	start            sync.Once
	policy           behavior.Policy
	reserved         *quic.SendStream
	reservationReady <-chan struct{}
	reservationError error
	// opened once the writer opened its stream and wrote its type (open)
	opened atomic.Bool

	// the queue's items: queued, and written by the pump; wrote is closed
	// and replaced each time one is written
	progress        sync.Mutex
	queued, written uint64
	wrote           chan struct{}

	// opportunistic: what is sent waits in pending for a packet the
	// connection sends for something else, which takes it (take), the
	// stream's type before the first (typed once it went), as quiche's
	// decoder stream sender buffers its instructions until
	// QuicSpdySession::MaybeBundleOpportunistically flushes them
	// (h3.qpack.decoder_writes opportunistic)
	opportunistic bool
	bundled       sync.Once
	mu            sync.Mutex
	pending       []byte
	typed         bool
}

// qpackPendingBytes bounds what an opportunistic writer keeps for the next
// packet: an engine resource ceiling, not a browser's choice.
const qpackPendingBytes = 64 << 10

func newQPACKInstructionWriter(c *Conn, kind uint64, pol behavior.Policy) *qpackInstructionWriter {
	return &qpackInstructionWriter{conn: c, kind: kind, queue: make(chan []byte, 64), policy: pol, wrote: make(chan struct{})}
}
func (w *qpackInstructionWriter) open() (*quic.SendStream, error) {
	str, err := w.conn.OpenUniStreamSync(w.conn.Context())
	if err == nil {
		_, err = str.Write(quicvarint.Append(nil, w.kind))
	}
	if err == nil {
		w.opened.Store(true)
	}
	return str, err
}
func (w *qpackInstructionWriter) run() {
	var str *quic.SendStream
	var err error
	if w.reservationReady != nil {
		select {
		case <-w.reservationReady:
		case <-w.conn.Context().Done():
			return
		}
		str, err = w.reserved, w.reservationError
		if err == nil && !w.opportunistic {
			_, err = str.Write(quicvarint.Append(nil, w.kind))
		}
	} else if w.opportunistic {
		str, err = w.conn.OpenUniStreamSync(w.conn.Context())
	} else {
		str, err = w.open()
	}
	if err != nil {
		w.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), qpackReason(w.policy, "h3.qpack.error_stream_unavailable_reason", err, 0))
		return
	}
	if w.opportunistic {
		w.bundleOn(str)
		return
	}
	w.pump(str)
}
func (w *qpackInstructionWriter) pump(str *quic.SendStream) {
	for {
		select {
		case <-w.conn.Context().Done():
			return
		case b := <-w.queue:
			if _, err := str.Write(b); err != nil {
				w.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), qpackReason(w.policy, "h3.qpack.error_stream_write_reason", err, 0))
				return
			}
			w.progress.Lock()
			w.written++
			close(w.wrote)
			w.wrote = make(chan struct{})
			w.progress.Unlock()
		}
	}
}
func (w *qpackInstructionWriter) send(b []byte) error {
	if w.opportunistic {
		return w.keep(b)
	}
	w.start.Do(func() { go w.run() })
	select {
	case <-w.conn.Context().Done():
		return context.Cause(w.conn.Context())
	default:
	}
	w.progress.Lock()
	select {
	case w.queue <- append([]byte(nil), b...):
		w.queued++
		w.progress.Unlock()
		return nil
	default:
		w.progress.Unlock()
	}
	w.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeExcessiveLoad), qpackReason(w.policy, "h3.qpack.error_queue_exhausted_reason", nil, 0))
	return errors.New("QPACK instruction queue exhausted")
}

// mark says how many items were queued, and whether the pump wrote them all.
func (w *qpackInstructionWriter) mark() (queued uint64, idle bool) {
	w.progress.Lock()
	defer w.progress.Unlock()
	return w.queued, w.written == w.queued
}

// ready says whether the writer's stream is reserved or open, so that a
// write of it waits for no stream to be opened.
func (w *qpackInstructionWriter) ready() bool {
	return w.reservationReady != nil || w.opened.Load()
}

// waitWritten waits until the pump wrote the first n items, or until done:
// the request, its write bundle's spilling or the connection ends.
func (w *qpackInstructionWriter) waitWritten(ctx context.Context, n uint64, spilled <-chan struct{}) {
	for {
		w.progress.Lock()
		written, wrote := w.written, w.wrote
		w.progress.Unlock()
		if written >= n {
			return
		}
		select {
		case <-wrote:
		case <-spilled:
			return
		case <-ctx.Done():
			return
		case <-w.conn.Context().Done():
			return
		}
	}
}

// keep has b wait for a packet the connection sends for something else: no
// table lock, nor the connection's own goroutine, waits for it.
func (w *qpackInstructionWriter) keep(b []byte) error {
	select {
	case <-w.conn.Context().Done():
		return context.Cause(w.conn.Context())
	default:
	}
	w.mu.Lock()
	full := len(w.pending)+len(b) > qpackPendingBytes
	if !full {
		w.pending = append(w.pending, b...)
	}
	w.mu.Unlock()
	if full {
		// not on the caller's goroutine, which may be the connection's own
		go w.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeExcessiveLoad), qpackReason(w.policy, "h3.qpack.error_queue_exhausted_reason", nil, 0))
		return errors.New("QPACK instruction queue exhausted")
	}
	w.start.Do(func() { go w.run() })
	return nil
}

// bundleOn has the connection send what the writer keeps on str, in the
// packets it sends for something else.
func (w *qpackInstructionWriter) bundleOn(str *quic.SendStream) {
	w.bundled.Do(func() { w.conn.conn.BundleOpportunistically(str, w.take) })
}

// take is the source of an opportunistic writer's stream: what waits, after
// the stream's type before the first instruction.
func (w *qpackInstructionWriter) take(b []byte) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return b
	}
	if !w.typed {
		b = quicvarint.Append(b, w.kind)
		w.typed = true
	}
	b = append(b, w.pending...)
	w.pending = w.pending[:0]
	return b
}

type qpackSession struct {
	conn                         *Conn
	decoder                      *dynamicQPACKDecoder
	encoder                      *dynamicQPACKEncoder
	encoderWriter, decoderWriter *qpackInstructionWriter
	order                        []uint64
	closeSpace                   string
	closeCode                    uint64
	closeFrame                   uint64
	closeReason                  string
	policy                       behavior.Policy
	reservationReady             chan struct{}
	reserveOnce                  sync.Once
	reservationError             error
}

func newQPACKSession(c *Conn, settings map[uint64]uint64, pol behavior.Policy) *qpackSession {
	s := &qpackSession{conn: c, encoderWriter: newQPACKInstructionWriter(c, 2, pol), decoderWriter: newQPACKInstructionWriter(c, 3, pol), policy: pol}
	s.decoderWriter.opportunistic = pol.Text("h3.qpack.decoder_writes") == "opportunistic"
	if pol.Text("h3.qpack.streams") == "deferred" {
		s.reservationReady = make(chan struct{})
		s.encoderWriter.reservationReady = s.reservationReady
		s.decoderWriter.reservationReady = s.reservationReady
	}
	s.order = pol.Numbers("h3.qpack.stream_order")
	s.closeSpace = pol.Text("h3.qpack.critical_close_space")
	s.closeCode = uint64(pol.Int("h3.qpack.critical_close_code"))
	s.closeFrame = uint64(pol.Int("h3.qpack.critical_close_frame_type"))
	s.closeReason = pol.Text("h3.qpack.critical_close_reason")
	s.decoder = newDynamicQPACKDecoder(settings[1], settings[7], s.decoderWriter.send)
	s.decoder.feedbackMode = pol.Text("h3.qpack.decoder_feedback")
	s.encoder = newDynamicQPACKEncoder(pol.Text("h3.qpack.encoder_strategy"), pol.Text("h3.qpack.huffman_names"), pol.Text("h3.qpack.huffman_values"), pol.Strings("h3.qpack.never_index"), s.encoderWriter.send)
	s.encoder.drainingPercent = uint64(pol.Int("h3.qpack.draining_percent"))
	s.encoder.budget = uint64(pol.Int("h3.qpack.encoder_table_bytes"))
	s.encoder.warmup = uint64(pol.Int("h3.qpack.encoder_warmup_sections"))
	s.encoder.baseMode = pol.Text("h3.qpack.reference_base")
	return s
}
func (s *qpackSession) receive(r io.Reader, encoder bool) {
	var err error
	code := ErrCodeQPACKDecoderStreamError
	if encoder {
		err = s.decoder.readEncoder(r)
		code = ErrCodeQPACKEncoderStreamError
	} else {
		err = s.encoder.feedback(r)
	}
	if s.conn.Context().Err() != nil {
		return
	}
	var reset *quic.StreamError
	if err == io.EOF || errors.As(err, &reset) {
		if s.closeSpace == "transport" {
			s.conn.conn.CloseWithTransportError(quic.TransportErrorCode(s.closeCode), s.closeFrame, s.closeReason)
		} else {
			s.conn.CloseWithError(quic.ApplicationErrorCode(s.closeCode), s.closeReason)
		}
		return
	}
	fallback := "decoder"
	if encoder {
		fallback = "encoder"
	}
	s.conn.CloseWithError(quic.ApplicationErrorCode(code), qpackReason(s.policy, qpackProblemKey(err, fallback), err, 0))
}
func (s *qpackSession) decode(ctx context.Context, id quic.StreamID, b []byte, limit int) qpack.DecodeFunc {
	// Even when the advertised field-section limit is disabled, retain a hard
	// allocation ceiling. This cannot be disabled by an untrusted peer/profile.
	bound := uint64(headerBytesLimit(limit))
	wait, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.conn.Context(), cancel)
	defer stop()
	fields, err := s.decoder.decode(wait, uint64(id), b, bound)
	if err != nil {
		var wire *qpackWireError
		if errors.As(err, &wire) {
			s.conn.CloseWithError(quic.ApplicationErrorCode(wire.code), qpackReason(s.policy, qpackProblemKey(wire, "decompression"), wire, uint64(id)))
		}
	}
	i := 0
	return func() (qpack.HeaderField, error) {
		if err != nil {
			return qpack.HeaderField{}, err
		}
		if i == len(fields) {
			return qpack.HeaderField{}, io.EOF
		}
		f := fields[i]
		i++
		return f, nil
	}
}
func (s *qpackSession) cancel(id quic.StreamID) {
	if s.decoder.maximum > 0 {
		_ = s.decoderWriter.send(appendQPACKInt(nil, 6, 0x40, uint64(id)))
	}
}

func (s *qpackSession) startEager() error {
	for _, kind := range s.order {
		w := s.encoderWriter
		if kind == 3 {
			w = s.decoderWriter
		}
		var err error
		w.start.Do(func() {
			var str *quic.SendStream
			str, err = w.open()
			switch {
			case err == nil && w.opportunistic:
				w.mu.Lock()
				w.typed = true
				w.mu.Unlock()
				w.bundleOn(str)
			case err == nil:
				go w.pump(str)
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// startDeferred reserves stream identities in profile order without exposing
// either stream on the wire. The first instruction starts its writer and emits
// its type prefix. Feedback can queue during reservation without a table lock
// waiting for QUIC flow control; the writer alone waits for reservationReady.
func (s *qpackSession) startDeferred() error {
	s.reserveOnce.Do(func() {
		defer close(s.reservationReady)
		for _, kind := range s.order {
			w := s.encoderWriter
			if kind == 3 {
				w = s.decoderWriter
			}
			str, err := s.conn.OpenUniStreamSync(s.conn.Context())
			if err != nil {
				s.reservationError = err
				s.encoderWriter.reservationError = err
				s.decoderWriter.reservationError = err
				return
			}
			w.reserved = str
			if w.opportunistic {
				// asked from the first packet on, as a reset's Stream
				// Cancellation must go with the packet that acknowledges it
				w.bundleOn(str)
			}
		}
	})
	return s.reservationError
}
