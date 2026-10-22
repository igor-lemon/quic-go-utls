package http3

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
	"github.com/quic-go/qpack"
)

// Instruction writes have their own bounded queues. No table or HTTP request
// lock is held while waiting for QUIC flow control. Queue exhaustion terminates
// the connection instead of dropping a mandatory instruction or deadlocking.
type qpackInstructionWriter struct {
	conn   *Conn
	kind   uint64
	queue  chan []byte
	start  sync.Once
	policy behavior.Policy
}

func newQPACKInstructionWriter(c *Conn, kind uint64, pol behavior.Policy) *qpackInstructionWriter {
	return &qpackInstructionWriter{conn: c, kind: kind, queue: make(chan []byte, 64), policy: pol}
}
func (w *qpackInstructionWriter) open() (*quic.SendStream, error) {
	str, err := w.conn.OpenUniStreamSync(w.conn.Context())
	if err == nil {
		_, err = str.Write(quicvarint.Append(nil, w.kind))
	}
	return str, err
}
func (w *qpackInstructionWriter) run() {
	str, err := w.open()
	if err != nil {
		w.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), qpackReason(w.policy, "h3.qpack.error_stream_unavailable_reason", err, 0))
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
		}
	}
}
func (w *qpackInstructionWriter) send(b []byte) error {
	w.start.Do(func() { go w.run() })
	select {
	case <-w.conn.Context().Done():
		return context.Cause(w.conn.Context())
	default:
	}
	select {
	case w.queue <- append([]byte(nil), b...):
		return nil
	default:
		w.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeExcessiveLoad), qpackReason(w.policy, "h3.qpack.error_queue_exhausted_reason", nil, 0))
		return errors.New("QPACK instruction queue exhausted")
	}
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
}

func newQPACKSession(c *Conn, settings map[uint64]uint64, pol behavior.Policy) *qpackSession {
	s := &qpackSession{conn: c, encoderWriter: newQPACKInstructionWriter(c, 2, pol), decoderWriter: newQPACKInstructionWriter(c, 3, pol), policy: pol}
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
	bound := uint64(16 << 20)
	if limit >= 0 && uint64(limit) < bound {
		bound = uint64(limit)
	}
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
			if err == nil {
				go w.pump(str)
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}
