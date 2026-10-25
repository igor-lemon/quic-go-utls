package http3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3/qlog"
	"github.com/igor-lemon/quic-go-utls/qlogwriter"
	"github.com/igor-lemon/quic-go-utls/quicvarint"

	"github.com/quic-go/qpack"
)

const maxQuarterStreamID = 1<<60 - 1

var errGoAway = errors.New("connection in graceful shutdown")

// invalidStreamID is a stream ID that is invalid. The first valid stream ID in QUIC is 0.
const invalidStreamID = quic.StreamID(-1)

// Conn is an HTTP/3 connection.
// It has all methods from the quic.Conn expect for AcceptStream, AcceptUniStream,
// SendDatagram and ReceiveDatagram.
type Conn struct {
	conn *quic.Conn

	ctx context.Context

	isServer bool
	logger   *slog.Logger

	enableDatagrams bool

	decoder *qpack.Decoder
	qpack   *qpackSession

	streamMx     sync.Mutex
	streams      map[quic.StreamID]*stateTrackingStream
	lastStreamID quic.StreamID
	maxStreamID  quic.StreamID

	settings         *Settings
	receivedSettings chan struct{}

	// alps is what a client took of its server's ALPS, whose settings the
	// control stream's are held to, when its profile takes them as quiche
	// does (h3.peer_settings); nil otherwise
	alps *alpsState

	idleTimeout time.Duration
	idleTimer   *time.Timer

	qlogger qlogwriter.Recorder
}

func newConnection(
	ctx context.Context,
	quicConn *quic.Conn,
	enableDatagrams bool,
	isServer bool,
	logger *slog.Logger,
	idleTimeout time.Duration,
) *Conn {
	var qlogger qlogwriter.Recorder
	if qlogTrace := quicConn.QlogTrace(); qlogTrace != nil && qlogTrace.SupportsSchemas(qlog.EventSchema) {
		qlogger = qlogTrace.AddProducer()
	}
	c := &Conn{
		ctx:              ctx,
		conn:             quicConn,
		isServer:         isServer,
		logger:           logger,
		idleTimeout:      idleTimeout,
		enableDatagrams:  enableDatagrams,
		decoder:          qpack.NewDecoder(),
		receivedSettings: make(chan struct{}),
		streams:          make(map[quic.StreamID]*stateTrackingStream),
		maxStreamID:      invalidStreamID,
		lastStreamID:     invalidStreamID,
		qlogger:          qlogger,
	}
	if idleTimeout > 0 {
		c.idleTimer = time.AfterFunc(idleTimeout, c.onIdleTimer)
	}
	return c
}

func (c *Conn) OpenStream() (*quic.Stream, error) {
	return c.conn.OpenStream()
}

func (c *Conn) OpenStreamSync(ctx context.Context) (*quic.Stream, error) {
	return c.conn.OpenStreamSync(ctx)
}

func (c *Conn) OpenUniStream() (*quic.SendStream, error) {
	return c.conn.OpenUniStream()
}

func (c *Conn) OpenUniStreamSync(ctx context.Context) (*quic.SendStream, error) {
	return c.conn.OpenUniStreamSync(ctx)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) HandshakeComplete() <-chan struct{} {
	return c.conn.HandshakeComplete()
}

func (c *Conn) ConnectionState() quic.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *Conn) onIdleTimer() {
	c.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "idle timeout")
}

func (c *Conn) clearStream(id quic.StreamID) {
	c.streamMx.Lock()
	defer c.streamMx.Unlock()

	delete(c.streams, id)
	if c.idleTimeout > 0 && len(c.streams) == 0 {
		c.idleTimer.Reset(c.idleTimeout)
	}
	// The server is performing a graceful shutdown.
	// If no more streams are remaining, close the connection.
	if c.maxStreamID != invalidStreamID {
		if len(c.streams) == 0 {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "")
		}
	}
}

func (c *Conn) openRequestStream(
	ctx context.Context,
	requestWriter *requestWriter,
	reqDone chan<- struct{},
	disableCompression bool,
	maxHeaderBytes int,
) (*RequestStream, error) {
	c.streamMx.Lock()
	maxStreamID := c.maxStreamID
	var nextStreamID quic.StreamID
	if c.lastStreamID == invalidStreamID {
		nextStreamID = 0
	} else {
		nextStreamID = c.lastStreamID + 4
	}
	c.streamMx.Unlock()
	// Streams with stream ID equal to or greater than the stream ID carried in the GOAWAY frame
	// will be rejected, see section 5.2 of RFC 9114.
	if maxStreamID != invalidStreamID && nextStreamID >= maxStreamID {
		return nil, errGoAway
	}

	str, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	hstr := newStateTrackingStream(str, c, func(b []byte) error { return c.sendDatagram(str.StreamID(), b) })
	c.streamMx.Lock()
	c.streams[str.StreamID()] = hstr
	c.lastStreamID = str.StreamID()
	c.streamMx.Unlock()
	rsp := &http.Response{}
	trace := httptrace.ContextClientTrace(ctx)
	rs := newRequestStream(
		newStream(hstr, c, trace, func(r io.Reader, hf *headersFrame) error {
			hdr, err := c.decodeTrailers(r, str.StreamID(), hf, maxHeaderBytes, ctx)
			if err != nil {
				return err
			}
			rsp.Trailer = hdr
			return nil
		}, c.qlogger),
		requestWriter,
		reqDone,
		c.decoder,
		disableCompression,
		maxHeaderBytes,
		rsp,
	)
	rs.qpack = c.qpack
	rs.decodeContext, rs.cancelDecode = context.WithCancel(ctx)
	hstr.decodeCancel = rs.cancelDecode
	return rs, nil
}

func (c *Conn) decodeTrailers(r io.Reader, streamID quic.StreamID, hf *headersFrame, maxHeaderBytes int, contexts ...context.Context) (http.Header, error) {
	// If maxHeaderBytes is negative, don't enforce limit (used when not sending SETTINGS_MAX_FIELD_SECTION_SIZE)
	if maxHeaderBytes >= 0 && hf.Length > uint64(maxHeaderBytes) {
		maybeQlogInvalidHeadersFrame(c.qlogger, streamID, hf.Length)
		return nil, fmt.Errorf("http3: HEADERS frame too large: %d bytes (max: %d)", hf.Length, maxHeaderBytes)
	}

	b := make([]byte, hf.Length)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	decodeFn := c.decoder.Decode(b)
	if c.qpack != nil {
		ctx := c.Context()
		if len(contexts) > 0 {
			ctx = contexts[0]
		}
		decodeFn = c.qpack.decode(ctx, streamID, b, maxHeaderBytes)
	}
	var fields []qpack.HeaderField
	if c.qlogger != nil {
		fields = make([]qpack.HeaderField, 0, 16)
	}
	trailers, err := parseTrailers(decodeFn, &fields)
	if err != nil {
		maybeQlogInvalidHeadersFrame(c.qlogger, streamID, hf.Length)
		return nil, err
	}
	if c.qlogger != nil {
		qlogParsedHeadersFrame(c.qlogger, streamID, hf, fields)
	}
	return trailers, nil
}

// only used by the server
func (c *Conn) acceptStream(ctx context.Context) (*stateTrackingStream, error) {
	str, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	strID := str.StreamID()
	hstr := newStateTrackingStream(str, c, func(b []byte) error { return c.sendDatagram(strID, b) })
	c.streamMx.Lock()
	c.streams[strID] = hstr
	if c.idleTimeout > 0 {
		if len(c.streams) == 1 {
			c.idleTimer.Stop()
		}
	}
	c.streamMx.Unlock()
	return hstr, nil
}

func (c *Conn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	return c.conn.CloseWithError(code, msg)
}

func (c *Conn) handleUnidirectionalStreams(hijack func(StreamType, quic.ConnectionTracingID, *quic.ReceiveStream, error) (hijacked bool)) {
	var (
		rcvdControlStr      atomic.Bool
		rcvdQPACKEncoderStr atomic.Bool
		rcvdQPACKDecoderStr atomic.Bool
	)

	for {
		str, err := c.conn.AcceptUniStream(context.Background())
		if err != nil {
			if c.logger != nil {
				c.logger.Debug("accepting unidirectional stream failed", "error", err)
			}
			return
		}

		go func(str *quic.ReceiveStream) {
			streamType, err := quicvarint.Read(quicvarint.NewReader(str))
			if err != nil {
				id := c.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
				if hijack != nil && hijack(StreamType(streamType), id, str, err) {
					return
				}
				if c.logger != nil {
					c.logger.Debug("reading stream type on stream failed", "stream ID", str.StreamID(), "error", err)
				}
				return
			}
			// We're only interested in the control stream here.
			switch streamType {
			case streamTypeControlStream:
			case streamTypeQPACKEncoderStream:
				if isFirst := rcvdQPACKEncoderStr.CompareAndSwap(false, true); !isFirst {
					c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK encoder stream")
				}
				if c.qpack != nil {
					c.qpack.receive(str, true)
				}
				return
			case streamTypeQPACKDecoderStream:
				if isFirst := rcvdQPACKDecoderStr.CompareAndSwap(false, true); !isFirst {
					c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate QPACK decoder stream")
				}
				if c.qpack != nil {
					c.qpack.receive(str, false)
				}
				return
			case streamTypePushStream:
				if c.isServer {
					// only the server can push
					c.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "")
				} else {
					// we never increased the Push ID, so we don't expect any push streams
					c.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
				}
				return
			default:
				if hijack != nil {
					if hijack(
						StreamType(streamType),
						c.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID),
						str,
						nil,
					) {
						return
					}
				}
				str.CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
				return
			}
			// Only a single control stream is allowed.
			if isFirstControlStr := rcvdControlStr.CompareAndSwap(false, true); !isFirstControlStr {
				c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeStreamCreationError), "duplicate control stream")
				return
			}
			c.handleControlStream(str)
		}(str)
	}
}

func (c *Conn) handleControlStream(str *quic.ReceiveStream) {
	fp := &frameParser{closeConn: c.conn.CloseWithError, r: str, streamID: str.StreamID(), booleansAsSaid: c.alps != nil}
	f, err := fp.ParseNext(c.qlogger)
	if err != nil {
		var serr *quic.StreamError
		if err == io.EOF || errors.As(err, &serr) {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
			return
		}
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
		return
	}
	sf, ok := f.(*settingsFrame)
	if !ok {
		c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeMissingSettings), "")
		return
	}
	c.settings = &Settings{
		EnableDatagrams:       sf.Datagram,
		EnableExtendedConnect: sf.ExtendedConnect,
		Other:                 sf.Other,
	}
	if c.alps != nil {
		// after what ALPS gave, which the handshake that let this stream come
		// has: the settings held to it, then the encoder told what both say
		c.alps.take(c.conn.ConnectionState())
		if p := c.alps.peer.control(settingsSaid(sf)); p != nil {
			c.closeFor(p)
			return
		}
		if c.qpack != nil {
			c.qpack.encoder.configure(c.alps.peer.capacity, c.alps.peer.blocked)
		}
	} else if c.qpack != nil {
		c.qpack.encoder.configure(sf.Other[1], sf.Other[7])
	}
	close(c.receivedSettings)
	if sf.Datagram {
		// If datagram support was enabled on our side as well as on the server side,
		// we can expect it to have been negotiated both on the transport and on the HTTP/3 layer.
		// Note: ConnectionState() will block until the handshake is complete (relevant when using 0-RTT).
		if c.enableDatagrams && !c.ConnectionState().SupportsDatagrams {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeSettingsError), "missing QUIC Datagram support")
			return
		}
		go func() {
			if err := c.receiveDatagrams(); err != nil {
				if c.logger != nil {
					c.logger.Debug("receiving datagrams failed", "error", err)
				}
			}
		}()
	}

	// we don't support server push, hence we don't expect any GOAWAY frames from the client
	if c.isServer {
		return
	}

	for {
		f, err := fp.ParseNext(c.qlogger)
		if err != nil {
			var serr *quic.StreamError
			if err == io.EOF || errors.As(err, &serr) {
				c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), "")
				return
			}
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameError), "")
			return
		}
		// GOAWAY is the only frame allowed at this point:
		// * unexpected frames are ignored by the frame parser
		// * we don't support any extension that might add support for more frames
		goaway, ok := f.(*goAwayFrame)
		if !ok {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return
		}
		if goaway.StreamID%4 != 0 { // client-initiated, bidirectional streams
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
			return
		}
		c.streamMx.Lock()
		if c.maxStreamID != invalidStreamID && goaway.StreamID > c.maxStreamID {
			c.streamMx.Unlock()
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeIDError), "")
			return
		}
		c.maxStreamID = goaway.StreamID
		hasActiveStreams := len(c.streams) > 0
		c.streamMx.Unlock()

		// immediately close the connection if there are currently no active requests
		if !hasActiveStreams {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "")
			return
		}
	}
}

func (c *Conn) sendDatagram(streamID quic.StreamID, b []byte) error {
	// TODO: this creates a lot of garbage and an additional copy
	data := make([]byte, 0, len(b)+8)
	quarterStreamID := uint64(streamID / 4)
	data = quicvarint.Append(data, uint64(streamID/4))
	data = append(data, b...)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.DatagramCreated{
			QuaterStreamID: quarterStreamID,
			Raw: qlog.RawInfo{
				Length:        len(data),
				PayloadLength: len(b),
			},
		})
	}
	return c.conn.SendDatagram(data)
}

func (c *Conn) receiveDatagrams() error {
	for {
		b, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		quarterStreamID, n, err := quicvarint.Parse(b)
		if err != nil {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("could not read quarter stream id: %w", err)
		}
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.DatagramParsed{
				QuaterStreamID: quarterStreamID,
				Raw: qlog.RawInfo{
					Length:        len(b),
					PayloadLength: len(b) - n,
				},
			})
		}
		if quarterStreamID > maxQuarterStreamID {
			c.CloseWithError(quic.ApplicationErrorCode(ErrCodeDatagramError), "")
			return fmt.Errorf("invalid quarter stream id: %w", err)
		}
		streamID := quic.StreamID(4 * quarterStreamID)
		c.streamMx.Lock()
		dg, ok := c.streams[streamID]
		c.streamMx.Unlock()
		if !ok {
			continue
		}
		dg.enqueueDatagram(b[n:])
	}
}

// ReceivedSettings returns a channel that is closed once the peer's SETTINGS frame was received.
// Settings can be optained from the Settings method after the channel was closed.
func (c *Conn) ReceivedSettings() <-chan struct{} { return c.receivedSettings }

// Settings returns the settings received on this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *Conn) Settings() *Settings { return c.settings }

// Context returns the context of the underlying QUIC connection.
func (c *Conn) Context() context.Context { return c.ctx }

// closeFor closes the connection for a problem with what the server said,
// as the profile says (closeFor in alps.go).
func (c *Conn) closeFor(p *alpsProblem) {
	switch e := closeFor(c.alps.policy, p).(type) {
	case *quic.TransportError:
		c.conn.CloseWithTransportError(e.ErrorCode, e.FrameType, e.ErrorMessage)
	case *quic.ApplicationError:
		c.conn.CloseWithError(e.ErrorCode, e.ErrorMessage)
	}
}

// settingsSaid are the settings a received SETTINGS frame said: the field
// section, the two booleans, then the rest by identifier (the frame keeps
// no order of its own).
func settingsSaid(sf *settingsFrame) [][2]uint64 {
	var said [][2]uint64
	if sf.MaxFieldSectionSize >= 0 {
		said = append(said, [2]uint64{settingMaxFieldSectionSize, uint64(sf.MaxFieldSectionSize)})
	}
	if sf.ExtendedConnectSaid != nil {
		said = append(said, [2]uint64{settingExtendedConnect, *sf.ExtendedConnectSaid})
	}
	if sf.DatagramSaid != nil {
		said = append(said, [2]uint64{settingDatagram, *sf.DatagramSaid})
	}
	ids := make([]uint64, 0, len(sf.Other))
	for id := range sf.Other {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		said = append(said, [2]uint64{id, sf.Other[id]})
	}
	return said
}
