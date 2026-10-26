package http3

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"log/slog"
	"maps"
	"net/textproto"
	"strings"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3/qlog"
	"github.com/igor-lemon/quic-go-utls/quicvarint"

	"github.com/quic-go/qpack"
)

const (
	// MethodGet0RTT allows a GET request to be sent using 0-RTT.
	// Note that 0-RTT doesn't provide replay protection and should only be used for idempotent requests.
	MethodGet0RTT = "GET_0RTT"
	// MethodHead0RTT allows a HEAD request to be sent using 0-RTT.
	// Note that 0-RTT doesn't provide replay protection and should only be used for idempotent requests.
	MethodHead0RTT = "HEAD_0RTT"
)

const (
	defaultUserAgent              = "quic-go HTTP/3"
	defaultMaxResponseHeaderBytes = 10 * 1 << 20 // 10 MB
)

type errConnUnusable struct{ e error }

func (e *errConnUnusable) Unwrap() error { return e.e }
func (e *errConnUnusable) Error() string { return fmt.Sprintf("http3: conn unusable: %s", e.e.Error()) }

const max1xxResponses = 5 // arbitrary bound on number of informational responses

var defaultQuicConfig = &quic.Config{
	MaxIncomingStreams: -1, // don't allow the server to create bidirectional streams
	KeepAlivePeriod:    10 * time.Second,
}

// ClientConn is an HTTP/3 client doing requests to a single remote server.
type ClientConn struct {
	behavior behavior.Policy
	conn     *Conn

	// Requests wait until the local control stream preface and SETTINGS are queued.
	// This is a protocol ordering barrier, independent of browser policy.
	setupComplete chan struct{}
	setupErr      error
	controlStream *quic.SendStream
	controlWrite  chan struct{}

	// Enable support for HTTP/3 datagrams (RFC 9297).
	// If a QUICConfig is set, datagram support also needs to be enabled on the QUIC layer by setting enableDatagrams.
	enableDatagrams bool

	// Additional HTTP/3 settings.
	// It is invalid to specify any settings defined by RFC 9114 (HTTP/3) and RFC 9297 (HTTP Datagrams).
	additionalSettings map[uint64]uint64

	// Order in which to send additional settings
	additionalSettingsOrder []uint64

	// Pseudo-header order for HTTP/3 requests
	pseudoHeaderOrder []string

	// sendGreaseFrames, if true, sends GREASE frames on the HTTP/3 control stream.
	// Chrome sends GREASE frames to maintain protocol extensibility.
	sendGreaseFrames bool

	// priorityParam specifies the PRIORITY header field value to send with requests.
	// If 0, no PRIORITY header is sent.
	priorityParam uint32

	// maxResponseHeaderBytes specifies a limit on how many response bytes are
	// allowed in the server's response header.
	maxResponseHeaderBytes int

	// disableCompression, if true, prevents the Transport from requesting compression with an
	// "Accept-Encoding: gzip" request header when the Request contains no existing Accept-Encoding value.
	// If the Transport requests gzip on its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body.
	// However, if the user explicitly requested gzip it is not automatically uncompressed.
	disableCompression bool

	logger *slog.Logger

	requestWriter *requestWriter
	decoder       *qpack.Decoder
}

var _ http.RoundTripper = &ClientConn{}

func newClientConn(
	conn *quic.Conn,
	enableDatagrams bool,
	additionalSettings map[uint64]uint64,
	additionalSettingsOrder []uint64,
	pseudoHeaderOrder []string,
	sendGreaseFrames bool,
	priorityParam uint32,
	streamHijacker func(FrameType, quic.ConnectionTracingID, *quic.Stream, error) (hijacked bool, err error),
	uniStreamHijacker func(StreamType, quic.ConnectionTracingID, *quic.ReceiveStream, error) (hijacked bool),
	maxResponseHeaderBytes int,
	disableCompression bool,
	logger *slog.Logger,
	policies ...behavior.Policy,
) *ClientConn {
	pol := behavior.Legacy()
	if len(policies) > 0 && policies[0] != nil {
		pol = policies[0]
	}
	c := &ClientConn{
		behavior:                pol,
		setupComplete:           make(chan struct{}),
		controlWrite:            make(chan struct{}, 1),
		enableDatagrams:         enableDatagrams,
		additionalSettings:      additionalSettings,
		additionalSettingsOrder: additionalSettingsOrder,
		pseudoHeaderOrder:       pseudoHeaderOrder,
		sendGreaseFrames:        sendGreaseFrames,
		priorityParam:           priorityParam,
		disableCompression:      disableCompression,
		logger:                  logger,
	}
	if maxResponseHeaderBytes < 0 {
		// Negative value means don't send SETTINGS_MAX_FIELD_SECTION_SIZE
		// But use default for receiving (to avoid abortion)
		c.maxResponseHeaderBytes = -1
	} else if maxResponseHeaderBytes == 0 {
		// Zero means use default
		c.maxResponseHeaderBytes = defaultMaxResponseHeaderBytes
	} else {
		c.maxResponseHeaderBytes = maxResponseHeaderBytes
	}
	c.decoder = qpack.NewDecoder()
	c.requestWriter = newRequestWriterWithPseudoHeaderOrder(c.pseudoHeaderOrder, c.priorityParam)
	c.requestWriter.behavior = pol
	c.requestWriter.beforeHeaders = c.sendRequestPriority
	c.conn = newConnection(
		conn.Context(),
		conn,
		c.enableDatagrams,
		false, // client
		c.logger,
		0,
	)
	c.conn.qpack = newQPACKSession(c.conn, additionalSettings, pol)
	c.requestWriter.dynamic = c.conn.qpack.encoder
	c.requestWriter.instructions = c.conn.qpack.encoderWriter
	if pol.Text("h3.peer_settings") == "quiche" {
		encoder := c.conn.qpack.encoder
		// taken before the first request is written (roundTrip), or as the
		// control stream's SETTINGS come (handleControlStream)
		c.conn.alps = newALPSState(pol, encoder.configureEarly)
	}
	// send the SETTINGs frame, using 0-RTT data, if possible
	opened := pol.Text("h3.control_stream") == "with-finished"
	var openErr error
	if opened {
		// written now, which Transport.dial makes happen on the QUIC
		// connection's own goroutine as its handshake completes: the control
		// stream goes with the client's Finished, as quiche's
		// QuicSpdySession::SendInitialData sends it once encryption is
		// established; anything that waits for the connection stays below
		openErr = c.openControlStream()
	}
	go func() {
		c.setupErr = c.setupConn(opened, openErr)
		close(c.setupComplete)
		if err := c.setupErr; err != nil {
			if c.logger != nil {
				c.logger.Debug("Setting up connection failed", "error", err)
			}
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "")
		}
	}()
	if streamHijacker != nil {
		go c.handleBidirectionalStreams(streamHijacker)
	}
	go c.conn.handleUnidirectionalStreams(uniStreamHijacker)
	return c
}

// OpenRequestStream opens a new request stream on the HTTP/3 connection.
func (c *ClientConn) OpenRequestStream(ctx context.Context) (*RequestStream, error) {
	if err := c.waitForSetup(ctx); err != nil {
		return nil, err
	}
	return c.conn.openRequestStream(ctx, c.requestWriter, nil, c.disableCompression, c.maxResponseHeaderBytes)
}

// waitForSetup waits for local initialization, never for peer SETTINGS or an ACK.
// Closing setupComplete publishes setupErr and the completed stream Write, whose
// onHasStreamData callback enqueues the control stream before any request stream.
func (c *ClientConn) waitForSetup(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	select {
	case <-c.setupComplete:
		return c.setupErr
	case <-ctx.Done():
		return ctx.Err()
	case <-c.conn.Context().Done():
		return context.Cause(c.conn.Context())
	}
}

// setupConn opens the control stream, unless it was (opened, failing with
// err), and then the QPACK streams.
func (c *ClientConn) setupConn(opened bool, err error) error {
	if !opened {
		err = c.openControlStream()
	}
	if err == nil {
		switch c.behavior.Text("h3.qpack.streams") {
		case "eager":
			err = c.conn.qpack.startEager()
		case "deferred":
			err = c.conn.qpack.startDeferred()
		}
	}
	return err
}

// openControlStream opens the control stream and writes what it begins with:
// its type, the SETTINGS, and the frames h3.control_order puts after them.
// It waits for nothing: the stream is opened only where the server allows
// one, and so little is written that the stream keeps it all for sending.
func (c *ClientConn) openControlStream() error {
	if c.additionalSettings[1] > qpackTableSafetyLimit || c.additionalSettings[7] > qpackBlockedSafetyLimit {
		return errors.New("QPACK settings exceed engine safety bounds")
	}
	// open the control stream
	str, err := c.conn.OpenUniStream()
	if err != nil {
		return err
	}
	b := make([]byte, 0, 64)
	b = quicvarint.Append(b, streamTypeControlStream)
	// send the SETTINGS frame
	b = (&settingsFrame{
		Datagram:            c.enableDatagrams,
		Other:               c.additionalSettings,
		OtherOrder:          c.additionalSettingsOrder,
		MaxFieldSectionSize: int64(c.maxResponseHeaderBytes),
	}).Append(b)
	if c.conn.qlogger != nil {
		sf := qlog.SettingsFrame{
			MaxFieldSectionSize: int64(c.maxResponseHeaderBytes),
			Other:               maps.Clone(c.additionalSettings),
		}
		if c.enableDatagrams {
			sf.Datagram = pointer(true)
		}
		c.conn.qlogger.RecordEvent(qlog.FrameCreated{
			StreamID: str.StreamID(),
			Raw:      qlog.RawInfo{Length: len(b)},
			Frame:    qlog.Frame{Frame: sf},
		})
	}

	// SETTINGS was already encoded first. Every following initial frame and
	// its order is selected by the explicit policy, not a browser-name branch.
	for _, component := range c.behavior.Strings("h3.control_order")[1:] {
		switch component {
		case "priority":
			if c.priorityParam > 0 && c.behavior.Text("h3.priority_updates") == "initial" {
				b = appendPriorityUpdateFrameForStream(b, c.priorityParam, 0, c.behavior.Text("h3.priority_value"))
			}
		case "grease":
			if c.sendGreaseFrames {
				b = appendGreaseFramePolicy(b, c.behavior)
			}
		}
	}
	c.controlStream = str

	_, err = str.Write(b)
	return err
}

// appendGreaseFrame appends a GREASE frame to the buffer.
// GREASE frames help maintain protocol extensibility by sending unknown frame types.
// Chrome sends GREASE frames on the control stream after SETTINGS.
func appendGreaseFrame(b []byte) []byte { return appendGreaseFramePolicy(b, behavior.Legacy()) }
func appendGreaseFramePolicy(b []byte, pol behavior.Policy) []byte {
	frameType := generateGREASEFrameTypePolicy(pol)
	lengths := pol.Numbers("h3.grease_payload_lengths")
	// The selector deliberately retains the relationship with the frame's N.
	// Independently drawing a legal length would lose this observable relation.
	n := (frameType - 33) / 31
	length := lengths[n%uint64(len(lengths))]
	b = quicvarint.Append(b, frameType)
	b = quicvarint.Append(b, length)
	start := len(b)
	b = append(b, make([]byte, int(length))...)
	if _, err := cryptorand.Read(b[start:]); err != nil {
		panic(err)
	}

	return b
}

// generateGREASEFrameType generates a GREASE frame type.
// GREASE frame types are of the form 0x1f * N + 0x21 where N is a large random number.
func generateGREASEFrameType() uint64 { return generateGREASEFrameTypePolicy(behavior.Legacy()) }
func generateGREASEFrameTypePolicy(pol behavior.Policy) uint64 {
	var draw [8]byte
	if _, err := cryptorand.Read(draw[:]); err != nil {
		panic(err)
	}
	bits := pol.Uint("h3.grease_frame_n_bits")
	n := binary.BigEndian.Uint64(draw[:]) & ((uint64(1) << bits) - 1)
	return 31*n + 33
}

// appendPriorityUpdateFrame appends a PRIORITY_UPDATE frame to the buffer.
// Chrome sends priority information on the control stream.
// Frame type and field value are supplied by the profile.
func appendPriorityUpdateFrame(b []byte, priorityParam uint32) []byte {
	return appendPriorityUpdateFramePolicy(b, priorityParam, behavior.Legacy().Text("h3.priority_value"))
}
func appendPriorityUpdateFramePolicy(b []byte, priorityParam uint32, value string) []byte {
	return appendPriorityUpdateFrameForStream(b, priorityParam, 0, value)
}
func appendPriorityUpdateFrameForStream(b []byte, priorityParam uint32, streamID quic.StreamID, value string) []byte {
	// The configured request PRIORITY_UPDATE frame type.
	frameType := uint64(priorityParam)

	// Build payload: prioritized_stream_id + priority_field_value
	priorityPayload := make([]byte, 0, 16)

	// The live request stream, including later requests on the same connection.
	priorityPayload = quicvarint.Append(priorityPayload, uint64(streamID))

	// The current priority field value.
	priorityPayload = append(priorityPayload, []byte(value)...)

	// Append frame type
	b = quicvarint.Append(b, frameType)

	// Append frame length
	b = quicvarint.Append(b, uint64(len(priorityPayload)))

	// Append payload
	b = append(b, priorityPayload...)

	return b
}

func (c *ClientConn) handleBidirectionalStreams(streamHijacker func(FrameType, quic.ConnectionTracingID, *quic.Stream, error) (hijacked bool, err error)) {
	for {
		str, err := c.conn.conn.AcceptStream(context.Background())
		if err != nil {
			if c.logger != nil {
				c.logger.Debug("accepting bidirectional stream failed", "error", err)
			}
			return
		}
		fp := &frameParser{
			r:         str,
			closeConn: c.conn.CloseWithError,
			unknownFrameHandler: func(ft FrameType, e error) (processed bool, err error) {
				id := c.conn.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
				return streamHijacker(ft, id, str, e)
			},
		}
		go func() {
			if _, err := fp.ParseNext(c.conn.qlogger); err == errHijacked {
				return
			}
			if err != nil {
				if c.logger != nil {
					c.logger.Debug("error handling stream", "error", err)
				}
			}
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "received HTTP/3 frame on bidirectional stream")
		}()
	}
}

// RoundTrip executes a request and returns a response
func (c *ClientConn) RoundTrip(req *http.Request) (*http.Response, error) {
	rsp, err := c.roundTrip(req)
	if err != nil && req.Context().Err() != nil {
		// if the context was canceled, return the context cancellation error
		err = req.Context().Err()
	}
	return rsp, err
}

func (c *ClientConn) roundTrip(req *http.Request) (*http.Response, error) {
	if err := c.waitForSetup(req.Context()); err != nil {
		return nil, &errConnUnusable{e: err}
	}
	// Immediately send out this request, if this is a 0-RTT request.
	switch req.Method {
	case MethodGet0RTT:
		// don't modify the original request
		reqCopy := *req
		req = &reqCopy
		req.Method = http.MethodGet
	case MethodHead0RTT:
		// don't modify the original request
		reqCopy := *req
		req = &reqCopy
		req.Method = http.MethodHead
	default:
		// wait for the handshake to complete
		select {
		case <-c.conn.HandshakeComplete():
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		if c.conn.alps != nil {
			// ALPS's settings before the request is written
			c.conn.alps.take(c.conn.ConnectionState())
		}
	}

	// It is only possible to send an Extended CONNECT request once the SETTINGS were received.
	// See section 3 of RFC 8441.
	if isExtendedConnectRequest(req) {
		connCtx := c.conn.Context()
		// wait for the server's SETTINGS frame to arrive
		select {
		case <-c.conn.ReceivedSettings():
		case <-connCtx.Done():
			return nil, context.Cause(connCtx)
		}
		if !c.conn.Settings().EnableExtendedConnect {
			return nil, errors.New("http3: server didn't enable Extended CONNECT")
		}
	}

	reqDone := make(chan struct{})
	str, err := c.conn.openRequestStream(
		req.Context(),
		c.requestWriter,
		reqDone,
		c.disableCompression,
		c.maxResponseHeaderBytes,
	)
	if err != nil {
		return nil, &errConnUnusable{e: err}
	}

	// Request Cancellation:
	// This go routine keeps running even after RoundTripOpt() returns.
	// It is shut down when the application is done processing the body.
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-req.Context().Done():
			str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
			str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
		case <-reqDone:
		}
	}()

	rsp, err := c.doRequest(req, str)
	if err != nil { // if any error occurred
		close(reqDone)
		<-done
		return nil, maybeReplaceError(err)
	}
	return rsp, maybeReplaceError(err)
}

// ReceivedSettings returns a channel that is closed once the server's HTTP/3 settings were received.
// Settings can be obtained from the Settings method after the channel was closed.
func (c *ClientConn) ReceivedSettings() <-chan struct{} {
	return c.conn.ReceivedSettings()
}

// Settings returns the HTTP/3 settings for this connection.
// It is only valid to call this function after the channel returned by ReceivedSettings was closed.
func (c *ClientConn) Settings() *Settings {
	return c.conn.Settings()
}

// CloseWithError closes the connection with the given error code and message.
// It is invalid to call this function after the connection was closed.
func (c *ClientConn) CloseWithError(code ErrCode, msg string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// Context returns a context that is cancelled when the connection is closed.
func (c *ClientConn) Context() context.Context {
	return c.conn.Context()
}

// cancelingReader reads from the io.Reader.
// It cancels writing on the stream if any error other than io.EOF occurs.
type cancelingReader struct {
	r   io.Reader
	str *RequestStream
}

func (r *cancelingReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	if err != nil && err != io.EOF {
		r.str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
	}
	return n, err
}

func (c *ClientConn) sendRequestBody(str *RequestStream, body io.ReadCloser, contentLength int64) error {
	defer body.Close()
	buf := make([]byte, c.behavior.Int("h3.body_copy_bytes"))
	sr := &cancelingReader{str: str, r: body}
	if contentLength == -1 {
		_, err := io.CopyBuffer(str, sr, buf)
		return err
	}

	// make sure we don't send more bytes than the content length
	n, err := io.CopyBuffer(str, io.LimitReader(sr, contentLength), buf)
	if err != nil {
		return err
	}
	var extra int64
	extra, err = io.CopyBuffer(io.Discard, sr, buf)
	n += extra
	if n > contentLength {
		str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
		return fmt.Errorf("http: ContentLength=%d with Body length %d", contentLength, n)
	}
	return err
}

func (c *ClientConn) doRequest(req *http.Request, str *RequestStream) (*http.Response, error) {
	trace := httptrace.ContextClientTrace(req.Context())
	// the request's writes, its FIN among them when it has no body, go out
	// together when its profile says so
	bundle := str.bundleWrites()
	var sendingReqFailed bool
	if err := str.sendRequestHeader(req); err != nil {
		traceWroteRequest(trace, err)
		if c.logger != nil {
			c.logger.Debug("error writing request", "error", err)
		}
		sendingReqFailed = true
	}
	if !sendingReqFailed && req.Body == nil {
		traceWroteRequest(trace, nil)
		str.Close()
	}
	if bundle != nil {
		// before the body, which no write of the bundle waits for
		bundle.Flush()
	}
	if !sendingReqFailed && req.Body != nil {
		// send the request body asynchronously
		go func() {
			contentLength := int64(-1)
			// According to the documentation for http.Request.ContentLength,
			// a value of 0 with a non-nil Body is also treated as unknown content length.
			if req.ContentLength > 0 {
				contentLength = req.ContentLength
			}
			err := c.sendRequestBody(str, req.Body, contentLength)
			traceWroteRequest(trace, err)
			if err != nil {
				if c.logger != nil {
					c.logger.Debug("error writing request", "error", err)
				}
			}
			str.Close()
		}()
	}

	// copy from net/http: support 1xx responses
	var num1xx int // number of informational 1xx headers received
	var res *http.Response
	for {
		var err error
		res, err = str.ReadResponse()
		if err != nil {
			return nil, err
		}
		resCode := res.StatusCode
		is1xx := 100 <= resCode && resCode <= 199
		// treat 101 as a terminal status, see https://github.com/golang/go/issues/26161
		is1xxNonTerminal := is1xx && resCode != http.StatusSwitchingProtocols
		if is1xxNonTerminal {
			num1xx++
			if num1xx > max1xxResponses {
				str.CancelRead(quic.StreamErrorCode(ErrCodeExcessiveLoad))
				str.CancelWrite(quic.StreamErrorCode(ErrCodeExcessiveLoad))
				return nil, errors.New("http3: too many 1xx informational responses")
			}
			traceGot1xxResponse(trace, resCode, textproto.MIMEHeader(res.Header))
			if resCode == http.StatusContinue {
				traceGot100Continue(trace)
			}
			continue
		}
		break
	}
	connState := c.conn.ConnectionState().TLS
	res.TLS = &connState
	res.Request = req
	return res, nil
}

// Conn returns the underlying HTTP/3 connection.
// This method is only useful for advanced use cases, such as when the application needs to
// open streams on the HTTP/3 connection (e.g. WebTransport).
func (c *ClientConn) Conn() *Conn {
	return c.conn
}

// sendRequestPriority runs outside the QPACK/header locks, on both RoundTrip
// and OpenRequestStream/SendRequestHeader. A canceled caller never closes the
// connection's critical stream. At most one bounded frame write is in flight;
// flow control cannot create an unbounded writer queue or block a table lock.
func (c *ClientConn) sendRequestPriority(req *http.Request, streamID quic.StreamID) error {
	if c.priorityParam == 0 || c.behavior.Text("h3.priority_updates") != "per-request" {
		return nil
	}
	value := c.behavior.Text("h3.priority_value")
	if c.behavior.Text("h3.priority_source") == "header" {
		for name, values := range req.Header {
			if strings.EqualFold(name, "priority") && len(values) > 0 {
				value = strings.Join(values, ", ")
				break
			}
		}
	}
	if strings.ContainsAny(value, "\r\n\x00") || len(value) > c.maxPriorityBytes() {
		return errors.New("http3: invalid priority field")
	}
	if err := req.Context().Err(); err != nil {
		return err
	}
	select {
	case c.controlWrite <- struct{}{}:
	case <-req.Context().Done():
		return req.Context().Err()
	case <-c.conn.Context().Done():
		return context.Cause(c.conn.Context())
	}
	if err := req.Context().Err(); err != nil {
		<-c.controlWrite
		return err
	}
	b := appendPriorityUpdateFrameForStream(nil, c.priorityParam, streamID, value)
	done := make(chan error, 1)
	go func() {
		_, err := c.controlStream.Write(b)
		if err != nil {
			c.conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "")
		}
		<-c.controlWrite
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-req.Context().Done():
		return req.Context().Err()
	case <-c.conn.Context().Done():
		return context.Cause(c.conn.Context())
	}
}

// This is an engine resource ceiling, not an emulated browser preference.
func (c *ClientConn) maxPriorityBytes() int { return 16 << 10 }
