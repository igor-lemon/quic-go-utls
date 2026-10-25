package http3

import (
	"context"
	"errors"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/http/httpguts"

	"github.com/igor-lemon/quic-go-utls"
)

// Settings are HTTP/3 settings that apply to the underlying connection.
type Settings struct {
	// Support for HTTP/3 datagrams (RFC 9297)
	EnableDatagrams bool
	// Extended CONNECT, RFC 9220
	EnableExtendedConnect bool
	// Other settings, defined by the application
	Other map[uint64]uint64
}

// RoundTripOpt are options for the Transport.RoundTripOpt method.
type RoundTripOpt struct {
	// OnlyCachedConn controls whether the Transport may create a new QUIC connection.
	// If set true and no cached connection is available, RoundTripOpt will return ErrNoCachedConn.
	OnlyCachedConn bool
}

type clientConn interface {
	OpenRequestStream(context.Context) (*RequestStream, error)
	RoundTrip(*http.Request) (*http.Response, error)
}

type roundTripperWithCount struct {
	cancel     context.CancelFunc
	dialing    chan struct{} // closed as soon as quic.Dial(Early) returned
	dialErr    error
	conn       *quic.Conn
	clientConn clientConn

	useCount atomic.Int64
}

// gone says whether r's connection was made and has gone away since.
func (r *roundTripperWithCount) gone() bool {
	select {
	case <-r.dialing:
		return r.dialErr == nil && r.conn.Context().Err() != nil
	default:
		return false
	}
}

func (r *roundTripperWithCount) Close() error {
	r.cancel()
	<-r.dialing
	if r.conn != nil {
		return r.conn.CloseWithError(0, "")
	}
	return nil
}

// Transport implements the http.RoundTripper interface
type Transport struct {
	Behavior behavior.Policy
	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// QUICConfig is the quic.Config used for dialing new connections.
	// If nil, reasonable default values will be used.
	QUICConfig *quic.Config

	// Dial specifies an optional dial function for creating QUIC
	// connections for requests.
	// If Dial is nil, a UDPConn will be created at the first request
	// and will be reused for subsequent connections to other servers.
	Dial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)

	// Enable support for HTTP/3 datagrams (RFC 9297).
	// If a QUICConfig is set, datagram support also needs to be enabled on the QUIC layer by setting EnableDatagrams.
	EnableDatagrams bool

	// Additional HTTP/3 settings.
	// It is invalid to specify any settings defined by RFC 9114 (HTTP/3) and RFC 9297 (HTTP Datagrams).
	AdditionalSettings map[uint64]uint64

	// AdditionalSettingsOrder specifies the order in which to send AdditionalSettings.
	// If nil or empty, settings will be sent in random map iteration order.
	AdditionalSettingsOrder []uint64

	// PseudoHeaderOrder specifies the order in which to send pseudo-headers in HTTP/3 requests.
	// If nil or empty, defaults to Chrome-like order: :method, :authority, :scheme, :path
	PseudoHeaderOrder []string

	// SendGreaseFrames, if true, sends GREASE frames on the HTTP/3 control stream.
	// Chrome sends GREASE frames to maintain protocol extensibility.
	SendGreaseFrames bool

	// PriorityParam specifies the PRIORITY header field value to send with requests.
	// Chrome sends this value in HTTP/3 requests to indicate request priority.
	// If 0, no PRIORITY header is sent.
	// Example: Chrome 133 uses 984832
	PriorityParam uint32

	// MaxResponseHeaderBytes specifies a limit on how many response bytes are
	// allowed in the server's response header.
	// Zero means to use a default limit.
	// Set to -1 to disable sending SETTINGS_MAX_FIELD_SECTION_SIZE.
	MaxResponseHeaderBytes int

	// DisableCompression, if true, prevents the Transport from requesting compression with an
	// "Accept-Encoding: gzip" request header when the Request contains no existing Accept-Encoding value.
	// If the Transport requests gzip on its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body.
	// However, if the user explicitly requested gzip it is not automatically uncompressed.
	DisableCompression bool

	StreamHijacker    func(FrameType, quic.ConnectionTracingID, *quic.Stream, error) (hijacked bool, err error)
	UniStreamHijacker func(StreamType, quic.ConnectionTracingID, *quic.ReceiveStream, error) (hijacked bool)

	Logger *slog.Logger

	mutex sync.Mutex

	initOnce sync.Once
	initErr  error

	newClientConn func(*quic.Conn) clientConn

	clients   map[string]*roundTripperWithCount
	transport *quic.Transport
	closed    bool
}

var (
	_ http.RoundTripper = &Transport{}
	_ io.Closer         = &Transport{}
)

var (
	// ErrNoCachedConn is returned when Transport.OnlyCachedConn is set
	ErrNoCachedConn = errors.New("http3: no cached connection was available")
	// ErrTransportClosed is returned when attempting to use a closed Transport
	ErrTransportClosed = errors.New("http3: transport is closed")
)

func (t *Transport) init() error {
	if t.Behavior == nil {
		t.Behavior = behavior.Legacy()
	}
	if t.newClientConn == nil {
		t.newClientConn = func(conn *quic.Conn) clientConn {
			return newClientConn(
				conn,
				t.EnableDatagrams,
				t.AdditionalSettings,
				t.AdditionalSettingsOrder,
				t.PseudoHeaderOrder,
				t.SendGreaseFrames,
				t.PriorityParam,
				t.StreamHijacker,
				t.UniStreamHijacker,
				t.MaxResponseHeaderBytes,
				t.DisableCompression,
				t.Logger,
				t.Behavior.Clone(),
			)
		}
	}
	if t.QUICConfig == nil {
		t.QUICConfig = defaultQuicConfig.Clone()
		t.QUICConfig.EnableDatagrams = t.EnableDatagrams
	}
	if t.Behavior.Has("h3.alps_reader") && t.QUICConfig.VerifyHandshake == nil {
		// what the server gives in ALPS is read as the handshake ends
		t.QUICConfig = t.QUICConfig.Clone()
		t.QUICConfig.VerifyHandshake = VerifyALPS(t.Behavior)
	}
	if t.EnableDatagrams && !t.QUICConfig.EnableDatagrams {
		return errors.New("HTTP Datagrams enabled, but QUIC Datagrams disabled")
	}
	if len(t.QUICConfig.Versions) == 0 {
		t.QUICConfig = t.QUICConfig.Clone()
		t.QUICConfig.Versions = []quic.Version{quic.SupportedVersions()[0]}
	}
	if len(t.QUICConfig.Versions) != 1 {
		return errors.New("can only use a single QUIC version for dialing a HTTP/3 connection")
	}
	if t.QUICConfig.MaxIncomingStreams == 0 {
		t.QUICConfig.MaxIncomingStreams = -1 // don't allow any bidirectional streams
	}
	if t.Dial == nil {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return err
		}
		t.transport = &quic.Transport{Conn: udpConn}
	}
	return nil
}

// Preconnect establishes and caches a verified QUIC connection without sending
// an HTTP request. A caller racing transports selects one before dispatching the
// request, so uploads and side effects are never raced or replayed here.
func (t *Transport) Preconnect(ctx context.Context, addr string) error {
	t.initOnce.Do(func() { t.initErr = t.init() })
	if t.initErr != nil {
		return t.initErr
	}
	cl, _, err := t.getClient(ctx, addr, false)
	if err != nil {
		return err
	}
	defer cl.useCount.Add(-1)
	select {
	case <-cl.dialing:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	if cl.dialErr != nil {
		t.removeClient(addr, cl)
		return cl.dialErr
	}
	select {
	case <-cl.conn.HandshakeComplete():
		return nil
	case <-cl.conn.Context().Done():
		return context.Cause(cl.conn.Context())
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// HasConn says whether t holds a QUIC connection to hostname (host:port) that
// was made and is still up: a request with OnlyCachedConn goes on it rather
// than on a connection of another protocol, as Chromium sends a request on a
// QUIC session it has for the origin. One still being dialed is none yet.
func (t *Transport) HasConn(hostname string) bool {
	t.mutex.Lock()
	cl, ok := t.clients[hostname]
	t.mutex.Unlock()
	if !ok {
		return false
	}
	select {
	case <-cl.dialing:
	default:
		return false
	}
	return cl.dialErr == nil && cl.conn.Context().Err() == nil
}

// RoundTripOpt is like RoundTrip, but takes options.
func (t *Transport) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	rsp, err := t.roundTripOpt(req, opt)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	return rsp, nil
}

func (t *Transport) roundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	t.initOnce.Do(func() { t.initErr = t.init() })
	if t.initErr != nil {
		return nil, t.initErr
	}

	if req.URL == nil {
		return nil, errors.New("http3: nil Request.URL")
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("http3: unsupported protocol scheme: %s", req.URL.Scheme)
	}
	if req.URL.Host == "" {
		return nil, errors.New("http3: no Host in request URL")
	}
	if req.Header == nil {
		return nil, errors.New("http3: nil Request.Header")
	}
	if req.Method != "" && !validMethod(req.Method) {
		return nil, fmt.Errorf("http3: invalid method %q", req.Method)
	}
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			// [http.HeaderOrderKey] magic ordering key is consumed by the request
			// writer to order regular headers.
			// [http.PHeaderOrderKey] is not used for http3 therefore not deleted on
			// this step to avoid req.Header mutation.
			if k == http.HeaderOrderKey || k == http.PHeaderOrderKey {
				continue
			}

			return nil, fmt.Errorf("http3: invalid http header field name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("http3: invalid http header field value %q for key %v", v, k)
			}
		}
	}

	return t.doRoundTripOpt(req, opt, 0)
}

func (t *Transport) doRoundTripOpt(req *http.Request, opt RoundTripOpt, attempt int) (*http.Response, error) {
	hostname := authorityAddr(hostnameFromURL(req.URL))
	trace := httptrace.ContextClientTrace(req.Context())
	traceGetConn(trace, hostname)
	cl, isReused, err := t.getClient(req.Context(), hostname, opt.OnlyCachedConn)
	if err != nil {
		return nil, err
	}

	select {
	case <-cl.dialing:
	case <-req.Context().Done():
		return nil, context.Cause(req.Context())
	}

	if cl.dialErr != nil {
		t.removeClient(hostname, cl)
		return nil, cl.dialErr
	}
	defer cl.useCount.Add(-1)
	var alps *alpsState
	if cc, ok := cl.clientConn.(*ClientConn); ok {
		alps = cc.conn.alps
	}
	traceGotConn(trace, cl.conn, isReused, alps)
	rsp, err := cl.clientConn.RoundTrip(req)
	if err != nil {
		// request aborted due to context cancellation
		select {
		case <-req.Context().Done():
			return nil, err
		default:
		}
		t.removeClient(hostname, cl)
		retryReq, retryErr := (*http.Request)(nil), err
		if attempt < t.Behavior.Int("h3.retry_unprocessed_attempts")-1 {
			retryReq, retryErr = canRetryRequest(err, req)
		}
		if retryErr != nil && attempt < t.Behavior.Int("h3.retry_attempts")-1 && t.retryProtocolError(err, req) {
			retryReq, retryErr = replayH3Request(req)
		}
		req, err = retryReq, retryErr
		if err != nil {
			return nil, err
		}
		return t.doRoundTripOpt(req, opt, attempt+1)
	}
	return rsp, nil
}

// Protocol-error replay is opt-in by method and exact error space/code. It
// happens only before a response is returned; body-read failures never enter it.
func (t *Transport) retryProtocolError(err error, req *http.Request) bool {
	if req.Context().Err() != nil || !slices.Contains(t.Behavior.Strings("h3.retry_methods"), req.Method) {
		return false
	}
	// An explicit profile cannot make a non-idempotent operation safe to replay.
	switch req.Method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
	default:
		return false
	}
	var app *quic.ApplicationError
	var transport *quic.TransportError
	var h3 *Error
	var qp *qpackWireError
	var code uint64
	key := "h3.retry_application_errors"
	switch {
	case errors.As(err, &transport):
		code = uint64(transport.ErrorCode)
		key = "h3.retry_transport_errors"
	case errors.As(err, &app):
		code = uint64(app.ErrorCode)
	case errors.As(err, &h3):
		code = uint64(h3.ErrorCode)
	case errors.As(err, &qp):
		code = uint64(qp.code)
	default:
		return false
	}
	return slices.Contains(t.Behavior.Numbers(key), code)
}
func replayH3Request(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("http3: protocol retry requires a replayable body")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	copy := req.Clone(req.Context())
	copy.Body = body
	return copy, nil
}

func canRetryRequest(err error, req *http.Request) (*http.Request, error) {
	// error occurred while opening the stream, we can be sure that the request wasn't sent out
	var connErr *errConnUnusable
	if errors.As(err, &connErr) {
		return req, nil
	}

	// If the request stream is reset, we can only be sure that the request wasn't processed
	// if the error code is H3_REQUEST_REJECTED.
	var e *Error
	if !errors.As(err, &e) || e.ErrorCode != ErrCodeRequestRejected {
		return nil, err
	}
	// if the body is nil (or http.NoBody), it's safe to reuse this request and its body
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	// if the request body can be reset back to its original state via req.GetBody, do that
	if req.GetBody != nil {
		newBody, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		reqCopy := *req
		reqCopy.Body = newBody
		req = &reqCopy
		return &reqCopy, nil
	}
	return nil, fmt.Errorf("http3: Transport: cannot retry err [%w] after Request.Body was written; define Request.GetBody to avoid this error", err)
}

// RoundTrip does a round trip.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.RoundTripOpt(req, RoundTripOpt{})
}

func (t *Transport) getClient(ctx context.Context, hostname string, onlyCached bool) (rtc *roundTripperWithCount, isReused bool, err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if t.closed {
		return nil, false, ErrTransportClosed
	}

	if t.clients == nil {
		t.clients = make(map[string]*roundTripperWithCount)
	}

	cl, ok := t.clients[hostname]
	if ok && cl.gone() {
		// A connection that went away, idle past its timeout or closed by
		// the server, takes no request, as Chromium's pool forgets a QUIC
		// session once it closes: the next is dialed anew.
		delete(t.clients, hostname)
		ok = false
	}
	if !ok {
		if onlyCached {
			return nil, false, ErrNoCachedConn
		}
		ctx, cancel := context.WithCancel(ctx)
		cl = &roundTripperWithCount{
			dialing: make(chan struct{}),
			cancel:  cancel,
		}
		go func() {
			defer close(cl.dialing)
			defer cancel()
			conn, rt, err := t.dial(ctx, hostname)
			if err != nil {
				cl.dialErr = err
				return
			}
			cl.conn = conn
			cl.clientConn = rt
		}()
		t.clients[hostname] = cl
	}
	select {
	case <-cl.dialing:
		if cl.dialErr != nil {
			delete(t.clients, hostname)
			return nil, false, cl.dialErr
		}
		select {
		case <-cl.conn.HandshakeComplete():
			isReused = true
		default:
		}
	default:
	}
	cl.useCount.Add(1)
	return cl, isReused, nil
}

func (t *Transport) dial(ctx context.Context, hostname string) (*quic.Conn, clientConn, error) {
	var tlsConf *tls.Config
	if t.TLSClientConfig == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = t.TLSClientConfig.Clone()
	}
	if tlsConf.ServerName == "" {
		sni, _, err := net.SplitHostPort(hostname)
		if err != nil {
			// It's ok if net.SplitHostPort returns an error - it could be a hostname/IP address without a port.
			sni = hostname
		}
		tlsConf.ServerName = sni
	}
	// Replace existing ALPNs by H3
	tlsConf.NextProtos = []string{NextProtoH3}

	dial := t.Dial
	if dial == nil {
		dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			network := "udp"
			udpAddr, err := t.resolveUDPAddr(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			trace := httptrace.ContextClientTrace(ctx)
			traceConnectStart(trace, network, udpAddr.String())
			traceTLSHandshakeStart(trace)
			conn, err := t.transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			var state tls.ConnectionState
			if conn != nil {
				state = conn.ConnectionState().TLS
			}
			traceTLSHandshakeDone(trace, state, err)
			traceConnectDone(trace, network, udpAddr.String(), err)
			return conn, err
		}
	}
	conn, err := dial(ctx, hostname, tlsConf, t.QUICConfig)
	if err != nil {
		return nil, nil, err
	}
	return conn, t.newClientConn(conn), nil
}

func (t *Transport) resolveUDPAddr(ctx context.Context, network, addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, err
	}
	resolver := net.DefaultResolver
	// The fhttp fork's httptrace can't hook into the standard library resolver
	// (net uses its own internal/nettrace key), so fire the DNS events here.
	trace := httptrace.ContextClientTrace(ctx)
	traceDNSStart(trace, host)
	ipAddrs, err := resolver.LookupIPAddr(ctx, host)
	traceDNSDone(trace, ipAddrs, err)
	if err != nil {
		return nil, err
	}
	addrs := addrList(ipAddrs)
	ip := addrs.forResolve(network, addr)
	return &net.UDPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, nil
}

// removeClient forgets cl, the client of hostname a request failed on, unless
// another has taken its place since: a connection dialed anew after it went
// away is not forgotten for the failure of a request on the one before.
func (t *Transport) removeClient(hostname string, cl *roundTripperWithCount) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if t.clients[hostname] == cl {
		delete(t.clients, hostname)
	}
}

// NewClientConn creates a new HTTP/3 client connection on top of a QUIC connection.
// Most users should use RoundTrip instead of creating a connection directly.
// Specifically, it is not needed to perform GET, POST, HEAD and CONNECT requests.
//
// Obtaining a ClientConn is only needed for more advanced use cases, such as
// using Extended CONNECT for WebTransport or the various MASQUE protocols.
func (t *Transport) NewClientConn(conn *quic.Conn) *ClientConn {
	return newClientConn(
		conn,
		t.EnableDatagrams,
		t.AdditionalSettings,
		t.AdditionalSettingsOrder,
		t.PseudoHeaderOrder,
		t.SendGreaseFrames,
		t.PriorityParam,
		t.StreamHijacker,
		t.UniStreamHijacker,
		t.MaxResponseHeaderBytes,
		t.DisableCompression,
		t.Logger,
		t.Behavior.Clone(),
	)
}

// Close closes the QUIC connections that this Transport has used.
// A Transport cannot be used after it has been closed.
func (t *Transport) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for _, cl := range t.clients {
		if err := cl.Close(); err != nil {
			return err
		}
	}
	t.clients = nil
	if t.transport != nil {
		if err := t.transport.Close(); err != nil {
			return err
		}
		if err := t.transport.Conn.Close(); err != nil {
			return err
		}
		t.transport = nil
	}
	t.closed = true
	return nil
}

func hostnameFromURL(url *url.URL) string {
	if url != nil {
		return url.Host
	}
	return ""
}

func validMethod(method string) bool {
	/*
				     Method         = "OPTIONS"                ; Section 9.2
		   		                    | "GET"                    ; Section 9.3
		   		                    | "HEAD"                   ; Section 9.4
		   		                    | "POST"                   ; Section 9.5
		   		                    | "PUT"                    ; Section 9.6
		   		                    | "DELETE"                 ; Section 9.7
		   		                    | "TRACE"                  ; Section 9.8
		   		                    | "CONNECT"                ; Section 9.9
		   		                    | extension-method
		   		   extension-method = token
		   		     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// copied from net/http/http.go
func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}

// CloseIdleConnections closes any QUIC connections in the transport's pool that are currently idle.
// An idle connection is one that was previously used for requests but is now sitting unused.
// This method does not interrupt any connections currently in use.
// It also does not affect connections obtained via NewClientConn.
func (t *Transport) CloseIdleConnections() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for hostname, cl := range t.clients {
		if cl.useCount.Load() == 0 {
			cl.Close()
			delete(t.clients, hostname)
		}
	}
}
