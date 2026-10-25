package http3

import (
	"slices"
	"strconv"
	"sync"
	"unicode/utf8"

	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	"github.com/igor-lemon/utls/behavior"
)

// What a server gives in ALPS for h3, read as Chrome reads it (h3.alps_reader
// "quiche": QuicSpdySession::OnAlpsData, its HttpDecoder and
// AlpsFrameDecoder) once the handshake is done and before the connection
// says it is (quic.Config.VerifyHandshake, as TlsClientHandshaker::
// FinishHandshake does): HTTP/3 frames, of which one SETTINGS frame is
// taken as the control stream's would be (peerSettings), ACCEPT_CH frames
// are kept, unknown frames passed over, ORIGIN frames as the profile says,
// and anything else refused, which closes the connection with the code and
// reason the profile says. The settings ALPS gave hold the control stream's
// SETTINGS to them (QuicSpdyClientSessionBase::OnSettingsFrame).

// The HTTP/3 frame types the reader knows (RFC 9114, quiche's HttpFrameType).
const (
	alpsData           = 0x0
	alpsHeaders        = 0x1
	alpsCancelPush     = 0x3
	alpsSettings       = 0x4
	alpsPushPromise    = 0x5
	alpsGoAway         = 0x7
	alpsOrigin         = 0xc
	alpsMaxPushID      = 0xd
	alpsMetadata       = 0x4d
	alpsAcceptCH       = 0x89
	alpsPriorityUpdate = 0xf0700
)

// alpsPayloadLimit is how long a frame the reader takes whole may be
// (quiche's kPayloadLengthLimit); GOAWAY and MAX_PUSH_ID take one varint.
const alpsPayloadLimit = 1 << 20

// alpsAbandon is the condition of an ORIGIN frame a profile abandons the
// connection for (h3.alps_origin_frames "abandon").
const alpsAbandon = "abandon"

// alpsProblem is why a server's ALPS, or its settings, are refused: the
// condition (of h3.alps_errors, or of h3.settings_errors when settings, or
// alpsAbandon), and its placeholders' values.
type alpsProblem struct {
	condition string
	values    map[string]string
	settings  bool
}

// alpsRead is what ALPS gave: the entries of its ACCEPT_CH frames, an origin
// and a value each, in order.
type alpsRead struct {
	acceptCH [][2]string
}

// readALPS reads b, ALPS's HTTP/3 frames, as quiche's HttpDecoder reads one
// buffer of them for AlpsFrameDecoder, taking the settings of its SETTINGS
// frame into peer as they are read: a frame type the buffer ends inside
// ends it as a frame boundary does (HttpDecoder::AtFrameBoundary); a frame
// of HTTP/2, a push frame, a frame ALPS may not carry, a field that does
// not read, a frame cut short or past its type's length, a second SETTINGS
// frame and a setting peer refuses are refused, the first found. ORIGIN
// frames are passed over unread as unknown ones are ("skip"), read and
// passed over ("read", quiche's enable_h3_origin_frame), or end the
// connection where Chrome 155's network service ends ("abandon": its
// AlpsFrameDecoder::OnOriginFrameStart is NOTREACHED, measured).
func readALPS(b []byte, origins string, peer *peerSettings) (alpsRead, *alpsProblem) {
	var read alpsRead
	settingsSeen := false
	refused := func(condition string) (alpsRead, *alpsProblem) {
		return read, &alpsProblem{condition: condition}
	}
	for len(b) > 0 {
		typ, n, err := quicvarint.Parse(b)
		if err != nil {
			return read, nil // a type cut short: a frame boundary still, to quiche
		}
		b = b[n:]
		switch typ {
		case 0x2, 0x6, 0x8, 0x9: // PRIORITY, PING, WINDOW_UPDATE, CONTINUATION
			return read, &alpsProblem{condition: "http2_frame", values: map[string]string{"type": strconv.FormatUint(typ, 10)}}
		case alpsCancelPush:
			return refused("cancel_push")
		case alpsPushPromise:
			return refused("push_promise")
		}
		length, n, err := quicvarint.Parse(b)
		if err != nil {
			return refused("incomplete")
		}
		b = b[n:]
		origin := typ == alpsOrigin && origins != "skip"
		whole := typ == alpsSettings || typ == alpsGoAway || typ == alpsMaxPushID || typ == alpsPriorityUpdate ||
			typ == alpsAcceptCH || origin
		if whole {
			limit := uint64(alpsPayloadLimit)
			if typ == alpsGoAway || typ == alpsMaxPushID {
				limit = 8
			}
			if length > limit {
				return refused("too_large")
			}
		}
		switch {
		case typ == alpsData:
			return refused("data")
		case typ == alpsHeaders:
			return refused("headers")
		case typ == alpsPriorityUpdate:
			return refused("priority_update")
		case typ == alpsMetadata:
			return refused("metadata")
		case origin && origins == alpsAbandon:
			return refused(alpsAbandon)
		}
		if length > uint64(len(b)) {
			return refused("incomplete")
		}
		payload := b[:length]
		b = b[length:]
		switch {
		case typ == alpsSettings:
			settings, condition := settingsOf(payload)
			if condition != "" {
				return refused(condition)
			}
			if settingsSeen {
				return refused("settings_twice")
			}
			settingsSeen = true
			for _, s := range settings {
				if p := peer.take(s[0], s[1]); p != nil {
					return read, p
				}
			}
		case typ == alpsGoAway || typ == alpsMaxPushID:
			name := "goaway"
			if typ == alpsMaxPushID {
				name = "max_push_id"
			}
			_, n, err := quicvarint.Parse(payload)
			if err != nil {
				return refused(name + "_id")
			}
			if n != len(payload) {
				return refused(name + "_extra")
			}
			return refused(name)
		case typ == alpsAcceptCH:
			for len(payload) > 0 {
				origin, rest, ok := varintString(payload)
				if !ok {
					return refused("accept_ch_origin")
				}
				value, rest, ok := varintString(rest)
				if !ok {
					return refused("accept_ch_value")
				}
				read.acceptCH = append(read.acceptCH, [2]string{origin, value})
				payload = rest
			}
		case origin:
			for len(payload) > 0 {
				n := 2
				if len(payload) >= 2 {
					n += int(payload[0])<<8 | int(payload[1])
				}
				if n > len(payload) {
					return refused("origin_origin")
				}
				payload = payload[n:]
			}
		}
	}
	return read, nil
}

// varintString is a string with its length before it in a varint, and what
// follows it; false when either does not read.
func varintString(b []byte) (string, []byte, bool) {
	n, l, err := quicvarint.Parse(b)
	if err != nil || n > uint64(len(b)-l) {
		return "", nil, false
	}
	return string(b[l : l+int(n)]), b[l+int(n):], true
}

// settingsOf are the settings of a SETTINGS frame's payload, in order, or
// the condition it is refused for: an identifier or a value that does not
// read, or an identifier said twice (HttpDecoder::ParseSettingsFrame).
func settingsOf(p []byte) ([][2]uint64, string) {
	var settings [][2]uint64
	seen := map[uint64]bool{}
	for len(p) > 0 {
		id, n, err := quicvarint.Parse(p)
		if err != nil {
			return nil, "setting_id"
		}
		p = p[n:]
		value, n, err := quicvarint.Parse(p)
		if err != nil {
			return nil, "setting_value"
		}
		p = p[n:]
		if seen[id] {
			return nil, "setting_twice"
		}
		seen[id] = true
		settings = append(settings, [2]uint64{id, value})
	}
	return settings, ""
}

// The settings of the QPACK table and of the field section (RFC 9204, RFC
// 9114), which the server's settings are held to across ALPS and the
// control stream.
const (
	settingTableCapacity  = 0x1
	settingBlockedStreams = 0x7
)

// peerSettings are the settings a server has given, ALPS's then its control
// stream's, each taken as quiche's QuicSpdySession::OnSetting takes it
// (h3.peer_settings "quiche"): the capacity of the QPACK table the client's
// encoder writes into, fixed once said other than 0; the field section and
// the blocked streams, never made smaller; an HTTP/2 setting refused; a
// setting the profile holds to 0 or 1 refused otherwise; the rest passed
// over.
type peerSettings struct {
	capacity, blocked, field uint64
	fieldSaid                bool
	http2                    []uint64
	booleans                 []uint64
	booleanNames             []string
}

func newPeerSettings(pol behavior.Policy) *peerSettings {
	return &peerSettings{http2: pol.Numbers("h3.settings_http2"), booleans: pol.Numbers("h3.settings_boolean"),
		booleanNames: pol.Strings("h3.settings_boolean_names")}
}

// take takes a setting, or says why it is refused.
func (s *peerSettings) take(id, value uint64) *alpsProblem {
	refused := func(condition string, values map[string]string) *alpsProblem {
		return &alpsProblem{condition: condition, values: values, settings: true}
	}
	said := func(current uint64) map[string]string {
		return map[string]string{"value": strconv.FormatUint(value, 10), "current": strconv.FormatUint(current, 10)}
	}
	if i := slices.Index(s.booleans, id); i >= 0 && value > 1 {
		return refused("boolean", map[string]string{"name": s.booleanNames[i], "value": strconv.FormatUint(value, 10)})
	}
	if slices.Contains(s.http2, id) {
		return refused("http2", map[string]string{"id": strconv.FormatUint(id, 10)})
	}
	switch id {
	case settingTableCapacity:
		if s.capacity != 0 && value != s.capacity {
			return refused("capacity", said(s.capacity))
		}
		s.capacity = value
	case settingMaxFieldSectionSize:
		if s.field > value {
			return refused("field_section", said(s.field))
		}
		s.field, s.fieldSaid = value, true
	case settingBlockedStreams:
		if value < s.blocked {
			return refused("blocked", said(s.blocked))
		}
		s.blocked = value
	}
	return nil
}

// control takes the settings of the server's control stream, in order: one
// it gave in ALPS other than its default must be said again
// (QuicSpdyClientSessionBase::OnSettingsFrame, the field section first, then
// the blocked streams, then the capacity), then each is taken.
func (s *peerSettings) control(settings [][2]uint64) *alpsProblem {
	has := func(id uint64) bool {
		return slices.ContainsFunc(settings, func(x [2]uint64) bool { return x[0] == id })
	}
	for _, o := range []struct {
		given bool
		id    uint64
		cond  string
	}{
		{s.fieldSaid, settingMaxFieldSectionSize, "omitted_field_section"},
		{s.blocked != 0, settingBlockedStreams, "omitted_blocked"},
		{s.capacity != 0, settingTableCapacity, "omitted_capacity"},
	} {
		if o.given && !has(o.id) {
			return &alpsProblem{condition: o.cond, settings: true}
		}
	}
	for _, x := range settings {
		if p := s.take(x[0], x[1]); p != nil {
			return p
		}
	}
	return nil
}

// closeFor is the error a problem closes the connection with, its code,
// space and reason the profile's: ALPS's own (h3.alps_close_*, the detail
// of h3.alps_errors in its reason) or a setting's (h3.settings_close_*);
// an ORIGIN frame a profile abandons the connection for ends it without a
// word.
func closeFor(pol behavior.Policy, p *alpsProblem) error {
	if p.condition == alpsAbandon {
		return quic.ErrHandshakeAbandoned
	}
	space, code := pol.Text("h3.alps_close_space"), pol.Uint("h3.alps_close_code")
	var reason string
	if p.settings {
		space, code = pol.Text("h3.settings_close_space"), pol.Uint("h3.settings_close_code")
		reason, _ = behavior.Template(pol.Templates("h3.settings_errors")[p.condition], p.values)
	} else {
		detail, _ := behavior.Template(pol.Templates("h3.alps_errors")[p.condition], p.values)
		reason, _ = behavior.Template(pol.Text("h3.alps_close_reason"), map[string]string{"detail": detail})
	}
	reason = bounded(reason)
	if space == "transport" {
		return &quic.TransportError{ErrorCode: quic.TransportErrorCode(code), FrameType: pol.Uint("h3.alps_close_frame_type"), ErrorMessage: reason}
	}
	return &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(code), ErrorMessage: reason}
}

// bounded cuts a reason past what a close frame carries of it, on a rune.
func bounded(s string) string {
	const limit = 1024
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// alpsGiven is the ALPS a connection's server gave for h3: none for another
// protocol. (Empty ALPS, which quiche does not read, reads as nothing.)
func alpsGiven(cs quic.ConnectionState) []byte {
	if cs.TLS.NegotiatedProtocol != NextProtoH3 {
		return nil
	}
	return cs.TLS.PeerApplicationSettings
}

// VerifyALPS is the quic.Config.VerifyHandshake of a client whose profile
// reads ALPS (h3.alps_reader): the ALPS a server gave for h3, read once the
// handshake is done.
func VerifyALPS(pol behavior.Policy) func(quic.ConnectionState) error {
	return func(cs quic.ConnectionState) error {
		if b := alpsGiven(cs); b != nil {
			if _, p := readALPS(b, pol.Text("h3.alps_origin_frames"), newPeerSettings(pol)); p != nil {
				return closeFor(pol, p)
			}
		}
		return nil
	}
}

// alpsState is what a connection took of its server's ALPS once its
// handshake was done (took): its peer settings, which the control stream's
// go on from, and the ACCEPT_CH entries.
type alpsState struct {
	policy    behavior.Policy
	once      sync.Once
	peer      *peerSettings
	acceptCH  [][2]string
	configure func(capacity, blocked uint64)
}

// newALPSState is a client's, whose encoder configure tells the QPACK
// table's capacity and blocked streams ALPS gave.
func newALPSState(pol behavior.Policy, configure func(capacity, blocked uint64)) *alpsState {
	return &alpsState{policy: pol, peer: newPeerSettings(pol), configure: configure}
}

// take reads the ALPS of a connection whose handshake is done, once, and
// nothing before: the same reading VerifyALPS let through, so it is refused
// for nothing; the encoder is told what its settings say before any request
// is written, as quiche's is in FinishHandshake.
func (a *alpsState) take(cs quic.ConnectionState) {
	if !cs.TLS.HandshakeComplete {
		return // a request in 0-RTT: nothing given yet
	}
	a.once.Do(func() {
		if b := alpsGiven(cs); b != nil {
			read, _ := readALPS(b, a.policy.Text("h3.alps_origin_frames"), a.peer)
			a.acceptCH = read.acceptCH
			// a table to write into from the first request; blocked streams
			// alone wait for the control stream's table, which says them again
			if a.peer.capacity != 0 {
				a.configure(a.peer.capacity, a.peer.blocked)
			}
		}
	})
}

// acceptCHFor is the value of the first ACCEPT_CH entry ALPS gave for
// origin, as Chromium keeps it (QuicChromiumClientSession::
// OnAcceptChFrameReceivedViaAlps: an entry whose origin is not written as
// its scheme, host and port serialize is none's; the first of each kept).
func (a *alpsState) acceptCHFor(origin string) (string, bool) {
	for _, e := range a.acceptCH {
		if e[0] == origin {
			return e[1], true
		}
	}
	return "", false
}
