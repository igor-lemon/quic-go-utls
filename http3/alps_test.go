package http3

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
)

// chromeALPSPolicy is Chrome 155's reading of ALPS for h3 (bench/h3alps,
// cohorts hpa and hpb), laid over the frozen Chromium data.
func chromeALPSPolicy(t *testing.T, over map[string]any) behavior.Policy {
	t.Helper()
	p := behavior.Legacy()
	set := map[string]any{
		"quic.preserve_extensions": []uint64{0, 65037, 27, 45, 51764, 10, 13, 51, 16, 43, 41, 17613},
		"quic.alps_protocols":      []string{"h3"}, "quic.close_early_application": "application",
		"h3.alps_reader": "quiche", "h3.alps_origin_frames": "abandon", "h3.alps_close_space": "transport",
		"h3.alps_close_code": 10, "h3.alps_close_frame_type": 6, "h3.alps_close_reason": "28:Error processing ALPS data: {detail}",
		"h3.alps_errors": map[string]string{"data": "DATA frame forbidden", "headers": "HEADERS frame forbidden",
			"goaway": "GOAWAY frame forbidden", "max_push_id": "MAX_PUSH_ID frame forbidden",
			"priority_update": "PRIORITY_UPDATE frame forbidden", "metadata": "METADATA frame forbidden",
			"settings_twice": "multiple SETTINGS frames", "incomplete": "incomplete HTTP/3 frame", "too_large": "Frame is too large.",
			"setting_id": "Unable to read setting identifier.", "setting_value": "Unable to read setting value.",
			"setting_twice": "Duplicate setting identifier.", "goaway_id": "Unable to read GOAWAY ID.",
			"goaway_extra": "Superfluous data in GOAWAY frame.", "max_push_id_id": "Unable to read MAX_PUSH_ID push_id.",
			"max_push_id_extra": "Superfluous data in MAX_PUSH_ID frame.", "priority_update_id": "Unable to read prioritized element id.",
			"accept_ch_origin": "Unable to read ACCEPT_CH origin.", "accept_ch_value": "Unable to read ACCEPT_CH value.",
			"origin_origin": "Unable to read ORIGIN origin.", "http2_frame": "HTTP/2 frame received in a HTTP/3 connection: {type}",
			"cancel_push": "CANCEL_PUSH frame received.", "push_promise": "PUSH_PROMISE frame received."},
		"h3.peer_settings": "quiche", "h3.settings_close_space": "application", "h3.settings_close_code": 265,
		"h3.settings_errors": map[string]string{"http2": "169:received HTTP/2 specific setting in HTTP/3 session: {id}",
			"boolean":               "207:Received {name} with invalid value {value}",
			"capacity":              "164:Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: {value} while current value is: {current}",
			"field_section":         "164:Server sent an SETTINGS_MAX_FIELD_SECTION_SIZE: {value} which reduces current value: {current}",
			"blocked":               "164:Server sent an SETTINGS_QPACK_BLOCKED_STREAMS: {value} which reduces current value: {current}",
			"omitted_field_section": "164:Server accepted 0-RTT but omitted non-default SETTINGS_MAX_FIELD_SECTION_SIZE",
			"omitted_blocked":       "164:Server accepted 0-RTT but omitted non-default SETTINGS_QPACK_BLOCKED_STREAMS",
			"omitted_capacity":      "164:Server accepted 0-RTT but omitted non-default SETTINGS_QPACK_MAX_TABLE_CAPACITY"},
		"h3.settings_http2": []uint64{2, 3, 4, 5}, "h3.settings_boolean": []uint64{8, 51},
		"h3.settings_boolean_names": []string{"SETTINGS_ENABLE_CONNECT_PROTOCOL", "SETTINGS_H3_DATAGRAM"},
	}
	for k, v := range over {
		if v == nil {
			delete(set, k)
		} else {
			set[k] = v
		}
	}
	for k, v := range set {
		p[k], _ = json.Marshal(v)
	}
	require.NoError(t, p.Validate())
	return p
}

func h3Frame(typ uint64, payload ...byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

func h3Settings(pairs ...uint64) []byte {
	var p []byte
	for _, v := range pairs {
		p = quicvarint.Append(p, v)
	}
	return h3Frame(0x4, p...)
}

func h3AcceptCH(entries ...string) []byte {
	var p []byte
	for _, e := range entries {
		p = quicvarint.Append(p, uint64(len(e)))
		p = append(p, e...)
	}
	return h3Frame(0x89, p...)
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// longFrame is a frame header of typ saying a payload of length bytes, with
// none of it.
func longFrame(typ, length uint64) []byte {
	return quicvarint.Append(quicvarint.Append(nil, typ), length)
}

func TestALPSIsReadAsQuicheReadsIt(t *testing.T) {
	pol := chromeALPSPolicy(t, nil)
	for _, tc := range []struct {
		name      string
		alps      []byte
		origins   string
		condition string
		values    map[string]string
	}{
		{"nothing", nil, "", "", nil},
		{"SETTINGS", h3Settings(6, 1048576, 8, 1), "", "", nil},
		{"an unknown frame, then SETTINGS", cat(h3Frame(0x21, 1, 2, 3), h3Settings(6, 1)), "", "", nil},
		{"an unknown frame of nothing", h3Frame(0x21), "", "", nil},
		{"a GREASE and an unknown setting", h3Settings(0x40, 7, 0xabcd, 1), "", "", nil},
		{"a type cut short at the end", cat(h3Settings(6, 1), []byte{0x40}), "", "", nil},
		{"a lone type cut short", []byte{0x80, 0x00}, "", "", nil},
		{"PRIORITY of HTTP/2", []byte{0x02}, "", "http2_frame", map[string]string{"type": "2"}},
		{"PING of HTTP/2", h3Frame(0x6), "", "http2_frame", map[string]string{"type": "6"}},
		{"WINDOW_UPDATE of HTTP/2", []byte{0x08}, "", "http2_frame", map[string]string{"type": "8"}},
		{"CONTINUATION of HTTP/2", []byte{0x09}, "", "http2_frame", map[string]string{"type": "9"}},
		{"CANCEL_PUSH", []byte{0x03}, "", "cancel_push", nil},
		{"PUSH_PROMISE", h3Frame(0x5), "", "push_promise", nil},
		{"a type and no length", []byte{0x21}, "", "incomplete", nil},
		{"a length cut short", []byte{0x21, 0x40}, "", "incomplete", nil},
		{"SETTINGS, then a length cut short", cat(h3Settings(6, 1), []byte{0x21, 0x40}), "", "incomplete", nil},
		{"a payload cut short", []byte{0x04, 0x0a, 0x06, 0x01}, "", "incomplete", nil},
		{"a payload a byte short", []byte{0x04, 0x03, 0x06, 0x01}, "", "incomplete", nil},
		{"an unknown frame cut short", []byte{0x21, 0x03, 0x01}, "", "incomplete", nil},
		{"GOAWAY of 9 bytes", longFrame(0x7, 9), "", "too_large", nil},
		{"MAX_PUSH_ID of 9 bytes", longFrame(0xd, 9), "", "too_large", nil},
		{"SETTINGS past a MiB", longFrame(0x4, 1<<20+1), "", "too_large", nil},
		{"SETTINGS of a MiB, cut short", longFrame(0x4, 1<<20), "", "incomplete", nil},
		{"PRIORITY_UPDATE past a MiB", longFrame(0xf0700, 1<<20+1), "", "too_large", nil},
		{"ACCEPT_CH past a MiB", longFrame(0x89, 1<<20+1), "", "too_large", nil},
		{"ORIGIN past a MiB, read", longFrame(0xc, 1<<20+1), "read", "too_large", nil},
		{"ORIGIN past a MiB, passed over", longFrame(0xc, 1<<20+1), "skip", "incomplete", nil},
		{"an unknown frame past a MiB", longFrame(0x21, 1<<20+1), "", "incomplete", nil},
		{"DATA", h3Frame(0x0), "", "data", nil},
		{"DATA said longer than ALPS", longFrame(0x0, 100), "", "data", nil},
		{"HEADERS", h3Frame(0x1, 1, 2), "", "headers", nil},
		{"PRIORITY_UPDATE", h3Frame(0xf0700, 0, 'u', '=', '1'), "", "priority_update", nil},
		{"METADATA", h3Frame(0x4d), "", "metadata", nil},
		{"GOAWAY", h3Frame(0x7, 0), "", "goaway", nil},
		{"GOAWAY of no ID", h3Frame(0x7), "", "goaway_id", nil},
		{"GOAWAY of an ID cut short", h3Frame(0x7, 0x40), "", "goaway_id", nil},
		{"GOAWAY of a byte more", h3Frame(0x7, 0, 0), "", "goaway_extra", nil},
		{"MAX_PUSH_ID", h3Frame(0xd, 0), "", "max_push_id", nil},
		{"MAX_PUSH_ID of no ID", h3Frame(0xd), "", "max_push_id_id", nil},
		{"MAX_PUSH_ID of a byte more", h3Frame(0xd, 0, 0), "", "max_push_id_extra", nil},
		{"two SETTINGS", cat(h3Settings(6, 1), h3Settings(6, 1)), "", "settings_twice", nil},
		{"a setting twice", h3Settings(6, 1, 6, 2), "", "setting_twice", nil},
		{"a setting with no value", h3Frame(0x4, 0x06), "", "setting_value", nil},
		{"a setting identifier cut short", h3Frame(0x4, 0x40), "", "setting_id", nil},
		{"a setting refused", h3Settings(8, 2), "", "boolean",
			map[string]string{"name": "SETTINGS_ENABLE_CONNECT_PROTOCOL", "value": "2"}},
		{"ACCEPT_CH whose origin is cut short", h3Frame(0x89, 5, 'a'), "", "accept_ch_origin", nil},
		{"ACCEPT_CH whose value is cut short", h3Frame(0x89, 1, 'a', 5, 'b'), "", "accept_ch_value", nil},
		{"ACCEPT_CH of an origin and no value", h3Frame(0x89, 1, 'a'), "", "accept_ch_value", nil},
		{"ORIGIN, Chrome's", h3Frame(0xc, 0, 3, 'a', 'b', 'c'), "abandon", "abandon", nil},
		{"ORIGIN cut short, Chrome's", h3Frame(0xc, 0), "abandon", "abandon", nil},
		{"ORIGIN whose length is cut short, Chrome's", []byte{0x0c, 0x40}, "abandon", "incomplete", nil},
		{"ORIGIN past a MiB, Chrome's", longFrame(0xc, 1<<20+1), "abandon", "too_large", nil},
		{"ORIGIN, read", h3Frame(0xc, 0, 3, 'a', 'b', 'c', 0, 0), "read", "", nil},
		{"ORIGIN of a byte, read", h3Frame(0xc, 0), "read", "origin_origin", nil},
		{"ORIGIN of an origin cut short, read", h3Frame(0xc, 0, 5, 'a'), "read", "origin_origin", nil},
		{"ORIGIN of a length and no origin, read", h3Frame(0xc, 0, 5), "read", "origin_origin", nil},
		{"ORIGIN cut short, passed over", h3Frame(0xc, 0), "skip", "", nil},
	} {
		origins := tc.origins
		if origins == "" {
			origins = "abandon"
		}
		_, p := readALPS(tc.alps, origins, newPeerSettings(pol))
		if tc.condition == "" {
			require.Nil(t, p, tc.name)
			continue
		}
		require.NotNil(t, p, tc.name)
		require.Equal(t, tc.condition, p.condition, tc.name)
		require.Equal(t, tc.values, p.values, tc.name)
	}
}

func TestALPSKeepsEveryACCEPTCHEntryAndTakesItsSettings(t *testing.T) {
	pol := chromeALPSPolicy(t, nil)
	peer := newPeerSettings(pol)
	read, p := readALPS(cat(h3Settings(1, 4096, 6, 2000, 7, 100), h3AcceptCH("https://a.test", "Sec-CH-UA-Arch", "https://b.test", "x"),
		h3AcceptCH("https://a.test", "Sec-CH-UA-Model"), h3AcceptCH()), "abandon", peer)
	require.Nil(t, p)
	require.Equal(t, [][2]string{{"https://a.test", "Sec-CH-UA-Arch"}, {"https://b.test", "x"}, {"https://a.test", "Sec-CH-UA-Model"}}, read.acceptCH)
	require.EqualValues(t, 4096, peer.capacity)
	require.EqualValues(t, 2000, peer.field)
	require.True(t, peer.fieldSaid)
	require.EqualValues(t, 100, peer.blocked)
	a := &alpsState{acceptCH: read.acceptCH}
	value, ok := a.acceptCHFor("https://a.test")
	require.True(t, ok)
	require.Equal(t, "Sec-CH-UA-Arch", value, "the first entry of the origin")
	_, ok = a.acceptCHFor("https://A.test")
	require.False(t, ok, "an origin written otherwise is another's")
}

func TestAServersSettingsAreTakenAsQuicheTakesThem(t *testing.T) {
	pol := chromeALPSPolicy(t, nil)
	for _, tc := range []struct {
		name      string
		alps      [][2]uint64 // what ALPS gave, taken first
		control   [][2]uint64 // then the control stream's
		condition string
		values    map[string]string
	}{
		{"booleans of 0 and 1", nil, [][2]uint64{{8, 0}, {51, 1}}, "", nil},
		{"SETTINGS_ENABLE_CONNECT_PROTOCOL 2", nil, [][2]uint64{{8, 2}}, "boolean",
			map[string]string{"name": "SETTINGS_ENABLE_CONNECT_PROTOCOL", "value": "2"}},
		{"SETTINGS_H3_DATAGRAM 3", nil, [][2]uint64{{51, 3}}, "boolean", map[string]string{"name": "SETTINGS_H3_DATAGRAM", "value": "3"}},
		{"an HTTP/2 setting", nil, [][2]uint64{{4, 65535}}, "http2", map[string]string{"id": "4"}},
		{"an unknown setting", nil, [][2]uint64{{0xabcd, 9}}, "", nil},
		{"a capacity of 0, then another", [][2]uint64{{1, 0}}, [][2]uint64{{1, 4096}}, "", nil},
		{"the capacity said again", [][2]uint64{{1, 4096}}, [][2]uint64{{1, 4096}}, "", nil},
		{"the capacity changed", [][2]uint64{{1, 4096}}, [][2]uint64{{1, 8192}}, "capacity",
			map[string]string{"value": "8192", "current": "4096"}},
		{"the capacity not said again", [][2]uint64{{1, 4096}}, [][2]uint64{{6, 1}}, "omitted_capacity", nil},
		{"the field section made smaller", [][2]uint64{{6, 2000000}}, [][2]uint64{{6, 1048576}}, "field_section",
			map[string]string{"value": "1048576", "current": "2000000"}},
		{"the field section made larger", [][2]uint64{{6, 100}}, [][2]uint64{{6, 1048576}}, "", nil},
		{"the field section said again", [][2]uint64{{6, 100}}, [][2]uint64{{6, 100}}, "", nil},
		{"the field section not said again", [][2]uint64{{6, 100}}, [][2]uint64{{7, 1}}, "omitted_field_section", nil},
		{"the blocked streams made fewer", [][2]uint64{{7, 100}}, [][2]uint64{{7, 10}}, "blocked",
			map[string]string{"value": "10", "current": "100"}},
		{"the blocked streams made more", [][2]uint64{{7, 10}}, [][2]uint64{{7, 100}}, "", nil},
		{"the blocked streams not said again", [][2]uint64{{7, 100}}, nil, "omitted_blocked", nil},
		{"of three not said again, the field section first", [][2]uint64{{1, 4096}, {6, 1}, {7, 1}}, nil, "omitted_field_section", nil},
		{"of two not said again, the blocked streams first", [][2]uint64{{1, 4096}, {7, 1}}, nil, "omitted_blocked", nil},
		{"none given in ALPS, none needed", nil, nil, "", nil},
	} {
		peer := newPeerSettings(pol)
		for _, s := range tc.alps {
			require.Nil(t, peer.take(s[0], s[1]), tc.name)
		}
		p := peer.control(tc.control)
		if tc.condition == "" {
			require.Nil(t, p, tc.name)
			continue
		}
		require.NotNil(t, p, tc.name)
		require.True(t, p.settings, tc.name)
		require.Equal(t, tc.condition, p.condition, tc.name)
		require.Equal(t, tc.values, p.values, tc.name)
	}
}

func TestAProblemClosesAsTheProfileSays(t *testing.T) {
	pol := chromeALPSPolicy(t, nil)
	var te *quic.TransportError
	require.ErrorAs(t, closeFor(pol, &alpsProblem{condition: "http2_frame", values: map[string]string{"type": "6"}}), &te)
	require.EqualValues(t, 10, te.ErrorCode)
	require.EqualValues(t, 6, te.FrameType)
	require.Equal(t, "28:Error processing ALPS data: HTTP/2 frame received in a HTTP/3 connection: 6", te.ErrorMessage)
	var ae *quic.ApplicationError
	require.ErrorAs(t, closeFor(pol, &alpsProblem{condition: "capacity", settings: true,
		values: map[string]string{"value": "8192", "current": "4096"}}), &ae)
	require.EqualValues(t, 0x109, ae.ErrorCode)
	require.Equal(t, "164:Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: 8192 while current value is: 4096", ae.ErrorMessage)
	require.ErrorIs(t, closeFor(pol, &alpsProblem{condition: alpsAbandon}), quic.ErrHandshakeAbandoned)
	// ALPS's close as an application's, of the profile's
	app := chromeALPSPolicy(t, map[string]any{"h3.alps_close_space": "application", "h3.alps_close_frame_type": nil,
		"h3.alps_close_code": 0x101})
	require.ErrorAs(t, closeFor(app, &alpsProblem{condition: "data"}), &ae)
	require.EqualValues(t, 0x101, ae.ErrorCode)
	require.Equal(t, "28:Error processing ALPS data: DATA frame forbidden", ae.ErrorMessage)
	// a setting's as a transport close, which says the frame type ALPS's says
	transport := chromeALPSPolicy(t, map[string]any{"h3.settings_close_space": "transport", "h3.settings_close_code": 0xa})
	require.ErrorAs(t, closeFor(transport, &alpsProblem{condition: "http2", settings: true, values: map[string]string{"id": "4"}}), &te)
	require.EqualValues(t, 0xa, te.ErrorCode)
	require.EqualValues(t, 6, te.FrameType)
	// a reason past 1024 bytes cut on a rune
	long := chromeALPSPolicy(t, map[string]any{"h3.alps_errors": func() map[string]string {
		m := pol.Templates("h3.alps_errors")
		m["data"] = strings.Repeat("é", 512)
		return m
	}(), "h3.alps_close_reason": "a{detail}"})
	require.ErrorAs(t, closeFor(long, &alpsProblem{condition: "data"}), &te)
	require.Equal(t, "a"+strings.Repeat("é", 511), te.ErrorMessage, "1024 bytes would cut a rune")
	require.Equal(t, "ab", bounded("ab"))
	require.Equal(t, strings.Repeat("a", 1023), bounded(strings.Repeat("a", 1023)+"é"))
}

func TestOnlyALPSOfSomethingForH3IsRead(t *testing.T) {
	verify := VerifyALPS(chromeALPSPolicy(t, nil))
	state := func(proto string, alps []byte) quic.ConnectionState {
		return quic.ConnectionState{TLS: tls.ConnectionState{NegotiatedProtocol: proto, PeerApplicationSettings: alps}}
	}
	require.NoError(t, verify(state("h3", nil)))
	require.NoError(t, verify(state("h3", []byte{})), "quiche reads ALPS of something alone")
	require.NoError(t, verify(state("h2", h3Frame(0x0))), "another protocol's")
	require.NoError(t, verify(state("h3", h3Settings(6, 1))))
	var te *quic.TransportError
	require.ErrorAs(t, verify(state("h3", h3Frame(0x0))), &te)
	require.Equal(t, "28:Error processing ALPS data: DATA frame forbidden", te.ErrorMessage)
}

func TestWhatALPSGaveIsTakenOnceAndToldTheEncoder(t *testing.T) {
	pol := chromeALPSPolicy(t, nil)
	var told [][2]uint64
	a := newALPSState(pol, func(capacity, blocked uint64) { told = append(told, [2]uint64{capacity, blocked}) })
	cs := quic.ConnectionState{TLS: tls.ConnectionState{NegotiatedProtocol: "h3", HandshakeComplete: true,
		PeerApplicationSettings: cat(h3Settings(1, 4096, 7, 100), h3AcceptCH("https://a.test", "Sec-CH-UA-Arch"))}}
	a.take(cs)
	a.take(cs)
	require.Equal(t, [][2]uint64{{4096, 100}}, told, "once")
	value, ok := a.acceptCHFor("https://a.test")
	require.True(t, ok)
	require.Equal(t, "Sec-CH-UA-Arch", value)
	// blocked streams alone tell the encoder nothing: the control stream's
	// table says them again
	told = nil
	alone := newALPSState(pol, func(capacity, blocked uint64) { told = append(told, [2]uint64{capacity, blocked}) })
	alone.take(quic.ConnectionState{TLS: tls.ConnectionState{NegotiatedProtocol: "h3", HandshakeComplete: true, PeerApplicationSettings: h3Settings(7, 100)}})
	require.Nil(t, told)
	require.EqualValues(t, 100, alone.peer.blocked)
	// ALPS of no QPACK settings tells the encoder nothing
	told = nil
	b := newALPSState(pol, func(capacity, blocked uint64) { told = append(told, [2]uint64{capacity, blocked}) })
	b.take(quic.ConnectionState{TLS: tls.ConnectionState{NegotiatedProtocol: "h3", HandshakeComplete: true, PeerApplicationSettings: h3Settings(6, 1)}})
	require.Nil(t, told)
	c := newALPSState(pol, func(capacity, blocked uint64) { told = append(told, [2]uint64{capacity, blocked}) })
	c.take(quic.ConnectionState{TLS: tls.ConnectionState{NegotiatedProtocol: "h3", HandshakeComplete: true}})
	require.Nil(t, told)
	_, ok = c.acceptCHFor("https://a.test")
	require.False(t, ok)
	// before the handshake is done (a request in 0-RTT) nothing is taken, and
	// what the handshake then gives is
	d := newALPSState(pol, func(capacity, blocked uint64) { told = append(told, [2]uint64{capacity, blocked}) })
	d.take(quic.ConnectionState{TLS: tls.ConnectionState{NegotiatedProtocol: "h3"}})
	_, ok = d.acceptCHFor("https://a.test")
	require.False(t, ok)
	cs.TLS.HandshakeComplete = true
	d.take(cs)
	_, ok = d.acceptCHFor("https://a.test")
	require.True(t, ok)
}

func TestTheSettingsOfAFrameAreSaidInOrder(t *testing.T) {
	two, three := uint64(2), uint64(3)
	require.Equal(t, [][2]uint64{{6, 100}, {8, 2}, {0x33, 3}, {1, 4096}, {7, 9}},
		settingsSaid(&settingsFrame{MaxFieldSectionSize: 100, ExtendedConnectSaid: &two, DatagramSaid: &three,
			Other: map[uint64]uint64{7: 9, 1: 4096}}))
	require.Nil(t, settingsSaid(&settingsFrame{MaxFieldSectionSize: -1}))
	require.Equal(t, [][2]uint64{{6, 0}}, settingsSaid(&settingsFrame{MaxFieldSectionSize: 0}), "a field section of 0 is said")
}

// alpsSpec is a QUIC hello of a uTLS client offering ALPS for h3, as
// tls-client's profileQUICSpec makes one of a Chrome profile.
func alpsSpec(params []byte) (tls.ClientHelloSpec, error) {
	return tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS13, TLSVersMax: tls.VersionTLS13,
		CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.Ed25519, tls.ECDSAWithP256AndSHA256}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13}},
			&tls.ALPNExtension{AlpnProtocols: []string{"h3"}},
			&tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h3"}},
			&tls.GenericExtension{Id: 57, Data: append([]byte(nil), params...)},
		},
	}, nil
}

// alpsServer is an HTTP/3 server that gives the ALPS alps makes of its
// address for h3, its control stream's SETTINGS beside its own those of
// control, late after its handshake; its requests' headers go on headers,
// and how each connection ended on closed.
func alpsServer(t *testing.T, alps func(addr string) []byte, control map[uint64]uint64, late time.Duration, ready ...<-chan struct{}) (addr string, headers chan http.Header, closed chan error) {
	t.Helper()
	cfg := getTLSConfig()
	conn := newUDPConnLocalhost(t)
	addr = conn.LocalAddr().String()
	if alps != nil {
		cfg.ApplicationSettings = map[string][]byte{"h3": alps(addr)}
	}
	ln, err := quic.ListenEarly(conn, ConfigureTLSConfig(cfg), &quic.Config{})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	headers = make(chan http.Header, 8)
	closed = make(chan error, 8)
	srv := &Server{AdditionalSettings: control, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		w.Write([]byte("ok"))
	})}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				<-conn.Context().Done()
				closed <- context.Cause(conn.Context())
			}()
			go func() {
				if len(ready) > 0 {
					select {
					case <-ready[0]:
					case <-conn.Context().Done():
						return
					}
				}
				time.Sleep(late)
				srv.ServeQUICConn(conn)
			}()
		}
	}()
	return addr, headers, closed
}

// alpsClient is a client of pol, its QUIC hello offering ALPS.
func alpsClient(t *testing.T, pol behavior.Policy) *Transport {
	t.Helper()
	cfg := getTLSClientConfig()
	cfg.QUICClientHelloSpec = alpsSpec
	tr := &Transport{Behavior: pol, TLSClientConfig: cfg, QUICConfig: &quic.Config{Behavior: pol}}
	t.Cleanup(func() { tr.Close() })
	return tr
}

func TestAClientTakesWhatItsServerGaveInALPS(t *testing.T) {
	pol := chromeALPSPolicy(t, nil)
	// the control stream's SETTINGS a second late, the same as ALPS's
	addr, headers, _ := alpsServer(t, func(addr string) []byte {
		return cat(h3Settings(1, 4096, 6, 1048576, 7, 100), h3AcceptCH("https://"+addr, "Sec-CH-UA-Arch"))
	}, map[uint64]uint64{1: 4096, 7: 100}, time.Second)
	tr := alpsClient(t, pol)
	type alpsConn interface {
		AcceptCH(string) (string, bool)
	}
	var conn alpsConn
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		conn = i.Conn.(alpsConn)
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	require.NoError(t, err)
	var maximum, blocked uint64
	var asked string
	req.HeaderFor = func(protocol string, header http.Header) http.Header {
		// as the request is written: ALPS's settings told the encoder, and its
		// ACCEPT_CH read, before the control stream's SETTINGS came
		tr.mutex.Lock()
		enc := tr.clients[addr].clientConn.(*ClientConn).conn.qpack.encoder
		tr.mutex.Unlock()
		enc.mu.Lock()
		maximum, blocked = enc.maximum, enc.blockedLimit
		enc.mu.Unlock()
		asked = protocol
		value, ok := conn.AcceptCH("https://" + addr)
		require.True(t, ok)
		out := header.Clone()
		out.Set("sec-ch-ua-arch", value)
		return out
	}
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	rsp.Body.Close()
	require.Equal(t, 200, rsp.StatusCode)
	require.EqualValues(t, 4096, maximum)
	require.EqualValues(t, 100, blocked)
	require.Equal(t, http.ProtocolHTTP3, asked)
	require.Equal(t, "Sec-CH-UA-Arch", (<-headers).Get("Sec-CH-UA-Arch"), "the header HeaderFor gave is the one written")
	_, ok := conn.AcceptCH("https://other.test")
	require.False(t, ok)
}

func TestAConnectionThatReadsNoALPSAsksNothingOfIt(t *testing.T) {
	addr, _, _ := alpsServer(t, func(addr string) []byte { return h3AcceptCH("https://"+addr, "x") }, nil, 0)
	tr := alpsClient(t, behavior.Legacy())
	var conn interface{ AcceptCH(string) (string, bool) }
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		conn = i.Conn.(interface{ AcceptCH(string) (string, bool) })
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	require.NoError(t, err)
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	rsp.Body.Close()
	_, ok := conn.AcceptCH("https://" + addr)
	require.False(t, ok)
}

func TestAnALPSAClientRefusesClosesItsConnection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		alps   []byte
		remote func(t *testing.T, err error)
	}{
		{"DATA", h3Frame(0x0), func(t *testing.T, err error) {
			var te *quic.TransportError
			require.ErrorAs(t, err, &te)
			require.EqualValues(t, 10, te.ErrorCode)
			require.EqualValues(t, 6, te.FrameType)
			require.Equal(t, "28:Error processing ALPS data: DATA frame forbidden", te.ErrorMessage)
		}},
		{"an HTTP/2 setting", h3Settings(4, 65535), func(t *testing.T, err error) {
			// an application close in the Initial, which quic-go's server refuses
			// as the bench's did Chrome's
			var te *quic.TransportError
			require.ErrorAs(t, err, &te)
			require.Equal(t, quic.FrameEncodingError, te.ErrorCode)
		}},
	} {
		alps := tc.alps
		addr, _, closed := alpsServer(t, func(string) []byte { return alps }, nil, 0)
		tr := alpsClient(t, chromeALPSPolicy(t, nil))
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		require.NoError(t, err)
		_, err = tr.RoundTrip(req)
		require.Error(t, err, tc.name)
		select {
		case err := <-closed:
			tc.remote(t, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the server's connection did not end", tc.name)
		}
	}
	// a client that reads no ALPS lets it be
	addr, _, _ := alpsServer(t, func(string) []byte { return h3Frame(0x0) }, nil, 0)
	tr := alpsClient(t, behavior.Legacy())
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	require.NoError(t, err)
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	rsp.Body.Close()
}

func TestTheControlStreamsSettingsAreHeldToWhatALPSGave(t *testing.T) {
	for _, tc := range []struct {
		name    string
		alps    []byte
		control map[uint64]uint64
		reason  string
	}{
		{"the capacity changed", h3Settings(1, 4096), map[uint64]uint64{1: 8192},
			"164:Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: 8192 while current value is: 4096"},
		{"the blocked streams not said again", h3Settings(7, 100), nil,
			"164:Server accepted 0-RTT but omitted non-default SETTINGS_QPACK_BLOCKED_STREAMS"},
		{"no ALPS, SETTINGS_ENABLE_CONNECT_PROTOCOL 2", nil, map[uint64]uint64{8: 2},
			"207:Received SETTINGS_ENABLE_CONNECT_PROTOCOL with invalid value 2"},
		{"no ALPS, an HTTP/2 setting", nil, map[uint64]uint64{4: 1},
			"169:received HTTP/2 specific setting in HTTP/3 session: 4"},
		{"no ALPS, SETTINGS_H3_DATAGRAM 2", nil, map[uint64]uint64{0x33: 2},
			"207:Received SETTINGS_H3_DATAGRAM with invalid value 2"},
	} {
		var alps func(string) []byte
		if tc.alps != nil {
			given := tc.alps
			alps = func(string) []byte { return given }
		}
		addr, _, closed := alpsServer(t, alps, tc.control, 0)
		tr := alpsClient(t, chromeALPSPolicy(t, nil))
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		require.NoError(t, err)
		if rsp, err := tr.RoundTrip(req); err == nil {
			rsp.Body.Close()
		}
		select {
		case err := <-closed:
			var ae *quic.ApplicationError
			require.ErrorAs(t, err, &ae, tc.name)
			require.True(t, ae.Remote, tc.name)
			require.EqualValues(t, 0x109, ae.ErrorCode, tc.name)
			require.Equal(t, tc.reason, ae.ErrorMessage, tc.name)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the server's connection did not end", tc.name)
		}
	}
}

func TestAControlStreamsSettingRefusedClosesAsTheProfileSays(t *testing.T) {
	// a profile whose settings close the connection as a transport's would
	pol := chromeALPSPolicy(t, map[string]any{"h3.settings_close_space": "transport", "h3.settings_close_code": 0xa})
	addr, _, closed := alpsServer(t, nil, map[uint64]uint64{4: 1}, 0)
	tr := alpsClient(t, pol)
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	require.NoError(t, err)
	if rsp, err := tr.RoundTrip(req); err == nil {
		rsp.Body.Close()
	}
	select {
	case err := <-closed:
		var te *quic.TransportError
		require.ErrorAs(t, err, &te)
		require.True(t, te.Remote)
		require.EqualValues(t, 0xa, te.ErrorCode)
		require.EqualValues(t, 6, te.FrameType)
		require.Equal(t, "169:received HTTP/2 specific setting in HTTP/3 session: 4", te.ErrorMessage)
	case <-time.After(5 * time.Second):
		t.Fatal("the server's connection did not end")
	}
}

func TestATransportReadsALPSOnlyAsItsProfileSays(t *testing.T) {
	tr := &Transport{Behavior: chromeALPSPolicy(t, nil)}
	require.NoError(t, tr.init())
	require.NotNil(t, tr.QUICConfig.VerifyHandshake)
	tr = &Transport{Behavior: behavior.Legacy()}
	require.NoError(t, tr.init())
	require.Nil(t, tr.QUICConfig.VerifyHandshake)
	// a caller's own is left as it is
	mine := errors.New("mine")
	tr = &Transport{Behavior: chromeALPSPolicy(t, nil), QUICConfig: &quic.Config{VerifyHandshake: func(quic.ConnectionState) error { return mine }}}
	require.NoError(t, tr.init())
	require.ErrorIs(t, tr.QUICConfig.VerifyHandshake(quic.ConnectionState{}), mine)
}

func TestAControlStreamOfNoRequestIsHeldToWhatALPSGave(t *testing.T) {
	// a connection made for no request: its control stream's SETTINGS are
	// still held to ALPS's, and refused
	sendControl := make(chan struct{})
	addr, headers, closed := alpsServer(t, func(string) []byte { return h3Settings(1, 4096) }, map[uint64]uint64{1: 8192}, 0, sendControl)
	tr := alpsClient(t, chromeALPSPolicy(t, nil))
	// Establish a connection before the deliberately invalid regular SETTINGS.
	// Preconnect may otherwise observe a terminal peer condition first; its
	// success is only a valid precondition before that stimulus is released.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, tr.Preconnect(ctx, addr))
	close(sendControl)
	select {
	case err := <-closed:
		var ae *quic.ApplicationError
		require.ErrorAs(t, err, &ae)
		require.EqualValues(t, 0x109, ae.ErrorCode)
		require.True(t, ae.Remote)
		require.Equal(t, "164:Server sent an SETTINGS_QPACK_MAX_TABLE_CAPACITY: 8192 while current value is: 4096", ae.ErrorMessage)
	case <-time.After(5 * time.Second):
		t.Fatal("the server's connection did not end")
	}
	select {
	case request := <-headers:
		t.Fatalf("Preconnect emitted an HTTP request: %v", request)
	default:
	}
}

func TestTheControlStreamTellsTheEncoderItsBlockedStreams(t *testing.T) {
	addr, _, _ := alpsServer(t, func(string) []byte { return h3Settings(1, 4096, 7, 100) }, map[uint64]uint64{1: 4096, 7: 200}, 0)
	tr := alpsClient(t, chromeALPSPolicy(t, nil))
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	require.NoError(t, err)
	rsp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	rsp.Body.Close()
	tr.mutex.Lock()
	cc := tr.clients[addr].clientConn.(*ClientConn)
	tr.mutex.Unlock()
	<-cc.ReceivedSettings()
	require.Eventually(t, func() bool {
		enc := cc.conn.qpack.encoder
		enc.mu.Lock()
		defer enc.mu.Unlock()
		return enc.blockedLimit == 200 && enc.maximum == 4096
	}, 2*time.Second, 5*time.Millisecond)
}
