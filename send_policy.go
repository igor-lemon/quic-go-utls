package quic

import (
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/ackhandler"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/utls/behavior"
)

// sendPolicyOf is how a client's profile numbers its packets and probes a
// silent server (quic.packet_numbers, quic.first_packet_number,
// quic.packet_number_length, quic.pto_skip, quic.pto_probes,
// quic.alarm_slack_ms); nothing said is quic-go's way.
func sendPolicyOf(p behavior.Policy) ackhandler.SendPolicy {
	return ackhandler.SendPolicy{
		SharedPacketNumbers:      p.Text("quic.packet_numbers") == "shared",
		FirstPacketNumber:        protocol.PacketNumber(p.Uint("quic.first_packet_number")),
		WindowPacketNumberLength: p.Text("quic.packet_number_length") == "window",
		SkipInEverySpace:         p.Text("quic.pto_skip") == "every-space",
		Probes:                   p.Int("quic.pto_probes"),
		AlarmSlack:               time.Duration(p.Uint("quic.alarm_slack_ms")) * time.Millisecond,
	}
}

// ptoPolicyOf is how a client's profile works out a probe timeout
// (quic.pto_initial_rtt_ms, quic.pto_no_sample_multiplier,
// quic.pto_no_sample_min_ms, quic.pto_rttvar_multiplier).
func ptoPolicyOf(p behavior.Policy) utils.PTOPolicy {
	return utils.PTOPolicy{
		InitialRTT:         time.Duration(p.Uint("quic.pto_initial_rtt_ms")) * time.Millisecond,
		NoSampleMultiplier: p.Int("quic.pto_no_sample_multiplier"),
		NoSampleMin:        time.Duration(p.Uint("quic.pto_no_sample_min_ms")) * time.Millisecond,
		RTTVarMultiplier:   p.Int("quic.pto_rttvar_multiplier"),
	}
}
