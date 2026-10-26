package quic

import (
	"time"

	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/qlog"
	"github.com/igor-lemon/utls/behavior"
)

// idleClose is an idle timeout said to the peer: it closes the connection
// as an idle timeout, and its CONNECTION_CLOSE is close.
type idleClose struct{ close *qerr.TransportError }

func (e *idleClose) Error() string   { return qerr.ErrIdleTimeout.Error() }
func (e *idleClose) Timeout() bool   { return true }
func (e *idleClose) Temporary() bool { return false }
func (e *idleClose) Unwrap() []error { return []error{qerr.ErrIdleTimeout, e.close} }

// alarmSlack is how late a client's alarms fire, as the profile says
// (quic.alarm_slack_ms): its loss detection, idle and 1-RTT ACK alarms.
func (c *Conn) alarmSlack() time.Duration {
	if c.perspective != protocol.PerspectiveClient {
		return 0
	}
	return time.Duration(c.config.Policy().Uint("quic.alarm_slack_ms")) * time.Millisecond
}

// handshakeIdleTimeout is how long a handshake may be idle, the alarm's
// slack with it: the timer and the check after it go by it alike.
func (c *Conn) handshakeIdleTimeout() time.Duration {
	return c.config.HandshakeIdleTimeout + c.alarmSlack()
}

// closeIdle ends a connection idle for elapsed. A client whose profile
// says quic.idle_close after-pto tells the peer when its probes went
// unanswered, as quiche's OnIdleNetworkDetected does: a CONNECTION_CLOSE of
// the profile's code and reason, the handshake's while it is not complete,
// which lists the packets kept undecrypted. Otherwise it ends silently.
func (c *Conn) closeIdle(elapsed time.Duration) {
	p := c.config.Policy()
	if c.perspective != protocol.PerspectiveClient || p.Text("quic.idle_close") != "after-pto" ||
		c.sentPacketHandler.PTOCount() == 0 {
		c.destroyImpl(qerr.ErrIdleTimeout)
		return
	}
	template, timeout := p.Text("quic.idle_close_reason"), c.idleTimeout
	if !c.handshakeComplete {
		template, timeout = p.Text("quic.handshake_idle_close_reason"), c.config.HandshakeIdleTimeout
	}
	values := behavior.QUICReasonValues{Elapsed: elapsed, Timeout: timeout}
	if names := p.Strings("quic.undecryptable_level_names"); len(names) == 4 {
		for _, u := range c.undecryptablePackets {
			values.Undecryptable = append(values.Undecryptable,
				behavior.QUICUndecryptable{Level: names[levelIndex(u.packetType)], Length: len(u.data)})
		}
	}
	// the profile's template was held to the placeholders when it was loaded
	reason, _ := behavior.QUICReason(template, values)
	c.closeLocal(&idleClose{close: &qerr.TransportError{
		ErrorCode:    qerr.TransportErrorCode(p.Uint("quic.idle_close_code")),
		ErrorMessage: reason,
	}})
}

// levelIndex is the place of a packet's encryption level in
// quic.undecryptable_level_names: Initial, Handshake, 0-RTT, 1-RTT.
func levelIndex(t qlog.PacketType) int {
	switch t {
	case qlog.PacketTypeHandshake:
		return 1
	case qlog.PacketType0RTT:
		return 2
	case qlog.PacketType1RTT:
		return 3
	}
	return 0
}
