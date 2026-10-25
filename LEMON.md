# quic-go-utls for tls-forge

A fork of [bogdanfinn/quic-go-utls](https://github.com/bogdanfinn/quic-go-utls)
v1.0.10-utls (`4e6a46505b5f54c5bff5db72b600795648364e09`), on the branch
`tls-forge`, for [tls-forge](https://github.com/Sec-CH-Lemon/tls-forge).

- The module is `github.com/igor-lemon/quic-go-utls`, and it imports fhttp
  and utls as `github.com/igor-lemon/fhttp` and `github.com/igor-lemon/utls`,
  the forks tls-forge patches: tls-client hands their types to this module's
  http3, so both have to name the same ones. On another base:

      grep -rlE 'github\.com/bogdanfinn/(fhttp|utls|quic-go-utls)' --include='*.go' --include=go.mod . |
        xargs perl -pi -e 's#github\.com/bogdanfinn/(fhttp|utls|quic-go-utls)\b#github.com/igor-lemon/$1#g'

  then `git diff --name-only -- '*.go' | xargs gofmt -w`, which puts the
  renamed imports back in order, `go mod edit
  -require=github.com/igor-lemon/fhttp@<version>
  -require=github.com/igor-lemon/utls@<version>` and `go mod tidy`.
- At the base, `go vet` refuses `integrationtests/self/self_go125_test.go`
  (utls's ConnectionState has no CurveID), upstream as here.
- A client's QUIC handshake as Chrome 155's, by its profile (2026-10-25):
  one packet number counter for the three spaces from
  `quic.first_packet_number`, numbers as long as quiche's window rule makes
  them (`internal/ackhandler/send_policy.go`: `SetSendPolicy`, `PlanPacket`,
  `KeysInstalled`, `windowLength`, `leastAwaited`, `skipForProbe`; a history
  of the shared counter keeps the other spaces' numbers as gaps), one probe
  a probe timeout and a number skipped before it in every space, alarms
  `quic.alarm_slack_ms` late, a probe timeout as quiche works it out
  (`utils.PTOPolicy`), Initial and Handshake ACKs within
  `quic.handshake_ack_timer_ms` (`SetHandshakeAckDelay`), the handshake's
  idle and whole timeouts the profile's, an idle connection whose probes went
  unanswered closed with quiche's reason (`idle_close.go`), the first flight
  laid out by chaos (`chaos.go`, `chaos_stream.go`: quiche's
  `QuicChaosProtector` and `MultiPacketChaosProtect`), padding after an
  Initial's frames. `Config.VerifyHandshake` is asked of a client's
  connection once its TLS handshake is done, before the connection says it
  is: its error closes the connection before its Finished goes, a
  `TransportError` or `ApplicationError` as it is, `ErrHandshakeAbandoned`
  without a word. `quic.close_early_application` `application` sends an
  application close as it is in Initial and Handshake packets too, as
  quiche does. A close's coalesced packets fill the datagram to its size:
  upstream counted the 1-RTT packet without its AEAD tag and went 16 bytes
  past it.
- http3 reads a server's ALPS for h3 as Chrome does (2026-10-25,
  `http3/alps.go`, `h3.alps_reader` `quiche`: `readALPS` is quiche's
  HttpDecoder and AlpsFrameDecoder over one buffer, `VerifyALPS` the
  `VerifyHandshake` a Transport of such a profile installs): its SETTINGS
  taken as `QuicSpdySession::OnSetting` takes them (`peerSettings`), the
  QPACK encoder told the table before the first request
  (`configureEarly`: the warmup holds back the control stream's settings
  alone), the ACCEPT_CH entries kept for a trace's `GotConn` connection
  (`fakeConn.AcceptCH`); the control stream's SETTINGS held to them
  (`peerSettings.control`, the booleans kept as said for it,
  `frameParser.booleansAsSaid`). A request's header is the one its
  `HeaderFor` gives for `h3` (fhttp's `ProtocolHTTP3`). Tests
  `verify_handshake_test.go`, `http3/alps_test.go`,
  `http3/qpack_dynamic_test.go`.
- A request given only cached connections (`RoundTripOpt.OnlyCachedConn`)
  is not sent again after an error of the protocol (`h3.retry_attempts`,
  2026-10-25, `doRoundTripOpt`): its client was let go of, and the replay
  could only say `ErrNoCachedConn`, hiding the error its caller (tls-client's
  DNS path, which sends it over TCP) acts on. A request refused unprocessed
  is still tried again, and says there is no connection. Test
  `TestARequestOnlyACachedConnectionMayTakeIsNotSentAgainAfterAnErrorOfTheProtocol`.
