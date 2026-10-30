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
  Initial's frames. A split that falls on a piece of one byte is passed
  over, as quiche's `SplitCryptoFrame` passes it over, so a packet has a
  piece fewer than drawn now and then: the first flight's second packet
  about once in 7,000, which `TestAClientsFirstFlightIsLaidOutAsChromes`
  failed on until it allowed it (2026-10-25). `Config.VerifyHandshake` is asked of a client's
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
- A client after its handshake, as Chrome 155's (2026-10-26; quiche at
  Chrome 155's DEPS revision `0b2bc13f`, the same code at Chrome 151's
  `4729ceb2`; measured on `../net-fp-server/captures/review-20261023/bench`
  `h3` and `h3alps`): `quic.ecn` `none` marks no packet for ECN (quiche
  marks only for its Prague sender, ECT(1); Cubic and BBR, Chrome's, mark
  none), `quic.mtu_probes` `none` sends no path MTU probe (quiche's client
  probes only for the MTUH and MTUL connection options, which Chrome does not
  send), `quic.connection_id_change` `when-retired` keeps the server's
  connection ID until the server retires it (`connIDManager.whenRetired`:
  quic-go changed to the next one at once after the handshake, then every
  ~10,000 packets). `Config.InitialData` is called on a client's connection
  once its handshake is done and the server's stream limits are in, before
  the connection says it is and sends anything after: what it writes goes
  in the datagram that carries the Finished. http3 (`h3.control_stream`
  `with-finished`): the Transport's dial makes the client connection there
  (`earlyClientConn`, none once its dial took none, as with 0-RTT), and the
  connection writes its control stream at once (`openControlStream`), as
  quiche's `QuicSpdySession::SendInitialData` writes it once encryption is
  established; the QPACK streams are reserved after, on a goroutine of its
  own. `h3.peer_reset` `read-side`: a request stream the server resets has
  its read side closed alone (quiche's `QuicStream::OnStreamReset` of IETF
  QUIC): nothing more is sent on it for a request sent whole (quic-go reset
  its send side too, H3_FRAME_ERROR), one still sending is cancelled with
  H3_REQUEST_CANCELLED, as Chromium's `QuicHttpStream::Close` cancels a
  request it gives up on (read in the source; Chrome adds a STOP_SENDING
  that quic-go sends no more once the server reset). Tests
  `after_handshake_test.go` (the server's qlog: ECN, packet sizes,
  RETIRE_CONNECTION_ID, the stream with the Finished), `conn_id_manager_test.go`,
  `config_test.go`, `http3/after_handshake_test.go`; 36 mutants, all
  killed.
- How a client puts its HTTP/3 writes in packets, as Chrome 155's
  (2026-10-26; quiche at Chrome 155's DEPS revision `0b2bc13f`, Chromium
  155.0.8059.85; measured on `../net-fp-server/captures/review-20261023/
  bench` `h3` and `h3alps`). `Conn.BundleWrites` holds back the packets the
  writes on the connection's streams would send until the bundle is flushed
  (nested by count, `Flush` once), the streams' frames then in the order the
  streams were given something, as quiche's `ScopedPacketFlusher`; a stream
  already sending is held from where the bundle's writes begin
  (`SendStream.wroteAt`, `holdBack`, `heldAt`, its FIN too, retransmissions
  not), and a write that has to wait spills the bundle (`Spilled`).
  `Conn.BundleOpportunistically(str, source)` has a stream send only what
  `source` gives, asked by the packer before a packet that goes anyway (new
  frames, an ACK not of a retransmission, a DATAGRAM), first in it, as
  quiche's `MaybeBundleOpportunistically` flushes its decoder stream.
  `Stream.SetResetHandler` runs a function on the connection's goroutine as
  the peer's RESET_STREAM is taken, as quiche's `OnStreamReset`. http3:
  `h3.request_writes` `one-flush` bundles a request's PRIORITY_UPDATE, its
  QPACK encoder instructions (waiting for their writer when it had nothing
  else queued and its stream is reserved or open) and its HEADERS with FIN,
  as Chromium's `QuicHttpStream::DoLoop`; `h3.qpack.decoder_writes`
  `opportunistic` keeps the decoder's instructions (bounded) for the next
  such packet, a reset's Stream Cancellation made on the connection's
  goroutine so that it goes with the reset's ACK. Tests `bundle_test.go`,
  `bundle_unit_test.go`, `http3/bundle_test.go`; 106 mutants, all killed
  but one equivalent (a wait for no instruction).
- How late a client's ACK of a lone 1-RTT packet goes, as Chrome 155's on
  macOS (2026-10-26; quiche at Chrome 155's DEPS revision `0b2bc13f`,
  Chromium 155.0.8059.85; measured on `../net-fp-server/captures/
  review-20261023/bench` `h3alps` and `h3`). `ReceivedPacketHandler.
  SetAlarmSlack` has the application-data ACK alarm fire the profile's
  `quic.alarm_slack_ms` after its delay, as the loss detection and idle
  alarms did: Chrome's every alarm goes through one timer of its network
  thread, which the macOS kernel coalesces (not Chromium's task leeway,
  measured). The Initial and Handshake ACK alarms (1 ms) take none, and a
  server's alarms are on time. Tests `received_packet_tracker_test.go`,
  `received_packet_handler_test.go`, `chrome_conn_test.go`; 11 mutants, all
  killed.
- How a client acknowledges a long download, as Chrome 155's (2026-10-26;
  quiche's `QuicReceivedPacketManager` and `QuicConnection` at Chrome 155's
  DEPS revision `0b2bc13f`; measured on `../net-fp-server/captures/
  review-20261023/bench` `h3`'s `/big`). `ReceivedPacketHandler.
  SetAckDecimation` (`AckDecimation`: from an ack-eliciting packet numbered
  the least received plus `After`, an ACK every `Packets`, a packet so
  numbered waiting `RTTPercent` of the least round trip, 0 before a sample
  (`Conn.minRTT`), at least `Min` and at most the ACK delay) as quiche's
  `MaybeEnableAckDecimation` and `GetMaxAckDelay`; the application data's
  ACK alarm never put off by a later packet (quiche keeps the earliest
  timeout; without decimation the next packet makes an ACK due anyway, so
  quic-go's later alarm was never seen). `SetGapPackets`: each packet that
  leaves the highest range no longer than its count while a gap is below it
  (between ranges, or below `IgnoreBelow`) acknowledged at once, as quiche's
  `HasNewMissingPackets`. `SetAlarmSlackPercent`: the ACK alarm's slack no
  more than that part of its delay, as the macOS kernel coalesces a timer by
  a part of how long it waits. `AckQueued` and the connection's
  `acksAfterPacket` (`quic.ack_sent_after` `packet`): `handlePackets` stops
  taking packets once an ACK is due, and takes none while the run loop waits
  for room in the send queue to send it (`sendQueueFull`), as quiche's
  `ProcessUdpPacket` flushes its ACK. The packer's `ackOnlyMax`
  (`quic.ack_only_max`) and `maxData` (`quic.ack_only_frame` `max-data`):
  the packet after so many ACK-only ones carries MAX_DATA of the connection's
  receive window as it stands (`ConnectionFlowController.ReceiveWindow`), sent
  again if lost, as quiche's `OnAckNeedsRetransmittableFrame`, not a PING.
  Tests `internal/ackhandler/ack_decimation_test.go`, `ack_policy_test.go`
  (a full send queue in a `synctest` run loop),
  `internal/flowcontrol/connection_flow_controller_test.go`; 65 mutants, all
  killed but one equivalent (`sendQueueFull` set again where the loop finds
  the queue still full before sending: the queue fills only in
  `triggerSending`, after which the loop says so).

- A6 prerequisite: the Go1.25+ self-integration adapter reads uTLS's actual
  testingOnlyCurveID numeric ConnectionState witness with reflect (no unsafe),
  since the fork has no public CurveID. Missing/type-changed state fails hard.
  Existing P-384 and X25519MLKEM768 handshake-drop assertions remain unchanged;
  no production API or fabricated group is introduced.

- A6: the initial HTTP3 control stream queues at most the existing QUIC packet
  buffer on the handshake run loop. setupConn writes the rest in its goroutine
  before publishing setupComplete, preserving small with-Finished composition,
  SETTINGS ordering, request cancellation and Close under flow control.
  GREASE lengths/settings are unchanged data;1452 is protocol.MaxPacketBufferSize,
  not a browser threshold. Large finite policies no longer deadlock the run loop.

A6 coordinated dependency also preserves an explicitly configured zero HTTP2 connection increment (fhttp e44d38f). No QUIC runtime changes in this pin.

- Review problem 10 (2026-10-28): http3's TestARequestsWritesGoInOnePacket
  AsItsProfileSays failed once in the F09 gate, the request's first packet
  [10 0] without its PRIORITY_UPDATE. A Write put its data where a packet
  could take it, let go of the stream's mutex, and only then did
  onHasStreamData hold the stream for the open write bundle (holdBack). A
  stream still in the framer's queue for what it was given before (a control
  stream whose SETTINGS a request found queued but unsent, as the local
  SETTINGS barrier lets a request go as soon as they are queued) could be
  packed in between: the PRIORITY_UPDATE went with the SETTINGS. A Write or
  Close now holds itself while a bundle is open, under the mutex that gives
  the data (heldFromHere, by the sender's writeBundles); hold lets such a
  stream go when the bundle closed or spilled before it got there. Not for a
  waited Write's remainder (its bundle spilled), nor a reset stream's Close.
  TestWhatABundleIsGivenIsHeldBeforeAPacketCanTakeIt packs in that window,
  deterministically; TestAWriteThatWaitedIsNotHeldForWhatItGivesLast; seven
  mutants, all killed.
  The test itself read what the server heard first: under load loopback
  reorders, a packet is taken for lost, and its PRIORITY_UPDATE goes again
  beside the HEADERS of the next one ([0 2], [0 10 2]: 1 in 600 runs, before
  the fix and after it). It now reads what the client packed (its qlog's
  packets sent): the first packet with the HEADERS, and whether what it
  carries of the control stream went before in a packet of its own.

- Review A1 (2026-10-28): an HTTP/3 field whose value is invalid is refused
  with an error that names the field and not its value (`invalid header field
  value for x-token`), as x/net's HTTP/2 framer says it: the value may be a
  secret, and the error reaches a caller's logs. `TestRequestHeadersValidation`
  holds it with a secret value in a row of its own.

## HTTP/3 response allocation bound (2026-10-29)

Response HEADERS and trailers retain the existing 16 MiB QPACK engine ceiling
before allocating an encoded block and while accounting decoded fields. An
absent advertised limit (-1) or a larger caller limit cannot disable the safety
bound. The SETTINGS advertisement is unchanged. Both the static and dynamic
decoders and the public response-body path retain their limits.

Explicit AdditionalSettings ID 6 owns both the advertised field-section size
and the receive limit, including zero. The receive side alone is capped by the
engine ceiling; a conflicting legacy transport value cannot override JSON.

## Cancellation observation (2026-10-29)

The bundling test decodes the peer's decoder prefix (type3, Cancellation of
stream0), selects the frame carrying instruction byte1, and compares actual
client PacketSent numbers with the ACK of the reset. A type-only frame cannot
stand in for Cancellation. Immediate mode may precede the ACK or share an
immediate ACK; opportunistic mode must share the delayed ACK. A deterministic
preannounced type and a real delayed-mode negative control retain both rules.
No production code or browser policy changes in this test correction.

## Corrupt-packet recovery test budget (2026-10-29)

Five deterministically corrupted Initials exceed the old one-second driver
deadline while the unchanged QUIC engine recovers correctly on a later PTO.
Corruption tests now use the engine's total handshake budget (twice the default
handshake idle timeout), bound both stream directions to the same deadline,
and retain exact full-echo equality. A local PCG seed and recorded fault vector
replace the process-global random sequence, and XOR guarantees each selected
byte changes. The forced five-Initial case proves recovery beyond the old
budget. Other MITM driver defaults and all runtime protocol policy are unchanged.

## A11 causal ALPS observation

The no-request ALPS test releases deliberately conflicting regular SETTINGS
only after its successful Preconnect precondition. The original exact remote
error remains, with application code 0x109 and absence of HTTP requests also
checked. This removes an unsupported ordering assumption, not an engine retry:
200 race repetitions pass. The native red observation remains in A11 evidence;
the original fixture passed 200 local repetitions and its native failure's raw
per-test log was unavailable, so that particular cause is not claimed proven.

## A11 active packet-policy observation

The MTU/CID/ECN fixture gives every tested policy the same bounded periodic
stream stimulus. PMTU checks occur on sending; an idle sleep did not guarantee a
probe, even when extended to five seconds (retained failing evidence). Each
connection remains alive for the full 300 ms negative-observation window and
until all required positive events arrive, with one five-second deadline and no
redial/replay. Packet/CID/ECN assertions are unchanged. Twenty race repetitions
pass; host ECN capability remains explicitly reported rather than fabricated.
The externally supplied UDP socket is now closed by its test owner.

## A11 decompressed header-limit witness

The decompressed HEADERS integration fixture expects the exact QPACK limit
error, raised during bounded decoding before a full header map allocation. Its
independent raw compressed-size (<1024) assertion is retained, as are the
encoded-oversize error and (>1024) assertion. Both run twenty times under race.
