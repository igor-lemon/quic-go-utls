package handshake

import (
	"fmt"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	tls "github.com/igor-lemon/utls"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVersionInformationErrorPolicyAndWrap(t *testing.T) {
	base := (&wire.TransportParameters{ActiveConnectionIDLimit: 2}).Marshal(protocol.PerspectiveServer)
	for _, chrome := range []bool{false, true} {
		h := &cryptoSetup{perspective: protocol.PerspectiveClient, tlsConf: &tls.Config{ChromeBehavior: chrome}}
		err := h.handleTransportParameters(append(append([]byte{}, base...), 17, 0))
		var e *qerr.TransportError
		require.ErrorAs(t, err, &e)
		code := qerr.TransportParameterError
		if chrome {
			code = qerr.ProtocolViolation
		}
		require.Equal(t, code, e.ErrorCode)
		require.Same(t, err, wrapError(err))
	}
	for _, code := range []qerr.TransportErrorCode{qerr.TransportParameterError, qerr.VersionNegotiationErrorCode, qerr.ProtocolViolation} {
		e := &qerr.TransportError{ErrorCode: code}
		wrapped := fmt.Errorf("outer: %w", e)
		require.Same(t, wrapped, wrapError(wrapped))
	}
}
