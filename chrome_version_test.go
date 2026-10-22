package quic

import (
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
	"github.com/igor-lemon/quic-go-utls/internal/qerr"
	"github.com/igor-lemon/quic-go-utls/internal/utils"
	"github.com/igor-lemon/quic-go-utls/internal/wire"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestChromeClientVersionPolicy(t *testing.T) {
	for _, versions := range [][]Version{nil, {Version1}, {Version2}, {Version1, Version2}, {Version2, Version1}} {
		c := &Config{ChromeBehavior: true, Versions: versions}
		got, err := chromeClientVersionPolicy(c)
		if len(versions) == 0 || len(versions) == 1 && versions[0] == Version1 {
			require.NoError(t, err)
			require.Equal(t, []Version{Version1}, got.Versions)
			require.NotSame(t, c, got)
		} else {
			require.Error(t, err)
		}
		require.Equal(t, versions, c.Versions)
	}
	generic := &Config{Versions: []Version{Version2, Version1}}
	got, err := chromeClientVersionPolicy(generic)
	require.NoError(t, err)
	require.Same(t, generic, got)
}
func TestVersionInformationCheckedBeforeOtherParameters(t *testing.T) {
	for _, perspective := range []protocol.Perspective{protocol.PerspectiveClient, protocol.PerspectiveServer} {
		c := &Conn{logger: utils.DefaultLogger, perspective: perspective, version: Version1, config: &Config{ChromeBehavior: true}}
		for _, info := range []*wire.VersionInformation{nil, {ChosenVersion: 1}, {ChosenVersion: 1, AvailableVersions: []Version{Version2}}} {
			require.NoError(t, c.checkTransportParameters(&wire.TransportParameters{VersionInformation: info}))
		}
		err := c.checkTransportParameters(&wire.TransportParameters{VersionInformation: &wire.VersionInformation{ChosenVersion: Version2, AvailableVersions: []Version{Version2}}})
		var e *qerr.TransportError
		require.ErrorAs(t, err, &e)
		code := qerr.VersionNegotiationErrorCode
		if perspective == protocol.PerspectiveClient {
			code = qerr.ProtocolViolation
		}
		require.Equal(t, code, e.ErrorCode)
		if perspective == protocol.PerspectiveClient {
			err = c.handleTransportParameters(&wire.TransportParameters{VersionInformation: &wire.VersionInformation{ChosenVersion: Version2, AvailableVersions: []Version{Version2}}})
			require.ErrorAs(t, err, &e)
			require.Equal(t, code, e.ErrorCode)
		}
	}
}

func TestChromeVersionNegotiationRejectsWrongReflection(t *testing.T) {
	id := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	wrong := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})
	for _, test := range []struct {
		src, dst protocol.ConnectionID
		retry    bool
	}{
		{wrong, protocol.ConnectionID{}, false}, {id, wrong, false}, {id, protocol.ConnectionID{}, true},
	} {
		c := &Conn{config: &Config{ChromeBehavior: true}, version: Version1, origDestConnID: id, receivedRetry: test.retry}
		p := getVersionNegotiationPacket(test.src, test.dst, []protocol.Version{Version2})
		require.NoError(t, c.handleVersionNegotiationPacket(p))
		p.buffer.Release()
		require.Nil(t, c.closeErr.Load())
	}
	c := &Conn{config: &Config{ChromeBehavior: true}, version: Version1, origDestConnID: id}
	p := getVersionNegotiationPacket(id, protocol.ConnectionID{}, []protocol.Version{Version1, Version2})
	require.NoError(t, c.handleVersionNegotiationPacket(p))
	p.buffer.Release()
	require.Nil(t, c.closeErr.Load())
}
