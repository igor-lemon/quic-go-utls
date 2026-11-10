//go:build go1.25

package self_test

import tls "github.com/igor-lemon/utls"

// The group the handshake negotiated, as crypto/tls says it since Go 1.25,
// and uTLS since it took that release (v1.8.2-barnius).
func getCurveID(connState tls.ConnectionState) tls.CurveID {
	return connState.CurveID
}
