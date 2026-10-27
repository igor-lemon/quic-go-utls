//go:build go1.25

package self_test

import (
	tls "github.com/igor-lemon/utls"
	"reflect"
)

// uTLS retains the actual negotiated group in its upstream test-state field.
// This test-only adapter reads that numeric witness without unsafe or a new
// production API. Missing/changing state is a hard failure, never a fake group.
func getCurveID(connState tls.ConnectionState) tls.CurveID {
	group := reflect.ValueOf(connState).FieldByName("testingOnlyCurveID")
	if !group.IsValid() || group.Kind() != reflect.Uint16 {
		panic("uTLS negotiated-group test witness is unavailable")
	}
	return tls.CurveID(group.Uint())
}
