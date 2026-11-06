package http3

import (
	"bytes"
	"encoding/json"
	"testing"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptest"
	"github.com/igor-lemon/quic-go-utls/testutils/events"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
)

func TestCookieCrumbsAreCutAsQuicheCutsThem(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []string
	}{
		{"a=1", []string{"a=1"}},
		{"a=1; b=2", []string{"a=1", "b=2"}},
		{"a=1;b=2", []string{"a=1", "b=2"}},
		// One space dropped, not two; the empty crumbs too.
		{"a=1;  b=2", []string{"a=1", " b=2"}},
		{"a=1;", []string{"a=1", ""}},
		{"a=1; ", []string{"a=1", ""}},
		{"a=1;;b=2", []string{"a=1", "", "b=2"}},
		{"", []string{""}},
	} {
		var got []string
		cookieCrumbs(tc.value, func(crumb string) { got = append(got, crumb) })
		require.Equal(t, tc.want, got, tc.value)
	}
}

func TestACookieGoesAFieldACrumbWhereTheProfileSays(t *testing.T) {
	for _, crumbs := range []bool{true, false} {
		req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/", nil)
		req.Header = http.Header{"Cookie": {"a=1; b=2"}, "Accept": {"*/*"},
			http.HeaderOrderKey: {"accept", "cookie"}}
		w := newRequestWriter()
		w.behavior = behavior.Policy{"h3.cookie_crumbs": json.RawMessage(map[bool]string{true: "true", false: "false"}[crumbs])}
		var recorder events.Recorder
		buf := &bytes.Buffer{}
		require.NoError(t, w.WriteRequestHeader(buf, req, false, 42, &recorder))
		var cookies []string
		for _, f := range decodeRequestHeaderFields(t, buf, 42, &recorder) {
			if f.Name == "cookie" {
				cookies = append(cookies, f.Value)
			}
		}
		if crumbs {
			require.Equal(t, []string{"a=1", "b=2"}, cookies)
		} else {
			require.Equal(t, []string{"a=1; b=2"}, cookies)
		}
	}
}
