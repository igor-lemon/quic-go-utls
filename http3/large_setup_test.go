package http3

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/utls/behavior"
)

func TestLargeInitialControlWriteDoesNotBlockRunLoop(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "finite-exchange", true: "flow-blocked-close"}[blocked], func(t *testing.T) {
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			if blocked {
				ln, err := quic.Listen(udp, getTLSConfig(), &quic.Config{InitialStreamReceiveWindow: 32, MaxStreamReceiveWindow: 32})
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				accepted := make(chan struct{})
				go func() {
					c, e := ln.Accept(context.Background())
					if e == nil {
						close(accepted)
						<-c.Context().Done()
					}
				}()
			} else {
				server := &Server{TLSConfig: getTLSConfig(), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })}
				go func() { _ = server.Serve(udp) }()
				defer server.Close()
			}
			pol := behavior.Legacy()
			pol["h3.grease_payload_lengths"] = json.RawMessage(`[4096]`)
			pol["h3.control_stream"] = json.RawMessage(`"with-finished"`)
			conf := getTLSClientConfig()
			conf.ServerName = "localhost"
			tr := &Transport{TLSClientConfig: conf, Behavior: pol, SendGreaseFrames: true}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+udp.LocalAddr().String()+"/", nil)
			result := make(chan error, 1)
			go func() {
				res, e := tr.RoundTrip(req)
				if e == nil {
					body, readErr := io.ReadAll(res.Body)
					_ = res.Body.Close()
					e = readErr
					if string(body) != "ok" {
						t.Error("wrong body", string(body))
					}
				}
				result <- e
			}()
			select {
			case e := <-result:
				if !blocked && e != nil {
					t.Error(e)
				}
				if blocked && e == nil {
					t.Error("expected request cancellation")
				}
			case <-time.After(2 * time.Second):
				t.Error("large prefix blocked request cancellation")
			}
			closed := make(chan error, 1)
			go func() { closed <- tr.Close() }()
			select {
			case e := <-closed:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(time.Second):
				t.Error("large prefix blocked Transport.Close")
			}
		})
	}
}
