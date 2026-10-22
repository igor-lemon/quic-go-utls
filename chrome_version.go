package quic

import (
	"fmt"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
)

// A v1-only client cannot be downgraded to another version by a forged VN.
// Wider compatible/incompatible version selection needs its own authenticated
// history/validation implementation and is intentionally not advertised here.
func chromeClientVersionPolicy(c *Config) (*Config, error) {
	if c == nil || !c.ChromeBehavior {
		return c, nil
	}
	c = c.Clone()
	if len(c.Versions) == 0 {
		c.Versions = []Version{Version1}
	}
	if len(c.Versions) != 1 || c.Versions[0] != protocol.Version1 {
		return nil, fmt.Errorf("Chrome QUIC policy supports only version1;cross-version negotiation is unavailable")
	}
	return c, nil
}
