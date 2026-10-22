package quic

import (
	"fmt"
	"github.com/igor-lemon/quic-go-utls/internal/protocol"
)

// A v1-only client cannot be downgraded to another version by a forged VN.
// Wider compatible/incompatible version selection needs its own authenticated
// history/validation implementation and is intentionally not advertised here.
func chromeClientVersionPolicy(c *Config) (*Config, error) {
	if c == nil || !c.Policy().Flag("quic.enabled") {
		return c, nil
	}
	if err := c.Policy().Validate(); err != nil {
		return nil, err
	}
	c = c.Clone()
	if len(c.Versions) == 0 {
		for _, v := range c.Policy().Numbers("quic.versions") {
			c.Versions = append(c.Versions, Version(v))
		}
	}
	if len(c.Versions) != 1 || c.Versions[0] != protocol.Version1 {
		return nil, fmt.Errorf("profile QUIC policy supports only version1; cross-version negotiation is unavailable")
	}
	return c, nil
}
