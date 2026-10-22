package http3

import "testing"

func TestGreaseFrameDrawsAreNotConstant(t *testing.T) {
	seen := map[uint64]bool{}
	for range 16 {
		id := generateGREASEFrameType()
		if id < 0x21 || (id-0x21)%0x1f != 0 {
			t.Fatalf("invalid GREASE family %x", id)
		}
		seen[id] = true
	}
	if len(seen) == 1 {
		t.Fatal("constant GREASE frame type")
	}
}
