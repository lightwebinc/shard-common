package aerospike

import (
	"math"
	"testing"
	"time"
)

func TestExpiration(t *testing.T) {
	cases := []struct {
		ttl  time.Duration
		want uint32
	}{
		{0, math.MaxUint32},                // no expiry
		{-1 * time.Second, math.MaxUint32}, // negative → no expiry
		{time.Second, 1},                   // exact
		{1500 * time.Millisecond, 2},       // round up
		{60 * time.Second, 60},             // dedup window
		{10 * time.Minute, 600},            // block TTL
		{1 * time.Millisecond, 1},          // sub-second floors to 1s
	}
	for _, c := range cases {
		if got := expiration(c.ttl); got != c.want {
			t.Errorf("expiration(%s) = %d, want %d", c.ttl, got, c.want)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"db.internal:3100", "db.internal", 3100},
		{"db.internal", "db.internal", defaultPort},
		{"10.0.0.5:3000", "10.0.0.5", 3000},
	}
	for _, c := range cases {
		h, p, err := splitHostPort(c.in)
		if err != nil {
			t.Errorf("splitHostPort(%q): %v", c.in, err)
			continue
		}
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)", c.in, h, p, c.host, c.port)
		}
	}
}
