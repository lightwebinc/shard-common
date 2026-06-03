package tracing

import (
	"context"
	"testing"
	"time"
)

func TestInitNoopWhenDisabled(t *testing.T) {
	for _, opts := range []Options{
		{Service: "s", Sampling: 0, OTLPEndpoint: "collector:4317"},
		{Service: "s", Sampling: 1, OTLPEndpoint: ""},
	} {
		tr, shutdown, err := Init(context.Background(), opts)
		if err != nil {
			t.Fatalf("disabled Init returned error: %v", err)
		}
		if tr == nil || shutdown == nil {
			t.Fatal("nil tracer or shutdown from disabled Init")
		}
		// No-op spans must be usable without panicking.
		_, span := tr.Start(context.Background(), "noop")
		span.End()
		if err := shutdown(context.Background()); err != nil {
			t.Errorf("noop shutdown error: %v", err)
		}
	}
}

func TestInitEnabledBuildsProvider(t *testing.T) {
	// A reachable connection is not required: the gRPC exporter dials lazily,
	// so Init succeeds and returns a real tracer + shutdown.
	tr, shutdown, err := Init(context.Background(), Options{
		Service: "s", InstanceID: "i", Version: "v",
		OTLPEndpoint: "127.0.0.1:4317", Sampling: 1.0,
	})
	if err != nil {
		t.Fatalf("enabled Init error: %v", err)
	}
	_, span := tr.Start(context.Background(), "op")
	span.End()
	// Bound shutdown so the absent collector cannot stall the test.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Logf("shutdown error (expected without collector): %v", err)
	}
}
