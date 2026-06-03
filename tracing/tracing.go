// Package tracing provides an opt-in OpenTelemetry tracer shared by the fleet.
//
// Tracing is applied to control- and request-scoped flows only (NACK ->
// retransmit, manifest adoption, lifecycle) and MUST NOT be wired into the
// per-packet data-plane hot path. See the Distributed tracing section of
// bsv-multicast/docs/UnifiedLogging/unified-logging-plan.md.
//
// When sampling is 0 or no OTLP endpoint is configured, [Init] installs a
// no-op tracer: span creation is allocation-free and effectively free, so a
// binary built with tracing calls in place pays nothing until an operator opts
// in. Export is OTLP/gRPC, mirroring the metrics OTLP path, and runs through
// the out-of-process collector so an exporter stall cannot reach the data plane.
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Options configures [Init].
type Options struct {
	// Service is the OTel service.name; matches the logging/metrics identity.
	Service string
	// InstanceID is the OTel service.instance.id (hostname/pod).
	InstanceID string
	// Version is the build version.
	Version string
	// OTLPEndpoint is the gRPC collector endpoint (host:port). Empty disables.
	OTLPEndpoint string
	// Sampling is the head-based trace sampling ratio (0..1). 0 disables.
	Sampling float64
}

// Shutdown flushes and stops the tracer provider. It is always non-nil.
type Shutdown func(context.Context) error

// Init returns a Tracer and a Shutdown. With sampling <= 0 or an empty
// endpoint it returns a no-op tracer and a no-op shutdown (never an error), so
// callers can use the returned tracer unconditionally.
func Init(ctx context.Context, opts Options) (trace.Tracer, Shutdown, error) {
	noopShutdown := func(context.Context) error { return nil }
	if opts.Sampling <= 0 || opts.OTLPEndpoint == "" {
		return noop.NewTracerProvider().Tracer(opts.Service), noopShutdown, nil
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(opts.OTLPEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return noop.NewTracerProvider().Tracer(opts.Service), noopShutdown,
			fmt.Errorf("tracing: OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", opts.Service),
		attribute.String("service.instance.id", opts.InstanceID),
		attribute.String("service.version", opts.Version),
	))
	if err != nil {
		return noop.NewTracerProvider().Tracer(opts.Service), noopShutdown,
			fmt.Errorf("tracing: resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(opts.Sampling))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	return tp.Tracer(opts.Service), tp.Shutdown, nil
}
