// DUPLICATE FILE - DISABLED TO FIX COMPILATION ERROR
// This file is a duplicate of otel/otel.go and causes package conflicts.
// The main.go imports "heckel.io/ntfy/v2/otel" package, but this file has "package main"
// which creates function name conflicts. The correct implementation is in otel/otel.go.
//
// Disabled by changing package name to prevent compilation errors.

package main_DISABLED_DUPLICATE

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials"
)

// Global telemetry instances
var (
	otelTracer trace.Tracer
	otelMeter  metric.Meter
	otelLogger *slog.Logger
)

// setupTracing configures OpenTelemetry tracing with OTLP gRPC exporter.
func setupTracing(ctx context.Context, res *resource.Resource, otlpEndpoint string, bearerToken string) (*sdktrace.TracerProvider, error) {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(otlpEndpoint),
	}

	// Configure authentication if bearer token is provided
	if bearerToken != "" {
		opts = append(opts, otlptracegrpc.WithHeaders(map[string]string{
			"authorization": "Bearer " + bearerToken,
		}))
		// Use TLS when bearer token is provided (for Observe)
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else {
		// Use insecure connection for local development
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	traceExporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp, nil
}

// setupMetrics configures OpenTelemetry metrics with OTLP gRPC exporter.
func setupMetrics(ctx context.Context, res *resource.Resource, otlpEndpoint string, bearerToken string) (*sdkmetric.MeterProvider, error) {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(otlpEndpoint),
	}

	// Configure authentication if bearer token is provided
	if bearerToken != "" {
		opts = append(opts, otlpmetricgrpc.WithHeaders(map[string]string{
			"authorization": "Bearer " + bearerToken,
		}))
		// Use TLS when bearer token is provided (for Observe)
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else {
		// Use insecure connection for local development
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	metricExporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	return mp, nil
}

// setupLogging configures OpenTelemetry logging with OTLP gRPC exporter and structured logging.
func setupLogging(ctx context.Context, res *resource.Resource, otlpEndpoint, serviceName, bearerToken string) (*sdklog.LoggerProvider, error) {
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(otlpEndpoint),
	}

	// Configure authentication if bearer token is provided
	if bearerToken != "" {
		opts = append(opts, otlploggrpc.WithHeaders(map[string]string{
			"authorization": "Bearer " + bearerToken,
		}))
		// Use TLS when bearer token is provided (for Observe)
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else {
		// Use insecure connection for local development
		opts = append(opts, otlploggrpc.WithInsecure())
	}

	logExporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
		sdklog.WithResource(res),
	)
	global.SetLoggerProvider(lp)

	// Create structured logger that will send logs to OTLP
	otelHandler := otelslog.NewHandler(serviceName)
	otelLogger = slog.New(otelHandler)

	return lp, nil
}

// setupInstrumentation initializes OpenTelemetry with tracing, metrics, and logging.
// Returns a cleanup function that should be called before application shutdown.
func setupInstrumentation(serviceName string) func() {
	ctx := context.Background()

	// Get OTLP endpoint from environment or use default
	otlpEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint == "" {
		otlpEndpoint = "localhost:4317"
	}

	// Get bearer token for authentication (used by Observe)
	bearerToken := os.Getenv("OTEL_EXPORTER_OTLP_BEARER_TOKEN")

	// Create resource with service identification
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		slog.Error("failed to create resource", "error", err)
		panic(err)
	}

	// Setup tracing
	tp, err := setupTracing(ctx, res, otlpEndpoint, bearerToken)
	if err != nil {
		slog.Error("failed to setup tracing", "error", err)
		panic(err)
	}
	otelTracer = otel.Tracer(serviceName)

	// Setup metrics
	mp, err := setupMetrics(ctx, res, otlpEndpoint, bearerToken)
	if err != nil {
		slog.Error("failed to setup metrics", "error", err)
		panic(err)
	}
	otelMeter = otel.Meter(serviceName)

	// Setup logging
	lp, err := setupLogging(ctx, res, otlpEndpoint, serviceName, bearerToken)
	if err != nil {
		slog.Error("failed to setup logging", "error", err)
		panic(err)
	}

	otelLogger.Info("OpenTelemetry instrumentation initialized",
		"service", serviceName,
		"endpoint", otlpEndpoint,
		"authenticated", bearerToken != "")

	// Return cleanup function
	return func() {
		otelLogger.Info("Shutting down OpenTelemetry instrumentation")

		if err := tp.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown tracer provider", "error", err)
		}
		if err := mp.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown meter provider", "error", err)
		}
		if err := lp.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown logger provider", "error", err)
		}
	}
}

// GetOtelTracer returns the global tracer instance.
// Call setupInstrumentation first.
func GetOtelTracer() trace.Tracer {
	return otelTracer
}

// GetOtelMeter returns the global meter instance.
// Call setupInstrumentation first.
func GetOtelMeter() metric.Meter {
	return otelMeter
}

// GetOtelLogger returns the global structured logger instance.
// Call setupInstrumentation first.
func GetOtelLogger() *slog.Logger {
	return otelLogger
}
