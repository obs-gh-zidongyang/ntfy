package server

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"heckel.io/ntfy/v2/otel"
)

var (
	// Prometheus metrics (existing)
	metricMessagesPublishedSuccess     prometheus.Counter
	metricMessagesPublishedFailure     prometheus.Counter
	metricMessagesCached               prometheus.Gauge
	metricMessagePublishDurationMillis prometheus.Gauge
	metricFirebasePublishedSuccess     prometheus.Counter
	metricFirebasePublishedFailure     prometheus.Counter
	metricEmailsPublishedSuccess       prometheus.Counter
	metricEmailsPublishedFailure       prometheus.Counter
	metricEmailsReceivedSuccess        prometheus.Counter
	metricEmailsReceivedFailure        prometheus.Counter
	metricCallsMadeSuccess             prometheus.Counter
	metricCallsMadeFailure             prometheus.Counter
	metricUnifiedPushPublishedSuccess  prometheus.Counter
	metricMatrixPublishedSuccess       prometheus.Counter
	metricMatrixPublishedFailure       prometheus.Counter
	metricAttachmentsTotalSize         prometheus.Gauge
	metricVisitors                     prometheus.Gauge
	metricSubscribers                  prometheus.Gauge
	metricTopics                       prometheus.Gauge
	metricUsers                        prometheus.Gauge
	metricHTTPRequests                 *prometheus.CounterVec

	// OpenTelemetry metrics (new)
	otelMessagesPublished     metric.Int64Counter
	otelMessagePublishLatency metric.Int64Histogram
	otelFirebasePublished     metric.Int64Counter
	otelEmailsSent            metric.Int64Counter
	otelCallsMade             metric.Int64Counter
	otelSubscriptions         metric.Int64UpDownCounter
	otelActiveConnections     metric.Int64UpDownCounter
	otelCacheOperations       metric.Int64Counter
)

func initMetrics() {
	metricMessagesPublishedSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_messages_published_success",
	})
	metricMessagesPublishedFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_messages_published_failure",
	})
	metricMessagesCached = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntfy_messages_cached_total",
	})
	metricMessagePublishDurationMillis = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntfy_message_publish_duration_ms",
	})
	metricFirebasePublishedSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_firebase_published_success",
	})
	metricFirebasePublishedFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_firebase_published_failure",
	})
	metricEmailsPublishedSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_emails_sent_success",
	})
	metricEmailsPublishedFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_emails_sent_failure",
	})
	metricEmailsReceivedSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_emails_received_success",
	})
	metricEmailsReceivedFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_emails_received_failure",
	})
	metricCallsMadeSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_calls_made_success",
	})
	metricCallsMadeFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_calls_made_failure",
	})
	metricUnifiedPushPublishedSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_unifiedpush_published_success",
	})
	metricMatrixPublishedSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_matrix_published_success",
	})
	metricMatrixPublishedFailure = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ntfy_matrix_published_failure",
	})
	metricAttachmentsTotalSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntfy_attachments_total_size",
	})
	metricVisitors = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntfy_visitors_total",
	})
	metricUsers = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntfy_users_total",
	})
	metricSubscribers = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntfy_subscribers_total",
	})
	metricTopics = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ntfy_topics_total",
	})
	metricHTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ntfy_http_requests_total",
	}, []string{"http_code", "ntfy_code", "http_method"})

	// Initialize OpenTelemetry metrics
	initOtelMetrics()

	prometheus.MustRegister(
		metricMessagesPublishedSuccess,
		metricMessagesPublishedFailure,
		metricMessagesCached,
		metricMessagePublishDurationMillis,
		metricFirebasePublishedSuccess,
		metricFirebasePublishedFailure,
		metricEmailsPublishedSuccess,
		metricEmailsPublishedFailure,
		metricEmailsReceivedSuccess,
		metricEmailsReceivedFailure,
		metricCallsMadeSuccess,
		metricCallsMadeFailure,
		metricUnifiedPushPublishedSuccess,
		metricMatrixPublishedSuccess,
		metricMatrixPublishedFailure,
		metricAttachmentsTotalSize,
		metricVisitors,
		metricUsers,
		metricSubscribers,
		metricTopics,
		metricHTTPRequests,
	)
}

// initOtelMetrics initializes OpenTelemetry metrics
func initOtelMetrics() {
	meter := otel.GetOtelMeter()
	if meter == nil {
		return // OpenTelemetry not initialized
	}

	var err error

	// Messages published counter
	otelMessagesPublished, err = meter.Int64Counter(
		"ntfy.messages.published",
		metric.WithDescription("Total number of messages published"),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Log error but don't fail
	}

	// Message publish latency histogram
	otelMessagePublishLatency, err = meter.Int64Histogram(
		"ntfy.message.publish.duration",
		metric.WithDescription("Message publish duration"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		// Log error but don't fail
	}

	// Firebase published counter
	otelFirebasePublished, err = meter.Int64Counter(
		"ntfy.firebase.published",
		metric.WithDescription("Total number of Firebase notifications sent"),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Log error but don't fail
	}

	// Emails sent counter
	otelEmailsSent, err = meter.Int64Counter(
		"ntfy.emails.sent",
		metric.WithDescription("Total number of email notifications sent"),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Log error but don't fail
	}

	// Calls made counter
	otelCallsMade, err = meter.Int64Counter(
		"ntfy.calls.made",
		metric.WithDescription("Total number of phone calls made"),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Log error but don't fail
	}

	// Active subscriptions gauge
	otelSubscriptions, err = meter.Int64UpDownCounter(
		"ntfy.subscriptions.active",
		metric.WithDescription("Number of active subscriptions"),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Log error but don't fail
	}

	// Active connections gauge
	otelActiveConnections, err = meter.Int64UpDownCounter(
		"ntfy.connections.active",
		metric.WithDescription("Number of active connections"),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Log error but don't fail
	}

	// Cache operations counter
	otelCacheOperations, err = meter.Int64Counter(
		"ntfy.cache.operations",
		metric.WithDescription("Total number of cache operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		// Log error but don't fail
	}
}

// minc increments a prometheus.Counter if it is non-nil
func minc(counter prometheus.Counter) {
	if counter != nil {
		counter.Inc()
	}
}

// mset sets a prometheus.Gauge if it is non-nil
func mset[T int | int64 | float64](gauge prometheus.Gauge, value T) {
	if gauge != nil {
		gauge.Set(float64(value))
	}
}

// OpenTelemetry metric helper functions

// recordMessagePublished records a message published event with OpenTelemetry metrics
func recordMessagePublished(ctx context.Context, success bool, topic string, protocol string) {
	if otelMessagesPublished != nil {
		attrs := []attribute.KeyValue{
			attribute.Bool("success", success),
			attribute.String("topic", topic),
		}
		if protocol != "" {
			attrs = append(attrs, attribute.String("protocol", protocol))
		}
		otelMessagesPublished.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// recordMessagePublishLatency records message publish latency with OpenTelemetry metrics
func recordMessagePublishLatency(ctx context.Context, durationMs int64, topic string) {
	if otelMessagePublishLatency != nil {
		otelMessagePublishLatency.Record(ctx, durationMs, metric.WithAttributes(
			attribute.String("topic", topic),
		))
	}
}

// recordFirebasePublished records a Firebase notification event
func recordFirebasePublished(ctx context.Context, success bool) {
	if otelFirebasePublished != nil {
		otelFirebasePublished.Add(ctx, 1, metric.WithAttributes(
			attribute.Bool("success", success),
		))
	}
}

// recordEmailSent records an email notification event
func recordEmailSent(ctx context.Context, success bool) {
	if otelEmailsSent != nil {
		otelEmailsSent.Add(ctx, 1, metric.WithAttributes(
			attribute.Bool("success", success),
		))
	}
}

// recordCallMade records a phone call event
func recordCallMade(ctx context.Context, success bool) {
	if otelCallsMade != nil {
		otelCallsMade.Add(ctx, 1, metric.WithAttributes(
			attribute.Bool("success", success),
		))
	}
}

// recordSubscriptionChange records subscription count changes
func recordSubscriptionChange(ctx context.Context, delta int64, topic string) {
	if otelSubscriptions != nil {
		otelSubscriptions.Add(ctx, delta, metric.WithAttributes(
			attribute.String("topic", topic),
		))
	}
}

// recordConnectionChange records active connection count changes
func recordConnectionChange(ctx context.Context, delta int64, connectionType string) {
	if otelActiveConnections != nil {
		otelActiveConnections.Add(ctx, delta, metric.WithAttributes(
			attribute.String("type", connectionType),
		))
	}
}

// recordCacheOperation records cache operations
func recordCacheOperation(ctx context.Context, operation string, success bool) {
	if otelCacheOperations != nil {
		otelCacheOperations.Add(ctx, 1, metric.WithAttributes(
			attribute.String("operation", operation),
			attribute.Bool("success", success),
		))
	}
}
