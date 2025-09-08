package util

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelsql"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
)

// OpenInstrumentedDB opens a database connection with OpenTelemetry instrumentation.
// This should be used instead of sql.Open to automatically trace database operations.
func OpenInstrumentedDB(driverName, dataSourceName string) (*sql.DB, error) {
	// Open the database connection with OpenTelemetry instrumentation
	db, err := otelsql.Open(driverName, dataSourceName,
		otelsql.WithAttributes(
			attribute.String("db.system", "sqlite"),
		),
		otelsql.WithDBName("ntfy"),
	)
	if err != nil {
		return nil, err
	}

	// Report database stats as metrics
	otelsql.ReportDBStatsMetrics(db)

	return db, nil
}

// NewInstrumentedHTTPClient creates an HTTP client with OpenTelemetry instrumentation.
// This should be used instead of http.DefaultClient for external API calls.
func NewInstrumentedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

// InstrumentedHTTPClient is a default instrumented HTTP client with a 10-second timeout.
var InstrumentedHTTPClient = NewInstrumentedHTTPClient(10 * time.Second)
