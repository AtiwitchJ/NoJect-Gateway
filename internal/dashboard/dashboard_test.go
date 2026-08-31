package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"noject/internal/metrics"
)

func TestDashboardHandler(t *testing.T) {
	collector := metrics.NewCollector(10)
	collector.RecordRequest(200, "ALLOWED", "NONE", 100*time.Microsecond, 10*time.Millisecond, 20*time.Millisecond, nil)

	handler := NewHandler(collector)

	t.Run("Serve Dashboard HTML", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "NoJect Security Operations") {
			t.Error("expected dashboard title in HTML")
		}
	})

	t.Run("Serve JSON Stats API", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"total_requests":1`) {
			t.Errorf("expected total_requests:1 in JSON, got: %s", rec.Body.String())
		}
	})

	t.Run("Serve Prometheus Metrics", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "noject_requests_total 1") {
			t.Errorf("expected Prometheus metric 'noject_requests_total 1', got:\n%s", rec.Body.String())
		}
	})
}
