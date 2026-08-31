package metrics

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SecurityEvent represents a live audit/security alert for the dashboard.
type SecurityEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	TraceID        string    `json:"trace_id"`
	ClientID       string    `json:"client_id"`
	ClientIP       string    `json:"client_ip"`
	Route          string    `json:"route"`
	Action         string    `json:"action"`
	ThreatCategory string    `json:"threat_category"`
	Severity       string    `json:"severity"`
	Confidence     float64   `json:"confidence"`
	Reason         string    `json:"reason"`
}

// Collector tracks metrics for Prometheus and the live dashboard.
type Collector struct {
	mu sync.RWMutex

	// Counters
	totalRequests  uint64
	allowedRequests uint64
	blockedRequests uint64
	maskedRequests  uint64

	// Threat Category Counters
	threatCounts map[string]uint64

	// HTTP Status Counters
	statusCounts map[int]uint64

	// Latency Tracking (microseconds)
	totalWAFLatencyMicros   uint64
	totalGuardLatencyMicros uint64
	totalProxyLatencyMicros uint64

	// Ring Buffer for Recent Security Events (Max 50)
	recentEvents   []SecurityEvent
	maxRecentEvents int
}

var (
	defaultCollector *Collector
	once             sync.Once
)

// Default returns the singleton metrics collector.
func Default() *Collector {
	once.Do(func() {
		defaultCollector = NewCollector(50)
	})
	return defaultCollector
}

// NewCollector creates a new metrics collector.
func NewCollector(maxEvents int) *Collector {
	if maxEvents <= 0 {
		maxEvents = 50
	}
	return &Collector{
		threatCounts:    make(map[string]uint64),
		statusCounts:    make(map[int]uint64),
		recentEvents:    make([]SecurityEvent, 0, maxEvents),
		maxRecentEvents: maxEvents,
	}
}

// RecordRequest tracks request execution details.
func (c *Collector) RecordRequest(status int, action, threatCategory string, wafLatency, guardLatency, proxyLatency time.Duration, event *SecurityEvent) {
	atomic.AddUint64(&c.totalRequests, 1)

	switch strings.ToUpper(action) {
	case "ALLOWED":
		atomic.AddUint64(&c.allowedRequests, 1)
	case "BLOCKED":
		atomic.AddUint64(&c.blockedRequests, 1)
	case "MASKED":
		atomic.AddUint64(&c.maskedRequests, 1)
	}

	atomic.AddUint64(&c.totalWAFLatencyMicros, uint64(wafLatency.Microseconds()))
	atomic.AddUint64(&c.totalGuardLatencyMicros, uint64(guardLatency.Microseconds()))
	atomic.AddUint64(&c.totalProxyLatencyMicros, uint64(proxyLatency.Microseconds()))

	c.mu.Lock()
	defer c.mu.Unlock()

	c.statusCounts[status]++

	if threatCategory != "" && threatCategory != "NONE" {
		c.threatCounts[threatCategory]++
	}

	if event != nil && (action == "BLOCKED" || action == "MASKED" || threatCategory != "NONE") {
		if len(c.recentEvents) >= c.maxRecentEvents {
			c.recentEvents = c.recentEvents[1:]
		}
		c.recentEvents = append(c.recentEvents, *event)
	}
}

// StatsSnapshot represents aggregated stats for the JSON API.
type StatsSnapshot struct {
	TotalRequests      uint64            `json:"total_requests"`
	AllowedRequests    uint64            `json:"allowed_requests"`
	BlockedRequests    uint64            `json:"blocked_requests"`
	MaskedRequests     uint64            `json:"masked_requests"`
	ThreatBreakdown    map[string]uint64 `json:"threat_breakdown"`
	StatusBreakdown    map[int]uint64    `json:"status_breakdown"`
	AvgWAFLatencyMS    float64           `json:"avg_waf_latency_ms"`
	AvgGuardLatencyMS  float64           `json:"avg_guard_latency_ms"`
	AvgProxyLatencyMS  float64           `json:"avg_proxy_latency_ms"`
	RecentEvents       []SecurityEvent   `json:"recent_events"`
	Timestamp          time.Time         `json:"timestamp"`
}

// Snapshot returns a copy of current aggregated statistics.
func (c *Collector) Snapshot() StatsSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := atomic.LoadUint64(&c.totalRequests)
	threatCopy := make(map[string]uint64, len(c.threatCounts))
	for k, v := range c.threatCounts {
		threatCopy[k] = v
	}

	statusCopy := make(map[int]uint64, len(c.statusCounts))
	for k, v := range c.statusCounts {
		statusCopy[k] = v
	}

	eventsCopy := make([]SecurityEvent, len(c.recentEvents))
	copy(eventsCopy, c.recentEvents)

	var avgWAF, avgGuard, avgProxy float64
	if total > 0 {
		avgWAF = float64(atomic.LoadUint64(&c.totalWAFLatencyMicros)) / float64(total) / 1000.0
		avgGuard = float64(atomic.LoadUint64(&c.totalGuardLatencyMicros)) / float64(total) / 1000.0
		avgProxy = float64(atomic.LoadUint64(&c.totalProxyLatencyMicros)) / float64(total) / 1000.0
	}

	return StatsSnapshot{
		TotalRequests:     total,
		AllowedRequests:   atomic.LoadUint64(&c.allowedRequests),
		BlockedRequests:   atomic.LoadUint64(&c.blockedRequests),
		MaskedRequests:    atomic.LoadUint64(&c.maskedRequests),
		ThreatBreakdown:   threatCopy,
		StatusBreakdown:   statusCopy,
		AvgWAFLatencyMS:   avgWAF,
		AvgGuardLatencyMS: avgGuard,
		AvgProxyLatencyMS: avgProxy,
		RecentEvents:      eventsCopy,
		Timestamp:         time.Now().UTC(),
	}
}

// PrometheusExport exports all metrics in standard Prometheus text format.
func (c *Collector) PrometheusExport() string {
	snap := c.Snapshot()
	var b strings.Builder

	b.WriteString("# HELP noject_requests_total Total number of HTTP requests processed by NoJect Gateway\n")
	b.WriteString("# TYPE noject_requests_total counter\n")
	b.WriteString(fmt.Sprintf("noject_requests_total %d\n\n", snap.TotalRequests))

	b.WriteString("# HELP noject_requests_by_action_total Total number of requests categorized by action (ALLOWED, BLOCKED, MASKED)\n")
	b.WriteString("# TYPE noject_requests_by_action_total counter\n")
	b.WriteString(fmt.Sprintf("noject_requests_by_action_total{action=\"ALLOWED\"} %d\n", snap.AllowedRequests))
	b.WriteString(fmt.Sprintf("noject_requests_by_action_total{action=\"BLOCKED\"} %d\n", snap.BlockedRequests))
	b.WriteString(fmt.Sprintf("noject_requests_by_action_total{action=\"MASKED\"} %d\n\n", snap.MaskedRequests))

	b.WriteString("# HELP noject_threats_detected_total Total number of security threats detected by category\n")
	b.WriteString("# TYPE noject_threats_detected_total counter\n")
	for threat, count := range snap.ThreatBreakdown {
		b.WriteString(fmt.Sprintf("noject_threats_detected_total{threat=\"%s\"} %d\n", threat, count))
	}
	b.WriteString("\n")

	b.WriteString("# HELP noject_http_responses_total Total number of HTTP responses by status code\n")
	b.WriteString("# TYPE noject_http_responses_total counter\n")
	for status, count := range snap.StatusBreakdown {
		b.WriteString(fmt.Sprintf("noject_http_responses_total{code=\"%d\"} %d\n", status, count))
	}
	b.WriteString("\n")

	b.WriteString("# HELP noject_latency_seconds_average Average inspection latency in seconds\n")
	b.WriteString("# TYPE noject_latency_seconds_average gauge\n")
	b.WriteString(fmt.Sprintf("noject_latency_seconds_average{component=\"waf\"} %.6f\n", snap.AvgWAFLatencyMS/1000.0))
	b.WriteString(fmt.Sprintf("noject_latency_seconds_average{component=\"guard\"} %.6f\n", snap.AvgGuardLatencyMS/1000.0))
	b.WriteString(fmt.Sprintf("noject_latency_seconds_average{component=\"proxy\"} %.6f\n", snap.AvgProxyLatencyMS/1000.0))

	return b.String()
}
