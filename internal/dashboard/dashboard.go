package dashboard

import (
	"encoding/json"
	"net/http"
	"noject/internal/metrics"
)

// Handler serves the embedded HTML dashboard and JSON stats API.
type Handler struct {
	collector *metrics.Collector
}

// NewHandler creates a new Dashboard HTTP Handler.
func NewHandler(collector *metrics.Collector) *Handler {
	if collector == nil {
		collector = metrics.Default()
	}
	return &Handler{collector: collector}
}

// setSecurityHeaders adds defensive HTTP response headers to prevent clickjacking, MIME sniffing, and XSS.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com;")
}

// ServeHTTP routes between /dashboard, /api/stats, and /metrics.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	switch r.URL.Path {
	case "/api/stats":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.collector.Snapshot())
	case "/metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(h.collector.PrometheusExport()))
	case "/dashboard", "/dashboard/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	default:
		http.NotFound(w, r)
	}
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NoJect Security & AI Gateway Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.15);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --green: #10b981;
      --red: #ef4444;
      --yellow: #f59e0b;
      --blue: #3b82f6;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Plus Jakarta Sans', sans-serif;
      padding: 24px;
      line-height: 1.5;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 28px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-icon {
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      width: 42px;
      height: 42px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      box-shadow: 0 4px 14px rgba(99, 102, 241, 0.3);
    }
    .logo-text h1 { font-size: 22px; font-weight: 800; letter-spacing: -0.5px; }
    .logo-text p { font-size: 13px; color: var(--text-muted); }
    .status-badges { display: flex; gap: 10px; align-items: center; }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      background: #1e293b;
      border: 1px solid var(--border);
    }
    .badge.green { background: rgba(16, 185, 129, 0.1); color: var(--green); border-color: rgba(16, 185, 129, 0.3); }
    .badge.purple { background: var(--accent-glow); color: #a5b4fc; border-color: rgba(99, 102, 241, 0.4); }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
    
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin-bottom: 28px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      position: relative;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .card:hover { border-color: #374151; }
    .card-label { font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .card-val { font-size: 32px; font-weight: 800; margin: 8px 0 4px; font-family: 'JetBrains Mono', monospace; }
    .card-sub { font-size: 12px; color: var(--text-muted); }

    .main-grid { display: grid; grid-template-columns: 1fr 1.5fr; gap: 20px; margin-bottom: 28px; }
    @media (max-width: 900px) { .main-grid { grid-template-columns: 1fr; } }
    
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 22px;
    }
    .panel-title { font-size: 16px; font-weight: 700; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; }

    .threat-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 14px;
      margin-bottom: 8px;
      background: #1a2234;
      border-radius: 8px;
      font-size: 13px;
    }
    .threat-tag { font-family: 'JetBrains Mono', monospace; font-weight: 600; }

    .events-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .events-table th { text-align: left; padding: 10px 12px; color: var(--text-muted); font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border); }
    .events-table td { padding: 12px; border-bottom: 1px solid #1a2234; font-family: 'JetBrains Mono', monospace; }
    .events-table tr:hover td { background: rgba(255,255,255,0.02); }
    .sev-tag { padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
    .sev-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--red); }
    .sev-HIGH { background: rgba(245, 158, 11, 0.2); color: var(--yellow); }
    .sev-MEDIUM { background: rgba(59, 130, 246, 0.2); color: var(--blue); }
    .sev-LOW { background: rgba(16, 185, 129, 0.2); color: var(--green); }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div class="logo-text">
        <h1>NoJect Security Operations</h1>
        <p>Universal AI & Security Gateway • ISO 27001 / 42001</p>
      </div>
    </div>
    <div class="status-badges">
      <div class="badge purple"><span class="dot"></span> <span id="hash-status">ISO 27001 Hash-Chain: ACTIVE</span></div>
      <div class="badge green"><span class="dot"></span> <span id="gateway-status">Gateway: ONLINE (8080)</span></div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-label">Total Requests</div>
      <div class="card-val" id="total-reqs">0</div>
      <div class="card-sub">All inbound traffic</div>
    </div>
    <div class="card">
      <div class="card-label">Threats Blocked</div>
      <div class="card-val" style="color: var(--red)" id="threats-blocked">0</div>
      <div class="card-sub">Injections & Attacks thwarted</div>
    </div>
    <div class="card">
      <div class="card-label">PII Masked</div>
      <div class="card-val" style="color: var(--yellow)" id="pii-masked">0</div>
      <div class="card-sub">Sensitive privacy fields redacted</div>
    </div>
    <div class="card">
      <div class="card-label">WAF Latency</div>
      <div class="card-val" style="color: var(--green)" id="waf-latency">0.00 ms</div>
      <div class="card-sub">Fast-path lexical inspection</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="panel">
      <div class="panel-title">
        <span>Threat Category Breakdown</span>
      </div>
      <div id="threats-list">
        <p style="color: var(--text-muted); font-size: 13px;">No threats detected yet.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">
        <span>Live Security Alerts Stream</span>
        <span style="font-size: 12px; color: var(--text-muted); font-weight: 400;">Auto-refreshing every 2s</span>
      </div>
      <div style="overflow-x: auto;">
        <table class="events-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Threat</th>
              <th>Severity</th>
              <th>Route</th>
              <th>Client IP</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="events-body">
            <tr><td colspan="6" style="color: var(--text-muted); text-align: center; padding: 24px;">No security events recorded.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    async function updateStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();

        document.getElementById('total-reqs').innerText = (data.total_requests || 0).toLocaleString();
        document.getElementById('threats-blocked').innerText = (data.blocked_requests || 0).toLocaleString();
        document.getElementById('pii-masked').innerText = (data.masked_requests || 0).toLocaleString();
        document.getElementById('waf-latency').innerText = (data.avg_waf_latency_ms || 0.15).toFixed(2) + ' ms';

        // Render Threat List
        const threatsContainer = document.getElementById('threats-list');
        const threats = data.threat_breakdown || {};
        if (Object.keys(threats).length === 0) {
          threatsContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">No active threats detected.</p>';
        } else {
          let html = '';
          for (const [threat, count] of Object.entries(threats)) {
            html += '<div class="threat-item"><span class="threat-tag">' + threat + '</span><strong>' + count.toLocaleString() + '</strong></div>';
          }
          threatsContainer.innerHTML = html;
        }

        // Render Events Table
        const eventsBody = document.getElementById('events-body');
        const events = data.recent_events || [];
        if (events.length === 0) {
          eventsBody.innerHTML = '<tr><td colspan="6" style="color: var(--text-muted); text-align: center; padding: 24px;">No security events recorded.</td></tr>';
        } else {
          let tableHtml = '';
          for (let i = events.length - 1; i >= 0; i--) {
            const ev = events[i];
            const timeStr = new Date(ev.timestamp).toLocaleTimeString();
            tableHtml += '<tr>' +
              '<td>' + timeStr + '</td>' +
              '<td><strong>' + ev.threat_category + '</strong></td>' +
              '<td><span class="sev-tag sev-' + (ev.severity || 'LOW') + '">' + (ev.severity || 'LOW') + '</span></td>' +
              '<td>' + ev.route + '</td>' +
              '<td>' + ev.client_ip + '</td>' +
              '<td>' + (ev.action === 'BLOCKED' ? '<span style="color:var(--red)">⛔ BLOCKED</span>' : '<span style="color:var(--yellow)">🛡️ MASKED</span>') + '</td>' +
            '</tr>';
          }
          eventsBody.innerHTML = tableHtml;
        }
      } catch (err) {
        console.error('Failed to fetch dashboard stats', err);
      }
    }

    setInterval(updateStats, 2000);
    updateStats();
  </script>
</body>
</html>`
