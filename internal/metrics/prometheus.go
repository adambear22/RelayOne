package metrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	AgentConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nodepass_agent_connections_total",
		Help: "Current number of connected agents",
	})

	AgentConnectionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nodepass_agent_connection_duration_seconds",
		Help:    "Duration of agent WebSocket connections",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	}, []string{"agent_id"})

	ActiveRules = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nodepass_active_rules",
		Help: "Number of active rules by status",
	}, []string{"status"})

	RuleSyncDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "nodepass_rule_sync_duration_seconds",
		Help:    "Time to sync rule to agent",
		Buckets: prometheus.DefBuckets,
	})

	RuleSyncErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nodepass_rule_sync_errors_total",
		Help: "Total rule sync failures",
	})

	TrafficBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nodepass_traffic_bytes_total",
		Help: "Total traffic bytes processed",
	}, []string{"direction"})

	TrafficReportDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "nodepass_traffic_report_duration_seconds",
		Help:    "Time to process traffic report",
		Buckets: prometheus.DefBuckets,
	})

	OverlimitUsers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nodepass_overlimit_users",
		Help: "Current number of overlimit users",
	})

	SSEClients = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nodepass_sse_clients",
		Help: "Current number of SSE clients connected",
	})
)

func SetAgentConnections(count int) {
	if count < 0 {
		count = 0
	}
	AgentConnections.Set(float64(count))
}

func ObserveAgentConnectionDuration(agentID string, duration time.Duration) {
	label := strings.TrimSpace(agentID)
	if label == "" {
		label = "unknown"
	}
	AgentConnectionDuration.WithLabelValues(label).Observe(duration.Seconds())
}

func SetActiveRuleCount(status string, count int64) {
	label := strings.TrimSpace(status)
	if label == "" {
		label = "unknown"
	}
	if count < 0 {
		count = 0
	}
	ActiveRules.WithLabelValues(label).Set(float64(count))
}

func ObserveRuleSyncDuration(duration time.Duration) {
	RuleSyncDuration.Observe(duration.Seconds())
}

func IncRuleSyncError() {
	RuleSyncErrors.Inc()
}

func AddTrafficBytes(bytesIn, bytesOut, bytesTotal int64) {
	if bytesIn > 0 {
		TrafficBytesTotal.WithLabelValues("in").Add(float64(bytesIn))
	}
	if bytesOut > 0 {
		TrafficBytesTotal.WithLabelValues("out").Add(float64(bytesOut))
	}
	if bytesTotal > 0 {
		TrafficBytesTotal.WithLabelValues("total").Add(float64(bytesTotal))
	}
}

func ObserveTrafficReportDuration(duration time.Duration) {
	TrafficReportDuration.Observe(duration.Seconds())
}

func SetOverlimitUsers(count int64) {
	if count < 0 {
		count = 0
	}
	OverlimitUsers.Set(float64(count))
}

func SetSSEClients(count int) {
	if count < 0 {
		count = 0
	}
	SSEClients.Set(float64(count))
}
