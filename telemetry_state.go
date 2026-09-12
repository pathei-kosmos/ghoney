package main

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// LogEntry is the bounded event shown in the dashboard
type LogEntry struct {
	Timestamp   time.Time  `json:"timestamp"`
	IP          string     `json:"ip"`
	UserAgent   string     `json:"userAgent"`
	Path        string     `json:"path"`
	AttackType  string     `json:"attackType"`
	Confidence  confidence `json:"confidence,omitempty"`
	Details     string     `json:"details"`
	RawQuery    string     `json:"rawQuery"`
	BodySnippet string     `json:"bodySnippet"`
}

var (
	recentLogs []LogEntry
	logMutex   sync.Mutex

	metricsRegistry   = prometheus.NewRegistry()
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghoney_http_requests_total",
			Help: "Total HTTP requests grouped by bounded route, method, and status.",
		},
		[]string{"route", "method", "status"},
	)
	honeypotAttacksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghoney_honeypot_attacks_total",
			Help: "Total detection events grouped by bounded attack type and route.",
		},
		[]string{"attack_type", "route"},
	)
	honeypotDetectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghoney_honeypot_detections_total",
			Help: "Total detection events grouped by bounded attack type, route, and confidence.",
		},
		[]string{"attack_type", "route", "confidence"},
	)
	eventsDroppedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghoney_events_dropped_total",
			Help: "Total dashboard events evicted from the bounded in-memory buffer.",
		},
		[]string{"confidence"},
	)
)
