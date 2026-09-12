package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// Serialize complete stdout records across concurrent requests
var structuredLogger = log.New(os.Stdout, "", 0)

// Keep log output clean and register metrics once
func init() {
	log.SetFlags(0)
	metricsRegistry.MustRegister(httpRequestsTotal, honeypotAttacksTotal, honeypotDetectionsTotal, eventsDroppedTotal)
}

// Repair UTF8 before applying the byte limit
func truncateUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

// Write one bounded event through the shared record boundary
func writeStructuredEvent(logger *log.Logger, level string, entry LogEntry) {
	logger.Printf("level=%s ts=%s ip=%q ua=%q path=%q attack_type=%q confidence=%q details=%q query=%q body_snippet=%q",
		level,
		entry.Timestamp.Format(time.RFC3339),
		entry.IP,
		entry.UserAgent,
		entry.Path,
		entry.AttackType,
		entry.Confidence,
		entry.Details,
		entry.RawQuery,
		entry.BodySnippet,
	)
}

// Write one logfmt event and update the dashboard buffer
func logEvent(level, ip, userAgent, path, attackType, details, rawQuery, bodySnippet string, eventConfidence confidence) {
	entry := LogEntry{
		Timestamp:   time.Now().UTC(),
		IP:          truncateUTF8(ip, maxEventFieldSize),
		UserAgent:   truncateUTF8(userAgent, maxEventFieldSize),
		Path:        truncateUTF8(path, maxEventFieldSize),
		AttackType:  truncateUTF8(attackType, maxEventFieldSize),
		Confidence:  eventConfidence,
		Details:     truncateUTF8(details, maxEventFieldSize),
		RawQuery:    truncateUTF8(rawQuery, maxEventFieldSize),
		BodySnippet: truncateUTF8(bodySnippet, maxBodySnippetSize),
	}

	writeStructuredEvent(structuredLogger, level, entry)

	if eventConfidence == "" && attackType != "HoneypotAccess" && attackType != "NotFound" {
		return
	}

	logMutex.Lock()
	defer logMutex.Unlock()
	if len(recentLogs) < logBufferSize {
		recentLogs = append(recentLogs, entry)
		return
	}
	// Reserve capacity per confidence so one noisy class cannot erase the others
	evictionIndex := dashboardEvictionIndex(entry.Confidence)
	eventsDroppedTotal.WithLabelValues(confidenceMetricLabel(recentLogs[evictionIndex].Confidence)).Inc()
	copy(recentLogs[evictionIndex:], recentLogs[evictionIndex+1:])
	recentLogs[len(recentLogs)-1] = entry
}

// Choose the oldest event from the new class or a class above its reservation
func dashboardEvictionIndex(incoming confidence) int {
	counts := map[confidence]int{
		confidenceHigh:   0,
		confidenceMedium: 0,
		"":               0,
	}
	for _, entry := range recentLogs {
		counts[entry.Confidence]++
	}
	if counts[incoming] >= dashboardConfidenceReserve(incoming) {
		for index, entry := range recentLogs {
			if entry.Confidence == incoming {
				return index
			}
		}
	}
	for index, entry := range recentLogs {
		if counts[entry.Confidence] > dashboardConfidenceReserve(entry.Confidence) {
			return index
		}
	}
	return 0
}

// Keep the dashboard capacity split explicit and exhaustive
func dashboardConfidenceReserve(value confidence) int {
	switch value {
	case confidenceHigh:
		return logHighReserve
	case confidenceMedium:
		return logMediumReserve
	default:
		return logWeakReserve
	}
}

// Export empty-confidence access events under a stable Prometheus label
func confidenceMetricLabel(value confidence) string {
	if value == "" {
		return "none"
	}
	return string(value)
}

// Keep confidence ordering in one place
func confidenceRank(value confidence) int {
	switch value {
	case confidenceHigh:
		return 2
	case confidenceMedium:
		return 1
	default:
		return 0
	}
}

// Apply the browser security headers to every response
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// Bound handler work apart from transport deadlines
func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Reject work above the listener concurrency limit
func concurrencyLimitMiddleware(limit int, next http.Handler) http.Handler {
	slots := make(chan struct{}, limit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		}
	})
}

// Record requests with fixed route and method labels
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(writer, r)
		httpRequestsTotal.WithLabelValues(
			metricRoute(r.URL.Path),
			metricMethod(r.Method),
			fmt.Sprintf("%d", writer.statusCode),
		).Inc()
	})
}

// Read and classify each public request body once
func requestInspectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := remoteIP(r.RemoteAddr)
		body, err := readBoundedBody(w, r)
		if err != nil {
			status := http.StatusBadRequest
			attackType := "MalformedBody"
			details := "Failed to read request body"
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				status = http.StatusRequestEntityTooLarge
				attackType = "LargeBody"
				details = fmt.Sprintf("Body size exceeds %d bytes", maxRequestBodySize)
			}
			logEvent("warn", clientIP, r.UserAgent(), r.URL.Path, attackType, details, r.URL.RawQuery, "", confidenceHigh)
			http.Error(w, http.StatusText(status), status)
			return
		}

		detections := detectAttacks(detectionInput{
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Body:     string(body),
			Host:     r.Host,
			Header:   r.Header,
		})
		if len(detections) > 0 {
			route := metricRoute(r.URL.Path)
			for _, detection := range detections {
				honeypotAttacksTotal.WithLabelValues(detection.AttackType, route).Inc()
				honeypotDetectionsTotal.WithLabelValues(detection.AttackType, route, string(detection.Confidence)).Inc()
				logEvent(detectionLogLevel(detection.Confidence), clientIP, r.UserAgent(), r.URL.Path, detection.AttackType, detection.Details, r.URL.RawQuery, string(body), detection.Confidence)
			}
		} else if isHoneypotPath(r.URL.Path) {
			logEvent("info", clientIP, r.UserAgent(), r.URL.Path, "HoneypotAccess", "Accessed honeypot endpoint", r.URL.RawQuery, string(body), "")
		}

		next.ServeHTTP(w, r)
	})
}

// Reserve warn for high confidence detections
func detectionLogLevel(value confidence) string {
	if value == confidenceHigh {
		return "warn"
	}
	return "info"
}

// Apply the same wire and decoded limits to request bodies
func readBoundedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	boundedBody := http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	body, readErr := io.ReadAll(boundedBody)
	closeErr := boundedBody.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close request body: %w", closeErr)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		return body, nil
	}
	return readBoundedGzipBody(body)
}

// Decode nested gzip layers within fixed limits
func readBoundedGzipBody(body []byte) ([]byte, error) {
	decoded := body
	decodedWork := 0
	for layer := 0; layer < maxNestedGzipLayers; layer++ {
		if layer > 0 && !hasGzipSignature(decoded) {
			return decoded, nil
		}
		current, err := readSingleBoundedGzipBody(decoded)
		if err != nil {
			if layer == 0 {
				return nil, err
			}
			return decoded, nil
		}
		decodedWork += len(current)
		if decodedWork > maxGzipDecodedWorkSize {
			return nil, &http.MaxBytesError{Limit: int64(maxGzipDecodedWorkSize)}
		}
		decoded = current
	}
	if hasGzipSignature(decoded) {
		return nil, fmt.Errorf("nested gzip body exceeds %d layers", maxNestedGzipLayers)
	}
	return decoded, nil
}

// Recognize inner gzip data before another decoding pass
func hasGzipSignature(body []byte) bool {
	return len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b
}

// Decode one gzip layer within the body limit
func readSingleBoundedGzipBody(body []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("open gzip request body: %w", err)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(maxRequestBodySize+1)))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read gzip request body: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close gzip request body: %w", closeErr)
	}
	if len(decoded) > maxRequestBodySize {
		return nil, &http.MaxBytesError{Limit: int64(maxRequestBodySize)}
	}
	return decoded, nil
}
