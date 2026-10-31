package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Serialize complete stdout records across concurrent requests
var structuredLogger = log.New(os.Stdout, "", 0)

// Keep log output clean and register metrics once
func init() {
	log.SetFlags(0)
	metricsRegistry.MustRegister(httpRequestsTotal, honeypotAttacksTotal, honeypotDetectionsTotal, eventsDroppedTotal, stdoutEventsDroppedTotal)
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

// Write one escaped log record
func writeStructuredEvent(logger *log.Logger, level string, entry LogEntry) error {
	return logger.Output(2, fmt.Sprintf("level=%s ts=%s ip=%q ua=%q path=%q attack_type=%q confidence=%q details=%q query=%q body_snippet=%q method=%q source=%q sample=%q",
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
		entry.Method,
		entry.Source,
		entry.Sample,
	))
}

// Log request fields and the matched payload
func logRequestEvent(level string, r *http.Request, attackType, details, body string, eventConfidence confidence, match detectionMatch) {
	recordEvent(level, LogEntry{
		Timestamp:   time.Now().UTC(),
		IP:          remoteIP(r.RemoteAddr),
		UserAgent:   r.UserAgent(),
		Path:        r.URL.Path,
		Method:      r.Method,
		AttackType:  attackType,
		Details:     details,
		RawQuery:    r.URL.RawQuery,
		BodySnippet: body,
		Confidence:  eventConfidence,
		Source:      match.source,
		Sample:      match.sample,
	})
}

// Bound fields before logging and buffering
func recordEvent(level string, entry LogEntry) {
	entry.IP = truncateUTF8(entry.IP, maxEventFieldSize)
	entry.UserAgent = truncateUTF8(entry.UserAgent, maxEventFieldSize)
	entry.Path = truncateUTF8(entry.Path, maxEventFieldSize)
	entry.Method = truncateUTF8(entry.Method, 64)
	entry.AttackType = truncateUTF8(entry.AttackType, maxEventFieldSize)
	entry.Details = truncateUTF8(entry.Details, maxEventFieldSize)
	entry.RawQuery = truncateUTF8(entry.RawQuery, maxEventFieldSize)
	entry.BodySnippet = truncateUTF8(entry.BodySnippet, maxBodySnippetSize)
	entry.Source = truncateUTF8(entry.Source, maxEventFieldSize)
	entry.Sample = truncateUTF8(entry.Sample, maxBodySnippetSize)

	stdoutEvents.enqueue(level, entry)

	if entry.Confidence == "" && entry.AttackType != "HoneypotAccess" && entry.AttackType != "NotFound" && entry.AttackType != "Overload" {
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

// Return the buffer reserve for a confidence level
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

// Rank confidence for comparison
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

// Apply the timeout to the context and body reads
func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		controller := http.NewResponseController(w)
		deadline, _ := ctx.Deadline()
		// net/http rearms the read deadline for the next request
		_ = controller.SetReadDeadline(deadline)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Reject work above the listener concurrency limit
func concurrencyLimitMiddleware(limit int, next http.Handler, rejected http.Handler) http.Handler {
	slots := make(chan struct{}, limit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(w, r)
		default:
			if rejected != nil {
				rejected.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		}
	})
}

// Log overload without reading the body
func handlePublicOverload(w http.ResponseWriter, r *http.Request) {
	// Close the connection so net/http does not drain the unread body
	w.Header().Set("Connection", "close")
	var sample strings.Builder
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range r.Header[name] {
			if sample.Len() >= maxBodySnippetSize {
				break
			}
			sample.WriteString(truncateUTF8(name+": "+value+"\n", maxBodySnippetSize-sample.Len()))
		}
		if sample.Len() >= maxBodySnippetSize {
			break
		}
	}
	logRequestEvent("info", r, "Overload", "Public request concurrency limit reached", "", "", detectionMatch{source: "request headers", sample: sample.String()})
	http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
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

// Inspect the public request before routing
func requestInspectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readBoundedBody(w, r)
		if err != nil {
			status := http.StatusBadRequest
			eventConfidence := confidenceHigh
			attackType := "MalformedBody"
			details := "Failed to read request body"
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				status = http.StatusRequestEntityTooLarge
				attackType = "LargeBody"
				details = fmt.Sprintf("Body size exceeds %d bytes", maxRequestBodySize)
			}
			var timeoutError net.Error
			if errors.Is(err, errUnsupportedContentEncoding) {
				status, attackType, details = http.StatusUnsupportedMediaType, "UnsupportedEncoding", "Unsupported request content encoding"
			} else if errors.As(err, &timeoutError) && timeoutError.Timeout() || r.Context().Err() != nil {
				status, attackType, details = http.StatusRequestTimeout, "InspectionTimeout", "Request inspection deadline exceeded"
			}
			match := detectionMatch{}
			if errors.Is(err, errUnsupportedContentEncoding) {
				w.Header().Set("Connection", "close")
				eventConfidence = confidenceMedium
				match = detectionMatch{source: "Content-Encoding header", sample: strings.Join(r.Header.Values("Content-Encoding"), ", ")}
			}
			// Inspect available fields without reading the rejected body again
			inspectRequestFields(r, "")
			logRequestEvent(detectionLogLevel(eventConfidence), r, attackType, details, "", eventConfidence, match)
			http.Error(w, http.StatusText(status), status)
			return
		}

		if inspectRequestFields(r, string(body)) == 0 && r.Context().Err() == nil && isHoneypotPath(r.URL.Path) {
			logRequestEvent("info", r, "HoneypotAccess", "Accessed honeypot endpoint", string(body), "", detectionMatch{})
		}

		if r.Context().Err() != nil {
			logRequestEvent("info", r, "InspectionTimeout", "Request inspection deadline exceeded", string(body), "", detectionMatch{})
			http.Error(w, http.StatusText(http.StatusRequestTimeout), http.StatusRequestTimeout)
			return
		}
		// Keep the decoded body for 404 logs
		r = r.WithContext(context.WithValue(r.Context(), inspectedBodyKey{}, string(body)))
		next.ServeHTTP(w, r)
	})
}

// Inspect available request fields under the existing request deadline
func inspectRequestFields(r *http.Request, body string) int {
	detections := detectAttacksContext(r.Context(), detectionInput{
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Body:     body,
		Host:     r.Host,
		Header:   r.Header,
	})
	route := metricRoute(r.URL.Path)
	for _, detection := range detections {
		honeypotAttacksTotal.WithLabelValues(detection.AttackType, route).Inc()
		honeypotDetectionsTotal.WithLabelValues(detection.AttackType, route, string(detection.Confidence)).Inc()
		logRequestEvent(detectionLogLevel(detection.Confidence), r, detection.AttackType, detection.Details, body, detection.Confidence, detectionMatch{source: detection.Source, sample: detection.Sample})
	}
	return len(detections)
}

// inspectedBodyKey keeps the decoded body private to the request
type inspectedBodyKey struct{}

// Reserve warn for high confidence detections
func detectionLogLevel(value confidence) string {
	if value == confidenceHigh {
		return "warn"
	}
	return "info"
}

// Distinguish unsupported representations from malformed compressed streams
var errUnsupportedContentEncoding = errors.New("unsupported content encoding")

// Parse every coding in application order before reading the body
func requestContentEncodings(header http.Header) ([]string, error) {
	encodings := make([]string, 0)
	for _, line := range header.Values("Content-Encoding") {
		for _, value := range strings.Split(line, ",") {
			value = strings.ToLower(strings.TrimSpace(value))
			switch value {
			case "identity", "gzip", "x-gzip", "deflate":
			default:
				return nil, errUnsupportedContentEncoding
			}
			encodings = append(encodings, value)
			if len(encodings) > maxNestedGzipLayers {
				return nil, errUnsupportedContentEncoding
			}
		}
	}
	return encodings, nil
}

// Read and decode the body within size limits
func readBoundedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	encodings, err := requestContentEncodings(r.Header)
	if err != nil {
		return nil, err
	}
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
	decoded := body
	work := 0
	layers := 0
	gzipDeclared := false
	for index := len(encodings) - 1; index >= 0; index-- {
		switch encodings[index] {
		case "identity":
			continue
		case "gzip", "x-gzip":
			gzipDeclared = true
			decoded, err = readSingleBoundedGzipBody(decoded)
		case "deflate":
			decoded, err = readBoundedDeflateBody(decoded)
		}
		if err != nil {
			return nil, err
		}
		layers++
		work += len(decoded)
		if work > maxGzipDecodedWorkSize {
			return nil, &http.MaxBytesError{Limit: int64(maxGzipDecodedWorkSize)}
		}
	}
	// Retain bounded support for nested gzip sent with one declared coding
	for gzipDeclared && hasGzipSignature(decoded) {
		if layers >= maxNestedGzipLayers {
			return nil, fmt.Errorf("nested gzip body exceeds %d layers", maxNestedGzipLayers)
		}
		current, err := readSingleBoundedGzipBody(decoded)
		if err != nil {
			break
		}
		decoded = current
		layers++
		work += len(decoded)
		if work > maxGzipDecodedWorkSize {
			return nil, &http.MaxBytesError{Limit: int64(maxGzipDecodedWorkSize)}
		}
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
	return readSingleBoundedCompressedBody(reader, "gzip")
}

// Decode zlib-wrapped or legacy raw DEFLATE within the request body limit
func readBoundedDeflateBody(body []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(body))
	if err == nil {
		return readSingleBoundedCompressedBody(reader, "zlib deflate")
	}
	rawReader := flate.NewReader(bytes.NewReader(body))
	return readSingleBoundedCompressedBody(rawReader, "raw deflate")
}

// Read and close a compressed stream within the body limit
func readSingleBoundedCompressedBody(reader io.ReadCloser, encoding string) ([]byte, error) {
	decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(maxRequestBodySize+1)))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read %s request body: %w", encoding, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s request body: %w", encoding, closeErr)
	}
	if len(decoded) > maxRequestBodySize {
		return nil, &http.MaxBytesError{Limit: int64(maxRequestBodySize)}
	}
	return decoded, nil
}
