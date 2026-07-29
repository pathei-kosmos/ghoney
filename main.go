package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultPublicAddr  = ":8080"
	defaultAdminAddr   = "127.0.0.1:9090"
	maxRequestBodySize = 4 * 1024
	maxBodySnippetSize = 256
	maxEventFieldSize  = 1024
	maxHeaderBytes     = 16 * 1024
	// Include net/http's 4 KiB buffered read slop
	maxDetectionSourceSize = maxHeaderBytes + 4*1024
	// Leave room for Unicode case folding without dropping the tail
	maxCanonicalSourceSize = maxDetectionSourceSize * 2
	maxDetectionSources    = 16
	maxDecodePasses        = 3
	maxXMLExpansionSize    = maxRequestBodySize * 8
	requestTimeout         = 5 * time.Second
	shutdownTimeout        = 5 * time.Second
	logBufferSize          = 100
	maxConcurrentPublic    = 128
	envPublicAddr          = "GHONEY_ADDR"
	envAdminAddr           = "GHONEY_ADMIN_ADDR"
	unknownMetricRoute     = "not_found"
	unknownMetricMethod    = "OTHER"
	asciiArtBanner         = `
       _
  __ _| |__   ___  _ __   ___ _   _
 / _` + "`" + ` | '_ \ / _ \| '_ \ / _ \ | | |
| (_| | | | | (_) | | | |  __/ |_| |
 \__, |_| |_|\___/|_| |_|\___|\__, |
 |___/                        |___/

`
)

// Ship static assets inside the binary
//
//go:embed static/*
var staticAssets embed.FS

// LogEntry is the bounded event shape exposed to the dashboard
type LogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	IP          string    `json:"ip"`
	UserAgent   string    `json:"userAgent"`
	Path        string    `json:"path"`
	AttackType  string    `json:"attackType"`
	Details     string    `json:"details"`
	RawQuery    string    `json:"rawQuery"`
	BodySnippet string    `json:"bodySnippet"`
}

// detection carries one fixed attack class and its bounded explanation
type detection struct {
	AttackType string
	Details    string
}

// detectionInput keeps attacker-controlled sources separate during matching
type detectionInput struct {
	Path     string
	RawQuery string
	Body     string
	Host     string
	Header   http.Header
}

// detectionSource holds the bounded canonical forms of one request field
type detectionSource struct {
	name     string
	variants []string
}

// loggingResponseWriter tracks the first status written by a handler
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
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

	// Compile signatures once outside the request path
	pathTraversalRegex      = regexp.MustCompile(`(?:\.{2,}[/\\]|\.\.;[/\\])`)
	sqlQuotedBooleanRegex   = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*(?:or|and)\\s+(?:not\\s+)?(?:\\d+|'[^']*'|\"[^\"]*\")\\s*(?:=|like)\\s*(?:\\d+|'[^']*'|\"[^\"]*\")")
	sqlNumericBooleanRegex  = regexp.MustCompile(`(?i)(?:^|[?&;\s])(?:[a-z_][a-z0-9_.-]*=)?\d+\s+(?:or|and)\s+\d+\s*=\s*\d+`)
	sqlCommentTailRegex     = regexp.MustCompile("(?i)(?:'|\"|`)\\s*(?:--|#)")
	sqlUnionRegex           = regexp.MustCompile(`(?i)\bunion\s+(?:all\s+)?select\b`)
	sqlFunctionRegex        = regexp.MustCompile(`(?i)\b(?:sleep|benchmark|pg_sleep|load_file|xp_cmdshell|extractvalue|updatexml)\s*\(|\bwaitfor\s+delay\b|\binto\s+outfile\b|\binformation_schema\b`)
	sqlStackedRegex         = regexp.MustCompile(`(?i);\s*(?:select|insert|update|delete|drop|alter|create|exec|execute)\b`)
	sqlVersionCommentRegex  = regexp.MustCompile(`(?is)/\*!\d{0,6}\s*(.*?)\*/`)
	sqlBlockCommentRegex    = regexp.MustCompile(`(?s)/\*.*?\*/`)
	xmlExternalEntityRegex  = regexp.MustCompile(`(?is)<!entity\s+(?:%\s*)?[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlExternalDoctypeRegex = regexp.MustCompile(`(?is)<!doctype\s+[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlIncludeRegex         = regexp.MustCompile(`(?is)<(?:xi:include|xinclude)\b[^>]{0,512}\bhref\s*=\s*["'](?:file|https?)://`)
	xmlEntityDeclaration    = regexp.MustCompile(`(?is)<!entity\s+(%\s*)?([a-z_][a-z0-9_:.-]*)\s+(?:"([^"]*)"|'([^']*)')\s*>`)
	xmlEntityReference      = regexp.MustCompile(`(?i)([&%])([a-z_][a-z0-9_:.-]*);`)
	commandSeparatorRegex   = regexp.MustCompile("(?i)(?:;|\\|\\||&&|\\||&[\\t ]*|\\$\\(|`|[\\r\\n])[\\t ]*(?:(?:\\$\\{ifs\\}|\\$ifs\\$9)[\\t ]*)*(?:sudo[\\t ]+)?(?:/usr/bin/|/bin/)?\\b(?:whoami|id|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|env|printenv|ls|sleep|python|python3|perl|ruby|busybox)(?:\\.exe)?(?:[\\t ]|$|[;&|)`<>]|\\$\\{ifs\\}|\\$ifs(?:\\$9)?)")
	commandAssignmentRegex  = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:cmd|command|exec|execute|shell)["']?\s*(?:=|:)\s*["']?(?:/usr/bin/|/bin/)?(?:whoami|id|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|env|printenv|ls|sleep|python|python3|perl|ruby|busybox)(?:\.exe)?\b`)
	ssrfAssignmentRegex     = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:url|uri|redirect|next|target|dest|destination|callback|continue|return|return_url|endpoint|proxy)["']?\s*(?:=|:)\s*["']?([^"'&,\s}]+)`)
	localFileRegex          = regexp.MustCompile(`(?i)(?:/(?:etc/(?:passwd|shadow|hosts|sudoers)|proc/(?:self|\d+)/(?:environ|cmdline|maps)|var/log/(?:auth\.log|secure)|root/\.ssh/)|[a-z]:\\(?:windows\\(?:win\.ini|system32(?:\\|$))|boot\.ini)|(?:php|file|zip|phar|expect|input|glob|ssh2)://)`)
	fileAssignmentRegex     = regexp.MustCompile(`(?i)(?:^|[?&;,\s])(?:file|page|include|template|path|document|folder|root)(?:\[[a-z0-9_-]*\])?\s*=\s*["']?([^"'&,\s}]+)`)
	fileJSONAssignmentRegex = regexp.MustCompile(`(?i)["'](?:file|page|include|template|path|document|folder|root)["']\s*:\s*["']([^"']+)`)
	detectionRuneReplacer   = strings.NewReplacer(
		"／", "/", "∕", "/", "⁄", "/",
		"＼", `\`, "﹨", `\`,
		"．", ".", "｡", ".", "。", ".",
	)
	inspectedHeaderNames = [...]string{
		"Cookie",
		"Forwarded",
		"Referer",
		"User-Agent",
		"X-Forwarded-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
	}
)

// Keep standard log output aligned with the logfmt records
func init() {
	log.SetFlags(0)
	metricsRegistry.MustRegister(httpRequestsTotal, honeypotAttacksTotal)
}

// Repair UTF-8 before enforcing the byte cap
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

// Emit logfmt and retain only bounded dashboard events
func logEvent(level, ip, userAgent, path, attackType, details, rawQuery, bodySnippet string) {
	entry := LogEntry{
		Timestamp:   time.Now().UTC(),
		IP:          truncateUTF8(ip, maxEventFieldSize),
		UserAgent:   truncateUTF8(userAgent, maxEventFieldSize),
		Path:        truncateUTF8(path, maxEventFieldSize),
		AttackType:  truncateUTF8(attackType, maxEventFieldSize),
		Details:     truncateUTF8(details, maxEventFieldSize),
		RawQuery:    truncateUTF8(rawQuery, maxEventFieldSize),
		BodySnippet: truncateUTF8(bodySnippet, maxBodySnippetSize),
	}

	fmt.Printf("level=%s ts=%s ip=%q ua=%q path=%q attack_type=%q details=%q query=%q body_snippet=%q\n",
		level,
		entry.Timestamp.Format(time.RFC3339),
		entry.IP,
		entry.UserAgent,
		entry.Path,
		entry.AttackType,
		entry.Details,
		entry.RawQuery,
		entry.BodySnippet,
	)

	if level != "warn" && attackType != "HoneypotAccess" {
		return
	}

	logMutex.Lock()
	defer logMutex.Unlock()
	if len(recentLogs) < logBufferSize {
		recentLogs = append(recentLogs, entry)
		return
	}
	copy(recentLogs, recentLogs[1:])
	recentLogs[len(recentLogs)-1] = entry
}

// Apply the shared browser security policy
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

// Attach the deadline used by delayed handlers
func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Cap public work, including delayed responses
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

// Record metrics with a fixed label set
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

// Buffer and classify each public request body once
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
			logEvent("warn", clientIP, r.UserAgent(), r.URL.Path, attackType, details, r.URL.RawQuery, "")
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
				logEvent("warn", clientIP, r.UserAgent(), r.URL.Path, detection.AttackType, detection.Details, r.URL.RawQuery, string(body))
			}
		} else if isHoneypotPath(r.URL.Path) {
			logEvent("info", clientIP, r.UserAgent(), r.URL.Path, "HoneypotAccess", "Accessed honeypot endpoint", r.URL.RawQuery, string(body))
		}

		next.ServeHTTP(w, r)
	})
}

// Apply the same body cap to fixed and streamed requests
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
	return body, nil
}

// Return every distinct attack class found in one bounded request
func detectAttacks(input detectionInput) []detection {
	sources := buildDetectionSources(input)
	detections := make([]detection, 0, 6)

	if source, ok := firstRegexMatch(sources, pathTraversalRegex); ok {
		detections = append(detections, detection{
			AttackType: "Path Traversal",
			Details:    "Detected traversal sequence in " + source,
		})
	}
	if source, ok := firstSQLMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "SQL Injection",
			Details:    "Detected SQL injection pattern in " + source,
		})
	}
	if source, ok := firstXMLMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "XML Entity",
			Details:    "Detected external or expansive XML construct in " + source,
		})
	}
	if source, ok := firstRegexMatch(sources, commandSeparatorRegex, commandAssignmentRegex); ok {
		detections = append(detections, detection{
			AttackType: "Command Injection",
			Details:    "Detected command execution pattern in " + source,
		})
	}
	if source, ok := firstSSRFMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "SSRF",
			Details:    "Detected private or local target in " + source,
		})
	}
	if source, ok := firstFileInclusionMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "LFI/RFI",
			Details:    "Detected local or remote file inclusion in " + source,
		})
	}
	return detections
}

// Build bounded variants without combining independent request fields
func buildDetectionSources(input detectionInput) []detectionSource {
	sources := make([]detectionSource, 0, maxDetectionSources)
	appendDetectionSource := func(name, value string, plusAsSpace bool) {
		if value == "" || len(sources) >= maxDetectionSources {
			return
		}
		variants := normalizeDetectionVariants(value, plusAsSpace)
		if len(variants) > 0 {
			sources = append(sources, detectionSource{name: name, variants: variants})
		}
	}

	appendDetectionSource("request path", input.Path, false)
	appendDetectionSource("query string", input.RawQuery, true)
	appendDetectionSource("request body", input.Body, isFormContentType(input.Header.Get("Content-Type")))
	if isJSONContentType(input.Header.Get("Content-Type")) {
		if decoded, ok := decodeJSONStringLiterals(input.Body); ok {
			appendDetectionSource("decoded JSON body", decoded, false)
		}
	}
	appendDetectionSource("Host header", input.Host, false)

	for _, name := range inspectedHeaderNames {
		if len(sources) >= maxDetectionSources {
			return sources
		}
		values := input.Header.Values(name)
		if len(values) > 0 {
			variants := normalizeDetectionHeaderValues(name, values)
			if len(variants) > 0 {
				sources = append(sources, detectionSource{name: name + " header", variants: variants})
			}
		}
	}
	return sources
}

// Normalize repeated header values separately under the server read budget
func normalizeDetectionHeaderValues(name string, values []string) []string {
	variants := make([]string, 0, (maxDecodePasses+1)*2)
	seen := make(map[string]struct{}, cap(variants))
	remaining := maxDetectionSourceSize
	lineOverhead := len(name) + 4

	for _, value := range values {
		available := remaining - lineOverhead
		if available <= 0 {
			break
		}
		remaining = available
		if len(value) > available {
			value = sampleHeaderEdges(value, available)
			remaining = 0
		} else {
			remaining -= len(value)
		}
		for _, variant := range normalizeDetectionVariants(value, false) {
			appendUniqueVariant(&variants, seen, variant)
		}
	}
	return variants
}

// Preserve both ends when a synthetic header exceeds the HTTP read window
func sampleHeaderEdges(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	if limit == 1 {
		return value[len(value)-1:]
	}
	prefixSize := (limit - 1) / 2
	suffixSize := limit - prefixSize - 1
	return value[:prefixSize] + "\x00" + value[len(value)-suffixSize:]
}

// Recognize form encoding without trusting optional parameters
func isFormContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	return strings.TrimSpace(contentType) == "application/x-www-form-urlencoded"
}

// Match JSON media types without trusting optional parameters
func isJSONContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	contentType = strings.TrimSpace(contentType)
	return contentType == "application/json" || strings.HasSuffix(contentType, "+json")
}

// Unescape valid JSON string literals while retaining the surrounding syntax
func decodeJSONStringLiterals(value string) (string, bool) {
	if value == "" || !json.Valid([]byte(value)) {
		return "", false
	}

	var decoded strings.Builder
	decoded.Grow(len(value))
	changed := false
	for offset := 0; offset < len(value); {
		if value[offset] != '"' {
			decoded.WriteByte(value[offset])
			offset++
			continue
		}

		end := offset + 1
		for end < len(value) {
			if value[end] == '\\' {
				end += 2
				continue
			}
			if value[end] == '"' {
				break
			}
			end++
		}
		if end >= len(value) {
			return "", false
		}

		var literal string
		if err := json.Unmarshal([]byte(value[offset:end+1]), &literal); err != nil {
			return "", false
		}
		decoded.WriteByte('"')
		decoded.WriteString(strings.ReplaceAll(literal, `"`, `\"`))
		decoded.WriteByte('"')
		changed = changed || literal != value[offset+1:end]
		offset = end + 1
	}
	if !changed {
		return "", false
	}
	return decoded.String(), true
}

// Keep raw and decoded forms through a small fixed number of passes
func normalizeDetectionVariants(value string, plusAsSpace bool) []string {
	value = truncateDetectionSource(value)
	if value == "" {
		return nil
	}

	variants := make([]string, 0, (maxDecodePasses+1)*2)
	seen := make(map[string]struct{}, cap(variants))
	current := value
	for pass := 0; pass <= maxDecodePasses; pass++ {
		current = html.UnescapeString(current)
		canonical := canonicalizeDetectionText(current)
		appendUniqueVariant(&variants, seen, canonical)
		appendUniqueVariant(&variants, seen, strings.Join(strings.Fields(canonical), " "))

		if pass == maxDecodePasses {
			break
		}
		decoded, changed := decodeDetectionEscapes(current, plusAsSpace)
		if !changed || decoded == current {
			break
		}
		current = decoded
	}
	return variants
}

// Normalize case and common separator lookalikes while preserving newlines
func canonicalizeDetectionText(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = detectionRuneReplacer.Replace(value)
	value = strings.ToLower(value)
	return truncateUTF8(strings.TrimSpace(value), maxCanonicalSourceSize)
}

// Bound raw input before constant-width UTF-8 repair
func truncateDetectionSource(value string) string {
	if len(value) > maxDetectionSourceSize {
		value = value[:maxDetectionSourceSize]
	}
	return strings.ToValidUTF8(value, "?")
}

// Retain malformed escapes while decoding every valid percent sequence
func decodeDetectionEscapes(value string, plusAsSpace bool) (string, bool) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	changed := false

	for index := 0; index < len(value); index++ {
		switch {
		case plusAsSpace && value[index] == '+':
			decoded.WriteByte(' ')
			changed = true
		case value[index] == '%' && index+5 < len(value) && (value[index+1] == 'u' || value[index+1] == 'U'):
			runeValue, ok := decodeHexRune(value[index+2 : index+6])
			if !ok {
				decoded.WriteByte(value[index])
				continue
			}
			decoded.WriteRune(runeValue)
			index += 5
			changed = true
		case value[index] == '%' && index+2 < len(value):
			high, highOK := hexNibble(value[index+1])
			low, lowOK := hexNibble(value[index+2])
			if !highOK || !lowOK {
				decoded.WriteByte(value[index])
				continue
			}
			decoded.WriteByte(high<<4 | low)
			index += 2
			changed = true
		default:
			decoded.WriteByte(value[index])
		}
	}
	return decoded.String(), changed
}

// Decode one legacy percent-u sequence without accepting invalid runes
func decodeHexRune(value string) (rune, bool) {
	var decoded rune
	for index := 0; index < len(value); index++ {
		nibble, ok := hexNibble(value[index])
		if !ok {
			return 0, false
		}
		decoded = decoded<<4 | rune(nibble)
	}
	if !utf8.ValidRune(decoded) {
		return 0, false
	}
	return decoded, true
}

// Convert one ASCII hexadecimal digit
func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

// Append one canonical form without repeated matching work
func appendUniqueVariant(variants *[]string, seen map[string]struct{}, value string) {
	if value == "" {
		return
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	*variants = append(*variants, value)
}

// Return the source of the first fixed signature match
func firstRegexMatch(sources []detectionSource, patterns ...*regexp.Regexp) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			for _, pattern := range patterns {
				if pattern.MatchString(variant) {
					return source.name, true
				}
			}
		}
	}
	return "", false
}

// Match SQL syntax across raw and comment-collapsed variants
func firstSQLMatch(sources []detectionSource) (string, bool) {
	patterns := [...]*regexp.Regexp{
		sqlQuotedBooleanRegex,
		sqlNumericBooleanRegex,
		sqlCommentTailRegex,
		sqlUnionRegex,
		sqlFunctionRegex,
		sqlStackedRegex,
	}
	for _, source := range sources {
		for _, variant := range source.variants {
			unwrapped := sqlVersionCommentRegex.ReplaceAllString(variant, " $1 ")
			candidates := [...]string{
				variant,
				unwrapped,
				sqlBlockCommentRegex.ReplaceAllString(unwrapped, ""),
				sqlBlockCommentRegex.ReplaceAllString(unwrapped, " "),
			}
			for _, candidate := range candidates {
				for _, pattern := range patterns {
					if pattern.MatchString(candidate) {
						return source.name, true
					}
				}
			}
		}
	}
	return "", false
}

// Restrict XML entity matching to body-derived forms
func firstXMLMatch(sources []detectionSource) (string, bool) {
	for _, source := range sources {
		if source.name != "request body" {
			continue
		}
		for _, variant := range source.variants {
			if isXMLAttack(variant) {
				return source.name, true
			}
		}
	}
	return "", false
}

// Match named URL parameters whose target resolves syntactically to local space
func firstSSRFMatch(sources []detectionSource) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			if anyCapturedValue(variant, ssrfAssignmentRegex, isLocalTarget) {
				return source.name, true
			}
		}
	}
	return "", false
}

// Match sensitive local paths, wrappers, and remote include parameters
func firstFileInclusionMatch(sources []detectionSource) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			for _, pattern := range [...]*regexp.Regexp{fileAssignmentRegex, fileJSONAssignmentRegex} {
				if anyCapturedValue(variant, pattern, isFileInclusionTarget) {
					return source.name, true
				}
			}
			if allowsDirectFileProbe(source.name) && hasDirectLocalFileProbe(variant, source.name == "request body") {
				return source.name, true
			}
		}
	}
	return "", false
}

// Recognize external XML features and material entity expansion
func isXMLAttack(value string) bool {
	return xmlExternalEntityRegex.MatchString(value) ||
		xmlExternalDoctypeRegex.MatchString(value) ||
		xmlIncludeRegex.MatchString(value) ||
		hasDangerousEntityExpansion(value)
}

// Detect cycles and expansion without resolving entity content
func hasDangerousEntityExpansion(value string) bool {
	definitions := make(map[string]string)
	for _, match := range xmlEntityDeclaration.FindAllStringSubmatch(value, -1) {
		if len(match) != 5 {
			continue
		}
		name := match[2]
		if strings.TrimSpace(match[1]) != "" {
			name = "%" + name
		}
		entityValue := match[3]
		if entityValue == "" {
			entityValue = match[4]
		}
		definitions[name] = entityValue
	}

	states := make(map[string]uint8, len(definitions))
	sizes := make(map[string]int, len(definitions))
	for name := range definitions {
		if _, dangerous := expandedEntitySize(name, definitions, states, sizes); dangerous {
			return true
		}
	}
	return false
}

// Compute one expansion with cycle detection and saturating arithmetic
func expandedEntitySize(name string, definitions map[string]string, states map[string]uint8, sizes map[string]int) (int, bool) {
	switch states[name] {
	case 1:
		return 0, true
	case 2:
		return sizes[name], false
	}

	states[name] = 1
	value := definitions[name]
	size := 0
	cursor := 0
	for _, match := range xmlEntityReference.FindAllStringSubmatchIndex(value, -1) {
		var dangerous bool
		size, dangerous = addXMLExpansionSize(size, match[0]-cursor)
		if dangerous {
			return size, true
		}

		reference := value[match[4]:match[5]]
		if value[match[2]:match[3]] == "%" {
			reference = "%" + reference
		}
		referenceSize := match[1] - match[0]
		if _, exists := definitions[reference]; exists {
			referenceSize, dangerous = expandedEntitySize(reference, definitions, states, sizes)
			if dangerous {
				return referenceSize, true
			}
		}
		size, dangerous = addXMLExpansionSize(size, referenceSize)
		if dangerous {
			return size, true
		}
		cursor = match[1]
	}

	var dangerous bool
	size, dangerous = addXMLExpansionSize(size, len(value)-cursor)
	if dangerous {
		return size, true
	}
	states[name] = 2
	sizes[name] = size
	return size, false
}

// Stop expansion accounting once the suspicious threshold is crossed
func addXMLExpansionSize(size, addition int) (int, bool) {
	if addition > maxXMLExpansionSize-size {
		return maxXMLExpansionSize + 1, true
	}
	return size + addition, false
}

// Keep direct probes on request fields that can carry a target path
func allowsDirectFileProbe(source string) bool {
	switch source {
	case "request path", "query string", "request body",
		"X-Original-URL header", "X-Rewrite-URL header":
		return true
	default:
		return false
	}
}

// Match local targets outside command and XML execution contexts
func hasDirectLocalFileProbe(value string, body bool) bool {
	if body && isXMLAttack(value) {
		return false
	}
	for offset := 0; offset < len(value); {
		match := localFileRegex.FindStringIndex(value[offset:])
		if match == nil {
			return false
		}
		start := offset + match[0]
		end := offset + match[1]
		contextStart := strings.LastIndexAny(value[:start], "&,") + 1
		context := value[contextStart:end]
		if !pathTraversalRegex.MatchString(context) &&
			!commandSeparatorRegex.MatchString(context) &&
			!commandAssignmentRegex.MatchString(context) {
			return true
		}
		offset = end
	}
	return false
}

// Scan every capture without retaining an attacker-sized match slice
func anyCapturedValue(value string, pattern *regexp.Regexp, accept func(string) bool) bool {
	for offset := 0; offset < len(value); {
		match := pattern.FindStringSubmatchIndex(value[offset:])
		if match == nil {
			return false
		}
		if len(match) >= 4 && match[2] >= 0 && accept(value[offset+match[2]:offset+match[3]]) {
			return true
		}
		if match[1] <= 0 {
			return false
		}
		offset += match[1]
	}
	return false
}

// Classify URL targets without performing attacker-controlled DNS lookups
func isLocalTarget(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	if strings.HasPrefix(candidate, "//") {
		candidate = "http:" + candidate
	} else if !strings.Contains(candidate, "://") {
		candidate = "http://" + candidate
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	switch parsed.Scheme {
	case "file":
		return true
	case "http", "https", "ftp", "gopher", "dict", "ldap":
	default:
		return false
	}

	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if zoneIndex := strings.LastIndexByte(host, '%'); zoneIndex >= 0 {
		host = host[:zoneIndex]
	}
	if host == "" {
		return false
	}
	switch host {
	case "localhost", "localhost.localdomain", "localtest.me",
		"metadata.google.internal", "instance-data.ec2.internal",
		"168.63.129.16":
		return true
	}
	for _, suffix := range [...]string{".localhost", ".local", ".localdomain", ".internal", ".svc", ".cluster.local", ".localtest.me"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseLooseIPv4(host)
	}
	if ip != nil {
		return isLocalIP(ip)
	}
	for _, suffix := range [...]string{".nip.io", ".sslip.io"} {
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		encodedHost := strings.TrimSuffix(host, suffix)
		for _, candidate := range [...]string{encodedHost, strings.ReplaceAll(encodedHost, "-", ".")} {
			if ip := parseLooseIPv4(candidate); ip != nil && isLocalIP(ip) {
				return true
			}
		}
	}
	return false
}

// Classify parsed addresses without expanding the host network surface
func isLocalIP(ip net.IP) bool {
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
		if ipv4[0] == 100 && ipv4[1]&0xc0 == 0x40 {
			return true
		}
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// Parse legacy one-to-four-part IPv4 forms used in SSRF bypasses
func parseLooseIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for index, part := range parts {
		value, ok := parseIPv4Part(part)
		if !ok {
			return nil
		}
		values[index] = value
	}

	var address uint64
	switch len(values) {
	case 1:
		if values[0] > 0xffffffff {
			return nil
		}
		address = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil
		}
		address = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil
		}
		address = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, value := range values {
			if value > 0xff {
				return nil
			}
		}
		address = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}
	return net.IPv4(byte(address>>24), byte(address>>16), byte(address>>8), byte(address))
}

// Parse decimal, octal, or hexadecimal IPv4 components
func parseIPv4Part(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	base := 10
	digits := part
	switch {
	case strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X"):
		base = 16
		digits = part[2:]
	case len(part) > 1 && part[0] == '0':
		base = 8
		digits = part[1:]
	}
	if digits == "" {
		return 0, false
	}
	value, err := strconv.ParseUint(digits, base, 32)
	return value, err == nil
}

// Restrict inclusion matching to file-like parameters and actionable targets
func isFileInclusionTarget(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if localFileRegex.MatchString(candidate) {
		return true
	}
	if strings.HasPrefix(candidate, "//") {
		return true
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	switch parsed.Scheme {
	case "http", "https", "ftp", "tftp", "data":
		return true
	default:
		return false
	}
}

// Use the socket peer instead of forwarding headers
func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// Match the public decoy routes
func isHoneypotPath(path string) bool {
	return path == "/admin" || path == "/api/v1/auth" || path == "/.git/config"
}

// Collapse paths into a fixed Prometheus label set
func metricRoute(path string) string {
	switch path {
	case "/admin", "/api/v1/auth", "/.git/config", "/dashboard", "/api/dashboard-data", "/metrics", "/health":
		return path
	case "/static/admin.css", "/static/style.css", "/static/app.js":
		return "/static/*"
	default:
		return unknownMetricRoute
	}
}

// Collapse custom methods into one Prometheus series
func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return unknownMetricMethod
	}
}

// WriteHeader records the first status like net/http
func (w *loggingResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// Write records the implicit success status before the body
func (w *loggingResponseWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(payload)
}

// Unwrap exposes the underlying writer to http.ResponseController
func (w *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Delay for one to three seconds unless the request is cancelled
func applyRandomDelay(ctx context.Context) bool {
	delay, err := rand.Int(rand.Reader, big.NewInt(2000))
	if err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "crypto/rand delay fallback", err.Error())
		delay = big.NewInt(time.Now().UnixNano() % 2000)
	}
	timer := time.NewTimer(time.Duration(delay.Int64()+1000) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Generate per-request bait instead of storing fake secrets
func randomToken(prefix string, byteCount int) (string, error) {
	payload := make([]byte, byteCount)
	if _, err := rand.Read(payload); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// Build a short-lived decoy token with random signature bytes
func newFakeJWT() (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims, err := json.Marshal(struct {
		Subject string `json:"sub"`
		Role    string `json:"role"`
		Issuer  string `json:"iss"`
		Issued  int64  `json:"iat"`
		Expires int64  `json:"exp"`
	}{
		Subject: "administrator",
		Role:    "admin",
		Issuer:  "internal-auth",
		Issued:  time.Now().Unix(),
		Expires: time.Now().Add(15 * time.Minute).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encode fake JWT claims: %w", err)
	}
	signature, err := randomToken("", 32)
	if err != nil {
		return "", err
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + signature, nil
}

// Serve the public administrator decoy
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowedWithDelay(w, r, http.MethodGet)
		return
	}
	http.ServeFileFS(w, r, staticAssets, "static/admin_login.html")
}

// Return a fresh fake token for each login attempt
func handleAPIV1Auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowedWithDelay(w, r, http.MethodPost)
		return
	}
	token, err := newFakeJWT()
	if err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "fake token generation failed", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"token": token, "status": "success"}); err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "fake auth response failed", err.Error())
	}
}

// Serve generated Git bait under reserved example domains
func handleGitConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowedWithDelay(w, r, http.MethodGet)
		return
	}
	token, err := randomToken("glpat-", 15)
	if err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "fake Git token generation failed", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := fmt.Fprintf(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
[remote "origin"]
	url = git@internal-git.example.com:platform/control-plane.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[credential]
	helper = store
# CI_DEPLOY_TOKEN = %s
`, token); err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "fake Git config response failed", err.Error())
	}
}

// Copy dashboard events newest first before encoding
func handleDashboardData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	logMutex.Lock()
	logsCopy := make([]LogEntry, len(recentLogs))
	for i, j := 0, len(recentLogs)-1; i < len(recentLogs); i, j = i+1, j-1 {
		logsCopy[i] = recentLogs[j]
	}
	logMutex.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(logsCopy); err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "dashboard encoding failed", err.Error())
	}
}

// Log unknown public traffic before the delayed 404
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	logEvent("info", remoteIP(r.RemoteAddr), r.UserAgent(), r.URL.Path, "NotFound", "Accessed undefined path", r.URL.RawQuery, "")
	if !applyRandomDelay(r.Context()) {
		return
	}
	http.NotFound(w, r)
}

// Delay unsupported methods on decoy routes
func methodNotAllowedWithDelay(w http.ResponseWriter, r *http.Request, allowed string) {
	if !applyRandomDelay(r.Context()) {
		return
	}
	w.Header().Set("Allow", allowed)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

// Serve one embedded asset with read-only methods
func embeddedFileHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		http.ServeFileFS(w, r, staticAssets, path)
	}
}

// Assemble the public honeypot routes
func publicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/api/v1/auth", handleAPIV1Auth)
	mux.HandleFunc("/.git/config", handleGitConfig)
	mux.HandleFunc("/static/admin.css", embeddedFileHandler("static/admin.css"))
	mux.HandleFunc("/", handleNotFound)

	handler := requestInspectionMiddleware(mux)
	handler = concurrencyLimitMiddleware(maxConcurrentPublic, handler)
	handler = metricsMiddleware(handler)
	handler = timeoutMiddleware(handler)
	return securityHeadersMiddleware(handler)
}

// Assemble the operational routes for the admin listener
func adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard", embeddedFileHandler("static/dashboard.html"))
	mux.HandleFunc("/static/style.css", embeddedFileHandler("static/style.css"))
	mux.HandleFunc("/static/app.js", embeddedFileHandler("static/app.js"))
	mux.HandleFunc("/api/dashboard-data", handleDashboardData)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := io.WriteString(w, "OK\n"); err != nil {
			log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "health response failed", err.Error())
		}
	})
	mux.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{}))

	handler := metricsMiddleware(mux)
	handler = timeoutMiddleware(handler)
	return securityHeadersMiddleware(handler)
}

// Apply the same transport limits to both listeners
func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       requestTimeout + time.Second,
		WriteTimeout:      requestTimeout + time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// Read an address override without accepting blank values
func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// Run both listeners and stop them together
func run(ctx context.Context) error {
	publicAddr := envOrDefault(envPublicAddr, defaultPublicAddr)
	adminAddr := envOrDefault(envAdminAddr, defaultAdminAddr)
	publicServer := newHTTPServer(publicAddr, publicHandler())
	adminServer := newHTTPServer(adminAddr, adminHandler())
	servers := []*http.Server{publicServer, adminServer}
	errorsCh := make(chan error, len(servers))

	for _, server := range servers {
		server := server
		go func() {
			err := server.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errorsCh <- err
		}()
	}

	fmt.Print(asciiArtBanner)
	fmt.Printf("level=info ts=%s msg=%q public_addr=%q admin_addr=%q\n",
		time.Now().UTC().Format(time.RFC3339),
		"ghoney listening",
		publicAddr,
		adminAddr,
	)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errorsCh:
		if runErr == nil {
			runErr = errors.New("HTTP server stopped unexpectedly")
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var shutdownErr error
	for _, server := range servers {
		shutdownErr = errors.Join(shutdownErr, server.Shutdown(shutdownCtx))
	}
	return errors.Join(runErr, shutdownErr)
}

// Tie server shutdown to process signals
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatalf("level=fatal ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "server stopped", err.Error())
	}
}
