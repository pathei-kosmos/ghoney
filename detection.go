package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	defaultPublicAddr  = ":8080"
	defaultAdminAddr   = "127.0.0.1:9090"
	maxRequestBodySize = 4 * 1024
	maxBodySnippetSize = 256
	maxEventFieldSize  = 1024
	maxHeaderBytes     = 16 * 1024
	// Include the 4 KiB buffered read margin from net/http
	maxDetectionSourceSize = maxHeaderBytes + 4*1024
	// Leave room for Unicode case folding without losing the tail
	maxCanonicalSourceSize = maxDetectionSourceSize * 2
	maxDetectionSources    = 16
	maxDecodePasses        = 3
	maxXMLExpansionSize    = maxRequestBodySize * 8
	requestTimeout         = 5 * time.Second
	shutdownTimeout        = 5 * time.Second
	logBufferSize          = 100
	maxConcurrentPublic    = 128
	maxConcurrentAdmin     = 32
	envPublicAddr          = "GHONEY_ADDR"
	envAdminAddr           = "GHONEY_ADMIN_ADDR"
	envAdminUser           = "GHONEY_ADMIN_USER"
	envAdminPassword       = "GHONEY_ADMIN_PASSWORD"
	envAdminPasswordFile   = "GHONEY_ADMIN_PASSWORD_FILE"
	defaultAdminUser       = "ghoney"
	minAdminPasswordBytes  = 16
	maxAdminPasswordBytes  = 256
	maxJNDIExpansionPasses = 4
	maxBase64Candidates    = 16
	minBase64ValueSize     = 8
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

// Embed static assets in the binary
//
//go:embed static/*
var staticAssets embed.FS

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

// detection holds one attack class and a bounded explanation
type detection struct {
	AttackType string
	Details    string
	Confidence confidence
}

// confidence keeps logs and metric labels within known values
type confidence string

const (
	confidenceMedium confidence = "medium"
	confidenceHigh   confidence = "high"
)

// detectionInput keeps request fields separate during matching
type detectionInput struct {
	Path     string
	RawQuery string
	Body     string
	Host     string
	Header   http.Header
}

// detectionSource holds bounded forms of one request field
type detectionSource struct {
	name     string
	variants []string
}

// loggingResponseWriter tracks the first response status
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

// adminCredentials stores only fixed size credential hashes
type adminCredentials struct {
	enabled      bool
	usernameHash [sha256.Size]byte
	passwordHash [sha256.Size]byte
}

// appConfig holds validated settings for both listeners
type appConfig struct {
	publicAddr      string
	adminAddr       string
	adminCredential adminCredentials
}

// runtimeDependencies make listener startup easy to test
type runtimeDependencies struct {
	listen func(network, address string) (net.Listener, error)
	serve  func(server *http.Server, listener net.Listener) error
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

	// Compile signatures once at startup
	pathTraversalRegex             = regexp.MustCompile(`(?:\.{2,}[/\\]|\.\.;[/\\])`)
	sqlQuotedBooleanRegex          = regexp.MustCompile("(?i)(?:'|\"|`|\\))\\s*(?:or|and)\\s+(?:not\\s+)?(?:\\d+|'[^']*'|\"[^\"]*\")\\s*(?:=|like)\\s*(?:\\d+|'[^']*'|\"[^\"]*\")")
	sqlTruncatedQuotedBooleanRegex = regexp.MustCompile("(?i)(?:'|\")\\)?\\s*(?:or|and)\\s+\\(?\\s*(?:'[^']{0,128}'|\"[^\"]{0,128}\")\\s*(?:=|like)\\s*(?:'[^']{0,128}|\"[^\"]{0,128})")
	sqlNumericBooleanRegex         = regexp.MustCompile(`(?i)(?:^|[?&;\s])(?:[a-z_][a-z0-9_.-]*=)?\d+\s+(?:or|and)\s+\d+\s*=\s*\d+`)
	sqlCommentTailRegex            = regexp.MustCompile("(?i)(?:'|\"|`)\\s*(?:--|#)")
	sqlUnionRegex                  = regexp.MustCompile(`(?i)\bunion(?:\s+(?:all\s+)?select\b|(?:\s+all)?\s*\(\s*select\b)`)
	sqlFunctionRegex               = regexp.MustCompile(`(?i)\b(?:benchmark|pg_sleep|load_file|xp_cmdshell|extractvalue|updatexml)\s*\(|\bwaitfor\s+delay\b|\binto\s+outfile\b|\binformation_schema\b`)
	sqlSleepRegex                  = regexp.MustCompile(`(?i)\bsleep\s*\(`)
	sqlStackedRegex                = regexp.MustCompile(`(?i);\s*(?:select|insert|update|delete|drop|alter|create|exec|execute)\b`)
	sqlStructuredStackedRegex      = regexp.MustCompile(`(?i);\s*(?:select\b.{0,512}\bfrom\b|insert\s+into\b|update\s+[^\s;]{1,128}\s+set\b|delete\s+from\b|(?:drop|alter|create)\s+(?:table|database|schema|index|view|user|procedure|function)\b|(?:exec|execute)\s+(?:xp_cmdshell|sp_executesql)\b)`)
	sqlVersionCommentRegex         = regexp.MustCompile(`(?is)/\*!\d{0,6}\s*(.*?)\*/`)
	sqlBlockCommentRegex           = regexp.MustCompile(`(?s)/\*.*?\*/`)
	xmlExternalEntityRegex         = regexp.MustCompile(`(?is)<!entity\s+(?:%\s*)?[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlExternalDoctypeRegex        = regexp.MustCompile(`(?is)<!doctype\s+[a-z_][a-z0-9_:.-]*\s+(?:system|public)\s+["']`)
	xmlIncludeRegex                = regexp.MustCompile(`(?is)<(?:xi:include|xinclude)\b[^>]{0,512}\bhref\s*=\s*["'](?:file|https?)://`)
	xmlEntityDeclaration           = regexp.MustCompile(`(?is)<!entity\s+(%\s*)?([a-z_][a-z0-9_:.-]*)\s+(?:"([^"]*)"|'([^']*)')\s*>`)
	xmlEntityReference             = regexp.MustCompile(`(?i)([&%])([a-z_][a-z0-9_:.-]*);`)
	commandAmbiguousSeparatorRegex = regexp.MustCompile("(?i)(?:;|&[\\t ]*)[\\t ]*(?:(?:\\$\\{ifs\\}|\\$ifs\\$9)[\\t ]*)*(?:sudo[\\t ]+)?(?:/usr/bin/|/bin/)?\\b(?:id|env|ls)(?:\\.exe)?(?:[\\t ]|$|[;&|)`<>]|\\$\\{ifs\\}|\\$ifs(?:\\$9)?)")
	commandExplicitSeparatorRegex  = regexp.MustCompile("(?i)(?:;|&[\\t ]*)[\\t ]*(?:(?:\\$\\{ifs\\}|\\$ifs\\$9)[\\t ]*)*(?:sudo[\\t ]+)?(?:/usr/bin/|/bin/)?\\b(?:whoami|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|printenv|sleep|python|python3|perl|ruby|busybox)(?:\\.exe)?(?:[\\t ]|$|[;&|)`<>]|\\$\\{ifs\\}|\\$ifs(?:\\$9)?)")
	commandStrongSeparatorRegex    = regexp.MustCompile("(?i)(?:\\|\\||&&|\\||[\\r\\n])[\\t ]*(?:(?:\\$\\{ifs\\}|\\$ifs\\$9)[\\t ]*)*(?:sudo[\\t ]+)?(?:/usr/bin/|/bin/)?\\b(?:whoami|id|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|env|printenv|ls|sleep|python|python3|perl|ruby|busybox)(?:\\.exe)?(?:[\\t ]|$|[;&|)`<>]|\\$\\{ifs\\}|\\$ifs(?:\\$9)?)")
	commandSubstitutionRegex       = regexp.MustCompile("(?i)(?:\\$\\(|`)[\\t ]*(?:(?:\\$\\{ifs\\}|\\$ifs\\$9)[\\t ]*)*(?:sudo[\\t ]+)?(?:/usr/bin/|/bin/)?(?:whoami|id|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|env|printenv|ls|sleep|python|python3|perl|ruby|busybox)\\b")
	commandAssignmentRegex         = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:cmd|command|exec|execute|shell)["']?\s*(?:=|:)\s*["']?(?:/usr/bin/|/bin/)?(?:whoami|id|uname|cat|curl|wget|ping|sh|bash|dash|zsh|nc|netcat|powershell|pwsh|cmd|nslookup|dig|env|printenv|ls|sleep|python|python3|perl|ruby|busybox)(?:\.exe)?\b`)
	ssrfHighAssignmentRegex        = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:url|uri|redirect|next|target|dest|destination|callback|continue|return|return_url|endpoint|proxy|fetch|webhook)["']?\s*(?:=|:)\s*["']?([^"'&,\s}]+)`)
	ssrfMediumAssignmentRegex      = regexp.MustCompile(`(?i)(?:^|[?&;,\s{])["']?(?:host|src|image)["']?\s*(?:=|:)\s*["']?([^"'&,\s}]+)`)
	localFileRegex                 = regexp.MustCompile(`(?i)(?:/(?:etc/(?:passwd|shadow|hosts|sudoers)|proc/(?:self|\d+)/(?:environ|cmdline|maps)|var/log/(?:auth\.log|secure)|root/\.ssh/)|[a-z]:\\(?:windows\\(?:win\.ini|system32(?:\\|$))|boot\.ini)|(?:php|file|zip|phar|expect|input|glob|ssh2)://)`)
	fileAssignmentRegex            = regexp.MustCompile(`(?i)(?:^|[?&;,\s])(?:file|page|include|template|path|document|folder|root)(?:\[[a-z0-9_-]*\])?\s*=\s*["']?([^"'&,\s}]+)`)
	fileJSONAssignmentRegex        = regexp.MustCompile(`(?i)["'](?:file|page|include|template|path|document|folder|root)["']\s*:\s*["']([^"']+)`)
	xssActiveTagRegex              = regexp.MustCompile(`(?is)<\s*/?\s*(?:script|iframe|object|embed)\b`)
	xssAmbiguousTagRegex           = regexp.MustCompile(`(?is)<\s*/?\s*(?:svg|math|img|video|audio|link|meta|style)\b`)
	xssEventHandlerRegex           = regexp.MustCompile(`(?i)(?:^|[\t\n\f\r <"'=])(?:onerror|onload|onclick|onmouseover|onfocus|onblur|onsubmit|oninput|onchange|onanimationstart|ontoggle|onpointerover|onmouseenter|onmouseleave|onmessage|onhashchange)\s*=`)
	xssTagEventHandlerRegex        = regexp.MustCompile(`(?is)<[^<>]{0,1000}[\t\n\f\r ]on[a-z][a-z0-9_-]*\s*=`)
	xssJavaScriptURIRegex          = regexp.MustCompile(`(?i)\bjavascript\s*:`)
	jndiLookupRegex                = regexp.MustCompile(`(?i)\$\{\s*jndi\s*:`)
	jndiExpandedLookupRegex        = regexp.MustCompile(`(?i)\bjndi\s*:`)
	jndiCaseLookupRegex            = regexp.MustCompile(`(?i)\$\{\s*(?:lower|upper)\s*:\s*([^{}])\s*}`)
	jndiDefaultLookupRegex         = regexp.MustCompile(`(?i)\$\{\s*::-\s*([^{}])\s*}`)
	jndiEnvironmentDefaultRegex    = regexp.MustCompile(`(?i)\$\{\s*env\s*:[^{}:]{1,128}:-\s*([^{}])\s*}`)
	detectionRuneReplacer          = strings.NewReplacer(
		"／", "/", "∕", "/", "⁄", "/",
		"＼", `\`, "﹨", `\`,
		"．", ".", "｡", ".", "。", ".",
	)
	urlIgnoredControlReplacer = strings.NewReplacer("\t", "", "\n", "", "\r", "")
	inspectedHeaderNames      = [...]string{
		"Cookie",
		"Forwarded",
		"Referer",
		"User-Agent",
		"X-Forwarded-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
	}
)

// Return one event per family with the strongest confidence
func detectAttacks(input detectionInput) []detection {
	sources := buildDetectionSources(input)
	detections := make([]detection, 0, 9)

	if source, ok := firstRegexMatch(sources, pathTraversalRegex); ok {
		detections = append(detections, detection{
			AttackType: "Path Traversal",
			Details:    "Detected traversal sequence in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstSQLMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "SQL Injection",
			Details:    "Detected SQL injection pattern in " + source,
			Confidence: value,
		})
	}
	if source, ok := firstXMLMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "XML Entity",
			Details:    "Detected external or expansive XML construct in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstCommandMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "Command Injection",
			Details:    "Detected command execution pattern in " + source,
			Confidence: value,
		})
	}
	if source, value := firstSSRFMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "SSRF",
			Details:    "Detected private or local target in " + source,
			Confidence: value,
		})
	}
	if source, ok := firstFileInclusionMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "LFI/RFI",
			Details:    "Detected local or remote file inclusion in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstXSSMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "XSS",
			Details:    "Detected executable browser content in " + source,
			Confidence: value,
		})
	}
	if source, ok := firstJNDIMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "JNDI Injection",
			Details:    "Detected JNDI lookup expression in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstNoSQLMatch(input); value != "" {
		detections = append(detections, detection{
			AttackType: "NoSQL Injection",
			Details:    "Detected explicit NoSQL operator in " + source,
			Confidence: value,
		})
	}
	return detections
}

// Build bounded variants without mixing request fields
func buildDetectionSources(input detectionInput) []detectionSource {
	sources := make([]detectionSource, 0, maxDetectionSources)
	appendDetectionSource := func(name, value string, plusAsSpace bool) {
		if value == "" || len(sources) >= maxDetectionSources {
			return
		}
		boundedValue := truncateDetectionSource(value)
		variants := normalizeDetectionVariants(boundedValue, plusAsSpace)
		switch name {
		case "query string":
			variants = appendBase64ParameterVariants(variants, boundedValue)
		case "request body":
			switch {
			case isFormContentType(input.Header.Get("Content-Type")):
				variants = appendBase64ParameterVariants(variants, boundedValue)
			case isJSONContentType(input.Header.Get("Content-Type")):
				variants = appendBase64JSONVariants(variants, boundedValue)
			}
		}
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

// Normalize repeated header values within the server read budget
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

// Preserve both ends when a header exceeds the HTTP read window
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

// Recognize form encoding while ignoring optional parameters
func isFormContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	return strings.TrimSpace(contentType) == "application/x-www-form-urlencoded"
}

// Match JSON media types while ignoring optional parameters
func isJSONContentType(contentType string) bool {
	contentType, _, _ = strings.Cut(strings.ToLower(contentType), ";")
	contentType = strings.TrimSpace(contentType)
	return contentType == "application/json" || strings.HasSuffix(contentType, "+json")
}

// Add bounded decoded values without joining independent fields
func appendBase64ParameterVariants(variants []string, value string) []string {
	fields := make([]base64Field, 0)
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == ';' }) {
		key, encoded, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		decodedKey, keyErr := url.QueryUnescape(strings.TrimSpace(key))
		decodedValue, valueErr := url.QueryUnescape(strings.TrimSpace(encoded))
		if keyErr != nil || valueErr != nil {
			continue
		}
		fields = append(fields, base64Field{key: decodedKey, value: decodedValue})
	}
	return appendBase64FieldVariants(variants, sampleBase64Fields(fields))
}

// Add decoded JSON string values in stable key order
func appendBase64JSONVariants(variants []string, value string) []string {
	if len(value) > maxRequestBodySize || !json.Valid([]byte(value)) {
		return variants
	}
	var document any
	if err := json.Unmarshal([]byte(value), &document); err != nil {
		return variants
	}
	fields := make([]base64Field, 0)
	collectBase64JSONFields(document, "", &fields)
	return appendBase64FieldVariants(variants, sampleBase64Fields(fields))
}

// Keep key context for decoded command and URL assignments
type base64Field struct {
	key   string
	value string
}

// Walk one bounded JSON document without decoding keys
func collectBase64JSONFields(value any, key string, fields *[]base64Field) {
	switch typed := value.(type) {
	case string:
		*fields = append(*fields, base64Field{key: key, value: typed})
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for childKey := range typed {
			keys = append(keys, childKey)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			collectBase64JSONFields(typed[childKey], childKey, fields)
		}
	case []any:
		for _, child := range typed {
			collectBase64JSONFields(child, key, fields)
		}
	}
}

// Preserve candidates from both ends of a structured source
func sampleBase64Fields(fields []base64Field) []base64Field {
	if len(fields) <= maxBase64Candidates {
		return fields
	}
	half := maxBase64Candidates / 2
	sampled := make([]base64Field, 0, maxBase64Candidates)
	sampled = append(sampled, fields[:half]...)
	sampled = append(sampled, fields[len(fields)-(maxBase64Candidates-half):]...)
	return sampled
}

// Append printable Base64 values within one aggregate decode budget
func appendBase64FieldVariants(variants []string, fields []base64Field) []string {
	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		seen[variant] = struct{}{}
	}
	remaining := maxRequestBodySize
	for _, field := range fields {
		decoded, ok := decodeBase64Text(field.value)
		if !ok || len(decoded) > remaining {
			continue
		}
		remaining -= len(decoded)
		candidate := decoded
		if field.key != "" {
			candidate = field.key + "=" + decoded
		}
		for _, variant := range normalizeDetectionVariants(candidate, false) {
			appendUniqueVariant(&variants, seen, variant)
		}
	}
	return variants
}

// Decode one complete textual Base64 value without recursion
func decodeBase64Text(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < minBase64ValueSize || len(value) > maxDetectionSourceSize {
		return "", false
	}
	encodings := [...]*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err != nil || len(decoded) == 0 || len(decoded) > maxRequestBodySize || !utf8.Valid(decoded) {
			continue
		}
		text := string(decoded)
		if isPrintableDetectionText(text) {
			return text, true
		}
	}
	return "", false
}

// Reject binary tokens that only happen to use a Base64 alphabet
func isPrintableDetectionText(value string) bool {
	for _, current := range value {
		if current != '\t' && current != '\n' && current != '\r' && !unicode.IsPrint(current) {
			return false
		}
	}
	return true
}

// Decode JSON strings while keeping the surrounding syntax
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

// Keep raw and decoded forms through a fixed number of passes
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

// Normalize case and common separator lookalikes while keeping newlines
func canonicalizeDetectionText(value string) string {
	value = strings.ToValidUTF8(value, "?")
	value = detectionRuneReplacer.Replace(value)
	value = strings.ToLower(value)
	return truncateUTF8(strings.TrimSpace(value), maxCanonicalSourceSize)
}

// Bound raw input before UTF8 repair
func truncateDetectionSource(value string) string {
	if len(value) > maxDetectionSourceSize {
		value = value[:maxDetectionSourceSize]
	}
	return strings.ToValidUTF8(value, "?")
}

// Keep malformed escapes and decode valid percent sequences
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

// Decode one legacy %u sequence and reject invalid runes
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

// Append one canonical form only once
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

// Return the source of the first signature match
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

// Match SQL syntax across raw and collapsed comment variants
func firstSQLMatch(sources []detectionSource) (string, confidence) {
	highPatterns := [...]*regexp.Regexp{
		sqlQuotedBooleanRegex,
		sqlTruncatedQuotedBooleanRegex,
		sqlCommentTailRegex,
		sqlUnionRegex,
		sqlFunctionRegex,
		sqlStructuredStackedRegex,
	}
	mediumPatterns := [...]*regexp.Regexp{
		sqlNumericBooleanRegex,
		sqlSleepRegex,
		sqlStackedRegex,
	}
	var mediumSource string
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
				for _, pattern := range highPatterns {
					if pattern.MatchString(candidate) {
						return source.name, confidenceHigh
					}
				}
				if mediumSource == "" {
					for _, pattern := range mediumPatterns {
						if pattern.MatchString(candidate) {
							mediumSource = source.name
							break
						}
					}
				}
			}
		}
	}
	if mediumSource != "" {
		return mediumSource, confidenceMedium
	}
	return "", ""
}

// Match shell signatures with a local quote splitting variant
func firstCommandMatch(sources []detectionSource) (string, confidence) {
	highPatterns := []*regexp.Regexp{commandAssignmentRegex, commandSubstitutionRegex, commandStrongSeparatorRegex, commandExplicitSeparatorRegex}
	mediumPatterns := []*regexp.Regexp{commandAmbiguousSeparatorRegex}
	if source, ok := firstDerivedRegexMatch(sources, highPatterns, collapseShellWordQuotes); ok {
		return source, confidenceHigh
	}
	if source, ok := firstDerivedRegexMatch(sources, mediumPatterns, collapseShellWordQuotes); ok {
		return source, confidenceMedium
	}
	return "", ""
}

// Match raw and family specific variants without changing shared sources
func firstDerivedRegexMatch(sources []detectionSource, patterns []*regexp.Regexp, derive func(string) string) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			candidates := [...]string{variant, derive(variant)}
			for index, candidate := range candidates {
				if index == 1 && candidate == variant {
					continue
				}
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

// Collapse balanced quotes only when they split one shell word
func collapseShellWordQuotes(value string) string {
	var collapsed strings.Builder
	collapsed.Grow(len(value))
	changed := false
	for index := 0; index < len(value); {
		quote := value[index]
		if (quote != '\'' && quote != '"') || index == 0 || !isShellWordByte(value[index-1]) {
			collapsed.WriteByte(value[index])
			index++
			continue
		}

		end := index + 1
		for end < len(value) && isShellWordByte(value[end]) {
			end++
		}
		if end == index+1 || end+1 >= len(value) || value[end] != quote || !isShellWordByte(value[end+1]) {
			collapsed.WriteByte(value[index])
			index++
			continue
		}

		collapsed.WriteString(value[index+1 : end])
		index = end + 1
		changed = true
	}
	if !changed {
		return value
	}
	return collapsed.String()
}

// Recognize bytes accepted inside the command names we track
func isShellWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_' || value == '-'
}

// Keep active browser constructs above ambiguous standalone tags and schemes
func firstXSSMatch(sources []detectionSource) (string, confidence) {
	if source, ok := firstRegexMatch(sources, xssActiveTagRegex, xssEventHandlerRegex, xssTagEventHandlerRegex); ok {
		return source, confidenceHigh
	}
	if source, ok := firstRegexMatch(sources, xssAmbiguousTagRegex); ok {
		return source, confidenceMedium
	}
	if source, ok := firstDerivedRegexMatch(sources, []*regexp.Regexp{xssJavaScriptURIRegex}, removeURLIgnoredControls); ok {
		return source, confidenceMedium
	}
	return "", ""
}

// Remove only controls ignored by the URL parser
func removeURLIgnoredControls(value string) string {
	return urlIgnoredControlReplacer.Replace(value)
}

// Expand local JNDI character tricks within a fixed budget
func firstJNDIMatch(sources []detectionSource) (string, bool) {
	for _, source := range sources {
		for _, variant := range source.variants {
			candidate := variant
			changed := false
			for pass := 0; pass < maxJNDIExpansionPasses; pass++ {
				expanded := jndiCaseLookupRegex.ReplaceAllString(candidate, "$1")
				expanded = jndiDefaultLookupRegex.ReplaceAllString(expanded, "$1")
				expanded = jndiEnvironmentDefaultRegex.ReplaceAllString(expanded, "$1")
				if expanded == candidate {
					break
				}
				candidate = expanded
				changed = true
			}
			if jndiLookupRegex.MatchString(candidate) || changed && jndiExpandedLookupRegex.MatchString(candidate) {
				return source.name, true
			}
		}
	}
	return "", false
}

// Match explicit NoSQL keys in JSON objects, query strings and form bodies
func firstNoSQLMatch(input detectionInput) (string, confidence) {
	bestSource := ""
	best := confidence("")
	keepStrongest := func(source string, value confidence) bool {
		if confidenceRank(value) > confidenceRank(best) {
			bestSource = source
			best = value
		}
		return best == confidenceHigh
	}

	if keepStrongest("request body", noSQLJSONConfidence(input.Body)) {
		return bestSource, best
	}
	for _, candidate := range normalizeDetectionVariants(input.RawQuery, true) {
		if keepStrongest("query string", noSQLParameterConfidence(candidate)) {
			return bestSource, best
		}
	}
	if isFormContentType(input.Header.Get("Content-Type")) {
		for _, candidate := range normalizeDetectionVariants(input.Body, true) {
			if keepStrongest("request body", noSQLParameterConfidence(candidate)) {
				return bestSource, best
			}
		}
	}
	return bestSource, best
}

// Read NoSQL operators from JSON keys rather than values
func noSQLJSONConfidence(body string) confidence {
	if body == "" || len(body) > maxRequestBodySize || !json.Valid([]byte(body)) {
		return ""
	}
	var value any
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		return ""
	}
	return noSQLValueConfidence(value)
}

// Find the strongest NoSQL operator in a JSON tree
func noSQLValueConfidence(value any) confidence {
	best := confidence("")
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			best = maxConfidence(best, noSQLKeyConfidence(key))
			best = maxConfidence(best, noSQLValueConfidence(child))
			if best == confidenceHigh {
				return best
			}
		}
	case []any:
		for _, child := range typed {
			best = maxConfidence(best, noSQLValueConfidence(child))
			if best == confidenceHigh {
				return best
			}
		}
	}
	return best
}

// Require dotted or bracket notation in query and form keys
func noSQLParameterConfidence(value string) confidence {
	best := confidence("")
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == '&' || r == ';' }) {
		key, _, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found || (!strings.Contains(key, ".") && !(strings.Contains(key, "[") && strings.Contains(key, "]"))) {
			continue
		}
		best = maxConfidence(best, noSQLKeyConfidence(key))
		if best == confidenceHigh {
			return best
		}
	}
	return best
}

// Read exact dotted and bracket NoSQL key parts
func noSQLKeyConfidence(key string) confidence {
	key = strings.ToLower(strings.Trim(strings.TrimSpace(key), `"'`))
	components := strings.FieldsFunc(key, func(r rune) bool { return r == '.' || r == '[' || r == ']' })
	for _, component := range components {
		switch component {
		case "$where", "$function":
			return confidenceHigh
		case "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex", "$exists":
			return confidenceMedium
		}
	}
	return ""
}

// Keep the strongest confidence found for a family
func maxConfidence(left, right confidence) confidence {
	if confidenceRank(right) > confidenceRank(left) {
		return right
	}
	return left
}

// Restrict XML entity checks to request bodies
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

// Match explicit and ambiguous URL sinks at separate confidence levels
func firstSSRFMatch(sources []detectionSource) (string, confidence) {
	for _, source := range sources {
		for _, variant := range source.variants {
			if anyCapturedValue(variant, ssrfHighAssignmentRegex, isLocalTarget) {
				return source.name, confidenceHigh
			}
		}
	}
	for _, source := range sources {
		for _, variant := range source.variants {
			if anyCapturedValue(variant, ssrfMediumAssignmentRegex, isLocalTarget) {
				return source.name, confidenceMedium
			}
		}
	}
	return "", ""
}

// Match sensitive paths, wrappers and remote includes
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

// Recognize external XML features and large entity expansion
func isXMLAttack(value string) bool {
	return xmlExternalEntityRegex.MatchString(value) ||
		xmlExternalDoctypeRegex.MatchString(value) ||
		xmlIncludeRegex.MatchString(value) ||
		hasDangerousEntityExpansion(value)
}

// Detect entity cycles and growth without resolving content
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

// Measure one entity expansion with cycle detection
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

// Stop counting once expansion crosses the threshold
func addXMLExpansionSize(size, addition int) (int, bool) {
	if addition > maxXMLExpansionSize-size {
		return maxXMLExpansionSize + 1, true
	}
	return size + addition, false
}

// Check direct probes only where a target path makes sense
func allowsDirectFileProbe(source string) bool {
	switch source {
	case "request path", "query string", "request body",
		"X-Original-URL header", "X-Rewrite-URL header":
		return true
	default:
		return false
	}
}

// Recognize every command shape when another detector excludes overlap
func hasCommandExecutionPattern(value string) bool {
	for _, pattern := range [...]*regexp.Regexp{
		commandAmbiguousSeparatorRegex,
		commandExplicitSeparatorRegex,
		commandStrongSeparatorRegex,
		commandSubstitutionRegex,
		commandAssignmentRegex,
	} {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// Match local targets outside command and XML contexts
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
		if !pathTraversalRegex.MatchString(context) && !hasCommandExecutionPattern(context) {
			return true
		}
		offset = end
	}
	return false
}

// Scan every capture without keeping a large match slice
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

// Classify URL targets without DNS lookups
func isLocalTarget(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	candidate = normalizeSpecialURL(candidate)
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

// Align special URL separators with browser and common client parsing
func normalizeSpecialURL(candidate string) string {
	separator := strings.IndexByte(candidate, ':')
	if separator <= 0 {
		return candidate
	}
	scheme := strings.ToLower(candidate[:separator])
	switch scheme {
	case "http", "https", "ftp":
	default:
		return candidate
	}
	remainder := strings.ReplaceAll(candidate[separator+1:], `\`, "/")
	remainder = strings.TrimLeft(remainder, "/")
	return scheme + "://" + remainder
}

// Classify parsed addresses without touching the network
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

// Parse legacy IPv4 forms with one to four parts
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

// Parse decimal, octal and hexadecimal IPv4 parts
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

// Restrict inclusion checks to file parameters and usable targets
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

// Match the public lure routes
func isHoneypotPath(path string) bool {
	return path == "/admin" || path == "/api/v1/auth" || path == "/.git/config"
}

// Collapse paths into fixed Prometheus labels
func metricRoute(path string) string {
	switch path {
	case "/admin", "/api/v1/auth", "/.git/config", "/dashboard", "/api/dashboard-data", "/metrics", "/health":
		return path
	case "/static/admin.css", "/static/admin-login.js", "/static/style.css", "/static/app.js":
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

// Unwrap exposes the wrapped writer to http.ResponseController
func (w *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
