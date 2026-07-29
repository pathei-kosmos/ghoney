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
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultPublicAddr   = ":8080"
	defaultAdminAddr    = "127.0.0.1:9090"
	maxRequestBodySize  = 4 * 1024
	maxBodySnippetSize  = 256
	maxEventFieldSize   = 1024
	maxHeaderBytes      = 16 * 1024
	requestTimeout      = 5 * time.Second
	shutdownTimeout     = 5 * time.Second
	logBufferSize       = 100
	maxConcurrentPublic = 128
	envPublicAddr       = "GHONEY_ADDR"
	envAdminAddr        = "GHONEY_ADMIN_ADDR"
	unknownMetricRoute  = "not_found"
	unknownMetricMethod = "OTHER"
	asciiArtBanner      = `
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
			Help: "Total detected honeypot attacks grouped by bounded type and route.",
		},
		[]string{"attack_type", "route"},
	)

	// Compile signatures once outside the request path
	sqlRegex       = regexp.MustCompile(`(?i)('|\")(?:--|#|\s*(?:OR|AND)\s+(?:\d+|'[^']*'|\"[^\"]*\")\s*=\s*(?:\d+|'[^']*'|\"[^\"]*\"))`)
	sqliExtraRegex = regexp.MustCompile(`(?i)\bunion\s+select\b|\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b`)
	xmlBombRegex   = regexp.MustCompile(`(?i)<!ENTITY\s+\S+\s+SYSTEM`)
	cmdiRegex      = regexp.MustCompile("(?i)(?:;|\\|\\||&&|\\$\\(|`)[^\\n]{0,100}(?:whoami|id|uname|cat|curl|wget|ping)")
	ssrfParamRegex = regexp.MustCompile(`(?i)(?:\burl\b|\buri\b|\bredirect\b|\bnext\b|\btarget\b|\bdest\b|\bdestination\b)\s*=\s*https?://`)
	ssrfHostRegex  = regexp.MustCompile(`(?i)\b169\.254\.169\.254\b|\blocalhost\b|\b127\.0\.0\.1\b|\b0\.0\.0\.0\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b`)
	lfiRegex       = regexp.MustCompile(`(?i)/etc/passwd|/proc/self/environ|\bphp://|\bfile://|\bdata:`)
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

		attackType, details := detectAttack(r.URL.Path, r.URL.RawQuery, string(body))
		if attackType != "" {
			route := metricRoute(r.URL.Path)
			honeypotAttacksTotal.WithLabelValues(attackType, route).Inc()
			logEvent("warn", clientIP, r.UserAgent(), r.URL.Path, attackType, details, r.URL.RawQuery, string(body))
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

// Return the first matching class after normalization
func detectAttack(path, rawQuery, body string) (string, string) {
	normalized := normalizeForDetection(path + " " + rawQuery + " " + body)
	switch {
	case strings.Contains(normalized, "../") || strings.Contains(normalized, `..\`):
		return "Path Traversal", "Detected traversal sequence in path, query, or body"
	case sqlRegex.MatchString(normalized) || sqliExtraRegex.MatchString(normalized):
		return "SQL Injection", "Detected SQL injection pattern"
	case body != "" && xmlBombRegex.MatchString(normalized):
		return "XML Bomb", "Detected external XML entity pattern"
	case cmdiRegex.MatchString(normalized):
		return "Command Injection", "Detected command injection pattern"
	case ssrfHostRegex.MatchString(normalized) && ssrfParamRegex.MatchString(normalized):
		return "SSRF", "Detected internal target in URL parameter"
	case lfiRegex.MatchString(normalized):
		return "LFI/RFI", "Detected local or remote file inclusion pattern"
	default:
		return "", ""
	}
}

// Decode common scanner obfuscation before matching
func normalizeForDetection(value string) string {
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "+", " ")
	for range 2 {
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			break
		}
		value = decoded
	}
	value = html.UnescapeString(value)
	value = strings.ToLower(value)
	return strings.Join(strings.Fields(value), " ")
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
