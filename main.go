package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	serverPort         = "8080"
	maxRequestBodySize = 4 * 1024 // 4KB
	requestTimeout     = 5 * time.Second
	logBufferSize      = 100
	cookieName         = "X-Ghoney-Trap"
	asciiArtBanner     = `
       _                            
  __ _| |__   ___  _ __   ___ _   _ 
 / _` + "`" + ` | '_ \ / _ \| '_ \ / _ \ | | |
| (_| | | | | (_) | | | |  __/ |_| |
 \__, |_| |_|\___/|_| |_|\___|\__, |
 |___/                        |___/ 
 
`
)

// LogEntry stores information about a request for the dashboard
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

var (
	recentLogs []LogEntry
	logMutex   sync.Mutex
	seededRand *PRNG // For crypto-seeded random numbers

	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghoney_http_requests_total",
			Help: "Total HTTP requests.",
		},
		[]string{"path", "method", "status"},
	)
	honeypotAttacksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghoney_honeypot_attacks_total",
			Help: "Total detected honeypot attacks.",
		},
		[]string{"attack_type", "path"},
	)

	// Precompiled regex for attack detection
	sqlRegex     = regexp.MustCompile(`(?i)('|\")(?:--|#|\s*(?:OR|AND)\s+(?:\d+|'[^']*'|\"[^\"]*\")\s*=\s*(?:\d+|'[^']*'|\"[^\"]*\"))`)
	xmlBombRegex = regexp.MustCompile(`(?i)<!ENTITY\s+\S+\s+SYSTEM`)
)

// PRNG uses crypto/rand for better non-determinism in delays
type PRNG struct{}

func (r *PRNG) Intn(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		log.Printf("level=error ts=%s msg=\"crypto/rand error for delay, fallback\" error=\"%v\"\n", time.Now().UTC().Format(time.RFC3339), err)
		return int(time.Now().UnixNano() % int64(max))
	}
	return int(n.Int64())
}

func init() {
	seededRand = &PRNG{}
	log.SetFlags(0) // Disable standard log prefixes for logfmt
}

// logEvent records an event in logfmt to stdout and stores critical ones for the dashboard
func logEvent(level, ip, userAgent, path, attackType, details, rawQuery, bodySnippet string) {
	sanitize := func(s string) string {
		s = strings.ReplaceAll(s, "\"", "'")
		s = strings.ReplaceAll(s, "\n", " ")
		s = strings.ReplaceAll(s, "\r", " ")
		return s
	}

	// Log to stdout in logfmt
	fmt.Printf("level=%s ts=%s ip=\"%s\" ua=\"%s\" path=\"%s\" attack_type=\"%s\" details=\"%s\" query=\"%s\" body_snippet=\"%s\"\n",
		level,
		time.Now().UTC().Format(time.RFC3339),
		sanitize(ip),
		sanitize(userAgent),
		sanitize(path),
		sanitize(attackType),
		sanitize(details),
		sanitize(rawQuery),
		sanitize(bodySnippet),
	)

	// Store for dashboard if it's a warning (attack) or specific info (honeypot access)
	isHoneypotAccess := path == "/admin" || path == "/api/v1/auth" || path == "/.git/config"
	if level == "warn" || (level == "info" && isHoneypotAccess) {
		logMutex.Lock()
		defer logMutex.Unlock()

		entry := LogEntry{
			Timestamp:   time.Now().UTC(),
			IP:          ip,
			UserAgent:   userAgent,
			Path:        path,
			AttackType:  attackType,
			Details:     details,
			RawQuery:    rawQuery,
			BodySnippet: bodySnippet, // Already escaped if it came from middleware
		}
		recentLogs = append(recentLogs, entry)
		if len(recentLogs) > logBufferSize {
			recentLogs = recentLogs[len(recentLogs)-logBufferSize:]
		}
	}
}

// Middleware: Adds security headers
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")
		next.ServeHTTP(w, r)
	})
}

// Middleware: Enforces request timeout
func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Middleware: Logs requests, sets trap cookie, detects basic attacks
func requestLogAndTrapMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		userAgent := r.UserAgent()
		path := r.URL.Path
		rawQuery := r.URL.RawQuery // Keep raw query for logging

		// Decode query for detection purposes
		var decodedQuery string
		if rawQuery != "" {
			dq, err := url.QueryUnescape(rawQuery)
			if err == nil {
				decodedQuery = dq
			} else {
				fmt.Printf("level=error ts=%s ip=\"%s\" msg=\"QueryUnescapeError\" path=\"%s\" query=\"%s\" error=\"%v\"\n",
					time.Now().UTC().Format(time.RFC3339), clientIP, path, rawQuery, err)
				decodedQuery = rawQuery // Fallback to raw if unescape fails
			}
		}

		if _, err := r.Cookie(cookieName); err != nil {
			http.SetCookie(w, &http.Cookie{
				Name: cookieName, Value: "1", Path: "/", HttpOnly: true,
				Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
			})
		}

		var bodyBytes []byte
		var bodySnippet string
		if r.Body != nil && r.ContentLength > 0 {
			if r.ContentLength > maxRequestBodySize {
				logEvent("warn", clientIP, userAgent, path, "LargeBody",
					fmt.Sprintf("Body size %d > %d", r.ContentLength, maxRequestBodySize), rawQuery, "")
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				httpRequestsTotal.WithLabelValues(path, r.Method, fmt.Sprintf("%d", http.StatusRequestEntityTooLarge)).Inc()
				return
			}
			var err error
			bodyBytes, err = io.ReadAll(r.Body) // Read the body
			if err != nil {
				// Log error, but continue
				fmt.Printf("level=error ts=%s ip=\"%s\" msg=\"BodyReadError\" path=\"%s\" error=\"%v\"\n",
					time.Now().UTC().Format(time.RFC3339), clientIP, path, err)
			} else {
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body for next handler
				// Create bodySnippet from bodyBytes, not the potentially modified body string
				if len(bodyBytes) > 256 {
					bodySnippet = string(bodyBytes[:256])
				} else {
					bodySnippet = string(bodyBytes)
				}
			}
		}

		attackType := "None"
		details := ""

		// Path Traversal (checks path and decoded query)
		if strings.Contains(path, "../") || (decodedQuery != "" && strings.Contains(decodedQuery, "../")) {
			attackType = "Path Traversal"
			details = "Detected '../' in path or query"
		}

		// SQL Injection (checks decoded query and body snippet)
		// Ensure attackType is not overwritten if Path Traversal was already found
		if attackType == "None" && ((decodedQuery != "" && sqlRegex.MatchString(decodedQuery)) || (bodySnippet != "" && sqlRegex.MatchString(bodySnippet))) {
			attackType = "SQL Injection"
			details = "Detected SQLi pattern in query or body"
		}

		// XML Bomb (checks body snippet)
		// Ensure attackType is not overwritten
		if attackType == "None" && bodySnippet != "" && xmlBombRegex.MatchString(bodySnippet) {
			attackType = "XML Bomb"
			details = "Detected XML bomb pattern in body"
		}

		// Logging based on detection or honeypot access
		isHoneypotPath := path == "/admin" || path == "/api/v1/auth" || path == "/.git/config"
		if attackType != "None" {
			honeypotAttacksTotal.WithLabelValues(attackType, path).Inc()
			// Body snippet for logging should be HTML escaped to prevent XSS in log viewers / dashboard
			logEvent("warn", clientIP, userAgent, path, attackType, details, rawQuery, html.EscapeString(bodySnippet))
		} else if isHoneypotPath {
			// Log access to honeypot paths if no specific attack was detected on them
			logEvent("info", clientIP, userAgent, path, "HoneypotAccess", "Accessed honeypot endpoint", rawQuery, html.EscapeString(bodySnippet))
		}
		// Note: Generic "NotFound" logs are handled by the handleNotFound catch-all for paths not triggering above

		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r) // Serve the request

		httpRequestsTotal.WithLabelValues(path, r.Method, fmt.Sprintf("%d", lrw.statusCode)).Inc()
		_ = startTime // Suppress unused variable if not logging duration
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func applyRandomDelay() {
	delay := time.Duration(seededRand.Intn(2000)+1000) * time.Millisecond // 1-3 seconds
	time.Sleep(delay)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		applyRandomDelay()
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "static/admin_login.html")
}

func handleAPIV1Auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		applyRandomDelay()
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	fakeJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjQyNjIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token": "%s", "status": "success"}`, fakeJWT)
}

func handleGitConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		applyRandomDelay()
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	fakeConfig := `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
[remote "origin"]
	url = git@internal-git.example.com:corp/secret-project.git
	# url = https://user:P@$$wOrd@internal-git.example.com/trap.git
	fetch = +refs/heads/*:refs/remotes/origin/*
# FAKE_API_KEY_FOR_SCANNER = glpat-abcdef1234567890abcd (DO NOT USE)
`
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // Corrected charset
	io.WriteString(w, fakeConfig)
}

func handleDashboardData(w http.ResponseWriter, r *http.Request) {
	logMutex.Lock()
	// Create a copy and reverse for newest-first display
	logsCopy := make([]LogEntry, len(recentLogs))
	for i, j := 0, len(recentLogs)-1; i < len(recentLogs); i, j = i+1, j-1 {
		logsCopy[i] = recentLogs[j]
	}
	logMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(logsCopy); err != nil {
		fmt.Printf("level=error ts=%s msg=\"DashboardError - Failed to marshal logs\" error=\"%v\"\n",
			time.Now().UTC().Format(time.RFC3339), err)
		http.Error(w, "Failed to generate dashboard data", http.StatusInternalServerError)
	}
}

// handleNotFound is the catch-all for undefined paths that haven't triggered specific attack logic in middleware
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	userAgent := r.UserAgent()
	rawQuery := r.URL.RawQuery

	logEvent("info", clientIP, userAgent, r.URL.Path, "NotFound", "Access to undefined path", rawQuery, "")
	applyRandomDelay()
	http.NotFound(w, r)
}

func main() {
	fmt.Print(asciiArtBanner)
	fmt.Printf("ghoney starting on port %s...\n", serverPort)
	fmt.Printf("Honeypot endpoints: /admin, /api/v1/auth, /.git/config on http://localhost:%s (host mapping)\n", serverPort)
	fmt.Printf("Dashboard: http://localhost:%s/dashboard\n", serverPort)
	fmt.Printf("Metrics: http://localhost:%s/metrics\n", serverPort)
	fmt.Printf("Health: http://localhost:%s/health\n", serverPort)

	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/index.html")
	})

	mux.HandleFunc("/api/dashboard-data", handleDashboardData)
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/api/v1/auth", handleAPIV1Auth)
	mux.HandleFunc("/.git/config", handleGitConfig)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/", handleNotFound)

	chainedHandler := timeoutMiddleware(securityHeadersMiddleware(requestLogAndTrapMiddleware(mux)))

	server := &http.Server{
		Addr:              ":" + serverPort,
		Handler:           chainedHandler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       requestTimeout + (1 * time.Second),
		WriteTimeout:      requestTimeout + (1 * time.Second),
		IdleTimeout:       60 * time.Second,
	}

	fmt.Printf("level=info ts=%s msg=\"ghoney server listening\" port=%s\n", time.Now().UTC().Format(time.RFC3339), serverPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("level=fatal ts=%s msg=\"could not listen on port\" port=%s error=\"%v\"\n", time.Now().UTC().Format(time.RFC3339), serverPort, err)
	}
}
