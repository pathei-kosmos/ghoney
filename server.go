package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Keep build metadata safe for use in an HTTP header
func dashboardVersion() string {
	value := strings.TrimSpace(buildVersion)
	if value == "" || len(value) > 64 || strings.ContainsAny(value, "\r\n") {
		return "dev"
	}
	return value
}

// Generate a fresh fake token for each response
func randomToken(prefix string, byteCount int) (string, error) {
	payload := make([]byte, byteCount)
	if _, err := rand.Read(payload); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// Serve the public sign in page
func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, r, http.MethodGet)
		return
	}
	http.ServeFileFS(w, r, staticAssets, "static/admin_login.html")
}

// Reject every sign in attempt without issuing credentials
func handleAPIV1Auth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "error"}); err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "fake auth response failed", err.Error())
	}
}

// Serve a fake Git config under a reserved example domain
func handleGitConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, r, http.MethodGet)
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

// Return a snapshot with newest events first
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
	w.Header().Set("X-Ghoney-Version", dashboardVersion())
	if err := json.NewEncoder(w).Encode(logsCopy); err != nil {
		log.Printf("level=error ts=%s msg=%q error=%q", time.Now().UTC().Format(time.RFC3339), "dashboard encoding failed", err.Error())
	}
}

// Log unknown public traffic before returning 404
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	logEvent("info", remoteIP(r.RemoteAddr), r.UserAgent(), r.URL.Path, "NotFound", "Accessed undefined path", r.URL.RawQuery, "", "")
	http.NotFound(w, r)
}

// Reject unsupported methods without adding delay
func methodNotAllowed(w http.ResponseWriter, _ *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

// Serve one embedded asset with read only methods and no stale cache
func embeddedFileHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFileFS(w, r, staticAssets, path)
	}
}

// Assemble the public routes and their limits
func publicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/api/v1/auth", handleAPIV1Auth)
	mux.HandleFunc("/.git/config", handleGitConfig)
	mux.HandleFunc("/static/admin.css", embeddedFileHandler("static/admin.css"))
	mux.HandleFunc("/static/admin-login.js", embeddedFileHandler("static/admin-login.js"))
	mux.HandleFunc("/", handleNotFound)

	handler := requestInspectionMiddleware(mux)
	handler = concurrencyLimitMiddleware(maxConcurrentPublic, handler)
	handler = metricsMiddleware(handler)
	handler = timeoutMiddleware(handler)
	return securityHeadersMiddleware(handler)
}

// Assemble admin routes with public health checks
func adminHandler(credentials adminCredentials) http.Handler {
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

	var handler http.Handler = mux
	handler = adminAuthMiddleware(credentials, handler)
	handler = metricsMiddleware(handler)
	handler = concurrencyLimitMiddleware(maxConcurrentAdmin, handler)
	handler = timeoutMiddleware(handler)
	return securityHeadersMiddleware(handler)
}

// Protect admin resources while leaving health public
func adminAuthMiddleware(credentials adminCredentials, next http.Handler) http.Handler {
	if !credentials.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		username, password, provided := r.BasicAuth()
		usernameHash := sha256.Sum256([]byte(username))
		passwordHash := sha256.Sum256([]byte(password))
		usernameOK := subtle.ConstantTimeCompare(usernameHash[:], credentials.usernameHash[:])
		passwordOK := subtle.ConstantTimeCompare(passwordHash[:], credentials.passwordHash[:])
		if !provided || usernameOK&passwordOK != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="ghoney admin", charset="UTF-8"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
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
