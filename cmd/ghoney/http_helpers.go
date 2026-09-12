package main

import (
	"net"
	"net/http"
)

// loggingResponseWriter tracks the first response status
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
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
