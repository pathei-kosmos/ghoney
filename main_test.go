package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// Reset shared events between handler tests
func resetRecentLogs(t *testing.T) {
	t.Helper()
	logMutex.Lock()
	recentLogs = nil
	logMutex.Unlock()
}

// TestDetectAttack covers the six documented signatures and benign traffic
func TestDetectAttack(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		query      string
		body       string
		attackType string
	}{
		{name: "SQL injection", path: "/api/v1/auth", body: "u=' OR 1=1 --", attackType: "SQL Injection"},
		{name: "double-encoded traversal", path: "/", query: "p=..%252F..%252Fetc%252Fpasswd", attackType: "Path Traversal"},
		{name: "XML external entity", path: "/", body: `<!ENTITY x SYSTEM "file:///etc/passwd">`, attackType: "XML Bomb"},
		{name: "command injection", path: "/", query: "cmd=whoami%20%26%26%20id", attackType: "Command Injection"},
		{name: "SSRF", path: "/", query: "url=http://169.254.169.254/latest/meta-data/", attackType: "SSRF"},
		{name: "file inclusion", path: "/", query: "file=php://filter/resource=/etc/passwd", attackType: "LFI/RFI"},
		{name: "benign request", path: "/products", query: "next=release-notes", body: "color=blue", attackType: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attackType, _ := detectAttack(test.path, test.query, test.body)
			if attackType != test.attackType {
				t.Fatalf("detectAttack() type = %q, want %q", attackType, test.attackType)
			}
		})
	}
}

// TestRequestInspectionScansTheFullAllowedBody checks beyond the stored snippet
func TestRequestInspectionScansTheFullAllowedBody(t *testing.T) {
	resetRecentLogs(t)
	body := strings.Repeat("a", maxBodySnippetSize+50) + ";whoami"
	request := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:1234"
	recorder := httptest.NewRecorder()
	nextCalled := false
	handler := requestInspectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(recorder, request)

	if !nextCalled || recorder.Code != http.StatusNoContent {
		t.Fatalf("request was not forwarded successfully: called=%v status=%d", nextCalled, recorder.Code)
	}
	logMutex.Lock()
	defer logMutex.Unlock()
	if len(recentLogs) != 1 || recentLogs[0].AttackType != "Command Injection" {
		t.Fatalf("full body was not classified: logs=%+v", recentLogs)
	}
	if len(recentLogs[0].BodySnippet) > maxBodySnippetSize {
		t.Fatalf("stored body snippet exceeds %d bytes", maxBodySnippetSize)
	}
}

// TestRequestInspectionRejectsOversizedBodies covers fixed and streamed bodies
func TestRequestInspectionRejectsOversizedBodies(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		name := "fixed length"
		if streamed {
			name = "streamed"
		}
		t.Run(name, func(t *testing.T) {
			resetRecentLogs(t)
			request := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(strings.Repeat("x", maxRequestBodySize+1)))
			if streamed {
				request.ContentLength = -1
			}
			recorder := httptest.NewRecorder()
			nextCalled := false
			handler := requestInspectionMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}))

			handler.ServeHTTP(recorder, request)

			if nextCalled {
				t.Fatal("oversized request reached the next handler")
			}
			if recorder.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
			}
		})
	}
}

// TestMetricLabelsStayBounded keeps attacker input out of Prometheus labels
func TestMetricLabelsStayBounded(t *testing.T) {
	for index := 0; index < 1000; index++ {
		path := "/scanner/" + strings.Repeat("x", index%50) + string(rune('a'+index%26))
		if route := metricRoute(path); route != unknownMetricRoute {
			t.Fatalf("metricRoute(%q) = %q, want %q", path, route, unknownMetricRoute)
		}
	}
	if method := metricMethod("CUSTOM-" + strings.Repeat("X", 100)); method != unknownMetricMethod {
		t.Fatalf("metricMethod() = %q, want %q", method, unknownMetricMethod)
	}
	if route := metricRoute("/static/app.js"); route != "/static/*" {
		t.Fatalf("static route = %q, want /static/*", route)
	}
}

// TestAdministrativeSurfaceIsSeparate checks the two route sets
func TestAdministrativeSurfaceIsSeparate(t *testing.T) {
	resetRecentLogs(t)
	adminRequest := httptest.NewRequest(http.MethodGet, "http://example.test/admin", nil)
	adminResponse := httptest.NewRecorder()
	publicHandler().ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("public decoy status = %d, want %d", adminResponse.Code, http.StatusOK)
	}

	dashboardRequest := httptest.NewRequest(http.MethodGet, "http://example.test/dashboard", nil)
	dashboardResponse := httptest.NewRecorder()
	adminHandler().ServeHTTP(dashboardResponse, dashboardRequest)
	if dashboardResponse.Code != http.StatusOK {
		t.Fatalf("admin dashboard status = %d, want %d", dashboardResponse.Code, http.StatusOK)
	}

	decoyOnAdminRequest := httptest.NewRequest(http.MethodGet, "http://example.test/admin", nil)
	decoyOnAdminResponse := httptest.NewRecorder()
	adminHandler().ServeHTTP(decoyOnAdminResponse, decoyOnAdminRequest)
	if decoyOnAdminResponse.Code != http.StatusNotFound {
		t.Fatalf("decoy on admin status = %d, want %d", decoyOnAdminResponse.Code, http.StatusNotFound)
	}
}

// TestSecurityHeadersRejectInlineScripts keeps inline execution out of the CSP
func TestSecurityHeadersRejectInlineScripts(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/health", nil)
	response := httptest.NewRecorder()
	adminHandler().ServeHTTP(response, request)

	policy := response.Header().Get("Content-Security-Policy")
	if strings.Contains(policy, "unsafe-inline") {
		t.Fatalf("CSP unexpectedly permits inline content: %q", policy)
	}
	if !strings.Contains(policy, "object-src 'none'") || !strings.Contains(policy, "frame-ancestors 'none'") {
		t.Fatalf("CSP is missing required isolation directives: %q", policy)
	}
}

// TestTruncateUTF8 preserves valid UTF-8 within the byte cap
func TestTruncateUTF8(t *testing.T) {
	value := strings.Repeat("é", 20)
	truncated := truncateUTF8(value, 11)
	if len(truncated) > 11 {
		t.Fatalf("truncated value is %d bytes, want at most 11", len(truncated))
	}
	if !utf8.ValidString(truncated) {
		t.Fatal("truncated value is not valid UTF-8")
	}

	// Replacement runes expand invalid input and still count toward the cap
	repaired := truncateUTF8(string([]byte{0xff, 'a', 0xfe, 'b'}), 4)
	if len(repaired) > 4 {
		t.Fatalf("repaired value is %d bytes, want at most 4", len(repaired))
	}
	if !utf8.ValidString(repaired) {
		t.Fatal("repaired value is not valid UTF-8")
	}
}

// TestFakeJWTUsesFreshValidClaims checks decoy token shape and lifetime
func TestFakeJWTUsesFreshValidClaims(t *testing.T) {
	token, err := newFakeJWT()
	if err != nil {
		t.Fatalf("newFakeJWT() error = %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims struct {
		Issued  int64 `json:"iat"`
		Expires int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	if claims.Expires <= claims.Issued {
		t.Fatalf("JWT expiration %d is not after issued-at %d", claims.Expires, claims.Issued)
	}
	if lifetime := claims.Expires - claims.Issued; lifetime < 899 || lifetime > 901 {
		t.Fatalf("JWT lifetime = %d seconds, want approximately 15 minutes", lifetime)
	}
}
