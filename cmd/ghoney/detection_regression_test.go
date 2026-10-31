package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Keep binary uploads separate from the text fields and original filename
func multipartDetectionFixture(t *testing.T, filename, value string) detectionInput {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("upload", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0xff, 0x00, 0xfe}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("q", value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return detectionInput{Body: body.String(), Header: http.Header{"Content-Type": {writer.FormDataContentType()}}}
}

// Cover extraction and decoding across request fields
func TestDetectionCoversFieldVariants(t *testing.T) {
	encodedSQL := base64.StdEncoding.EncodeToString([]byte("1 union select"))
	activeDocument := "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte("<script>alert(1)</script>"))
	plusToken := base64.StdEncoding.EncodeToString([]byte(";;><script>alert(1)</script>"))
	if !strings.Contains(plusToken, "+") {
		t.Fatal("fixture does not exercise literal plus")
	}
	repeatedHeaders := make([]string, 65)
	for index := range repeatedHeaders {
		repeatedHeaders[index] = fmt.Sprintf("benign-%d", index)
	}
	repeatedHeaders[64] = `${jndi:ldap://127.0.0.1/a}`
	denseHeaders := make([]string, 3501)
	for index := range denseHeaders {
		denseHeaders[index] = "a"
	}
	denseHeaders[3500] = "1 union select"
	tests := []struct {
		name       string
		input      detectionInput
		attackType string
		confidence confidence
	}{
		{"binary text run", detectionInput{Body: "1 OR 1=1" + strings.Repeat("\x00", 40)}, "SQL Injection", confidenceMedium},
		{"binary upload with SQL field", multipartDetectionFixture(t, "a.bin", "1 union select"), "SQL Injection", confidenceHigh},
		{"original upload filename", multipartDetectionFixture(t, "../../etc/passwd", "safe"), "Path Traversal", confidenceHigh},
		{"long header middle", detectionInput{Header: http.Header{"User-Agent": {strings.Repeat("a", 1500) + " 1 union select " + strings.Repeat("b", 1500)}}}, "SQL Injection", confidenceHigh},
		{"repeated header tail", detectionInput{Header: http.Header{"User-Agent": repeatedHeaders}}, "JNDI Injection", confidenceHigh},
		{"dense repeated header tail", detectionInput{Header: http.Header{"X": denseHeaders}}, "SQL Injection", confidenceHigh},
		{"custom header", detectionInput{Header: http.Header{"X-Api-Key": {"/etc/passwd"}}}, "LFI/RFI", confidenceHigh},
		{"spaced short command", detectionInput{RawQuery: "q=ok; id"}, "Command Injection", confidenceMedium},
		{"spaced listing command", detectionInput{RawQuery: "q=ok; ls /tmp"}, "Command Injection", confidenceMedium},
		{"additional command", detectionInput{RawQuery: "q=ok; systemctl"}, "Command Injection", confidenceHigh},
		{"empty shell expansion", detectionInput{RawQuery: "q=ok;i$@d"}, "Command Injection", confidenceMedium},
		{"shell default", detectionInput{RawQuery: "q=ok;i${x:-}d"}, "Command Injection", confidenceMedium},
		{"SQL column probe", detectionInput{RawQuery: "id=1 ORDER BY 1,2--"}, "SQL Injection", confidenceMedium},
		{"SQL conditional sleep", detectionInput{RawQuery: "id=1 AND SLEEP(5)"}, "SQL Injection", confidenceMedium},
		{"SQL scalar subquery", detectionInput{RawQuery: "id=1 AND (SELECT COUNT(*) FROM users)>0"}, "SQL Injection", confidenceMedium},
		{"SQL decimal operands", detectionInput{RawQuery: "id=1 OR 1.0=1.0"}, "SQL Injection", confidenceMedium},
		{"SQL exponent operand", detectionInput{RawQuery: "id=1 OR 1e0"}, "SQL Injection", confidenceMedium},
		{"spaced short URL parameter", detectionInput{RawQuery: "u = 2130706433"}, "SSRF", confidenceMedium},
		{"special network target", detectionInput{RawQuery: "url=http://192.0.0.192/latest/meta-data/"}, "SSRF", confidenceMedium},
		{"zero network target", detectionInput{RawQuery: "url=http://0.1.2.3/"}, "SSRF", confidenceHigh},
		{"decoded JSON file", detectionInput{Body: `{"x":"\u002fetc\u002fpasswd"}`, Header: http.Header{"Content-Type": {"application/json"}}}, "LFI/RFI", confidenceHigh},
		{"Unicode file", detectionInput{Body: string(encodeUTF16Fixture("/etc/passwd", binary.LittleEndian, true))}, "LFI/RFI", confidenceHigh},
		{"cookie file", detectionInput{Header: http.Header{"Cookie": {"session=/etc/passwd"}}}, "LFI/RFI", confidenceHigh},
		{"environment file", detectionInput{RawQuery: "x=.env"}, "LFI/RFI", confidenceHigh},
		{"Windows boot file", detectionInput{RawQuery: "file=C:/boot.ini"}, "LFI/RFI", confidenceHigh},
		{"JSON parameter NoSQL", detectionInput{RawQuery: `filter={"$where":"this.x"}`}, "NoSQL Injection", confidenceHigh},
		{"encoded cookie NoSQL", detectionInput{Header: http.Header{"Cookie": {"filter=" + base64.StdEncoding.EncodeToString([]byte(`{"$where":"this.x"}`))}}}, "NoSQL Injection", confidenceHigh},
		{"Unicode NoSQL", detectionInput{Body: string(encodeUTF16Fixture(`{"$where":"this.x"}`, binary.LittleEndian, true))}, "NoSQL Injection", confidenceHigh},
		{"multipart JSON NoSQL", multipartDetectionFixture(t, "a.bin", `{"$where":"this.x"}`), "NoSQL Injection", confidenceHigh},
		{"update NoSQL", detectionInput{Body: `{"$set":{"role":"admin"}}`}, "NoSQL Injection", confidenceMedium},
		{"short Base64", detectionInput{RawQuery: "q=O2lk"}, "Command Injection", confidenceMedium},
		{"deep Base64", detectionInput{RawQuery: "q=" + repeatedlyEncodeBase64("1 union select", 15)}, "SQL Injection", confidenceHigh},
		{"mixed Base64 escapes", detectionInput{Body: base64.StdEncoding.EncodeToString([]byte(repeatedlyEscapeQuery(encodedSQL, 2)))}, "SQL Injection", confidenceHigh},
		{"HTML query Base64", detectionInput{RawQuery: "q=" + fmt.Sprintf("&#%d;", encodedSQL[0]) + encodedSQL[1:]}, "SQL Injection", confidenceHigh},
		{"absolute executable path", detectionInput{RawQuery: "q=x; /tmp/pwn"}, "Command Injection", confidenceMedium},
		{"shell environment command", detectionInput{RawQuery: "q=x;${SHELL} -c id"}, "Command Injection", confidenceHigh},
		{"HTML wrapped Base64", detectionInput{Header: http.Header{"User-Agent": {fmt.Sprintf("&#%d;", encodedSQL[0]) + encodedSQL[1:]}}}, "SQL Injection", confidenceHigh},
		{"literal Base64 plus", detectionInput{RawQuery: "q=" + plusToken}, "XSS", confidenceHigh},
		{"encoded active document", detectionInput{Body: base64.StdEncoding.EncodeToString([]byte(activeDocument))}, "XSS", confidenceHigh},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			found := detectAttacks(test.input)
			for _, item := range found {
				if item.AttackType == test.attackType {
					if item.Confidence != test.confidence || item.Source == "" || item.Sample == "" {
						t.Fatalf("detection = %+v", item)
					}
					return
				}
			}
			t.Fatalf("missing %s in %+v", test.attackType, found)
		})
	}
}

// Keep matched payloads beyond the logged prefix
func TestRequestInspectionRetainsMatchedEvidence(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		attackType string
		token      string
		header     http.Header
	}{
		{name: "late query", path: "/?pad=" + strings.Repeat("a", 1500) + "&q=1%20union%20select", attackType: "SQL Injection", token: "union select"},
		{name: "late body", path: "/", body: strings.Repeat("a", 300) + ";whoami", attackType: "Command Injection", token: "whoami"},
		{name: "header", path: "/", header: http.Header{"X-Forwarded-For": {"admin' OR 1=1--"}}, attackType: "SQL Injection", token: "or 1=1"},
		{name: "late NoSQL key", path: "/", body: `{"comment":"$ne` + strings.Repeat("a", 1400) + `","filter":{"$where":"this.x"}}`, attackType: "NoSQL Injection", token: "$where"},
		{name: "late handler", path: "/", body: "<div " + strings.Repeat("a", 1200) + " onpointerdown=alert(1)>", attackType: "XSS", token: "onpointerdown="},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetRecentLogs(t)
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header = test.header
			publicHandler().ServeHTTP(httptest.NewRecorder(), request)
			logMutex.Lock()
			defer logMutex.Unlock()
			for _, entry := range recentLogs {
				if entry.AttackType == test.attackType {
					if entry.Method != http.MethodPost || !strings.Contains(entry.Sample, test.token) || len(entry.Sample) > maxBodySnippetSize {
						t.Fatalf("evidence = %+v", entry)
					}
					return
				}
			}
			t.Fatal("missing retained detection")
		})
	}
	resetRecentLogs(t)
	publicHandler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/unknown", strings.NewReader("ordinary body")))
	if len(recentLogs) != 1 || recentLogs[0].BodySnippet != "ordinary body" {
		t.Fatalf("unknown route logs = %+v", recentLogs)
	}
}

// Log rejected requests without reading their bodies
func TestPublicOverloadIsLoggedWithoutInspection(t *testing.T) {
	resetRecentLogs(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	handler := concurrencyLimitMiddleware(1, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}), http.HandlerFunc(handlePublicOverload))
	go func() {
		defer close(finished)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/hold", nil))
	}()
	defer func() {
		close(release)
		<-finished
	}()
	<-entered
	request := httptest.NewRequest(http.MethodPost, "/probe?q=1+OR+1=1", nil)
	request.Body = unreadableRequestBody{t: t}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Connection") != "close" {
		t.Fatalf("overload response = %+v", response.Result())
	}
	if len(recentLogs) != 1 || recentLogs[0].AttackType != "Overload" || recentLogs[0].Method != http.MethodPost || recentLogs[0].Path != "/probe" {
		t.Fatalf("overload logs = %+v", recentLogs)
	}
}

// unreadableRequestBody catches unexpected body reads
type unreadableRequestBody struct{ t *testing.T }

// Read must never be called on a rejected request
func (body unreadableRequestBody) Read([]byte) (int, error) {
	body.t.Error("rejected request body was read")
	return 0, io.ErrUnexpectedEOF
}

// Close has no resources to release in this fixture
func (unreadableRequestBody) Close() error { return nil }

// Interrupt an incomplete body read when the request expires
func TestInspectionDeadlineInterruptsBodyRead(t *testing.T) {
	resetRecentLogs(t)
	called := make(chan struct{}, 1)
	handler := timeoutMiddleware(requestInspectionMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called <- struct{}{} })))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		defer cancel()
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(server.Close)
	connection, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 3\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status = %d", response.StatusCode)
	}
	select {
	case <-called:
		t.Fatal("expired request reached the route")
	default:
	}
}

// Stop detection when the request is cancelled
func TestDetectionHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if found := detectAttacksContext(ctx, detectionInput{RawQuery: "q=" + url.QueryEscape(strings.Repeat("1 union select ", 1000))}); len(found) != 0 {
		t.Fatalf("cancelled detection = %+v", found)
	}
}

// Reject unsupported encodings before reading the body
func TestRequestInspectionRejectsUnsupportedEncodings(t *testing.T) {
	for _, encodings := range [][]string{{"br"}, {"gzip", "zstd"}, {"gzip,"}, {strings.Repeat("identity,", maxNestedGzipLayers) + "identity"}} {
		t.Run(strings.Join(encodings, "/"), func(t *testing.T) {
			resetRecentLogs(t)
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.Header["Content-Encoding"] = encodings
			request.Body = unreadableRequestBody{t: t}
			response := httptest.NewRecorder()
			requestInspectionMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unsupported coding reached the route") })).ServeHTTP(response, request)
			if response.Code != http.StatusUnsupportedMediaType || len(recentLogs) != 1 || recentLogs[0].AttackType != "UnsupportedEncoding" || recentLogs[0].Confidence != confidenceMedium {
				t.Fatalf("status=%d logs=%+v", response.Code, recentLogs)
			}
		})
	}
}
