package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// Check field detections and HTTP status when the body is rejected
func TestRejectedBodyRetainsFieldDetections(t *testing.T) {
	tests := []struct {
		name, target, body, encoding, header, attackType, rejection string
		status                                                      int
	}{
		{"unsupported query", "/?q=1+union+select", "ignored", "br", "", "SQL Injection", "UnsupportedEncoding", http.StatusUnsupportedMediaType},
		{"malformed header", "/", "invalid gzip", "gzip", "1 union select", "SQL Injection", "MalformedBody", http.StatusBadRequest},
		{"oversized path", "/../../etc/passwd", strings.Repeat("x", maxRequestBodySize+1), "", "", "Path Traversal", "LargeBody", http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetRecentLogs(t)
			request := httptest.NewRequest(http.MethodPost, test.target, strings.NewReader(test.body))
			if test.encoding != "" {
				request.Header.Set("Content-Encoding", test.encoding)
			}
			if test.header != "" {
				request.Header.Set("X-Probe", test.header)
			}
			response := httptest.NewRecorder()
			requestInspectionMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("rejected body reached the next handler")
			})).ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			logMutex.Lock()
			defer logMutex.Unlock()
			counts := make(map[string]int)
			for _, entry := range recentLogs {
				counts[entry.AttackType]++
				if entry.BodySnippet != "" {
					t.Fatal("rejected body retained as inspected text")
				}
			}
			if counts[test.attackType] != 1 || counts[test.rejection] != 1 {
				t.Fatalf("events = %v", counts)
			}
		})
	}
}

// Detect XML entities in uploaded text files
func TestMultipartTextUploadDetection(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("document", "document.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(`<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	found := detectAttacks(detectionInput{Body: body.String(), Header: http.Header{"Content-Type": {writer.FormDataContentType()}}})
	for _, item := range found {
		if item.AttackType == "XML Entity" && item.Confidence == confidenceHigh {
			return
		}
	}
	t.Fatalf("missing XML detection in %+v", found)
}

// eventTestSink provides a test writer for the logger
type eventTestSink func([]byte) (int, error)

// Let tests block or fail log writes
func (sink eventTestSink) Write(data []byte) (int, error) { return sink(data) }

// Check queue limits and shutdown when stdout is blocked
func TestEventWriterBackpressure(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var output bytes.Buffer
	sink := eventTestSink(func(data []byte) (int, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		return output.Write(data)
	})
	drops := make(chan string, 3)
	writer := newEventWriter(log.New(sink, "", 0), 1, func(reason string) { drops <- reason })
	writer.enqueue("info", LogEntry{Path: "/first"})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("output worker did not start")
	}
	// Fail if enqueue waits for stdout
	enqueued := make(chan struct{})
	go func() {
		writer.enqueue("info", LogEntry{Path: "/second"})
		writer.enqueue("info", LogEntry{Path: "/dropped"})
		close(enqueued)
	}()
	select {
	case <-enqueued:
	case <-time.After(time.Second):
		t.Fatal("producer blocked on output")
	}
	select {
	case reason := <-drops:
		if reason != "queue_full" {
			t.Fatalf("drop reason = %q", reason)
		}
	default:
		t.Fatal("missing queue saturation accounting")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer.shutdown(ctx)
	writer.enqueue("info", LogEntry{})
	select {
	case reason := <-drops:
		if reason != "shutdown" {
			t.Fatalf("drop reason = %q", reason)
		}
	default:
		t.Fatal("missing shutdown accounting")
	}
	unblock()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	writer.shutdown(ctx)
	select {
	case <-writer.done:
	default:
		t.Fatal("output worker did not drain")
	}
	if text := output.String(); strings.Count(text, "level=info") != 2 || strings.Index(text, "/first") >= strings.Index(text, "/second") {
		t.Fatalf("unexpected output: %q", text)
	}
}

// Count failed log writes
func TestEventWriterOutputFailure(t *testing.T) {
	drops := make(chan string, 1)
	sink := eventTestSink(func([]byte) (int, error) { return 0, errors.New("output unavailable") })
	writer := newEventWriter(log.New(sink, "", 0), 1, func(reason string) { drops <- reason })
	writer.enqueue("info", LogEntry{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	writer.shutdown(ctx)
	select {
	case reason := <-drops:
		if reason != "write_error" {
			t.Fatalf("drop reason = %q", reason)
		}
	default:
		t.Fatal("missing output failure accounting")
	}
}

// Fuzz decoding limits and UTF8 validity
func FuzzDetectionDecoding(f *testing.F) {
	for _, seed := range []string{"", "%252fetc%252fpasswd", "&#x3c;script&#x3e;", "data:text/html;base64,PHNjcmlwdD4=", "\xff\x00", strings.Repeat("%25", maxDetectionSourceSize)} {
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, value string, plusAsSpace bool) {
		value = value[:min(len(value), maxDetectionSourceSize)]
		variants, xssVariants := decodeFieldVariants(context.Background(), "", value, plusAsSpace)
		for _, group := range [][]string{variants, xssVariants} {
			if len(group) > maxNormalizationVariants {
				t.Fatalf("variant count = %d", len(group))
			}
			for _, variant := range group {
				if len(variant) > maxCanonicalSourceSize || !utf8.ValidString(variant) {
					t.Fatalf("invalid canonical variant of %d bytes", len(variant))
				}
			}
		}
	})
}
