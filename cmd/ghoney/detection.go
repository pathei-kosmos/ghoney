package main

import "net/http"

// detection holds one attack class and a bounded explanation
type detection struct {
	AttackType string
	Details    string
	Confidence confidence
}

// confidence keeps logs and metric labels within known values
type confidence string

const (
	confidenceMedium confidence = "medium"
	confidenceHigh   confidence = "high"
)

// detectionInput keeps request fields separate during matching
type detectionInput struct {
	Path     string
	RawQuery string
	Body     string
	Host     string
	Header   http.Header
}

// detectionSource holds bounded forms of one request field
type detectionSource struct {
	name        string
	variants    []string
	xssVariants []string
}

// Return one event per family with the strongest confidence
func detectAttacks(input detectionInput) []detection {
	sources := buildDetectionSources(input)
	detections := make([]detection, 0, 9)

	if source, ok := firstRegexMatch(sources, pathTraversalRegex); ok {
		detections = append(detections, detection{
			AttackType: "Path Traversal",
			Details:    "Detected traversal sequence in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstSQLMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "SQL Injection",
			Details:    "Detected SQL injection pattern in " + source,
			Confidence: value,
		})
	}
	if source, ok := firstXMLMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "XML Entity",
			Details:    "Detected external or expansive XML construct in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstCommandMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "Command Injection",
			Details:    "Detected command execution pattern in " + source,
			Confidence: value,
		})
	}
	if source, value := firstSSRFMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "SSRF",
			Details:    "Detected private or local target in " + source,
			Confidence: value,
		})
	}
	if source, ok := firstFileInclusionMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "LFI/RFI",
			Details:    "Detected local or remote file inclusion in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstXSSMatch(sources); value != "" {
		detections = append(detections, detection{
			AttackType: "XSS",
			Details:    "Detected executable browser content in " + source,
			Confidence: value,
		})
	}
	if source, ok := firstJNDIMatch(sources); ok {
		detections = append(detections, detection{
			AttackType: "JNDI Injection",
			Details:    "Detected JNDI lookup expression in " + source,
			Confidence: confidenceHigh,
		})
	}
	if source, value := firstNoSQLMatch(input); value != "" {
		detections = append(detections, detection{
			AttackType: "NoSQL Injection",
			Details:    "Detected explicit NoSQL operator in " + source,
			Confidence: value,
		})
	}
	return detections
}
