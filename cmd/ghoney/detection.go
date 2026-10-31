package main

import (
	"context"
	"net/http"
)

// detection holds one attack class and a bounded explanation
type detection struct {
	AttackType string
	Details    string
	Confidence confidence
	Source     string
	Sample     string
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
	ctx         context.Context
	variants    []string
	xssVariants []string
}

// Stop matching variants when their request has expired
func (source detectionSource) expired() bool {
	return source.ctx != nil && source.ctx.Err() != nil
}

// detectionMatch preserves the normalized evidence selected by a detector
type detectionMatch struct {
	source string
	sample string
}

// Return one event per family with the strongest confidence
func detectAttacks(input detectionInput) []detection {
	return detectAttacksContext(context.Background(), input)
}

// Stop between fields and families when the request expires
func detectAttacksContext(ctx context.Context, input detectionInput) []detection {
	sources := buildDetectionSourcesContext(ctx, input)
	rules := []struct {
		name    string
		details string
		match   func([]detectionSource) (detectionMatch, confidence)
	}{
		{"Path Traversal", "Detected traversal sequence in ", func(sources []detectionSource) (detectionMatch, confidence) {
			match, ok := firstRegexMatch(sources, pathTraversalRegex)
			if ok {
				return match, confidenceHigh
			}
			return detectionMatch{}, ""
		}},
		{"SQL Injection", "Detected SQL injection pattern in ", firstSQLMatch},
		{"XML Entity", "Detected external or expansive XML construct in ", func(sources []detectionSource) (detectionMatch, confidence) {
			match, ok := firstXMLMatch(sources)
			if ok {
				return match, confidenceHigh
			}
			return detectionMatch{}, ""
		}},
		{"Command Injection", "Detected command execution pattern in ", firstCommandMatch},
		{"SSRF", "Detected private or local target in ", firstSSRFMatch},
		{"LFI/RFI", "Detected local or remote file inclusion in ", firstFileInclusionMatch},
		{"XSS", "Detected executable browser content in ", firstXSSMatch},
		{"JNDI Injection", "Detected JNDI lookup expression in ", firstJNDIMatch},
		{"NoSQL Injection", "Detected explicit NoSQL operator in ", firstNoSQLMatch},
	}
	detections := make([]detection, 0, len(rules))
	for _, rule := range rules {
		if ctx.Err() != nil {
			return detections
		}
		match, value := rule.match(sources)
		if value != "" {
			detections = append(detections, detection{
				AttackType: rule.name,
				Details:    rule.details + match.source,
				Confidence: value,
				Source:     match.source,
				Sample:     match.sample,
			})
		}
	}
	return detections
}
